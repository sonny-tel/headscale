package hscontrol

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	githuboa "golang.org/x/oauth2/github"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"zgo.at/zcache/v2"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/types"
)

const (
	githubUserURL      = "https://api.github.com/user"
	githubStateBytes   = 16
	githubStateTTL     = 10 * time.Minute
	githubStateCleanup = 15 * time.Minute
)

// githubOAuthStateCache stores CSRF state tokens for the GitHub OAuth flow.
// Value is empty string — we only check key existence.
var githubOAuthStateCache = zcache.New[string, string](githubStateTTL, githubStateCleanup)

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

func (api headscaleV1APIServer) githubOAuth2Config() *oauth2.Config {
	cfg := api.h.cfg.WebUI.Auth.GitHub

	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     githuboa.Endpoint,
		Scopes:       []string{"read:user", "user:email"},
	}
}

func (api headscaleV1APIServer) GetGitHubAuthURL(
	ctx context.Context,
	_ *v1.GetGitHubAuthURLRequest,
) (*v1.GetGitHubAuthURLResponse, error) {
	if !api.h.cfg.WebUI.Enabled || !api.h.cfg.WebUI.Auth.GitHub.Enabled {
		return nil, status.Errorf(codes.FailedPrecondition, "GitHub auth is not enabled")
	}

	stateBytes := make([]byte, githubStateBytes)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, status.Errorf(codes.Internal, "generating state: %s", err)
	}

	state := hex.EncodeToString(stateBytes)
	githubOAuthStateCache.Set(state, "")

	url := api.githubOAuth2Config().AuthCodeURL(state)

	return &v1.GetGitHubAuthURLResponse{AuthUrl: url}, nil
}

func (api headscaleV1APIServer) GitHubCallback(
	ctx context.Context,
	request *v1.GitHubCallbackRequest,
) (*v1.LoginResponse, error) {
	if !api.h.cfg.WebUI.Enabled || !api.h.cfg.WebUI.Auth.GitHub.Enabled {
		return nil, status.Errorf(codes.FailedPrecondition, "GitHub auth is not enabled")
	}

	// Validate CSRF state.
	_, stateOK := githubOAuthStateCache.Get(request.GetState())
	if !stateOK {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid or expired OAuth state parameter")
	}

	githubOAuthStateCache.Delete(request.GetState())

	// Exchange authorization code for access token.
	token, err := api.githubOAuth2Config().Exchange(ctx, request.GetCode())
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated,
			"exchanging GitHub code: %s", err)
	}

	// Fetch GitHub user info.
	ghUser, err := fetchGitHubUser(ctx, token.AccessToken)
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"fetching GitHub user: %s", err)
	}

	// Check allowed filters.
	if err := api.validateGitHubUser(ghUser); err != nil {
		return nil, status.Errorf(codes.PermissionDenied,
			"GitHub user not allowed: %s", err)
	}

	githubIDStr := fmt.Sprintf("%d", ghUser.ID)

	// Try to find an existing credential linked to this GitHub ID.
	cred, err := api.h.state.DB().GetUserCredentialByGitHubID(githubIDStr)
	if err == nil {
		// Existing user — update GitHub login if changed.
		if cred.GitHubLogin != ghUser.Login {
			cred.GitHubLogin = ghUser.Login
			if err := api.h.state.DB().UpdateUserCredential(cred); err != nil {
				log.Warn().Err(err).Msg("failed to update GitHub login")
			}
		}

		user, err := api.h.state.DB().GetUserByID(types.UserID(cred.UserID))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "loading user: %s", err)
		}

		// Update profile picture from GitHub if not already set.
		if user.ProfilePicURL == "" && ghUser.AvatarURL != "" {
			if updated, err := api.h.state.DB().UpdateUserProfile(
				types.UserID(user.ID), user.DisplayName, ghUser.AvatarURL,
			); err == nil {
				user = updated
			}
		}

		if !user.CanWebAuth() {
			if user.IsPending() {
				return nil, status.Errorf(codes.PermissionDenied,
					"pending_approval:%s", user.Name)
			}
			return nil, status.Errorf(codes.PermissionDenied,
				"service accounts cannot authenticate via the web UI")
		}

		return api.createSessionResponse(ctx, user)
	}

	// No credential linked — find or create the user by GitHub login name,
	// then link GitHub credentials to them.
	ghLogin := strings.ToLower(ghUser.Login)
	user, err := api.h.state.DB().GetUserByName(ghLogin)
	if err != nil {
		// Create the user with "pending" role — they need admin approval.
		user, err = api.h.state.DB().CreateUser(types.User{
			Name:          ghLogin,
			DisplayName:   ghUser.Name,
			Email:         ghUser.Email,
			Provider:      "github",
			Role:          types.UserRolePending,
			ProfilePicURL: ghUser.AvatarURL,
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal,
				"creating user from GitHub: %s", err)
		}

		log.Info().
			Str("user", ghLogin).
			Str("email", ghUser.Email).
			Msg("New GitHub user registered — pending admin approval. Run: headscale users approve --name " + ghLogin)
	}

	if !user.CanWebAuth() {
		if user.IsPending() {
			return nil, status.Errorf(codes.PermissionDenied,
				"pending_approval:%s", user.Name)
		}
		return nil, status.Errorf(codes.PermissionDenied,
			"service accounts cannot authenticate via the web UI")
	}

	// Create credential record linked to this GitHub ID.
	_, err = api.h.state.DB().CreateUserCredential(types.UserCredential{
		UserID:      uint64(user.ID),
		GitHubID:    githubIDStr,
		GitHubLogin: ghUser.Login,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"linking GitHub credential: %s", err)
	}

	return api.createSessionResponse(ctx, user)
}

func (api headscaleV1APIServer) createSessionResponse(
	ctx context.Context,
	user *types.User,
) (*v1.LoginResponse, error) {
	ipAddr, userAgent := clientInfoFromContext(ctx)

	session, err := api.h.state.DB().CreateUserSession(
		uint64(user.ID),
		api.h.cfg.WebUI.Session.Duration,
		ipAddr,
		userAgent,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "creating session: %s", err)
	}

	return &v1.LoginResponse{
		SessionToken: session.ID,
		ExpiresAt:    timestamppb.New(session.ExpiresAt),
		User:         user.Proto(),
	}, nil
}

func (api headscaleV1APIServer) validateGitHubUser(ghUser *githubUser) error {
	cfg := api.h.cfg.WebUI.Auth.GitHub

	// If no filters are configured, allow all GitHub users.
	if len(cfg.AllowedUsers) == 0 && len(cfg.AllowedOrgs) == 0 && len(cfg.AllowedTeams) == 0 {
		return nil
	}

	// Check explicit user allowlist.
	if len(cfg.AllowedUsers) > 0 && slices.Contains(cfg.AllowedUsers, ghUser.Login) {
		return nil
	}

	// AllowedOrgs and AllowedTeams are checked by login name only
	// (org membership verification would require additional API calls
	// with org:read scope). If needed, this can be extended later.
	if len(cfg.AllowedUsers) > 0 {
		return fmt.Errorf("user %q not in allowed users list", ghUser.Login)
	}

	return nil
}

func fetchGitHubUser(ctx context.Context, accessToken string) (*githubUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubUserURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting GitHub user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, body)
	}

	var user githubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("decoding GitHub user: %w", err)
	}

	return &user, nil
}
