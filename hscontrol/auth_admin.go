package hscontrol

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

const (
	bcryptCost        = 12
	sessionCookiePath = "/"
)

// --- User Role & Credentials ---

func (api headscaleV1APIServer) SetUserRole(
	ctx context.Context,
	request *v1.SetUserRoleRequest,
) (*v1.SetUserRoleResponse, error) {
	// Try web session auth first. If no session token is present,
	// the caller is using the CLI (unix socket or API key) which is
	// already authenticated by the gRPC interceptor — allow it through.
	caller, err := api.authenticatedWebUser(ctx)
	if err != nil {
		token := sessionTokenFromContext(ctx)
		if token != "" {
			// A session token was provided but invalid — reject.
			return nil, err
		}
		// No session token: CLI caller, already authenticated by interceptor.
	} else {
		// Web session: only admins can change roles.
		if caller.Role != types.UserRoleAdmin {
			return nil, status.Errorf(codes.PermissionDenied, "only admins can change roles")
		}
	}

	role := request.GetRole()
	switch role {
	case types.UserRoleAdmin,
		types.UserRoleNetworkAdmin, types.UserRoleITAdmin,
		types.UserRoleMember, types.UserRoleServiceAccount,
		types.UserRolePending:
	default:
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid role %q; must be admin, network_admin, it_admin, member, pending, or service_account", role)
	}

	if err := api.h.state.DB().SetUserRole(request.GetId(), role); err != nil {
		return nil, status.Errorf(codes.Internal, "setting role: %s", err)
	}

	// Re-fetch the user to return updated state.
	users, err := api.h.state.DB().ListUsers()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fetching user: %s", err)
	}

	for _, u := range users {
		if uint64(u.ID) == request.GetId() {
			return &v1.SetUserRoleResponse{User: u.Proto()}, nil
		}
	}

	return nil, status.Errorf(codes.NotFound, "user not found")
}

func (api headscaleV1APIServer) SetUserCredentials(
	ctx context.Context,
	request *v1.SetUserCredentialsRequest,
) (*v1.SetUserCredentialsResponse, error) {
	caller, err := api.authenticatedWebUser(ctx)
	if err != nil {
		token := sessionTokenFromContext(ctx)
		if token != "" {
			// A session token was provided but invalid — reject.
			return nil, err
		}
		// No session token: CLI caller, already authenticated by interceptor.
	} else {
		// Web session: only admins/owners can set credentials for other users.
		if uint64(caller.ID) != request.GetUserId() && !caller.IsAdmin() {
			return nil, status.Errorf(codes.PermissionDenied, "insufficient permissions")
		}
	}

	targetID := request.GetUserId()
	password := request.GetPassword()
	minPwLen := api.h.cfg.WebUI.Auth.Local.MinPasswordLength
	if len(password) < minPwLen {
		return nil, status.Errorf(
			codes.InvalidArgument,
			"password must be at least %d characters", minPwLen,
		)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "hashing password: %s", err)
	}

	// Try to get existing credential; create if not found.
	cred, err := api.h.state.DB().GetUserCredential(targetID)
	if err != nil {
		// No credential yet — create one.
		_, err = api.h.state.DB().CreateUserCredential(types.UserCredential{
			UserID:       targetID,
			PasswordHash: string(hash),
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "creating credential: %s", err)
		}

		return &v1.SetUserCredentialsResponse{}, nil
	}

	// Update existing credential.
	cred.PasswordHash = string(hash)
	if err := api.h.state.DB().UpdateUserCredential(cred); err != nil {
		return nil, status.Errorf(codes.Internal, "updating credential: %s", err)
	}

	return &v1.SetUserCredentialsResponse{}, nil
}

// --- Password Authentication ---

func (api headscaleV1APIServer) LoginWithPassword(
	ctx context.Context,
	request *v1.LoginWithPasswordRequest,
) (*v1.LoginResponse, error) {
	if !api.h.cfg.WebUI.Enabled || !api.h.cfg.WebUI.Auth.Local.Enabled {
		return nil, status.Errorf(codes.FailedPrecondition, "local auth is not enabled")
	}

	// Find user by name.
	users, err := api.h.state.DB().ListUsers()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "listing users: %s", err)
	}

	var user *types.User
	for i := range users {
		if users[i].Name == request.GetUsername() {
			user = &users[i]

			break
		}
	}

	if user == nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	// Service accounts cannot web-auth.
	if !user.CanWebAuth() {
		return nil, status.Errorf(codes.PermissionDenied,
			"service accounts cannot authenticate via the web UI")
	}

	// Get credential record.
	cred, err := api.h.state.DB().GetUserCredential(uint64(user.ID))
	if err != nil {
		// No credential → can't password-auth.
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	// Check lockout.
	if cred.LockedUntil != nil && time.Now().UTC().Before(*cred.LockedUntil) {
		return nil, status.Errorf(codes.ResourceExhausted,
			"account locked until %s", cred.LockedUntil.Format(time.RFC3339))
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(cred.PasswordHash), []byte(request.GetPassword()),
	); err != nil {
		api.recordLoginFailure(cred)

		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	// Successful password — reset failed attempts.
	if err := api.h.state.DB().ResetFailedLogins(uint64(user.ID)); err != nil {
		log.Warn().Err(err).Msg("failed to reset login attempts")
	}

	api.h.state.DB().LogAuditEvent("user.login", user.Name, "user", user.Name, "password login")

	// If OTP is enabled, return partial response.
	if cred.OTPEnabled && cred.OTPSecret != "" {
		return &v1.LoginResponse{
			OtpRequired: true,
			User:        user.Proto(),
		}, nil
	}

	return api.createSessionResponse(ctx, user)
}

// --- OTP ---

func (api headscaleV1APIServer) SetupOTP(
	ctx context.Context,
	_ *v1.SetupOTPRequest,
) (*v1.SetupOTPResponse, error) {
	if !api.h.cfg.WebUI.Auth.Local.OTP.Enabled {
		return nil, status.Errorf(codes.FailedPrecondition, "OTP is not enabled")
	}

	user, err := api.authenticatedWebUser(ctx)
	if err != nil {
		return nil, err
	}

	cred, err := api.h.state.DB().GetUserCredential(uint64(user.ID))
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"no credentials found — set a password first")
	}

	otpCfg := api.h.cfg.WebUI.Auth.Local.OTP
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      otpCfg.Issuer,
		AccountName: user.Username(),
		Digits:      otpDigits(otpCfg.Digits),
		Period:      uint(otpCfg.Period),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generating OTP key: %s", err)
	}

	cred.OTPSecret = key.Secret()
	if err := api.h.state.DB().UpdateUserCredential(cred); err != nil {
		return nil, status.Errorf(codes.Internal, "saving OTP secret: %s", err)
	}

	return &v1.SetupOTPResponse{
		Secret: key.Secret(),
		OtpUrl: key.URL(),
	}, nil
}

func (api headscaleV1APIServer) VerifyOTP(
	ctx context.Context,
	request *v1.VerifyOTPRequest,
) (*v1.LoginResponse, error) {
	user, err := api.authenticatedWebUser(ctx)
	if err != nil {
		return nil, err
	}

	cred, err := api.h.state.DB().GetUserCredential(uint64(user.ID))
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "no credentials found")
	}

	if cred.OTPSecret == "" {
		return nil, status.Errorf(codes.FailedPrecondition, "OTP not set up")
	}

	otpCfg := api.h.cfg.WebUI.Auth.Local.OTP
	valid := totp.Validate(request.GetCode(), cred.OTPSecret)
	if !valid {
		valid, _ = totp.ValidateCustom(
			request.GetCode(), cred.OTPSecret, time.Now().UTC(),
			totp.ValidateOpts{
				Digits: otpDigits(otpCfg.Digits),
				Period: uint(otpCfg.Period),
			},
		)
	}

	if !valid {
		return nil, status.Errorf(codes.Unauthenticated, "invalid OTP code")
	}

	// Enable OTP on first successful verification.
	if !cred.OTPEnabled {
		cred.OTPEnabled = true
		if err := api.h.state.DB().UpdateUserCredential(cred); err != nil {
			log.Warn().Err(err).Msg("failed to enable OTP flag")
		}
	}

	return api.createSessionResponse(ctx, user)
}

func (api headscaleV1APIServer) ChangePassword(
	ctx context.Context,
	request *v1.ChangePasswordRequest,
) (*v1.ChangePasswordResponse, error) {
	user, err := api.authenticatedWebUser(ctx)
	if err != nil {
		return nil, err
	}

	cred, err := api.h.state.DB().GetUserCredential(uint64(user.ID))
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "no credentials found")
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(cred.PasswordHash), []byte(request.GetCurrentPassword()),
	); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "current password is incorrect")
	}

	minPwLen := api.h.cfg.WebUI.Auth.Local.MinPasswordLength
	if len(request.GetNewPassword()) < minPwLen {
		return nil, status.Errorf(
			codes.InvalidArgument,
			"new password must be at least %d characters", minPwLen,
		)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(request.GetNewPassword()), bcryptCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "hashing password: %s", err)
	}

	cred.PasswordHash = string(hash)
	if err := api.h.state.DB().UpdateUserCredential(cred); err != nil {
		return nil, status.Errorf(codes.Internal, "updating password: %s", err)
	}

	return &v1.ChangePasswordResponse{}, nil
}

// --- Session Management ---

func (api headscaleV1APIServer) ValidateSession(
	ctx context.Context,
	_ *v1.ValidateSessionRequest,
) (*v1.ValidateSessionResponse, error) {
	user, err := api.authenticatedWebUser(ctx)
	if err != nil {
		return nil, err
	}

	return &v1.ValidateSessionResponse{
		User: user.Proto(),
	}, nil
}

func (api headscaleV1APIServer) RefreshSession(
	ctx context.Context,
	_ *v1.RefreshSessionRequest,
) (*v1.LoginResponse, error) {
	user, err := api.authenticatedWebUser(ctx)
	if err != nil {
		return nil, err
	}

	return api.createSessionResponse(ctx, user)
}

func (api headscaleV1APIServer) WebAuthLogout(
	ctx context.Context,
	_ *v1.LogoutRequest,
) (*v1.LogoutResponse, error) {
	token := sessionTokenFromContext(ctx)
	if token != "" {
		if err := api.h.state.DB().DeleteUserSession(token); err != nil {
			log.Warn().Err(err).Msg("failed to delete session on logout")
		}
	}

	return &v1.LogoutResponse{}, nil
}

// --- Registration Auth Methods ---

func (api headscaleV1APIServer) GetRegistrationAuthMethods(
	ctx context.Context,
	_ *v1.GetRegistrationAuthMethodsRequest,
) (*v1.GetRegistrationAuthMethodsResponse, error) {
	return &v1.GetRegistrationAuthMethodsResponse{
		LocalAuthEnabled:  api.h.cfg.WebUI.Auth.Local.Enabled,
		GithubAuthEnabled: api.h.cfg.WebUI.Auth.GitHub.Enabled,
	}, nil
}

func (api headscaleV1APIServer) ApproveRegistration(
	ctx context.Context,
	request *v1.ApproveRegistrationRequest,
) (*v1.ApproveRegistrationResponse, error) {
	caller, err := api.authenticatedWebUser(ctx)
	if err != nil {
		return nil, err
	}

	if !caller.IsAdmin() {
		return nil, status.Errorf(codes.PermissionDenied, "admin role required")
	}

	authID := request.GetAuthId()
	if authID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "auth_id is required")
	}

	// Determine which user should own the newly registered node.
	// The frontend may send a user name via the Grpc-Metadata-X-Assign-User
	// header; otherwise, fall back to the admin caller.
	ownerUser := caller
	if md, ok := grpcMetadata(ctx); ok {
		if vals := md.Get("x-assign-user"); len(vals) > 0 && vals[0] != "" {
			u, err := api.h.state.GetUserByName(vals[0])
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "user %q not found", vals[0])
			}
			ownerUser = u
		}
	}

	registrationId, err := types.AuthIDFromString(authID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid auth_id: %v", err)
	}

	node, nodeChange, err := api.h.state.HandleNodeFromAuthPath(
		registrationId,
		types.UserID(ownerUser.ID),
		nil,
		util.RegisterMethodCLI,
	)
	if err != nil {
		return nil, err
	}

	routeChange, err := api.h.state.AutoApproveRoutes(node)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "auto approving routes: %v", err)
	}

	api.h.Change(nodeChange, routeChange)

	api.h.state.DB().LogAuditEvent("node.approved", caller.Name, "node", authID, fmt.Sprintf("approved by %s, assigned to %s", caller.Name, ownerUser.Name))

	return &v1.ApproveRegistrationResponse{}, nil
}

// --- Helpers ---

func (api headscaleV1APIServer) recordLoginFailure(cred *types.UserCredential) {
	cfg := api.h.cfg.WebUI.Auth.Local
	attempts := cred.FailedLoginAttempts + 1

	var lockUntil *time.Time
	if attempts >= cfg.MaxLoginAttempts {
		t := time.Now().UTC().Add(cfg.LockoutDuration)
		lockUntil = &t
	}

	if err := api.h.state.DB().RecordFailedLogin(cred.UserID, lockUntil); err != nil {
		log.Warn().Err(err).Msg("failed to record login failure")
	}
}

// authenticatedWebUser extracts the session token from gRPC metadata
// and returns the authenticated user. Service accounts are rejected.
func (api headscaleV1APIServer) authenticatedWebUser(
	ctx context.Context,
) (*types.User, error) {
	token := sessionTokenFromContext(ctx)
	if token == "" {
		return nil, status.Errorf(codes.Unauthenticated, "session token required")
	}

	session, err := api.h.state.DB().ValidateUserSession(token)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid or expired session")
	}

	if !session.User.CanWebAuth() {
		return nil, status.Errorf(codes.PermissionDenied,
			"service accounts cannot use the web UI")
	}

	return &session.User, nil
}

// sessionTokenFromContext extracts the web UI session token from gRPC metadata.
// Looks for the session cookie or an explicit "x-session-token" header.
func sessionTokenFromContext(ctx context.Context) string {
	md, ok := grpcMetadata(ctx)
	if !ok {
		return ""
	}

	// Cookie header forwarded from gRPC-gateway.
	if cookies := md.Get("grpcgateway-cookie"); len(cookies) > 0 {
		header := http.Header{}
		for _, c := range cookies {
			header.Add("Cookie", c)
		}

		req := http.Request{Header: header}
		if cookie, err := req.Cookie("hs_session"); err == nil {
			return cookie.Value
		}
	}

	// Explicit header.
	if tokens := md.Get("x-session-token"); len(tokens) > 0 {
		return tokens[0]
	}

	return ""
}

func clientInfoFromContext(ctx context.Context) (string, string) {
	md, ok := grpcMetadata(ctx)
	if !ok {
		return "", ""
	}

	var ipAddr, userAgent string

	if vals := md.Get("x-forwarded-for"); len(vals) > 0 {
		ipAddr = vals[0]
	}

	if vals := md.Get("grpcgateway-user-agent"); len(vals) > 0 {
		userAgent = vals[0]
	}

	return ipAddr, userAgent
}

func grpcMetadata(ctx context.Context) (metadata.MD, bool) {
	return metadata.FromIncomingContext(ctx)
}

func otpDigits(d int) otp.Digits {
	if d == 8 {
		return otp.DigitsEight
	}

	return otp.DigitsSix
}
