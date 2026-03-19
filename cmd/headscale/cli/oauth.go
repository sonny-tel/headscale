package cli

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(oauthCmd)
	oauthCmd.AddCommand(oauthListClientsCmd)

	oauthCreateClientCmd.Flags().StringSliceP("scopes", "s", nil,
		`Scopes for the OAuth client (comma-separated: "auth_keys,devices:core,services")`)
	mustMarkRequired(oauthCreateClientCmd, "scopes")
	oauthCreateClientCmd.Flags().StringP("expiration", "e", "",
		"Expiration time in RFC3339 format (e.g. 2025-12-31T23:59:59Z). Empty = no expiration")
	oauthCmd.AddCommand(oauthCreateClientCmd)

	oauthDeleteClientCmd.Flags().Uint64P("id", "i", 0, "OAuth client ID to delete")
	mustMarkRequired(oauthDeleteClientCmd, "id")
	oauthCmd.AddCommand(oauthDeleteClientCmd)
}

var oauthCmd = &cobra.Command{
	Use:     "oauth",
	Short:   "Manage OAuth clients for the Tailscale-compatible v2 API",
	Aliases: []string{"oauth-client"},
}

// oauthHTTPClient builds an HTTP client and base URL from CLI config.
func oauthHTTPClient() (*http.Client, string, string, error) {
	cfg, err := types.LoadCLIConfig()
	if err != nil {
		return nil, "", "", fmt.Errorf("loading config: %w", err)
	}

	apiKey := cfg.CLI.APIKey
	if apiKey == "" {
		return nil, "", "", fmt.Errorf("HEADSCALE_CLI_API_KEY or cli.api_key must be set")
	}

	address := cfg.CLI.Address
	if address == "" {
		return nil, "", "", fmt.Errorf("cli.address must be set for OAuth management")
	}

	scheme := "https"
	transport := &http.Transport{}
	if cfg.CLI.Insecure {
		transport.TLSClientConfig = &tls.Config{
			//nolint:gosec // User explicitly opted into insecure mode
			InsecureSkipVerify: true,
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.CLI.Timeout,
	}

	baseURL := fmt.Sprintf("%s://%s", scheme, address)

	return client, baseURL, apiKey, nil
}

// oauthDoRequest executes an HTTP request against the headscale server.
func oauthDoRequest(method, path string, body any) ([]byte, int, error) {
	client, baseURL, apiKey, err := oauthHTTPClient()
	if err != nil {
		return nil, 0, err
	}

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshalling request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	url := baseURL + path
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	log.Trace().Str("method", method).Str("url", url).Msg("OAuth CLI request")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

var oauthListClientsCmd = &cobra.Command{
	Use:     "list",
	Short:   "List OAuth clients",
	Aliases: []string{"ls", "show"},
	RunE: func(cmd *cobra.Command, args []string) error {
		respBody, status, err := oauthDoRequest("GET", "/api/v1/oauth/clients", nil)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("server returned %d: %s", status, string(respBody))
		}

		var result struct {
			Clients []struct {
				ID         uint64   `json:"id"`
				ClientID   string   `json:"client_id"`
				Scopes     []string `json:"scopes"`
				CreatedAt  string   `json:"created_at"`
				Expiration string   `json:"expiration"`
			} `json:"clients"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		format, _ := cmd.Flags().GetString("output")
		if format == outputFormatJSON || format == outputFormatJSONLine || format == outputFormatYAML {
			out, err := formatOutput(result, "", format)
			if err != nil {
				return err
			}
			fmt.Println(out)
			return nil
		}

		if len(result.Clients) == 0 {
			fmt.Println("No OAuth clients found.")
			return nil
		}

		tableData := pterm.TableData{
			{"ID", "Client ID", "Scopes", "Expiration", "Created"},
		}
		for _, c := range result.Clients {
			expiration := "never"
			if c.Expiration != "" {
				expiration = c.Expiration
			}
			created := c.CreatedAt
			scopes := ""
			for i, s := range c.Scopes {
				if i > 0 {
					scopes += ", "
				}
				scopes += s
			}
			tableData = append(tableData, []string{
				strconv.FormatUint(c.ID, 10),
				c.ClientID,
				scopes,
				expiration,
				created,
			})
		}

		return pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
	},
}

var oauthCreateClientCmd = &cobra.Command{
	Use:     "create",
	Short:   "Create a new OAuth client",
	Aliases: []string{"c", "new"},
	RunE: func(cmd *cobra.Command, args []string) error {
		scopes, err := cmd.Flags().GetStringSlice("scopes")
		if err != nil {
			return fmt.Errorf("getting scopes flag: %w", err)
		}

		expirationStr, _ := cmd.Flags().GetString("expiration")

		reqBody := map[string]any{
			"scopes": scopes,
		}
		if expirationStr != "" {
			// Validate the expiration format
			if _, err := time.Parse(time.RFC3339, expirationStr); err != nil {
				return fmt.Errorf("invalid expiration format (use RFC3339, e.g. 2025-12-31T23:59:59Z): %w", err)
			}
			reqBody["expiration"] = expirationStr
		}

		respBody, status, err := oauthDoRequest("POST", "/api/v1/oauth/clients", reqBody)
		if err != nil {
			return err
		}
		if status != http.StatusCreated {
			return fmt.Errorf("server returned %d: %s", status, string(respBody))
		}

		var result struct {
			ClientID     string   `json:"client_id"`
			ClientSecret string   `json:"client_secret"`
			Scopes       []string `json:"scopes"`
			Expiration   string   `json:"expiration"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		format, _ := cmd.Flags().GetString("output")
		if format == outputFormatJSON || format == outputFormatJSONLine || format == outputFormatYAML {
			out, err := formatOutput(result, "", format)
			if err != nil {
				return err
			}
			fmt.Println(out)
			return nil
		}

		fmt.Println()
		pterm.Success.Println("OAuth client created successfully!")
		fmt.Println()
		fmt.Printf("  Client ID:     %s\n", result.ClientID)
		fmt.Printf("  Client Secret: %s\n", result.ClientSecret)
		fmt.Println()
		pterm.Warning.Println("Save the client secret now — it cannot be retrieved later.")
		fmt.Println()
		fmt.Println("To use with the Tailscale K8s operator:")
		fmt.Printf("  CLIENT_ID_FILE:     Write '%s' to this file\n", result.ClientID)
		fmt.Printf("  CLIENT_SECRET_FILE: Write '%s' to this file\n", result.ClientSecret)

		return nil
	},
}

var oauthDeleteClientCmd = &cobra.Command{
	Use:     "delete",
	Short:   "Delete an OAuth client",
	Aliases: []string{"rm", "remove"},
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := cmd.Flags().GetUint64("id")
		if err != nil {
			return fmt.Errorf("getting id flag: %w", err)
		}

		path := fmt.Sprintf("/api/v1/oauth/clients/%d", id)
		respBody, status, err := oauthDoRequest("DELETE", path, nil)
		if err != nil {
			return err
		}

		if status != http.StatusOK {
			return fmt.Errorf("server returned %d: %s", status, string(respBody))
		}

		pterm.Success.Printf("OAuth client %d deleted.\n", id)
		return nil
	},
}
