package cli

import (
	"context"
	"fmt"
	"os"
	"strconv"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func init() {
	userCmd.AddCommand(setRoleCmd)
	setRoleCmd.Flags().Uint64P("identifier", "i", 0, "User identifier (ID)")
	mustMarkRequired(setRoleCmd, "identifier")
	setRoleCmd.Flags().StringP("role", "r", "", "New role (admin, network_admin, it_admin, member, service_account)")
	mustMarkRequired(setRoleCmd, "role")

	userCmd.AddCommand(setCredentialsCmd)
	setCredentialsCmd.Flags().Uint64P("identifier", "i", 0, "User identifier (ID)")
	mustMarkRequired(setCredentialsCmd, "identifier")
}

var setRoleCmd = &cobra.Command{
	Use:   "set-role --identifier ID --role ROLE",
	Short: "Set the role for a user",
	Long:  "Set the role for a user. Valid roles: admin, network_admin, it_admin, member, service_account.",
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetUint64("identifier")
		role, _ := cmd.Flags().GetString("role")

		response, err := client.SetUserRole(ctx, &v1.SetUserRoleRequest{
			Id:   id,
			Role: role,
		})
		if err != nil {
			return fmt.Errorf("setting role: %w", err)
		}

		return printOutput(cmd, response.GetUser(), fmt.Sprintf(
			"Role set to %q for user %s (ID %s)",
			role,
			response.GetUser().GetName(),
			strconv.FormatUint(response.GetUser().GetId(), util.Base10),
		))
	}),
}

var setCredentialsCmd = &cobra.Command{
	Use:   "set-credentials --identifier ID",
	Short: "Set web UI login credentials for a user",
	Long:  "Set or update the password for a user's web UI credentials. Reads password from stdin.",
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetUint64("identifier")

		fmt.Print("Enter new password: ")

		passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("reading password: %w", err)
		}

		fmt.Println()

		password := string(passwordBytes)
		if password == "" {
			return fmt.Errorf("password cannot be empty")
		}

		_, err = client.SetUserCredentials(ctx, &v1.SetUserCredentialsRequest{
			UserId:   id,
			Password: password,
		})
		if err != nil {
			return fmt.Errorf("setting credentials: %w", err)
		}

		return printOutput(cmd, map[string]string{"Result": "Credentials updated"}, "Credentials updated")
	}),
}
