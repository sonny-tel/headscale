package cli

import (
	"context"
	"fmt"
	"strconv"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/metadata"
)

func init() {
	rootCmd.AddCommand(providerCmd)

	providerCmd.AddCommand(providerAddAccountCmd)
	providerAddAccountCmd.Flags().String("provider", "mullvad", "Provider name")
	providerAddAccountCmd.Flags().String("account", "", "Provider account ID")
	providerAddAccountCmd.Flags().Int32("max-keys", 5, "Maximum keys per account")

	providerCmd.AddCommand(providerRemoveAccountCmd)

	providerCmd.AddCommand(providerListAccountsCmd)
	providerListAccountsCmd.Flags().String("provider", "", "Filter by provider name")

	providerCmd.AddCommand(providerSyncCmd)
	providerSyncCmd.Flags().String("provider", "mullvad", "Provider name")

	providerCmd.AddCommand(providerListRelaysCmd)
	providerListRelaysCmd.Flags().String("provider", "", "Filter by provider name")
	providerListRelaysCmd.Flags().String("country", "", "Filter by country code")

	providerCmd.AddCommand(providerListAllocationsCmd)
	providerListAllocationsCmd.Flags().String("provider", "", "Filter by provider name")

	providerCmd.AddCommand(providerFlushAllocationsCmd)
	providerFlushAllocationsCmd.Flags().String("provider", "mullvad", "Provider name")
}

var providerCmd = &cobra.Command{
	Use:     "provider",
	Short:   "Manage VPN provider accounts, relays, and key allocations",
	Aliases: []string{"vpn"},
}

var providerAddAccountCmd = &cobra.Command{
	Use:   "add-account",
	Short: "Add a VPN provider account",
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		providerName, _ := cmd.Flags().GetString("provider")
		accountID, _ := cmd.Flags().GetString("account")
		maxKeys, _ := cmd.Flags().GetInt32("max-keys")

		if accountID == "" {
			return fmt.Errorf("--account is required")
		}

		resp, err := client.AddProviderAccount(ctx, &v1.AddProviderAccountRequest{
			ProviderName: providerName,
			AccountId:    accountID,
			MaxKeys:      maxKeys,
		})
		if err != nil {
			return fmt.Errorf("adding provider account: %w", err)
		}

		return printOutput(cmd, resp.GetAccount(), "Provider account added")
	}),
}

var providerRemoveAccountCmd = &cobra.Command{
	Use:   "remove-account ID",
	Short: "Remove a VPN provider account",
	Args:  cobra.ExactArgs(1),
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseUint(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid account ID: %w", err)
		}

		_, err = client.RemoveProviderAccount(ctx, &v1.RemoveProviderAccountRequest{
			Id: id,
		})
		if err != nil {
			return fmt.Errorf("removing provider account: %w", err)
		}

		return printOutput(cmd, nil, "Provider account removed")
	}),
}

var providerListAccountsCmd = &cobra.Command{
	Use:     "list-accounts",
	Short:   "List VPN provider accounts",
	Aliases: []string{"ls-accounts"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		providerName, _ := cmd.Flags().GetString("provider")

		resp, err := client.ListProviderAccounts(ctx, &v1.ListProviderAccountsRequest{
			ProviderName: providerName,
		})
		if err != nil {
			return fmt.Errorf("listing provider accounts: %w", err)
		}

		return printListOutput(cmd, resp.GetAccounts(), func() error {
			tableData := pterm.TableData{
				{"ID", "Provider", "Account", "Keys", "Max Keys", "Enabled", "Expires"},
			}

			for _, acct := range resp.GetAccounts() {
				expires := "never"
				if acct.GetExpiresAt() != nil {
					expires = acct.GetExpiresAt().AsTime().Format("2006-01-02")
				}

				tableData = append(tableData, []string{
					strconv.FormatUint(acct.GetId(), 10),
					acct.GetProviderName(),
					acct.GetAccountId(),
					strconv.FormatInt(acct.GetActiveKeys(), 10),
					strconv.FormatInt(int64(acct.GetMaxKeys()), 10),
					strconv.FormatBool(acct.GetEnabled()),
					expires,
				})
			}

			return pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
		})
	}),
}

var providerSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Force relay cache refresh from provider API",
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		providerName, _ := cmd.Flags().GetString("provider")

		resp, err := client.SyncProviderRelays(ctx, &v1.SyncProviderRelaysRequest{
			ProviderName: providerName,
		})
		if err != nil {
			return fmt.Errorf("syncing relays: %w", err)
		}

		return printOutput(cmd, resp, fmt.Sprintf("Synced %d relays", resp.GetRelayCount()))
	}),
}

var providerListRelaysCmd = &cobra.Command{
	Use:     "list-relays",
	Short:   "List cached VPN provider relays",
	Aliases: []string{"ls-relays"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		providerName, _ := cmd.Flags().GetString("provider")
		countryCode, _ := cmd.Flags().GetString("country")

		resp, err := client.ListProviderRelays(ctx, &v1.ListProviderRelaysRequest{
			ProviderName: providerName,
			CountryCode:  countryCode,
		})
		if err != nil {
			return fmt.Errorf("listing relays: %w", err)
		}

		return printListOutput(cmd, resp.GetRelays(), func() error {
			tableData := pterm.TableData{
				{"Hostname", "Provider", "Country", "City", "Active"},
			}

			for _, r := range resp.GetRelays() {
				tableData = append(tableData, []string{
					r.GetHostname(),
					r.GetProviderName(),
					fmt.Sprintf("%s (%s)", r.GetCountry(), r.GetCountryCode()),
					fmt.Sprintf("%s (%s)", r.GetCity(), r.GetCityCode()),
					strconv.FormatBool(r.GetActive()),
				})
			}

			return pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
		})
	}),
}

var providerListAllocationsCmd = &cobra.Command{
	Use:     "list-allocations",
	Short:   "List VPN provider key allocations",
	Aliases: []string{"ls-alloc"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		providerName, _ := cmd.Flags().GetString("provider")

		resp, err := client.ListProviderAllocations(ctx, &v1.ListProviderAllocationsRequest{
			ProviderName: providerName,
		})
		if err != nil {
			return fmt.Errorf("listing allocations: %w", err)
		}

		return printListOutput(cmd, resp.GetAllocations(), func() error {
			tableData := pterm.TableData{
				{"ID", "Account ID", "Node ID", "Node Key", "Allocated At"},
			}

			for _, a := range resp.GetAllocations() {
				allocAt := ""
				if a.GetAllocatedAt() != nil {
					allocAt = a.GetAllocatedAt().AsTime().Format("2006-01-02 15:04:05")
				}

				tableData = append(tableData, []string{
					strconv.FormatUint(a.GetId(), 10),
					strconv.FormatUint(a.GetAccountId(), 10),
					strconv.FormatUint(a.GetNodeId(), 10),
					a.GetNodeKey(),
					allocAt,
				})
			}

			return pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
		})
	}),
}

var providerFlushAllocationsCmd = &cobra.Command{
	Use:     "flush-allocations",
	Short:   "Delete all key allocations and re-register keys with the provider",
	Long:    `Removes all existing WireGuard key allocation records from the database, then triggers a relay sync and key reconciliation so that keys are re-registered using the current API. Use this after updating the provider API integration.`,
	Aliases: []string{"flush"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		providerName, _ := cmd.Flags().GetString("provider")

		// Signal the server to flush allocations before syncing.
		ctx = metadata.AppendToOutgoingContext(ctx, "x-flush-allocations", "true")

		resp, err := client.SyncProviderRelays(ctx, &v1.SyncProviderRelaysRequest{
			ProviderName: providerName,
		})
		if err != nil {
			return fmt.Errorf("flushing allocations and syncing: %w", err)
		}

		return printOutput(cmd, resp, fmt.Sprintf("Flushed allocations, synced %d relays, and triggered key re-registration", resp.GetRelayCount()))
	}),
}
