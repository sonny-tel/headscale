// nolint
package hscontrol

import (
	"context"
	"sort"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"tailscale.com/types/key"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/provider"
	"github.com/juanfont/headscale/hscontrol/types/change"
)

func (api headscaleV1APIServer) AddProviderAccount(
	ctx context.Context,
	request *v1.AddProviderAccountRequest,
) (*v1.AddProviderAccountResponse, error) {
	providerName := request.GetProviderName()
	accountID := request.GetAccountId()

	if providerName == "" || accountID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "provider_name and account_id are required")
	}

	maxKeys := int(request.GetMaxKeys())
	if maxKeys <= 0 {
		maxKeys = 5
	}

	acct, err := api.h.state.DB().CreateProviderAccount(nil, providerName, accountID, maxKeys)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "creating provider account: %s", err)
	}

	// Ensure the provider manager is initialized for this provider.
	if err := api.h.ensureProviderManager(ctx, providerName); err != nil {
		log.Warn().Err(err).Str("provider", providerName).Msg("failed to initialize provider after adding account")
	}

	// Trigger reconciliation so nodes with the attr get keys allocated immediately.
	api.h.state.ReconcileProviderAllocations(ctx)

	api.h.Change(change.Change{
		Reason:       "provider account added",
		SendAllPeers: true,
	})

	return &v1.AddProviderAccountResponse{
		Account: providerAccountToProto(acct, 0),
	}, nil
}

func (api headscaleV1APIServer) RemoveProviderAccount(
	ctx context.Context,
	request *v1.RemoveProviderAccountRequest,
) (*v1.RemoveProviderAccountResponse, error) {
	id := request.GetId()
	if id == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "id is required")
	}

	if err := api.h.state.DB().DeleteProviderAccount(nil, uint(id)); err != nil {
		return nil, status.Errorf(codes.Internal, "deleting provider account: %s", err)
	}

	return &v1.RemoveProviderAccountResponse{}, nil
}

func (api headscaleV1APIServer) ListProviderAccounts(
	ctx context.Context,
	request *v1.ListProviderAccountsRequest,
) (*v1.ListProviderAccountsResponse, error) {
	accounts, err := api.h.state.DB().ListProviderAccounts(request.GetProviderName())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "listing provider accounts: %s", err)
	}

	protoAccounts := make([]*v1.ProviderAccount, 0, len(accounts))
	for i := range accounts {
		count, err := api.h.state.DB().CountAllocationsForAccount(accounts[i].ID)
		if err != nil {
			count = 0
		}

		protoAccounts = append(protoAccounts, providerAccountToProto(&accounts[i], count))
	}

	sort.Slice(protoAccounts, func(i, j int) bool {
		return protoAccounts[i].GetId() < protoAccounts[j].GetId()
	})

	return &v1.ListProviderAccountsResponse{
		Accounts: protoAccounts,
	}, nil
}

func (api headscaleV1APIServer) SyncProviderRelays(
	ctx context.Context,
	request *v1.SyncProviderRelaysRequest,
) (*v1.SyncProviderRelaysResponse, error) {
	providerName := request.GetProviderName()
	if providerName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "provider_name is required")
	}

	mgr := api.h.state.ProviderManager()
	if mgr == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "no provider manager configured")
	}

	// Check for flush-allocations metadata flag.
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get("x-flush-allocations"); len(vals) > 0 && vals[0] == "true" {
			// List allocations first WITHOUT deleting — deregister from API before removing DB records.
			allocs, err := api.h.state.DB().ListKeyAllocations(providerName)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "listing allocations for flush: %s", err)
			}

			var flushed int

			p, pOK := mgr.Provider(providerName)
			for _, alloc := range allocs {
				// Deregister from provider API first.
				if pOK {
					var nodeKey key.NodePublic
					if err := nodeKey.UnmarshalText([]byte(alloc.NodeKey)); err != nil {
						log.Warn().Err(err).
							Uint64("node_id", alloc.NodeID).
							Msg("failed to parse flushed allocation key for deregistration")
					} else if err := p.DeregisterKey(ctx, alloc.Account.AccountID, nodeKey); err != nil {
						log.Warn().Err(err).
							Uint64("node_id", alloc.NodeID).
							Msg("failed to deregister flushed key with provider")
					}
				}

				// Now safe to delete DB record.
				if err := api.h.state.DB().DeleteKeyAllocation(nil, alloc.ID); err != nil {
					log.Warn().Err(err).
						Uint64("node_id", alloc.NodeID).
						Msg("failed to delete flushed allocation record")

					continue
				}

				flushed++
			}

			log.Info().
				Str("provider", providerName).
				Int("flushed", flushed).
				Msg("flushed and deregistered provider key allocations")
		}
	}

	if err := api.h.state.SyncProviderRelays(ctx, providerName); err != nil {
		return nil, status.Errorf(codes.Internal, "syncing relays: %s", err)
	}

	// Reconcile key allocations — new relays might mean new nodes need keys.
	api.h.state.ReconcileProviderAllocations(ctx)

	relays := mgr.Cache().ListRelays(providerName)

	api.h.Change(change.Change{
		Reason:       "provider relay sync",
		SendAllPeers: true,
	})

	return &v1.SyncProviderRelaysResponse{
		RelayCount: int32(len(relays)),
	}, nil
}

func (api headscaleV1APIServer) ListProviderRelays(
	ctx context.Context,
	request *v1.ListProviderRelaysRequest,
) (*v1.ListProviderRelaysResponse, error) {
	mgr := api.h.state.ProviderManager()
	if mgr == nil {
		return &v1.ListProviderRelaysResponse{}, nil
	}

	providerName := request.GetProviderName()
	countryCode := request.GetCountryCode()

	relays := mgr.Cache().ListRelays(providerName)

	protoRelays := make([]*v1.ProviderRelay, 0, len(relays))
	for _, r := range relays {
		if countryCode != "" && r.CountryCode != countryCode {
			continue
		}

		protoRelays = append(protoRelays, &v1.ProviderRelay{
			Hostname:     r.Hostname,
			ProviderName: r.ProviderName,
			CountryCode:  r.CountryCode,
			Country:      r.Country,
			CityCode:     r.CityCode,
			City:         r.City,
			Active:       r.Active,
		})
	}

	return &v1.ListProviderRelaysResponse{
		Relays: protoRelays,
	}, nil
}

func (api headscaleV1APIServer) ListProviderAllocations(
	ctx context.Context,
	request *v1.ListProviderAllocationsRequest,
) (*v1.ListProviderAllocationsResponse, error) {
	allocs, err := api.h.state.DB().ListKeyAllocations(request.GetProviderName())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "listing allocations: %s", err)
	}

	protoAllocs := make([]*v1.KeyAllocation, 0, len(allocs))
	for _, a := range allocs {
		pa := &v1.KeyAllocation{
			Id:        uint64(a.ID),
			AccountId: uint64(a.AccountID),
			NodeId:    a.NodeID,
			NodeKey:   a.NodeKey,
		}
		if a.AllocatedAt != nil {
			pa.AllocatedAt = timestamppb.New(*a.AllocatedAt)
		}

		protoAllocs = append(protoAllocs, pa)
	}

	return &v1.ListProviderAllocationsResponse{
		Allocations: protoAllocs,
	}, nil
}

// ensureProviderManager ensures the provider manager is initialized and the
// given provider is registered. Called when a new account is added via the API.
func (h *Headscale) ensureProviderManager(ctx context.Context, providerName string) error {
	mgr := h.state.ProviderManager()
	if mgr == nil {
		mgr = provider.NewManager(h.cfg.BaseDomain)
		h.state.SetProviderManager(mgr)
	}

	if _, ok := mgr.Provider(providerName); !ok {
		if err := mgr.RegisterProvider(providerName); err != nil {
			return err
		}
	}

	// Perform initial relay sync for the new provider.
	return h.state.SyncProviderRelays(ctx, providerName)
}

func providerAccountToProto(acct *db.VPNProviderAccount, activeKeys int64) *v1.ProviderAccount {
	pa := &v1.ProviderAccount{
		Id:           uint64(acct.ID),
		ProviderName: acct.ProviderName,
		AccountId:    acct.AccountID,
		MaxKeys:      int32(acct.MaxKeys),
		ActiveKeys:   activeKeys,
		Enabled:      acct.Enabled,
		CreatedAt:    timestamppb.New(acct.CreatedAt),
		UpdatedAt:    timestamppb.New(acct.UpdatedAt),
	}

	if acct.ExpiresAt != nil {
		pa.ExpiresAt = timestamppb.New(*acct.ExpiresAt)
	}

	return pa
}
