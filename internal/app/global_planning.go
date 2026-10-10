package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oracle/oci-go-sdk/v65/identity"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/budget"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalcontrol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionops"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionplanner"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/nats-io/nats.go/jetstream"
)

// startRollouts opens the rollout store. knownBad, when set,
// is pointed at the store so placement admission enforces its list.
func startRollouts(ctx context.Context, cfg Config, js jetstream.JetStream, control authority.Fencer,
	fullClusterReady func() bool, knownBad *rolloutKnownBad,
) (*rollout.Store, error) {
	if js == nil {
		return nil, errors.New("rollout store requires JetStream")
	}
	store, _, err := retryControllerOpen(ctx, "open rollout store", fullClusterReady, false,
		func(attempt context.Context) (*rollout.Store, error) {
			return rollout.OpenStore(attempt, js, cfg.NATS.Cell, cfg.NATS.Replicas, control)
		}, nil)
	if err != nil {
		return nil, err
	}
	if knownBad != nil {
		knownBad.store.Store(store)
	}
	return store, nil
}

// rolloutKnownBad refuses placement admission until the mandatory rollout store opens.
type rolloutKnownBad struct {
	store atomic.Pointer[rollout.Store]
}

func newRolloutKnownBad() *rolloutKnownBad { return &rolloutKnownBad{} }

func (k *rolloutKnownBad) IsKnownBad(ctx context.Context, digest string) (bool, error) {
	store := k.store.Load()
	if store == nil {
		return false, errors.New("the rollout store is not open yet")
	}
	return store.IsKnownBad(ctx, digest)
}

// startRegionPlanner runs the region planner and its operations loop on the
// global home's leader. Only the home holds the global authority, so every
// other region starts nothing. Opening the stores and reading the OCI identity
// wait on the cluster and on OCI, so they run in the background and the
// controller does not wait for them; a failure is logged, not fatal.
func startRegionPlanner(ctx context.Context, cfg Config, js jetstream.JetStream, global *globalControl,
	rollups func() []globalview.Region, fullClusterReady func() bool, page *capacityPage,
) {
	if global == nil || global.authority == nil {
		return
	}
	go func() {
		if err := runRegionPlanner(ctx, cfg, js, global, rollups, fullClusterReady, page); err != nil && ctx.Err() == nil {
			slog.Error("region planner did not start", observability.ComponentKey, "regionplanner", "error", err)
		}
	}()
}

// runRegionPlanner opens the planner's stores and starts its loop. The capacity
// page reads the planner's decision from the store once it is open.
func runRegionPlanner(ctx context.Context, cfg Config, js jetstream.JetStream, global *globalControl,
	rollups func() []globalview.Region, fullClusterReady func() bool, page *capacityPage,
) error {
	subscriptions, tenancy, err := retryHomeIdentity(ctx, cfg.NATS.Cell)
	if err != nil {
		return fmt.Errorf("region subscription effector: %w", err)
	}
	lifecycle, _, err := retryControllerOpen(ctx, "open region lifecycle store", fullClusterReady, false,
		func(attempt context.Context) (*regionlifecycle.Store, error) {
			return regionlifecycle.OpenStore(attempt, js, cfg.NATS.Replicas, global.authority)
		}, nil)
	if err != nil {
		return err
	}
	planner, _, err := retryControllerOpen(ctx, "open region planner store", fullClusterReady, false,
		func(attempt context.Context) (*regionplanner.Store, error) {
			return regionplanner.OpenStore(attempt, js, cfg.NATS.Replicas, global.authority)
		}, nil)
	if err != nil {
		return err
	}
	page.planner.Store(planner)
	home := regionlifecycle.Home{Cell: cfg.NATS.Cell}
	if err := home.Validate(); err != nil {
		return err
	}
	capacity := func(ctx context.Context) (budget.Capacity, bool, error) {
		return budget.ReadCapacity(ctx, global.reader)
	}
	runner := &regionplanner.Runner{Home: home,
		Rollups: rollups,
		Roster: func(ctx context.Context) (globalcontrol.Roster, error) {
			roster, _, err := global.reader.Roster(ctx)
			return roster, err
		},
		Capacity: capacity, OCIRegions: subscriptions, State: planner, Lifecycle: lifecycle, Machine: regionlifecycle.Machine{}}
	loop := &regionops.Loop{Store: lifecycle, Machine: regionlifecycle.Machine{}, Home: home, Leader: global.authority,
		Plan:       runner.Plan,
		Admissions: regionops.BudgetAdmissions{Capacity: capacity},
		Effectors: regionops.Effectors{
			regionlifecycle.StepSubscribe: regionops.Subscription{API: subscriptions, TenancyID: tenancy},
		}}
	go loop.Run(ctx, regionplanner.Interval)
	return nil
}

// identityRetry is how often the planner retries the OCI identity it needs.
const identityRetry = time.Minute

// retryHomeIdentity retries homeIdentity every identityRetry until it succeeds
// or ctx ends. A repeated error is logged once, not on every retry.
func retryHomeIdentity(ctx context.Context, cell string) (identity.IdentityClient, string, error) {
	lastError := ""
	for {
		client, tenancy, err := homeIdentity(ctx, cell)
		if err == nil {
			return client, tenancy, nil
		}
		if text := err.Error(); text != lastError {
			slog.Warn("region subscription identity is not ready; retrying every minute",
				observability.ComponentKey, "regionplanner", "error", text)
			lastError = text
		}
		select {
		case <-ctx.Done():
			return identity.IdentityClient{}, "", ctx.Err()
		case <-time.After(identityRetry):
		}
	}
}

// homeIdentity returns an identity client for this controller's instance
// principal, retargeted to the tenancy's OCI home region where region
// subscriptions are managed, and the tenancy. The global-control home need
// not be the tenancy's home region, so the tenancy is asked; a home region
// outside the product catalog is refused rather than guessed at.
func homeIdentity(ctx context.Context, cell string) (identity.IdentityClient, string, error) {
	ociRegion, err := oci.Region(strings.ToUpper(cell)).OCIRegion()
	if err != nil {
		return identity.IdentityClient{}, "", err
	}
	factory, err := ociclient.InstancePrincipal(ociRegion)
	if err != nil {
		return identity.IdentityClient{}, "", err
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || tenancy == "" {
		return identity.IdentityClient{}, "", errors.New("instance principal has no tenancy")
	}
	lookup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	home, err := factory.HomeRegion(lookup, tenancy)
	if err != nil {
		return identity.IdentityClient{}, "", err
	}
	client, err := factory.Identity()
	if err != nil {
		return identity.IdentityClient{}, "", err
	}
	client.SetRegion(home)
	return client, tenancy, nil
}
