package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionplanner"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/nats-io/nats.go/jetstream"
)

// RolloutsConfig opens the regional rollout store so the dashboard and the
// insight deadline rule see the active rollout. Off by default.
type RolloutsConfig struct {
	Enabled bool `json:"enabled"`
}

// RegionPlannerConfig runs the region planner on the global home's leader.
// It only ever proposes: every proposal needs a signed approval before
// anything is admitted or spent. Off by default; it requires global control
// enabled with this region as the home.
type RegionPlannerConfig struct {
	Enabled             bool   `json:"enabled"`
	IntervalSeconds     int    `json:"interval_seconds,omitzero"`
	WindowSeconds       int    `json:"window_seconds,omitzero"`
	MaxRegions          int    `json:"max_regions"`
	MonthlyCeilingCents uint64 `json:"monthly_ceiling_cents"`
	// HomeMonthlyCents is the home region's own monthly cost. The home has
	// no lifecycle record but counts toward MaxRegions and the ceiling.
	HomeMonthlyCents       uint64 `json:"home_monthly_cents"`
	CapacityThreshold      int    `json:"capacity_threshold,omitzero"`
	LatencyThresholdMillis uint32 `json:"latency_threshold_millis,omitzero"`
	LatencySamples         int    `json:"latency_samples,omitzero"`
	// RegionMonthlyCents prices each product catalog cell the planner may
	// propose; a cell without a price is never proposed.
	RegionMonthlyCents map[string]uint64 `json:"region_monthly_cents"`
	// Overflow names the cell to propose when a cell is capacity-limited.
	Overflow map[string]string `json:"overflow,omitempty"`
}

const (
	defaultPlannerInterval = 10 * time.Minute
	defaultPlannerWindow   = 24 * time.Hour
)

// plannerPolicy builds and validates the planner and lifecycle policies.
func (c *RegionPlannerConfig) plannerPolicy(home string) (regionplanner.Policy, regionlifecycle.Policy, error) {
	window := time.Duration(c.WindowSeconds) * time.Second
	if window <= 0 {
		window = defaultPlannerWindow
	}
	policy := regionplanner.Policy{
		Catalog: regionplanner.CatalogFromRegions(c.RegionMonthlyCents, c.Overflow), Window: window,
		CapacityThreshold: max(c.CapacityThreshold, 3), LatencyThresholdMillis: max(c.LatencyThresholdMillis, 150),
		LatencySamples: max(c.LatencySamples, 3), MaxRegions: c.MaxRegions, MonthlyCeilingCents: c.MonthlyCeilingCents,
		Home: regionlifecycle.Home{Cell: home, MonthlyCents: c.HomeMonthlyCents},
	}
	// The planner never approves, so the lifecycle policy needs no
	// approvers here; approval runs through its own signed path.
	lifecycle := regionlifecycle.Policy{
		MaxRegions: c.MaxRegions, MonthlyCeilingCents: c.MonthlyCeilingCents,
		AdmissionTTL: regionlifecycle.DefaultAdmissionTTL, ProposalTTL: 72 * time.Hour,
		ApprovalMaxLifetime: 7 * 24 * time.Hour, ClockSkew: time.Minute, MinIdle: 14 * 24 * time.Hour,
	}
	if _, err := (regionplanner.Planner{Policy: policy}).Plan(nil, nil, time.Now()); err != nil {
		return regionplanner.Policy{}, regionlifecycle.Policy{}, fmt.Errorf("region planner policy: %w", err)
	}
	return policy, lifecycle, nil
}

// startRollouts opens the rollout store when enabled. knownBad, when set,
// is pointed at the store so placement admission enforces its list.
func startRollouts(ctx context.Context, cfg Config, js jetstream.JetStream, control authority.Fencer,
	fullClusterReady func() bool, knownBad *rolloutKnownBad,
) (insights.RolloutProvider, error) {
	if cfg.Controller.Rollouts == nil || !cfg.Controller.Rollouts.Enabled {
		return nil, nil
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

// rolloutKnownBad lets placement admission, which starts before the rollout
// store opens, read the cell's known-bad list. It exists only when the
// rollout store is enabled; until the store opens it refuses, so admission
// fails closed instead of skipping the list.
type rolloutKnownBad struct {
	store atomic.Pointer[rollout.Store]
}

// newRolloutKnownBad returns the placement known-bad source for cfg, or nil
// when the rollout store is disabled and no cell list exists.
func newRolloutKnownBad(cfg Config) *rolloutKnownBad {
	if cfg.Controller.Rollouts == nil || !cfg.Controller.Rollouts.Enabled {
		return nil
	}
	return &rolloutKnownBad{}
}

func (k *rolloutKnownBad) IsKnownBad(ctx context.Context, digest string) (bool, error) {
	store := k.store.Load()
	if store == nil {
		return false, errors.New("the rollout store is not open yet")
	}
	return store.IsKnownBad(ctx, digest)
}

// startRegionPlanner opens the region lifecycle store on the global home and
// runs the planner on the global leader. It returns the budget provider.
func startRegionPlanner(ctx context.Context, cfg Config, js jetstream.JetStream, global *globalControl,
	holds *placementHoldLog, fullClusterReady func() bool,
) (insights.BudgetProvider, error) {
	settings := cfg.Controller.RegionPlanner
	if settings == nil || !settings.Enabled {
		return nil, nil
	}
	if global == nil || global.authority == nil || cfg.Controller.Global == nil || cfg.Controller.Global.Home != cfg.NATS.Cell {
		return nil, errors.New("the region planner runs only in the global home with global control enabled")
	}
	policy, lifecyclePolicy, err := settings.plannerPolicy(cfg.NATS.Cell)
	if err != nil {
		return nil, err
	}
	store, _, err := retryControllerOpen(ctx, "open region lifecycle store", fullClusterReady, false,
		func(attempt context.Context) (*regionlifecycle.Store, error) {
			return regionlifecycle.OpenStore(attempt, js, cfg.NATS.Replicas, global.authority)
		}, nil)
	if err != nil {
		return nil, err
	}
	interval := time.Duration(settings.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = defaultPlannerInterval
	}
	runner := plannerRunner{source: holdSignals{cell: cfg.NATS.Cell, holds: holds}, planner: regionplanner.Planner{Policy: policy},
		store: store, machine: regionlifecycle.Machine{Policy: lifecyclePolicy}, leader: global.authority}
	go runner.run(ctx, interval)
	return regionplanner.Budgets{Policy: policy, Records: store}, nil
}

type plannerRunner struct {
	source  regionplanner.Source
	planner regionplanner.Planner
	store   *regionlifecycle.Store
	machine regionlifecycle.Machine
	leader  authority.Fencer
}

func (r plannerRunner) run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		r.tick(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// tick plans once on the global leader; followers do nothing.
func (r plannerRunner) tick(ctx context.Context, now time.Time) []string {
	snapshot := r.leader.Current()
	if !snapshot.CanMutate() {
		return nil
	}
	submitted, err := regionplanner.Run(ctx, r.source, r.planner, r.store, r.machine, snapshot.Epoch, now)
	if err != nil {
		slog.Warn("region planner run failed", observability.ComponentKey, "regionplanner", "error", err)
	}
	return submitted
}

// holdSignals turns the home region's placement holds into planner signals:
// a hold that reports OCI host capacity or a service limit is a capacity or
// limit signal for this cell, with the hold record as its evidence. Other
// regions' signals are not collected yet.
type holdSignals struct {
	cell  string
	holds *placementHoldLog
}

func (s holdSignals) Signals(_ context.Context, since time.Time) ([]regionplanner.Signal, error) {
	var signals []regionplanner.Signal
	for _, record := range s.holds.recent(time.Now()) {
		if record.At.Before(since) {
			continue
		}
		reason := strings.ToLower(record.Reason)
		kind := regionplanner.SignalKind("")
		switch {
		case strings.Contains(reason, "out of host capacity") || strings.Contains(reason, "outofhostcapacity") ||
			strings.Contains(reason, "insufficient capacity"):
			kind = regionplanner.SignalCapacityError
		case strings.Contains(reason, "limitexceeded") || strings.Contains(reason, "limit exceeded") ||
			strings.Contains(reason, "service limit"):
			kind = regionplanner.SignalLimitError
		default:
			continue
		}
		evidence := sha256.Sum256([]byte(record.At.UTC().Format(time.RFC3339Nano) + "\x00" + record.Reason))
		signals = append(signals, regionplanner.Signal{Kind: kind, Cell: strings.ToLower(s.cell),
			EvidenceDigest: hex.EncodeToString(evidence[:]), ObservedAt: record.At})
	}
	return signals, nil
}
