package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlink"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionops"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionplanner"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// RolloutsConfig opens the regional rollout store so the dashboard and the
// insight deadline rule see the active rollout. Off by default.
type RolloutsConfig struct {
	Enabled bool `json:"enabled"`
	// Executor runs the cell's orchestrator self-update from its desired
	// release (ts-orch rollout): the authority leader moves the controllers
	// one per wave, the seed last. It needs Enabled, and a root step agent
	// next to every controller to apply the steps; without one a published
	// release moves no unit, and its rollout freezes with the release marked
	// known bad. Off by default.
	Executor bool `json:"executor,omitzero"`
	// Policy overrides rollout.DefaultPolicy for the executor's rollouts.
	Policy *rollout.Policy `json:"policy,omitempty"`
	// AllowScopedAutoSign lets the leader admit update receipts signed under
	// a scoped binary update delegation. Set it exactly when the controllers'
	// step agents accept them (selfupdate --allow-scoped-auto-sign), so the
	// leader never admits a release no node stages.
	AllowScopedAutoSign bool `json:"allow_scoped_auto_sign,omitzero"`
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
	// Approvers maps each region approval actor to its base64 Ed25519
	// public key. Admission and every lifecycle step verify the record's
	// signed approval against it; empty verifies nothing, so nothing is
	// admitted or driven.
	Approvers map[string]string `json:"approvers,omitempty"`
	// PeerSignals also reads every interregion peer's capacity and limit
	// placement holds from its decision journal. Off by default: peer
	// journals are another region's data, and although they can only lead
	// to proposals, reading them is an opt-in trust decision.
	PeerSignals bool `json:"peer_signals,omitzero"`
	// Admit admits approved regions, and refreshes the cost admission of
	// in-flight ones, at their RegionMonthlyCents price under the region
	// maximum, the monthly ceiling and the approval's cap. Off by default.
	Admit bool `json:"admit,omitzero"`
	// Drive advances admitted regions one lifecycle step per tick through
	// the steps that have an effector. Off by default; a step without an
	// effector waits and is journaled once.
	Drive bool `json:"drive,omitzero"`
	// SubscribeRegions registers the region subscription effector (needs
	// Drive): the home's instance principal subscribes the tenancy to an
	// approved, admitted region. Off by default.
	SubscribeRegions bool `json:"subscribe_regions,omitzero"`
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
	// The planner never approves. Approvers only verify approvals that
	// arrive through their own signed path, before admission and steps.
	lifecycle := regionlifecycle.Policy{
		MaxRegions: c.MaxRegions, MonthlyCeilingCents: c.MonthlyCeilingCents,
		AdmissionTTL: regionlifecycle.DefaultAdmissionTTL, ProposalTTL: 72 * time.Hour,
		ApprovalMaxLifetime: 7 * 24 * time.Hour, ClockSkew: time.Minute, MinIdle: 14 * 24 * time.Hour,
	}
	if len(c.Approvers) != 0 {
		lifecycle.Approvers = make(map[string]ed25519.PublicKey, len(c.Approvers))
		for actor, encoded := range c.Approvers {
			key, err := decodePublicKey(encoded)
			if actor == "" || err != nil {
				return regionplanner.Policy{}, regionlifecycle.Policy{}, fmt.Errorf("region approver %q: %w", actor,
					errors.Join(err, errors.New("approver needs an actor and a base64 Ed25519 key")))
			}
			lifecycle.Approvers[actor] = key
		}
	}
	if c.SubscribeRegions && !c.Drive {
		return regionplanner.Policy{}, regionlifecycle.Policy{}, errors.New("subscribe_regions needs drive")
	}
	if (c.Admit || c.Drive) && len(lifecycle.Approvers) == 0 {
		return regionplanner.Policy{}, regionlifecycle.Policy{}, errors.New("admit and drive need region approvers")
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
// runs the region operations loop on the global leader: the planner, and,
// behind their own flags, admission and the lifecycle driver. It returns the
// budget provider.
func startRegionPlanner(ctx context.Context, cfg Config, js jetstream.JetStream, global *globalControl,
	holds *placementHoldLog, conn *nats.Conn, fullClusterReady func() bool,
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
	var subscriptions regionops.SubscriptionAPI
	var tenancy string
	if settings.Drive && settings.SubscribeRegions {
		if subscriptions, tenancy, err = homeIdentity(ctx, cfg.NATS.Cell); err != nil {
			return nil, fmt.Errorf("region subscription effector: %w", err)
		}
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
	sources := regionplanner.Sources{holdSignals{cell: cfg.NATS.Cell, holds: holds}}
	if settings.PeerSignals {
		peers := plannerPeers(cfg)
		federation, err := peerDecisions(cfg.NATS.Cell, conn, peers)
		if err != nil {
			return nil, fmt.Errorf("region planner peer signals: %w", err)
		}
		sources = append(sources, regionplanner.PeerHolds{
			Decisions: func() decisionlog.Source { return federation }, Peers: peers})
	}
	machine := regionlifecycle.Machine{Policy: lifecyclePolicy}
	runner := plannerRunner{source: sources, planner: regionplanner.Planner{Policy: policy},
		store: store, machine: machine, leader: global.authority}
	loop := &regionops.Loop{Store: store, Machine: machine, Home: policy.Home, Leader: global.authority, Plan: runner.plan}
	if settings.Admit {
		loop.Admissions = regionops.PriceList{MonthlyCents: settings.RegionMonthlyCents}
	}
	if settings.Drive {
		loop.Effectors = regionops.Effectors{}
		if subscriptions != nil {
			loop.Effectors[regionlifecycle.StepSubscribe] = regionops.Subscription{API: subscriptions, TenancyID: tenancy}
		}
	}
	go loop.Run(ctx, interval)
	return regionplanner.Budgets{Policy: policy, Records: store}, nil
}

// homeIdentity returns an identity client for this controller's instance
// principal, retargeted to the tenancy's OCI home region where region
// subscriptions are managed, and the tenancy. The global-control home need
// not be the tenancy's home region, so the tenancy is asked; a home region
// outside the product catalog is refused rather than guessed at.
func homeIdentity(ctx context.Context, cell string) (regionops.SubscriptionAPI, string, error) {
	ociRegion, err := oci.Region(strings.ToUpper(cell)).OCIRegion()
	if err != nil {
		return nil, "", err
	}
	factory, err := ociclient.InstancePrincipal(ociRegion)
	if err != nil {
		return nil, "", err
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || tenancy == "" {
		return nil, "", errors.New("instance principal has no tenancy")
	}
	client, err := factory.Identity()
	if err != nil {
		return nil, "", err
	}
	lookup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	response, err := client.GetTenancy(lookup, identity.GetTenancyRequest{TenancyId: &tenancy})
	if err != nil {
		return nil, "", fmt.Errorf("read the tenancy home region: %w", err)
	}
	home, err := tenancyHomeRegion(response.HomeRegionKey)
	if err != nil {
		return nil, "", err
	}
	client.SetRegion(home)
	return client, tenancy, nil
}

// tenancyHomeRegion maps the tenancy's home region key to its catalog OCI
// region.
func tenancyHomeRegion(key *string) (string, error) {
	if key == nil {
		return "", errors.New("tenancy has no home region key")
	}
	for _, entry := range catalog.Entries() {
		if strings.EqualFold(entry.OCIRegionKey, *key) {
			return entry.OCIRegion, nil
		}
	}
	return "", fmt.Errorf("tenancy home region %q is not a catalog region", *key)
}

// plannerPeers lists the regions whose placement holds the planner reads:
// the interregion roster, which is exactly the set the decision federation
// can reach.
func plannerPeers(cfg Config) []string {
	if cfg.NATS.Embedded == nil || cfg.NATS.Embedded.InterRegion == nil {
		return nil
	}
	return slices.Clone(cfg.NATS.Embedded.InterRegion.Peers)
}

// peerDecisions is a decision federation over the interregion peers only,
// built on the cell connection independently of the HTTP observability
// listener: the contract imports each peer's decision query service, so
// peer signals never depend on whether the dashboard runs.
func peerDecisions(cell string, conn *nats.Conn, peers []string) (decisionlog.Source, error) {
	if conn == nil || len(peers) == 0 {
		return nil, errors.New("peer signals need the cell connection and interregion peers")
	}
	links, err := regionlink.New(cell, conn, peers, regionRequestTimeout)
	if err != nil {
		return nil, err
	}
	for _, peer := range peers {
		if err := links.Link(peer, conn); err != nil {
			return nil, err
		}
	}
	return decisionlog.Federation{Links: links}, nil
}

type plannerRunner struct {
	source  regionplanner.Source
	planner regionplanner.Planner
	store   *regionlifecycle.Store
	machine regionlifecycle.Machine
	leader  authority.Fencer
}

// tick plans once on the global leader; followers do nothing.
func (r plannerRunner) tick(ctx context.Context, now time.Time) []string {
	snapshot := r.leader.Current()
	if !snapshot.CanMutate() {
		return nil
	}
	submitted, err := r.plan(ctx, snapshot.Epoch, now)
	if err != nil {
		slog.Warn("region planner run failed", observability.ComponentKey, "regionplanner", "error", err)
	}
	return submitted
}

func (r plannerRunner) plan(ctx context.Context, epoch uint64, now time.Time) ([]string, error) {
	return regionplanner.Run(ctx, r.source, r.planner, r.store, r.machine, epoch, now)
}

// holdSignals turns the home region's placement holds into planner signals:
// a hold that reports OCI host capacity or a service limit is a capacity or
// limit signal for this cell, with the hold record as its evidence. Other
// regions' holds come from regionplanner.PeerHolds (peer_signals).
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
		kind := regionplanner.ClassifyHold(record.Reason)
		if kind == "" {
			continue
		}
		evidence := sha256.Sum256([]byte(record.At.UTC().Format(time.RFC3339Nano) + "\x00" + record.Reason))
		signals = append(signals, regionplanner.Signal{Kind: kind, Cell: strings.ToLower(s.cell),
			EvidenceDigest: hex.EncodeToString(evidence[:]), ObservedAt: record.At})
	}
	return signals, nil
}
