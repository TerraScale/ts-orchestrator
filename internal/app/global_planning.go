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
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlink"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionops"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionplanner"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// RegionPlannerConfig runs the region planner on the global home's leader.
// It only proposes until the monthly budget guards admission (TS-804); then
// it approves its own proposals inside those guardrails. Off by default; it requires global
// control enabled with this region as the home.
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
	// PeerSignals also reads every interregion peer's capacity and limit
	// placement holds from its decision journal. Off by default: peer
	// journals are another region's data, and although they can only lead
	// to proposals, reading them is an opt-in trust decision.
	PeerSignals bool `json:"peer_signals,omitzero"`
	// Admit admits approved regions, and refreshes the cost admission of
	// in-flight ones, at their RegionMonthlyCents price under the region
	// maximum and the monthly ceiling. Off by default.
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

// plannerPolicy builds and validates the planner policy.
func (c *RegionPlannerConfig) plannerPolicy(home string) (regionplanner.Policy, error) {
	window := time.Duration(c.WindowSeconds) * time.Second
	if window <= 0 {
		window = defaultPlannerWindow
	}
	policy := regionplanner.Policy{
		Catalog: regionplanner.CatalogFromRegions(c.RegionMonthlyCents, c.Overflow), Window: window,
		CapacityThreshold: max(c.CapacityThreshold, 3), LatencyThresholdMillis: max(c.LatencyThresholdMillis, 150),
		LatencySamples: max(c.LatencySamples, 3), MaxRegions: c.MaxRegions, MonthlyCeilingCents: c.MonthlyCeilingCents,
		Home: regionlifecycle.Home{Cell: home},
	}
	// The home's cost comes out of the admission headroom, so zero would
	// overcommit the budget.
	if c.HomeMonthlyCents == 0 {
		return regionplanner.Policy{}, errors.New("region planner needs the home region's monthly cost")
	}
	if c.SubscribeRegions && !c.Drive {
		return regionplanner.Policy{}, errors.New("subscribe_regions needs drive")
	}
	if _, err := (regionplanner.Planner{Policy: policy}).Plan(nil, nil, time.Now()); err != nil {
		return regionplanner.Policy{}, fmt.Errorf("region planner policy: %w", err)
	}
	return policy, nil
}

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

// startRegionPlanner opens the region lifecycle store on the global home and
// runs the region operations loop on the global leader: the planner, and,
// behind their own flags, admission and the lifecycle driver.
func startRegionPlanner(ctx context.Context, cfg Config, js jetstream.JetStream, global *globalControl,
	holds *placementHoldLog, conn *nats.Conn, peers *rosterPeers, fullClusterReady func() bool,
) error {
	settings := cfg.Controller.RegionPlanner
	if settings == nil || !settings.Enabled {
		return nil
	}
	if global == nil || global.authority == nil {
		return errors.New("the region planner runs only in the global home")
	}
	policy, err := settings.plannerPolicy(cfg.NATS.Cell)
	if err != nil {
		return err
	}
	var subscriptions regionops.SubscriptionAPI
	var tenancy string
	if settings.Drive && settings.SubscribeRegions {
		if subscriptions, tenancy, err = homeIdentity(ctx, cfg.NATS.Cell); err != nil {
			return fmt.Errorf("region subscription effector: %w", err)
		}
	}
	store, _, err := retryControllerOpen(ctx, "open region lifecycle store", fullClusterReady, false,
		func(attempt context.Context) (*regionlifecycle.Store, error) {
			return regionlifecycle.OpenStore(attempt, js, cfg.NATS.Replicas, global.authority)
		}, nil)
	if err != nil {
		return err
	}
	interval := time.Duration(settings.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = defaultPlannerInterval
	}
	sources := regionplanner.Sources{holdSignals{cell: cfg.NATS.Cell, holds: holds}}
	if settings.PeerSignals {
		federation, err := peerDecisions(cfg.NATS.Cell, conn, peers)
		if err != nil {
			return fmt.Errorf("region planner peer signals: %w", err)
		}
		sources = append(sources, rosterHolds{peers: peers, federation: federation})
	}
	machine := regionlifecycle.Machine{}
	runner := plannerRunner{source: sources, planner: regionplanner.Planner{Policy: policy},
		store: store, machine: machine, leader: global.authority}
	loop := &regionops.Loop{Store: store, Machine: machine, Home: policy.Home, Leader: global.authority, Plan: runner.plan}
	if settings.Admit {
		// The home's spend comes out of the budget; the in-flight regions are
		// checked against what is left.
		headroom := settings.MonthlyCeilingCents - min(settings.MonthlyCeilingCents, settings.HomeMonthlyCents)
		loop.Admissions = regionops.PriceList{MonthlyCents: settings.RegionMonthlyCents, HeadroomCents: headroom}
	}
	if settings.Drive {
		loop.Effectors = regionops.Effectors{}
		if subscriptions != nil {
			loop.Effectors[regionlifecycle.StepSubscribe] = regionops.Subscription{API: subscriptions, TenancyID: tenancy}
		}
	}
	go loop.Run(ctx, interval)
	return nil
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
	lookup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	home, err := factory.HomeRegion(lookup, tenancy)
	if err != nil {
		return nil, "", err
	}
	client, err := factory.Identity()
	if err != nil {
		return nil, "", err
	}
	client.SetRegion(home)
	return client, tenancy, nil
}

// rosterHolds reads the placement holds of the roster's peers on every pass,
// so a region that joins or leaves the roster is read from the next pass on.
type rosterHolds struct {
	peers      *rosterPeers
	federation decisionlog.Source
}

func (holds rosterHolds) Signals(ctx context.Context, since time.Time) ([]regionplanner.Signal, error) {
	return regionplanner.PeerHolds{Decisions: func() decisionlog.Source { return holds.federation },
		Peers: holds.peers.current()}.Signals(ctx, since)
}

// peerDecisions is a decision federation over the roster peers, built on the
// cell connection independently of the HTTP observability listener: the
// contract imports each peer's decision query service, so peer signals never
// depend on whether the dashboard runs.
func peerDecisions(cell string, conn *nats.Conn, peers *rosterPeers) (decisionlog.Source, error) {
	if conn == nil {
		return nil, errors.New("peer signals need the cell connection")
	}
	links, err := regionlink.New(cell, conn, nil, regionRequestTimeout)
	if err != nil {
		return nil, err
	}
	linkRoster(links, conn, peers)
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
		slog.WarnContext(ctx, "region planner run failed", observability.ComponentKey, "regionplanner", "error", err)
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
