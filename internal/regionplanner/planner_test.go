package regionplanner

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

var now = time.Date(2026, time.October, 2, 12, 0, 0, 0, time.UTC)

func digest(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

func testPolicy() Policy {
	return Policy{
		Catalog: map[string]CatalogEntry{
			"gru": {Cell: "gru", OCIRegion: "sa-saopaulo-1", EstimatedMonthlyCents: 9_000, Overflow: "sfo"},
			"sfo": {Cell: "sfo", OCIRegion: "us-sanjose-1", EstimatedMonthlyCents: 9_000},
			"fra": {Cell: "fra", OCIRegion: "eu-frankfurt-1", EstimatedMonthlyCents: 9_500},
		},
		Window: 24 * time.Hour, CapacityThreshold: 3, LatencyThresholdMillis: 150, LatencySamples: 2,
		MaxRegions: 3, MonthlyCeilingCents: 20_000, Home: regionlifecycle.Home{Cell: "gru", MonthlyCents: 9_000},
	}
}

func activeGRU() regionlifecycle.Record {
	return regionlifecycle.Record{Version: 1, Cell: "gru", Generation: 30, ProposalGeneration: 1,
		Phase: regionlifecycle.Active, Proposal: regionlifecycle.Proposal{ID: "gru-founder", Cell: "gru",
			OCIRegion: "sa-saopaulo-1", Reason: "founder", EvidenceDigests: []string{digest("founder")},
			EstimatedMonthlyCents: 9_000, ProposedAt: now.Add(-90 * 24 * time.Hour)},
		UpdatedAt: now.Add(-60 * 24 * time.Hour)}
}

func signal(kind SignalKind, cell, label string, age time.Duration) Signal {
	return Signal{Kind: kind, Cell: cell, EvidenceDigest: digest(label), ObservedAt: now.Add(-age)}
}

func TestPlannerProposesFromEachSignalKind(t *testing.T) {
	t.Parallel()
	planner := Planner{Policy: testPolicy()}
	records := []regionlifecycle.Record{activeGRU()}

	proposals, err := planner.Plan([]Signal{signal(SignalUnplaceableIntent, "sfo", "intent-1", time.Hour)}, records, now)
	if err != nil || len(proposals) != 1 || proposals[0].Cell != "sfo" || proposals[0].OCIRegion != "us-sanjose-1" ||
		!strings.Contains(proposals[0].Reason, "unplaceable-intent") {
		t.Fatalf("unplaceable intent proposals = %+v, %v", proposals, err)
	}
	again, _ := planner.Plan([]Signal{signal(SignalUnplaceableIntent, "sfo", "intent-1", time.Hour)}, records, now)
	if again[0].ID != proposals[0].ID {
		t.Fatal("proposal IDs are not deterministic for the same evidence")
	}

	// Capacity errors in GRU propose its overflow region only at threshold.
	capacity := []Signal{
		signal(SignalCapacityError, "gru", "cap-1", time.Hour),
		signal(SignalLimitError, "gru", "limit-1", 2*time.Hour),
	}
	if proposals, _ := planner.Plan(capacity, records, now); len(proposals) != 0 {
		t.Fatalf("proposed below the capacity threshold: %+v", proposals)
	}
	capacity = append(capacity, signal(SignalCapacityError, "gru", "cap-1", time.Hour), signal(SignalCapacityError, "gru", "cap-2", 3*time.Hour))
	proposals, err = planner.Plan(capacity, records, now)
	if err != nil || len(proposals) != 1 || proposals[0].Cell != "sfo" || len(proposals[0].EvidenceDigests) != 3 {
		t.Fatalf("capacity proposals = %+v, %v (duplicate evidence must count once)", proposals, err)
	}

	latency := []Signal{
		{Kind: SignalLatency, Cell: "fra", EvidenceDigest: digest("lat-1"), ObservedAt: now.Add(-time.Hour), LatencyMillis: 220},
		{Kind: SignalLatency, Cell: "fra", EvidenceDigest: digest("lat-2"), ObservedAt: now.Add(-time.Hour), LatencyMillis: 90},
	}
	if proposals, _ := planner.Plan(latency, records, now); len(proposals) != 0 {
		t.Fatalf("proposed from one slow sample: %+v", proposals)
	}
	latency = append(latency, Signal{Kind: SignalLatency, Cell: "fra", EvidenceDigest: digest("lat-3"), ObservedAt: now.Add(-2 * time.Hour), LatencyMillis: 300})
	proposals, err = planner.Plan(latency, records, now)
	if err != nil || len(proposals) != 1 || proposals[0].Cell != "fra" || proposals[0].EstimatedMonthlyCents != 9_500 {
		t.Fatalf("latency proposals = %+v, %v", proposals, err)
	}
}

func TestPlannerIgnoresNoiseAndRespectsGuards(t *testing.T) {
	t.Parallel()
	planner := Planner{Policy: testPolicy()}
	records := []regionlifecycle.Record{activeGRU()}
	noise := []Signal{
		signal(SignalUnplaceableIntent, "iad", "unknown cell", time.Hour),
		signal(SignalUnplaceableIntent, "sfo", "too old", 25*time.Hour),
		signal(SignalUnplaceableIntent, "sfo", "future", -time.Hour),
		{Kind: SignalUnplaceableIntent, Cell: "sfo", EvidenceDigest: "not-a-digest", ObservedAt: now},
		{Kind: "rumor", Cell: "sfo", EvidenceDigest: digest("rumor"), ObservedAt: now},
		signal(SignalUnplaceableIntent, "gru", "already active", time.Hour),
		signal(SignalCapacityError, "sfo", "no overflow", time.Hour),
		signal(SignalCapacityError, "sfo", "no overflow 2", time.Hour),
		signal(SignalCapacityError, "sfo", "no overflow 3", time.Hour),
	}
	if proposals, err := planner.Plan(noise, records, now); err != nil || len(proposals) != 0 {
		t.Fatalf("noise proposals = %+v, %v", proposals, err)
	}

	both := []Signal{signal(SignalUnplaceableIntent, "sfo", "s", time.Hour), signal(SignalUnplaceableIntent, "fra", "f", time.Hour)}
	proposals, err := planner.Plan(both, records, now)
	// GRU commits 9_000. Cells are considered in sorted order: FRA fits
	// (18_500), then SFO would make 27_500 > 20_000 and is left for later.
	if err != nil || len(proposals) != 1 || proposals[0].Cell != "fra" {
		t.Fatalf("budget-limited proposals = %+v, %v", proposals, err)
	}
	limited := planner
	limited.Policy.MaxRegions = 1
	if proposals, _ := limited.Plan(both, records, now); len(proposals) != 0 {
		t.Fatalf("proposals beyond the region maximum: %+v", proposals)
	}

	rejected := activeGRU()
	rejected.Cell, rejected.Phase, rejected.UpdatedAt = "sfo", regionlifecycle.Rejected, now.Add(-time.Hour)
	rejected.Proposal.Cell = "sfo"
	if proposals, _ := planner.Plan(both[:1], append(records, rejected), now); len(proposals) != 0 {
		t.Fatalf("re-proposed a cell rejected within the window: %+v", proposals)
	}
	rejected.UpdatedAt = now.Add(-48 * time.Hour)
	if proposals, _ := planner.Plan(both[:1], append(records, rejected), now); len(proposals) != 1 {
		t.Fatalf("cell rejected long ago was not re-proposed: %+v", proposals)
	}
	for name, mutate := range map[string]func(*Policy){
		"empty catalog": func(p *Policy) { p.Catalog = nil },
		"self overflow": func(p *Policy) {
			p.Catalog["sfo"] = CatalogEntry{Cell: "sfo", OCIRegion: "x", EstimatedMonthlyCents: 1, Overflow: "sfo"}
		},
		"unknown overflow": func(p *Policy) {
			p.Catalog["sfo"] = CatalogEntry{Cell: "sfo", OCIRegion: "x", EstimatedMonthlyCents: 1, Overflow: "iad"}
		},
		"mismatched key": func(p *Policy) {
			p.Catalog["iad"] = CatalogEntry{Cell: "sfo", OCIRegion: "x", EstimatedMonthlyCents: 1}
		},
		"no window":         func(p *Policy) { p.Window = 0 },
		"no ceiling":        func(p *Policy) { p.MonthlyCeilingCents = 0 },
		"no latency sample": func(p *Policy) { p.LatencySamples = 0 },
		"no home region":    func(p *Policy) { p.Home = regionlifecycle.Home{} },
	} {
		policy := testPolicy()
		mutate(&policy)
		if _, err := (Planner{Policy: policy}).Plan(nil, nil, now); err == nil {
			t.Errorf("%s policy accepted", name)
		}
	}
}

type staticSource []Signal

func (s staticSource) Signals(context.Context, time.Time) ([]Signal, error) { return s, nil }

func TestRunOnlyProposesAndNeverApproves(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	js := newTestJetStream(t)
	global := startGlobalAuthority(ctx, t, js)
	store, err := regionlifecycle.OpenStore(ctx, js, 1, global)
	if err != nil {
		t.Fatal(err)
	}
	public, _, _ := ed25519.GenerateKey(nil)
	machine := regionlifecycle.Machine{Policy: regionlifecycle.Policy{
		MaxRegions: 3, MonthlyCeilingCents: 20_000, AdmissionTTL: regionlifecycle.DefaultAdmissionTTL,
		ProposalTTL: time.Hour, ApprovalMaxLifetime: time.Hour, MinIdle: time.Hour,
		Approvers: map[string]ed25519.PublicKey{"operator:x": public},
	}}
	planner := Planner{Policy: testPolicy()}
	source := staticSource{signal(SignalUnplaceableIntent, "sfo", "intent", time.Minute)}
	epoch := global.Current().Epoch
	submitted, err := Run(ctx, source, planner, store, machine, epoch, now)
	if err != nil || !slices.Equal(submitted, []string{"sfo"}) {
		t.Fatalf("run = %v, %v", submitted, err)
	}
	record, _, err := store.Get(ctx, "sfo")
	if err != nil || record.Phase != regionlifecycle.Proposed || record.Approval != nil || record.Admission != nil {
		t.Fatalf("planner record = %+v, %v", record, err)
	}
	if submitted, err := Run(ctx, source, planner, store, machine, epoch, now); err != nil || len(submitted) != 0 {
		t.Fatalf("second run = %v, %v; an open proposal must not be duplicated", submitted, err)
	}
	// After the proposal expires and is rejected, a later signal proposes anew.
	expired, revision, err := store.Get(ctx, "sfo")
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := machine.Expire(expired, now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(ctx, epoch, expired, rejected, revision); err != nil {
		t.Fatal(err)
	}
	later := now.Add(48 * time.Hour)
	submitted, err = Run(ctx, staticSource{signal(SignalUnplaceableIntent, "sfo", "intent-2", -47*time.Hour)}, planner, store, machine, epoch, later)
	if err != nil || !slices.Equal(submitted, []string{"sfo"}) {
		t.Fatalf("re-proposal = %v, %v", submitted, err)
	}
	record, _, err = store.Get(ctx, "sfo")
	if err != nil || record.Phase != regionlifecycle.Proposed || record.ProposalGeneration != rejected.Generation+1 {
		t.Fatalf("re-proposed record = %+v, %v", record, err)
	}
	if _, err := Run(ctx, source, planner, store, machine, epoch+1, later); err != nil {
		// No new proposal is needed, so a foreign epoch is never exercised.
		t.Fatalf("idle run = %v", err)
	}
}

func startGlobalAuthority(ctx context.Context, t *testing.T, js jetstream.JetStream) *authority.Runtime {
	t.Helper()
	runtime, err := authority.Start(ctx, js, authority.Config{
		Scope: protocol.GlobalScope, CandidateID: "gru-a", Replicas: 1,
		LeaseDuration: 5 * time.Second, RenewInterval: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	for !runtime.Current().CanMutate() {
		if ctx.Err() != nil {
			t.Fatal("global authority never became leader")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return runtime
}

func newTestJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	srv, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(t.TempDir(), "jetstream"),
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	return js
}
