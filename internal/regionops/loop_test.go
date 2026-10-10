package regionops

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/identity"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
)

type recorder struct {
	mu        sync.Mutex
	decisions []decisionlog.Decision
}

func (r *recorder) Record(_ context.Context, decision decisionlog.Decision) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.decisions = append(r.decisions, decision)
	return ""
}

func (r *recorder) kinds() []decisionlog.Kind {
	r.mu.Lock()
	defer r.mu.Unlock()
	var kinds []decisionlog.Kind
	for _, decision := range r.decisions {
		kinds = append(kinds, decision.Kind)
	}
	return kinds
}

// fakeIdentity is a tenancy whose subscriptions start IN_PROGRESS.
type fakeIdentity struct {
	mu      sync.Mutex
	status  map[string]identity.RegionSubscriptionStatusEnum
	creates []string
	tokens  []string
}

func (f *fakeIdentity) ListRegionSubscriptions(_ context.Context, request identity.ListRegionSubscriptionsRequest,
) (identity.ListRegionSubscriptionsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if request.TenancyId == nil || *request.TenancyId != "ocid1.tenancy.oc1..test" {
		return identity.ListRegionSubscriptionsResponse{}, errors.New("wrong tenancy")
	}
	var items []identity.RegionSubscription
	for name, status := range f.status {
		items = append(items, identity.RegionSubscription{RegionName: &name, Status: status})
	}
	return identity.ListRegionSubscriptionsResponse{Items: items}, nil
}

func (f *fakeIdentity) CreateRegionSubscription(_ context.Context, request identity.CreateRegionSubscriptionRequest,
) (identity.CreateRegionSubscriptionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := *request.RegionKey
	f.creates = append(f.creates, key)
	f.tokens = append(f.tokens, *request.OpcRetryToken)
	name := map[string]string{"SJC": "us-sanjose-1", "FRA": "eu-frankfurt-1"}[key]
	f.status[name] = identity.RegionSubscriptionStatusInProgress
	return identity.CreateRegionSubscriptionResponse{RegionSubscription: identity.RegionSubscription{
		RegionKey: &key, RegionName: &name, Status: identity.RegionSubscriptionStatusInProgress}}, nil
}

func (f *fakeIdentity) ready(name string) {
	f.mu.Lock()
	f.status[name] = identity.RegionSubscriptionStatusReady
	f.mu.Unlock()
}

type follower struct{}

func (follower) Current() authority.Snapshot         { return authority.Snapshot{Scope: protocol.GlobalScope} }
func (follower) Guard(context.Context, uint64) error { return authority.ErrNotLeader }

func TestLoopAdmitsSubscribesAndWaitsOnTheGlobalLeader(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	journal := &recorder{}
	t.Cleanup(decisionlog.SetDefault(journal))
	js := newTestJetStream(t)
	leader := startGlobalAuthority(ctx, t, js)
	store, err := regionlifecycle.OpenStore(ctx, js, 1, leader)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC()
	clock := start
	machine := regionlifecycle.Machine{}
	tenancy := &fakeIdentity{status: map[string]identity.RegionSubscriptionStatusEnum{
		"sa-saopaulo-1": identity.RegionSubscriptionStatusReady}}
	loop := &Loop{Store: store, Machine: machine, Home: regionlifecycle.Home{Cell: "gru"},
		Leader: leader, Admissions: PriceList{MonthlyCents: map[string]uint64{"sfo": 9_000}, HeadroomCents: 20_000},
		Effectors: Effectors{
			regionlifecycle.StepSubscribe: Subscription{API: tenancy, TenancyID: "ocid1.tenancy.oc1..test"},
		},
		Now: func() time.Time { return clock }}

	proposal := regionlifecycle.Proposal{ID: entityid.Derive("test-proposal", "sfo-g1-0123456789ab"), Cell: "sfo", OCIRegion: "us-sanjose-1",
		Reason: "planner: capacity", EvidenceDigests: []string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		EstimatedMonthlyCents: 9_000, ProposedAt: start}
	record, err := machine.Propose(proposal, start)
	if err != nil {
		t.Fatal(err)
	}
	epoch := leader.Current().Epoch
	if _, err := store.Create(ctx, epoch, record); err != nil {
		t.Fatal(err)
	}

	// A follower does nothing at all.
	if report := (&Loop{Store: store, Machine: machine, Leader: follower{}, Admissions: loop.Admissions}).Tick(ctx); report.Leader {
		t.Fatal("a follower ran the loop")
	}
	// An unapproved proposal is neither admitted nor driven.
	if report := loop.Tick(ctx); len(report.Admitted)+len(report.Advanced) != 0 || len(report.Errors) != 0 {
		t.Fatalf("unapproved tick = %+v", report)
	}

	record, revision, err := store.Get(ctx, "sfo")
	if err != nil {
		t.Fatal(err)
	}
	approved, err := machine.Approve(record, start)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(ctx, epoch, record, approved, revision); err != nil {
		t.Fatal(err)
	}

	// Admission, then the subscription: OCI accepts it but it is not READY,
	// so the step is held with its intent, never re-created.
	report := loop.Tick(ctx)
	if !slices.Equal(report.Admitted, []string{"sfo"}) || !slices.Equal(report.Advanced, []string{"sfo"}) {
		t.Fatalf("admit tick = %+v", report)
	}
	held, _, err := store.Get(ctx, "sfo")
	if err != nil || held.Phase != regionlifecycle.Held || held.Pending == nil || held.Admission == nil ||
		held.Admission.EstimatedMonthlyCents != 9_000 {
		t.Fatalf("held = %+v, %v", held, err)
	}
	if !slices.Equal(tenancy.creates, []string{"SJC"}) || tenancy.tokens[0] != held.Pending.CreateKey {
		t.Fatalf("subscriptions = %v tokens %v", tenancy.creates, tenancy.tokens)
	}
	// Still in progress: nothing changes and nothing is created again.
	if report := loop.Tick(ctx); len(report.Resumed)+len(report.Advanced) != 0 || len(report.Errors) != 0 {
		t.Fatalf("in-progress tick = %+v", report)
	}
	tenancy.ready("us-sanjose-1")
	if report := loop.Tick(ctx); !slices.Equal(report.Resumed, []string{"sfo"}) {
		t.Fatalf("ready tick = %+v", report)
	}
	subscribed, _, err := store.Get(ctx, "sfo")
	if err != nil || subscribed.Phase != regionlifecycle.Subscribed || len(subscribed.Completed) != 1 ||
		subscribed.Completed[0].ResourceID != "us-sanjose-1" || len(tenancy.creates) != 1 {
		t.Fatalf("subscribed = %+v, %v (creates %v)", subscribed, err, tenancy.creates)
	}

	// The foundation step has no effector: the region waits, the wait is
	// journaled once, and its admission is not churned.
	clock = start.Add(12 * time.Minute)
	for range 2 {
		if report := loop.Tick(ctx); !slices.Equal(report.Waiting, []string{"sfo"}) || len(report.Readmitted) != 0 {
			t.Fatalf("waiting tick = %+v", report)
		}
	}
	kinds := journal.kinds()
	held1 := slices.Index(kinds, decisionlog.KindHeld)
	if !slices.Contains(kinds, decisionlog.KindRegionAdmitted) || !slices.Contains(kinds, decisionlog.KindRegionStep) ||
		held1 < 0 || slices.Index(kinds[held1+1:], decisionlog.KindHeld) >= 0 {
		t.Fatalf("journal kinds = %v", kinds)
	}

	// With a foundation effector the stale admission is refreshed first.
	foundation := &countingEffector{}
	loop.Effectors[regionlifecycle.StepFoundation] = foundation
	// A refused readmission blocks the step even though the older admission
	// is still fresh: the new price exceeds the budget headroom.
	loop.Admissions = PriceList{MonthlyCents: map[string]uint64{"sfo": 11_000}, HeadroomCents: 10_000}
	if report := loop.Tick(ctx); len(report.Readmitted)+len(report.Advanced) != 0 || foundation.executed != 0 ||
		!slices.Equal(report.Waiting, []string{"sfo"}) {
		t.Fatalf("refused readmission tick = %+v, executed %d", report, foundation.executed)
	}
	loop.Admissions = PriceList{MonthlyCents: map[string]uint64{"sfo": 9_000}, HeadroomCents: 20_000}
	report = loop.Tick(ctx)
	if !slices.Equal(report.Readmitted, []string{"sfo"}) || !slices.Equal(report.Advanced, []string{"sfo"}) ||
		foundation.executed != 1 {
		t.Fatalf("readmit tick = %+v, executed %d", report, foundation.executed)
	}
	ready, _, err := store.Get(ctx, "sfo")
	if err != nil || ready.Phase != regionlifecycle.FoundationReady || !ready.Admission.AdmittedAt.Equal(clock) {
		t.Fatalf("foundation = %+v, %v", ready, err)
	}
}

type countingEffector struct{ executed int }

func (e *countingEffector) Execute(_ context.Context, _ regionlifecycle.Record, intent regionlifecycle.StepIntent,
) (regionlifecycle.StepResult, error) {
	e.executed++
	return regionlifecycle.StepResult{Step: intent.Step, CreateKey: intent.CreateKey,
		EvidenceDigest: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"}, nil
}

func (e *countingEffector) Observe(_ context.Context, _ regionlifecycle.Record, intent regionlifecycle.StepIntent,
) (regionlifecycle.Observation, error) {
	return regionlifecycle.Observation{Step: intent.Step, CreateKey: intent.CreateKey}, nil
}

func TestAdmissionRefusalsAreJournaledOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	journal := &recorder{}
	t.Cleanup(decisionlog.SetDefault(journal))
	js := newTestJetStream(t)
	leader := startGlobalAuthority(ctx, t, js)
	store, err := regionlifecycle.OpenStore(ctx, js, 1, leader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	machine := regionlifecycle.Machine{}
	proposal := regionlifecycle.Proposal{ID: entityid.Derive("test-proposal", entityid.Derive("test-proposal", "fra-g1-0123456789ab")), Cell: "fra", OCIRegion: "eu-frankfurt-1",
		Reason: "planner: latency", EvidenceDigests: []string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		EstimatedMonthlyCents: 9_000, ProposedAt: now}
	if _, err := store.Create(ctx, leader.Current().Epoch, mustProposed(t, machine, proposal, now)); err != nil {
		t.Fatal(err)
	}
	stored, revision, err := store.Get(ctx, "fra")
	if err != nil {
		t.Fatal(err)
	}
	approved, err := machine.Approve(stored, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(ctx, leader.Current().Epoch, stored, approved, revision); err != nil {
		t.Fatal(err)
	}
	// The home's 9,000 plus 9,000 exceeds the 12,000 ceiling: 3,000 headroom.
	loop := &Loop{Store: store, Machine: machine, Home: regionlifecycle.Home{Cell: "gru"},
		Leader: leader, Admissions: PriceList{MonthlyCents: map[string]uint64{"fra": 9_000}, HeadroomCents: 3_000}, Now: func() time.Time { return now }}
	for range 3 {
		if report := loop.Tick(ctx); len(report.Admitted) != 0 || !slices.Equal(report.Waiting, []string{"fra"}) {
			t.Fatalf("refused tick = %+v", report)
		}
	}
	if kinds := journal.kinds(); !slices.Equal(kinds, []decisionlog.Kind{decisionlog.KindHeld}) {
		t.Fatalf("journal = %v", kinds)
	}
	// A replacement proposal refused for the same reason is a new attempt and
	// journals its own refusal, even when no tick saw the rejected record.
	stored, revision, err = store.Get(ctx, "fra")
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := machine.Reject(stored, "operator: replan", now)
	if err != nil {
		t.Fatal(err)
	}
	if revision, err = store.Update(ctx, leader.Current().Epoch, stored, rejected, revision); err != nil {
		t.Fatal(err)
	}
	second := proposal
	second.ID = entityid.Derive("test-proposal", "fra-g2")
	reproposed, err := machine.Repropose(rejected, second, now)
	if err != nil {
		t.Fatal(err)
	}
	if revision, err = store.Repropose(ctx, leader.Current().Epoch, rejected, reproposed, revision); err != nil {
		t.Fatal(err)
	}
	approvedAgain, err := machine.Approve(reproposed, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(ctx, leader.Current().Epoch, reproposed, approvedAgain, revision); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if report := loop.Tick(ctx); len(report.Admitted) != 0 || !slices.Equal(report.Waiting, []string{"fra"}) {
			t.Fatalf("refused tick after repropose = %+v", report)
		}
	}
	if kinds := journal.kinds(); !slices.Equal(kinds, []decisionlog.Kind{decisionlog.KindHeld, decisionlog.KindHeld}) {
		t.Fatalf("journal after repropose = %v", kinds)
	}
	if _, err := (PriceList{}).Estimate(ctx, approved, now); err == nil {
		t.Fatal("a region without a price was estimated")
	}
}

func mustProposed(t *testing.T, machine regionlifecycle.Machine, proposal regionlifecycle.Proposal, now time.Time,
) regionlifecycle.Record {
	t.Helper()
	record, err := machine.Propose(proposal, now)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func startGlobalAuthority(ctx context.Context, t *testing.T, js jetstream.JetStream) *authority.Runtime {
	t.Helper()
	runtime, err := authority.Start(ctx, js, authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scope: protocol.GlobalScope, CandidateID: "0000000000F2D374M7NMRHJJQT", Replicas: 1,
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

// TestDriveWithoutEffectorsJournalsTheWait pins that drive on with no
// effector registered (drive without subscribe_regions) still journals, once,
// that an admitted region waits for its first step's effector.
func TestDriveWithoutEffectorsJournalsTheWait(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	journal := &recorder{}
	t.Cleanup(decisionlog.SetDefault(journal))
	js := newTestJetStream(t)
	leader := startGlobalAuthority(ctx, t, js)
	store, err := regionlifecycle.OpenStore(ctx, js, 1, leader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	machine := regionlifecycle.Machine{}
	proposal := regionlifecycle.Proposal{ID: entityid.Derive("test-proposal", entityid.Derive("test-proposal", "fra-g1-0123456789ab")), Cell: "fra", OCIRegion: "eu-frankfurt-1",
		Reason: "planner: latency", EvidenceDigests: []string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		EstimatedMonthlyCents: 9_000, ProposedAt: now}
	if _, err := store.Create(ctx, leader.Current().Epoch, mustProposed(t, machine, proposal, now)); err != nil {
		t.Fatal(err)
	}
	stored, revision, err := store.Get(ctx, "fra")
	if err != nil {
		t.Fatal(err)
	}
	approved, err := machine.Approve(stored, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(ctx, leader.Current().Epoch, stored, approved, revision); err != nil {
		t.Fatal(err)
	}
	loop := &Loop{Store: store, Machine: machine, Home: regionlifecycle.Home{Cell: "gru"},
		Leader: leader, Admissions: PriceList{MonthlyCents: map[string]uint64{"fra": 9_000}, HeadroomCents: 20_000}, Effectors: Effectors{},
		Now: func() time.Time { return now }}
	report := loop.Tick(ctx)
	if !slices.Equal(report.Admitted, []string{"fra"}) || !slices.Equal(report.Waiting, []string{"fra"}) ||
		len(report.Errors) != 0 {
		t.Fatalf("first tick = %+v", report)
	}
	if report := loop.Tick(ctx); !slices.Equal(report.Waiting, []string{"fra"}) || len(report.Advanced) != 0 {
		t.Fatalf("second tick = %+v", report)
	}
	if kinds := journal.kinds(); !slices.Equal(kinds, []decisionlog.Kind{decisionlog.KindRegionAdmitted,
		decisionlog.KindHeld}) {
		t.Fatalf("journal = %v", kinds)
	}
}
