package app

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

type switchingFencer struct {
	mu       sync.Mutex
	snapshot authority.Snapshot
}

func (fencer *switchingFencer) Current() authority.Snapshot {
	fencer.mu.Lock()
	defer fencer.mu.Unlock()
	return fencer.snapshot
}

func (*switchingFencer) Guard(context.Context, uint64) error { return nil }

func (fencer *switchingFencer) set(snapshot authority.Snapshot) {
	fencer.mu.Lock()
	fencer.snapshot = snapshot
	fencer.mu.Unlock()
}

type fakeClusterHealth struct{ ready atomic.Bool }

func (health *fakeClusterHealth) FullClusterReady(int) bool { return health.ready.Load() }
func (*fakeClusterHealth) Observe(context.Context) (observability.NATSView, error) {
	return observability.NATSView{ClusterPeers: 1, MetaLeader: "two"}, nil
}

func installTestJournal(t *testing.T) *decisionlog.Journal {
	t.Helper()
	journal := decisionlog.NewJournal(decisionlog.JournalConfig{Region: "lab", Member: "one"})
	t.Cleanup(decisionlog.SetDefault(journal))
	return journal
}

func waitForDecisions(t *testing.T, journal *decisionlog.Journal, kind decisionlog.Kind, count int) []decisionlog.Decision {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		result, _ := journal.Query(t.Context(), decisionlog.Query{Kinds: []decisionlog.Kind{kind}})
		if len(result.Decisions) >= count {
			return result.Decisions
		}
		if time.Now().After(deadline) {
			t.Fatalf("want %d %s decisions, have %d", count, kind, len(result.Decisions))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestWatchControlPlaneJournalsLeadershipAndHealth(t *testing.T) {
	journal := installTestJournal(t)
	previousWatch, previousHealth := controlPlaneWatchInterval, clusterHealthInterval
	controlPlaneWatchInterval, clusterHealthInterval = 20*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { controlPlaneWatchInterval, clusterHealthInterval = previousWatch, previousHealth })
	fencer := &switchingFencer{snapshot: authority.Snapshot{Ready: true, OwnerID: "two", Epoch: 4}}
	health := &fakeClusterHealth{}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { watchControlPlane(ctx, "lab", "one", fencer, health, 3); close(done) }()
	defer func() { cancel(); <-done }()

	health.ready.Store(true) // first formation: not journaled
	time.Sleep(200 * time.Millisecond)
	fencer.set(authority.Snapshot{Ready: true, Leader: true, OwnerID: "one", Epoch: 5})
	leader := waitForDecisions(t, journal, decisionlog.KindLeaderChanged, 1)
	if leader[0].Epoch != 5 || leader[0].Subject.ID != "one" ||
		leader[0].Reason != "This controller acquired the regional authority lease, ending epoch 4." {
		t.Fatalf("leader = %+v", leader[0])
	}
	health.ready.Store(false)
	degraded := waitForDecisions(t, journal, decisionlog.KindQuorumDegraded, 1)
	if degraded[0].Status != decisionlog.StatusFailed || len(degraded[0].Signals) < 3 {
		t.Fatalf("degraded = %+v", degraded[0])
	}
	health.ready.Store(true)
	waitForDecisions(t, journal, decisionlog.KindQuorumRestored, 1)
	if result, _ := journal.Query(t.Context(), decisionlog.Query{Kinds: []decisionlog.Kind{decisionlog.KindLeaderChanged}}); len(result.Decisions) != 1 {
		t.Fatalf("leadership journaled %d times", len(result.Decisions))
	}
}

func TestHoldJournalDeduplicatesReasons(t *testing.T) {
	journal := installTestJournal(t)
	holds := newHoldJournal("lab")
	now := time.Now()
	reason := "member m1 OCI host is not currently observed; retained volume creation is withheld"
	for range 5 {
		holds.record(t.Context(), reason, now)
		holds.record(t.Context(), "database db/p0 has a committed terminal teardown fence", now)
	}
	holds.record(t.Context(), reason, now.Add(holdRepeat))
	result, _ := journal.Query(t.Context(), decisionlog.Query{Kinds: []decisionlog.Kind{decisionlog.KindHeld}})
	if len(result.Decisions) != 3 {
		t.Fatalf("holds = %d", len(result.Decisions))
	}
	subjects := map[string]bool{}
	for _, decision := range result.Decisions {
		subjects[decision.Subject.String()] = true
	}
	if !subjects["seat/m1"] || !subjects["database/db/p0"] {
		t.Fatalf("subjects = %v", subjects)
	}
	log := new(placementHoldLog)
	log.record(reason)
	log.record("other")
	log.record(reason)
	if got := log.Holds(time.Now()); len(got) != 2 {
		t.Fatalf("active holds = %+v", got)
	}
}

func TestConfiguredRegions(t *testing.T) {
	if got := configuredRegions("gru"); !slices.Equal(got, []string{"GRU", "SFO", "FRA"}) {
		t.Fatalf("gru = %v", got)
	}
	if got := configuredRegions("lab"); got != nil {
		t.Fatalf("lab = %v", got)
	}
}
