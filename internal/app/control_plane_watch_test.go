package app

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// metaClusterHealth is a cluster whose JetStream meta leadership the test
// moves.
type metaClusterHealth struct {
	ready atomic.Bool
	meta  atomic.Bool
}

func (health *metaClusterHealth) FullClusterReady(int) bool { return health.ready.Load() }
func (health *metaClusterHealth) Observe(context.Context) (observability.NATSView, error) {
	view := observability.NATSView{ServerName: "lab-one", MetaClusterSize: 3, MetaLeader: "lab-two"}
	if health.meta.Load() {
		view.IsMetaLeader, view.MetaLeader = true, "lab-one"
	}
	return view, nil
}

func fastControlPlaneWatch(t *testing.T) {
	t.Helper()
	previousWatch, previousHealth := controlPlaneWatchInterval, clusterHealthInterval
	controlPlaneWatchInterval, clusterHealthInterval = 20*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { controlPlaneWatchInterval, clusterHealthInterval = previousWatch, previousHealth })
}

// A follower whose authority runtime reports a failure snapshot keeps its
// own candidate as OwnerID; that is no leader, so the follower journals the
// quorum loss instead of dropping it.
func TestQuorumLossIsJournaledWithoutAValidLease(t *testing.T) {
	journal := installTestJournal(t)
	fastControlPlaneWatch(t)
	fencer := &switchingFencer{snapshot: authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, OwnerID: "0000000000FH1WEBBP25VGJXZG", Epoch: 4,
		ExpiresAt: time.Now().Add(time.Hour)}}
	health := &metaClusterHealth{}
	health.ready.Store(true)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { watchControlPlane(ctx, "lab", "one", fencer, health, 3); close(done) }()
	defer func() { cancel(); <-done }()
	time.Sleep(150 * time.Millisecond)
	fencer.set(authority.Snapshot{Ready: false, OwnerID: "0000000000CAA4X2ZKZ65HN8EW", Reason: "control-log-unavailable"})
	health.ready.Store(false)
	degraded := waitForDecisions(t, journal, decisionlog.KindQuorumDegraded, 1)
	if degraded[0].Status != decisionlog.StatusFailed {
		t.Fatalf("degraded = %+v", degraded[0])
	}
}

// While another controller holds a valid lease, a follower leaves the
// journal entry to the leader.
func TestFollowerWithAValidLeaseLeavesQuorumToTheLeader(t *testing.T) {
	journal := installTestJournal(t)
	fastControlPlaneWatch(t)
	fencer := &switchingFencer{snapshot: authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, OwnerID: "0000000000FH1WEBBP25VGJXZG", Epoch: 4,
		ExpiresAt: time.Now().Add(time.Hour)}}
	health := &metaClusterHealth{}
	health.ready.Store(true)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { watchControlPlane(ctx, "lab", "one", fencer, health, 3); close(done) }()
	time.Sleep(150 * time.Millisecond)
	health.ready.Store(false)
	time.Sleep(250 * time.Millisecond)
	cancel()
	<-done
	result, _ := journal.Query(t.Context(), decisionlog.Query{Kinds: []decisionlog.Kind{decisionlog.KindQuorumDegraded}})
	if len(result.Decisions) != 0 {
		t.Fatalf("a follower journaled the leader's quorum loss: %+v", result.Decisions)
	}
}

// The elected JetStream meta leader journals its election once, so the NATS
// page's leadership timeline shows meta leader moves too.
func TestMetaLeaderElectionIsJournaledOnce(t *testing.T) {
	journal := installTestJournal(t)
	fastControlPlaneWatch(t)
	fencer := &switchingFencer{snapshot: authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, OwnerID: "0000000000FH1WEBBP25VGJXZG", Epoch: 4,
		ExpiresAt: time.Now().Add(time.Hour)}}
	health := &metaClusterHealth{}
	health.ready.Store(true)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { watchControlPlane(ctx, "lab", "one", fencer, health, 3); close(done) }()
	defer func() { cancel(); <-done }()
	time.Sleep(150 * time.Millisecond)
	health.meta.Store(true)
	elected := waitForDecisions(t, journal, decisionlog.KindLeaderChanged, 1)
	if elected[0].Subject.Kind != "nats-meta" || elected[0].Subject.ID != "one" ||
		elected[0].Reason != "The JetStream metadata group elected this server; lab-two led it before." {
		t.Fatalf("meta election = %+v", elected[0])
	}
	time.Sleep(250 * time.Millisecond)
	if result, _ := journal.Query(t.Context(), decisionlog.Query{Kinds: []decisionlog.Kind{decisionlog.KindLeaderChanged}}); len(result.Decisions) != 1 {
		t.Fatalf("meta election journaled %d times", len(result.Decisions))
	}
}

// A follower that saw the quorum loss while the leader's lease still looked
// valid keeps it unreported: when that lease then expires (the leader died
// with the cluster) the follower still journals it.
func TestQuorumLossSeenUnderAValidLeaseIsJournaledOnceTheLeaseExpires(t *testing.T) {
	journal := installTestJournal(t)
	fastControlPlaneWatch(t)
	fencer := &switchingFencer{snapshot: authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, OwnerID: "0000000000FH1WEBBP25VGJXZG", Epoch: 4,
		ExpiresAt: time.Now().Add(time.Hour)}}
	health := &metaClusterHealth{}
	health.ready.Store(true)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { watchControlPlane(ctx, "lab", "one", fencer, health, 3); close(done) }()
	defer func() { cancel(); <-done }()
	time.Sleep(150 * time.Millisecond)
	health.ready.Store(false)
	time.Sleep(200 * time.Millisecond)
	fencer.set(authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, OwnerID: "0000000000FH1WEBBP25VGJXZG", Epoch: 4, ExpiresAt: time.Now().Add(-time.Second)})
	waitForDecisions(t, journal, decisionlog.KindQuorumDegraded, 1)
}
