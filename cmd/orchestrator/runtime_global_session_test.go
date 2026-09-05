package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control"
)

type globalTestWorker struct {
	done    chan struct{}
	release <-chan struct{}
	failure error
}

func (w *globalTestWorker) Completion() <-chan struct{} { return w.done }
func (w *globalTestWorker) Close() error {
	if w.release != nil {
		<-w.release
	}
	<-w.done
	return w.failure
}
func awaitGlobal(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("global lifecycle condition did not become true")
}
func receivedGlobal[T any](t *testing.T, channel <-chan T) T {
	t.Helper()
	select {
	case result := <-channel:
		return result
	case <-time.After(6 * time.Second):
		t.Fatal("global lifecycle event timed out")
		var zero T
		return zero
	}
}

func TestGlobalWorkerLeaseLifecycle(t *testing.T) {
	cluster := newRotationStateCluster(t)
	connection := cluster.connect(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := openRotationTestLeaseStore(t, ctx, connection, true)
	lease := rotationTestLease(1, "global-controller-gru-lifecycle")
	putRotationTestLease(t, ctx, store, lease)
	var mu sync.Mutex
	leader := false
	snapshot := func() control.RegionalAuthoritySnapshot {
		mu.Lock()
		defer mu.Unlock()
		expiry := time.Now().Add(time.Minute)
		state := "follower"
		if leader {
			state = "leader"
		}
		return control.RegionalAuthoritySnapshot{State: state, IsLeader: leader, Epoch: 1, ObservedAt: time.Now(), LeaseExpiresAt: &expiry}
	}
	type started struct {
		session globalWorkerSession
		ctx     context.Context
		worker  *globalTestWorker
	}
	starts := make(chan started, 4)
	releaseFirst := make(chan struct{})
	count := 0
	supervisor, err := startLeaseOwnedGlobalWorkers(ctx, globalWorkerSessionConfig{CandidateID: lease.CandidateId, Snapshot: snapshot, OpenConnection: cluster.sessionConnect, Start: func(ctx context.Context, session globalWorkerSession) (component, error) {
		count++
		worker := &globalTestWorker{done: make(chan struct{})}
		if count == 1 {
			worker.release = releaseFirst
		}
		go func() { <-ctx.Done(); close(worker.done) }()
		starts <- started{session, ctx, worker}
		return worker, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer supervisor.Close()
	// A follower does not open a constructor despite a valid leader record.
	select {
	case <-starts:
		t.Fatal("follower started workers")
	case <-time.After(1100 * time.Millisecond):
	}
	mu.Lock()
	leader = true
	mu.Unlock()
	first := receivedGlobal(t, starts)
	awaitGlobal(t, func() bool { return supervisor.Snapshot().Ready })
	lease.IssuedAt = time.Now().UTC()
	putRotationTestLease(t, ctx, store, lease)
	if err := first.session.CheckEffectAuthority(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-starts:
		t.Fatal("same-lease renewal restarted workers")
	case <-time.After(1100 * time.Millisecond):
	}
	// LeaseID is part of ownership even when candidate and epoch remain equal.
	lease.LeaseId = "replacement-lease"
	lease.IssuedAt = time.Now().UTC()
	putRotationTestLease(t, ctx, store, lease)
	if err := first.session.CheckEffectAuthority(ctx); err == nil {
		t.Fatal("old lease retained effect authority")
	}
	if first.ctx.Err() == nil || supervisor.Snapshot().Ready {
		t.Fatal("failed effect proof did not cancel and withdraw readiness immediately")
	}
	select {
	case <-starts:
		t.Fatal("successor overlapped old shutdown")
	case <-time.After(1100 * time.Millisecond):
	}
	close(releaseFirst)
	second := receivedGlobal(t, starts)
	if second.session.Lease.LeaseId != lease.LeaseId {
		t.Fatal("successor received stale identity")
	}
	if err := first.session.CheckEffectAuthority(ctx); err == nil {
		t.Fatal("canceled session proof recovered")
	}
	awaitGlobal(t, func() bool { return supervisor.Snapshot().Ready })
	second.session.Connection.Close()
	awaitGlobal(t, func() bool { return second.ctx.Err() != nil && !supervisor.Snapshot().Ready })
	cancel()
	if err := supervisor.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestGlobalWorkerRefusesR1AndExpiredLease(t *testing.T) {
	cluster := newRotationStateCluster(t)
	connection := cluster.connect(t)
	ctx := context.Background()
	js, err := jetstream.New(connection)
	if err != nil {
		t.Fatal(err)
	}
	var store jetstream.KeyValue
	awaitGlobal(t, func() bool {
		var err error
		store, err = js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "ORCH_LEADERS", Storage: jetstream.FileStorage, Replicas: 1})
		return err == nil
	})
	lease := rotationTestLease(1, "global-controller-gru-r1")
	putRotationTestLease(t, ctx, store, lease)
	expiry := time.Now().Add(time.Minute)
	worker := &leaseOwnedGlobalWorkers{config: globalWorkerSessionConfig{CandidateID: lease.CandidateId, Snapshot: func() control.RegionalAuthoritySnapshot {
		return control.RegionalAuthoritySnapshot{State: "leader", IsLeader: true, Epoch: 1, ObservedAt: time.Now(), LeaseExpiresAt: &expiry}
	}, OpenConnection: cluster.sessionConnect, Start: func(context.Context, globalWorkerSession) (component, error) {
		t.Error("R1 or expired session started constructor")
		return nil, nil
	}}}
	if _, err := worker.acquire(ctx); err == nil {
		t.Fatal("R1 admitted operational workers")
	}
	lease.IssuedAt = time.Now().Add(-2 * time.Minute)
	if err := worker.serve(ctx, globalWorkerSession{Lease: lease}); err != nil {
		t.Fatal(err)
	}
}

func TestGlobalWorkerConstructorFailureCancelsBeforeJoin(t *testing.T) {
	for _, mode := range []string{"failed", "canceled-and-failed"} {
		t.Run(mode, func(t *testing.T) {
			cluster := newRotationStateCluster(t)
			connection := cluster.connect(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			store := openRotationTestLeaseStore(t, ctx, connection, true)
			lease := rotationTestLease(1, "global-controller-gru-construction")
			putRotationTestLease(t, ctx, store, lease)
			expiry := time.Now().Add(time.Minute)
			failure := errors.New("constructor failed")
			worker := &leaseOwnedGlobalWorkers{config: globalWorkerSessionConfig{CandidateID: lease.CandidateId, Snapshot: func() control.RegionalAuthoritySnapshot {
				return control.RegionalAuthoritySnapshot{State: "leader", IsLeader: true, Epoch: 1, ObservedAt: time.Now(), LeaseExpiresAt: &expiry}
			}, OpenConnection: cluster.sessionConnect, Start: func(ctx context.Context, _ globalWorkerSession) (component, error) {
				group := &globalTestWorker{done: make(chan struct{})}
				go func() { <-ctx.Done(); close(group.done) }()
				if mode == "canceled-and-failed" {
					cancel()
					return group, errors.Join(context.Canceled, failure)
				}
				return group, failure
			}}}
			session, err := worker.acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Connection.Close()
			if err := worker.serve(ctx, session); !errors.Is(err, failure) {
				t.Fatalf("constructor error=%v", err)
			}
		})
	}
}

func TestGlobalWorkerCloseFailureAndUnexpectedCompletionRemainFatal(t *testing.T) {
	failure := errors.New("disposal failed")
	done := make(chan struct{})
	close(done)
	if err := joinGlobalWorker(&globalTestWorker{done: done, failure: errors.Join(context.Canceled, failure)}); !errors.Is(err, failure) {
		t.Fatalf("close failure lost: %v", err)
	}
	cluster := newRotationStateCluster(t)
	connection := cluster.connect(t)
	ctx := context.Background()
	store := openRotationTestLeaseStore(t, ctx, connection, true)
	lease := rotationTestLease(1, "global-controller-gru-completed")
	putRotationTestLease(t, ctx, store, lease)
	expiry := time.Now().Add(time.Minute)
	worker := &leaseOwnedGlobalWorkers{config: globalWorkerSessionConfig{CandidateID: lease.CandidateId, Snapshot: func() control.RegionalAuthoritySnapshot {
		return control.RegionalAuthoritySnapshot{State: "leader", IsLeader: true, Epoch: 1, ObservedAt: time.Now(), LeaseExpiresAt: &expiry}
	}, OpenConnection: cluster.sessionConnect, Start: func(context.Context, globalWorkerSession) (component, error) {
		return &globalTestWorker{done: done}, nil
	}}}
	session, err := worker.acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Connection.Close()
	if err := worker.serve(ctx, session); err == nil || worker.Snapshot().Ready {
		t.Fatal("completed constructor was declared ready")
	}
}

func TestGlobalWorkerCancellationDuringDialIsClean(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dialing := make(chan struct{})
	expiry := time.Now().Add(time.Minute)
	worker, err := startLeaseOwnedGlobalWorkers(ctx, globalWorkerSessionConfig{CandidateID: "global-controller-gru-dial", Snapshot: func() control.RegionalAuthoritySnapshot {
		return control.RegionalAuthoritySnapshot{State: "leader", IsLeader: true, Epoch: 1, ObservedAt: time.Now(), LeaseExpiresAt: &expiry}
	}, OpenConnection: func(ctx context.Context) (*nats.Conn, error) { close(dialing); <-ctx.Done(); return nil, ctx.Err() }, Start: func(context.Context, globalWorkerSession) (component, error) {
		t.Error("canceled dial constructed workers")
		return nil, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	receivedGlobal(t, dialing)
	cancel()
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestGlobalWorkerExpiryCancelsBlockedConstructionAndCleansLateResult(t *testing.T) {
	cluster := newRotationStateCluster(t)
	connection := cluster.connect(t)
	ctx := context.Background()
	store := openRotationTestLeaseStore(t, ctx, connection, true)
	lease := rotationTestLease(1, "global-controller-gru-late")
	putRotationTestLease(t, ctx, store, lease)
	expiry := time.Now().Add(time.Minute)
	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	cleaned := make(chan struct{})
	worker := &leaseOwnedGlobalWorkers{config: globalWorkerSessionConfig{CandidateID: lease.CandidateId, Snapshot: func() control.RegionalAuthoritySnapshot {
		return control.RegionalAuthoritySnapshot{State: "leader", IsLeader: true, Epoch: 1, ObservedAt: time.Now(), LeaseExpiresAt: &expiry}
	}, OpenConnection: cluster.sessionConnect, Start: func(ctx context.Context, _ globalWorkerSession) (component, error) {
		entered <- ctx
		<-release
		done := make(chan struct{})
		close(done)
		return &lateGlobalTestWorker{globalTestWorker: globalTestWorker{done: done}, cleaned: cleaned}, nil
	}}}
	session, err := worker.acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Connection.Close()
	// Scheduling delay can consume a lease before a blocked constructor returns.
	session.Lease.IssuedAt = time.Now()
	session.Lease.DurationMilliseconds = 100
	served := make(chan error, 1)
	go func() { served <- worker.serve(ctx, session) }()
	lifetime := receivedGlobal(t, entered)
	awaitGlobal(t, func() bool { return lifetime.Err() != nil })
	select {
	case err := <-served:
		if err == nil {
			t.Fatal("unjoined constructor did not fail")
		}
	case <-time.After(globalWorkerJoin + time.Second):
		t.Fatal("constructor did not fail in bound")
	}
	close(release)
	receivedGlobal(t, cleaned)
	if worker.Snapshot().Ready {
		t.Fatal("late constructor was adopted")
	}
}

type lateGlobalTestWorker struct {
	globalTestWorker
	cleaned chan struct{}
}

func (w *lateGlobalTestWorker) Close() error {
	defer close(w.cleaned)
	return w.globalTestWorker.Close()
}

func TestGlobalWorkerMinorityCancelsLiveGroup(t *testing.T) {
	cluster := newRotationStateCluster(t)
	connection := cluster.connect(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := openRotationTestLeaseStore(t, ctx, connection, true)
	lease := rotationTestLease(1, "global-controller-gru-minority")
	putRotationTestLease(t, ctx, store, lease)
	expiry := time.Now().Add(time.Minute)
	started := make(chan context.Context, 1)
	worker, err := startLeaseOwnedGlobalWorkers(ctx, globalWorkerSessionConfig{CandidateID: lease.CandidateId, Snapshot: func() control.RegionalAuthoritySnapshot {
		return control.RegionalAuthoritySnapshot{State: "leader", IsLeader: true, Epoch: 1, ObservedAt: time.Now(), LeaseExpiresAt: &expiry}
	}, OpenConnection: cluster.sessionConnect, Start: func(ctx context.Context, _ globalWorkerSession) (component, error) {
		group := &globalTestWorker{done: make(chan struct{})}
		go func() { <-ctx.Done(); close(group.done) }()
		started <- ctx
		return group, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	lifetime := receivedGlobal(t, started)
	awaitGlobal(t, func() bool { return worker.Snapshot().Ready })
	cluster.servers[1].Shutdown()
	cluster.servers[2].Shutdown()
	awaitGlobal(t, func() bool { return lifetime.Err() != nil && !worker.Snapshot().Ready })
	select {
	case <-worker.Completion():
		t.Fatal("global proof loss terminated regional process lifetime")
	default:
	}
	cancel()
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
}
