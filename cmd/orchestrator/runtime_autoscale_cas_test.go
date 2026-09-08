package main

import (
	"errors"
	"sync"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
)

// Exercise the production journal-backed target store with two writers using
// the same CAS predecessor. Exactly one writer may commit; the loser must be
// reported as an autoscale conflict so a controller can safely drop its plan.
func TestProductionAutoscaleConcurrentControllersUseNATSTargetStoreCAS(t *testing.T) {
	ctx := t.Context()
	cluster := newRotationStateCluster(t)
	leaseStore := openRotationTestLeaseStore(t, ctx, cluster.connect(t), true)
	lease := rotationTestLease(1, "global-controller-gru-autoscale-cas")
	putRotationTestLease(t, ctx, leaseStore, lease)

	open := func() *autoscale.NATSTargetStore {
		t.Helper()
		journal, err := authorityjournal.New(authorityjournal.Config{
			Connection: cluster.connect(t), CandidateID: lease.CandidateId,
			AuthorityEpoch: uint64(lease.Epoch), LeaseID: lease.LeaseId, StateKey: "autoscale",
		}, func() map[string]autoscale.Target { return map[string]autoscale.Target{} }, func(map[string]autoscale.Target) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		store, err := autoscale.NewNATSTargetStore(journal)
		if err != nil {
			t.Fatal(err)
		}
		return store
	}

	initial := autoscale.Target{Region: "gru", Members: 2}
	seed := open()
	if err := seed.CompareAndSwap(ctx, "gru", nil, initial); err != nil {
		t.Fatal(err)
	}
	left, found, err := open().Load(ctx, "gru")
	if err != nil || !found {
		t.Fatalf("load predecessor: found=%v err=%v", found, err)
	}
	right := left
	left.OperationID, right.OperationID = "controller-left", "controller-right"

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		results <- open().CompareAndSwap(ctx, "gru", &initial, left)
	}()
	go func() {
		defer wg.Done()
		<-start
		results <- open().CompareAndSwap(ctx, "gru", &initial, right)
	}()
	close(start)
	wg.Wait()
	close(results)

	var committed, conflicted int
	for err := range results {
		switch {
		case err == nil:
			committed++
		case errors.Is(err, autoscale.ErrConflict):
			conflicted++
		default:
			t.Fatalf("concurrent CAS returned unexpected error: %v", err)
		}
	}
	if committed != 1 || conflicted != 1 {
		t.Fatalf("concurrent CAS outcomes: committed=%d conflicted=%d", committed, conflicted)
	}

	// Controllers consume the same real store and must treat a losing CAS as a
	// normal no-op while the winner admits only one scale-out step.
	now := time.Now().UTC()
	source := &runtimeAutoscaleSource{observations: []autoscale.Observation{
		{HostID: "h1", EngineID: "e1", Incarnation: "boot-1", Sequence: 1, ObservedAt: now, CPUPercent: 90, MemoryPercent: 90, Healthy: true, Authenticated: true},
		{HostID: "h2", EngineID: "e2", Incarnation: "boot-2", Sequence: 1, ObservedAt: now, CPUPercent: 90, MemoryPercent: 90, Healthy: true, Authenticated: true},
	}}
	if err := open().CompareAndSwap(ctx, "sfo", nil, autoscale.Target{Region: "sfo", Members: 2}); err != nil {
		t.Fatal(err)
	}
	controllers := make([]*autoscale.Controller, 2)
	for i := range controllers {
		controller, err := autoscale.New(autoscale.Config{Source: source, Targets: open(), Authority: runtimeAutoscaleAuthority{}, MinMembers: 2, MaxMembers: 3, CPUThreshold: 80, MemoryThreshold: 80, HighSamples: 1, ObservationMaxAge: time.Minute, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		controllers[i] = controller
	}
	plans := make(chan bool, len(controllers))
	start = make(chan struct{})
	wg.Add(len(controllers))
	for _, controller := range controllers {
		go func() {
			defer wg.Done()
			<-start
			_, created, err := controller.Evaluate(ctx, "sfo")
			if err != nil {
				t.Errorf("concurrent controller evaluation: %v", err)
			}
			plans <- created
		}()
	}
	close(start)
	wg.Wait()
	close(plans)
	created := 0
	for plan := range plans {
		if plan {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("concurrent controllers created %d plans, want one", created)
	}
	final, found, err := open().Load(ctx, "sfo")
	if err != nil || !found || final.Members != 3 {
		t.Fatalf("final controller target: found=%v target=%+v err=%v", found, final, err)
	}
}
