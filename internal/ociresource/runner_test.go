package ociresource

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

type snapshotAuthority struct{ snapshot authority.Snapshot }

func (a *snapshotAuthority) Current() authority.Snapshot { return a.snapshot }
func (a *snapshotAuthority) Guard(_ context.Context, epoch uint64) error {
	if !a.snapshot.Leader || epoch != a.snapshot.Epoch {
		return errors.New("fenced")
	}
	return nil
}

func TestRunnerOnlyRunsOnTheReadyLeaderAndSurvivesFailures(t *testing.T) {
	auth := &snapshotAuthority{}
	var ran []string
	var epochs []uint64
	pass := func(name string, err error) Pass {
		return Pass{Name: name, Run: func(_ context.Context, epoch uint64) error {
			ran = append(ran, name)
			epochs = append(epochs, epoch)
			return err
		}}
	}
	runner := Runner{Authority: auth, Passes: []Pass{pass("publish", errors.New("boom")), pass("nsg", nil)}}

	runner.Tick(t.Context())
	auth.snapshot = authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Leader: true, Ready: false, Epoch: 3}
	runner.Tick(t.Context())
	if len(ran) != 0 {
		t.Fatalf("a follower or unready leader ran %v", ran)
	}
	auth.snapshot.Ready = true
	runner.Tick(t.Context())
	if !slices.Equal(ran, []string{"publish", "nsg"}) || !slices.Equal(epochs, []uint64{3, 3}) {
		t.Fatalf("ran=%v epochs=%v", ran, epochs)
	}

	ran = nil
	runner.Passes = []Pass{pass("a", ErrFenced), pass("b", nil)}
	runner.Tick(t.Context())
	if !slices.Equal(ran, []string{"a"}) {
		t.Fatalf("passes ran after authority was lost: %v", ran)
	}
}

func TestRunnerStopsWithContextAndControllerPassIsFenced(t *testing.T) {
	if err := (Runner{}).Run(t.Context()); err == nil {
		t.Fatal("ran without authority or passes")
	}
	auth := &snapshotAuthority{snapshot: authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Leader: true, Ready: true, Epoch: 9}}
	store := NewMemoryStore()
	cloud := &fakeWidgets{cloud: map[string]widget{}}
	controller := &Controller[widgetSpec, widget]{Region: "GRU", Resource: cloud, Store: store,
		Ownership: Ownership{Mode: TagModeFreeform, Owner: "cell-gru"}, Authority: auth}
	put(t, store, "a", 1, PolicyEnforce, 2)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Runner{Authority: auth, Passes: []Pass{ControllerPass(controller)}, Interval: time.Hour}.Run(ctx)
	}()
	deadline := time.After(10 * time.Second)
	for {
		status, ok, _ := store.GetStatus(t.Context(), widgetKey("a"))
		if ok && status.Applied {
			break
		}
		select {
		case <-deadline:
			t.Fatal("runner never reconciled")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// A wake runs the next tick at once instead of after the interval.
func TestRunnerWakeStartsTheNextTick(t *testing.T) {
	auth := &snapshotAuthority{snapshot: authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Leader: true, Ready: true, Epoch: 1}}
	ticks := make(chan struct{}, 4)
	wake := make(chan struct{}, 1)
	runner := Runner{Authority: auth, Interval: time.Hour, Wake: wake,
		Passes: []Pass{{Name: "count", Run: func(context.Context, uint64) error { ticks <- struct{}{}; return nil }}}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = runner.Run(ctx) }()
	for i := range 2 {
		select {
		case <-ticks:
		case <-time.After(5 * time.Second):
			t.Fatalf("tick %d did not run", i)
		}
		wake <- struct{}{}
	}
}
