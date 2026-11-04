package ociresource

import (
	"context"
	"errors"
	"slices"
	"testing"

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
	store := integrationStore(t)
	auth := &snapshotAuthority{}
	var ran []string
	var epochs []uint64
	pass := func(name string, err error) Pass {
		return Pass{Name: name, Run: func(_ context.Context, epoch uint64) error {
			if storeErr := store.PutStatus(t.Context(), Status{Key: widgetKey(name), Generation: epoch}); storeErr != nil {
				return storeErr
			}
			ran = append(ran, name)
			epochs = append(epochs, epoch)
			return err
		}}
	}
	runner := Runner{Authority: auth, Passes: []Pass{pass("publish", errors.New("boom")), pass("nsg", nil)}}

	runner.Tick(t.Context())
	auth.snapshot = authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Leader: true, Ready: false, Epoch: 3}
	runner.Tick(t.Context())
	records, storeErr := store.ListStatus(t.Context(), "GRU")
	if storeErr != nil || len(records) != 0 || len(ran) != 0 {
		t.Fatalf("a follower or unready leader ran %v", ran)
	}
	auth.snapshot.Ready = true
	runner.Tick(t.Context())
	if !slices.Equal(ran, []string{"publish", "nsg"}) || !slices.Equal(epochs, []uint64{3, 3}) {
		t.Fatalf("ran=%v epochs=%v", ran, epochs)
	}

	records, storeErr = store.ListStatus(t.Context(), "GRU")
	if storeErr != nil || len(records) != 2 {
		t.Fatalf("persisted passes=%+v err=%v", records, storeErr)
	}
	ran = nil
	runner.Passes = []Pass{pass("a", ErrFenced), pass("b", nil)}
	runner.Tick(t.Context())
	if !slices.Equal(ran, []string{"a"}) {
		t.Fatalf("passes ran after authority was lost: %v", ran)
	}
}
