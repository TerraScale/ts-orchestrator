package app

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
)

func shortFounderBackoff(t *testing.T) {
	t.Helper()
	previousMin, previousMax := controllerFounderMinBackoff, controllerFounderMaxBackoff
	controllerFounderMinBackoff, controllerFounderMaxBackoff = time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { controllerFounderMinBackoff, controllerFounderMaxBackoff = previousMin, previousMax })
}

func TestFounderStartsWhileRegionalClusterIsWaiting(t *testing.T) {
	clusterWaiting := make(chan struct{})
	founderStarted := make(chan struct{})
	supervisor, stop, err := superviseFounderAndWaitCluster(t.Context(), func(ctx context.Context) error {
		close(clusterWaiting)
		select {
		case <-founderStarted:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, func(ctx context.Context) error {
		select {
		case <-clusterWaiting:
			close(founderStarted)
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	if err != nil {
		t.Fatalf("founder and cluster must progress concurrently: %v", err)
	}
	stop()
	if status := supervisor.Status(); status.Phase != bootstrapstart.FounderPhaseComplete {
		t.Fatalf("founder status = %+v", status)
	}
}

// A failing founder no longer cancels the cluster wait or the controller:
// the embedded broker stays up while the founder retries with backoff.
func TestFounderFailureDoesNotStopClusterWaitAndIsRetried(t *testing.T) {
	shortFounderBackoff(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var attempts atomic.Int32
	retried := make(chan struct{})
	succeeded := make(chan struct{})
	supervisor, stop, err := superviseFounderAndWaitCluster(ctx, func(ctx context.Context) error {
		select {
		case <-retried:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, func(context.Context) error {
		switch attempts.Add(1) {
		case 1:
			return errors.New("selected founder ledger held")
		case 2:
			close(retried)
			return errors.New("OCI launch out of host capacity")
		case 3:
			close(succeeded)
			return nil
		}
		return errors.New("founder ran after completing")
	})
	if err != nil {
		t.Fatalf("founder failure ended the regional cluster wait: %v", err)
	}
	defer stop()
	select {
	case <-succeeded:
	case <-ctx.Done():
		t.Fatalf("founder was not retried to completion: attempts=%d status=%+v", attempts.Load(), supervisor.Status())
	}
	stop()
	if status := supervisor.Status(); status.Phase != bootstrapstart.FounderPhaseComplete || status.Attempt != 3 {
		t.Fatalf("founder status = %+v", status)
	}
}

func TestClusterFailureWaitsForCanceledFounderBeforeReturn(t *testing.T) {
	founderStarted := make(chan struct{})
	founderCanceled := make(chan struct{})
	releaseFounder := make(chan struct{})
	returned := make(chan error, 1)
	want := errors.New("regional cluster failed")
	go func() {
		_, _, err := superviseFounderAndWaitCluster(t.Context(), func(context.Context) error {
			<-founderStarted
			return want
		}, func(ctx context.Context) error {
			close(founderStarted)
			<-ctx.Done()
			close(founderCanceled)
			<-releaseFounder
			return ctx.Err()
		})
		returned <- err
	}()
	select {
	case <-founderCanceled:
	case <-time.After(time.Second):
		t.Fatal("cluster failure did not cancel founder")
	}
	select {
	case err := <-returned:
		t.Fatalf("controller returned before in-flight founder stopped: %v", err)
	default:
	}
	close(releaseFounder)
	select {
	case err := <-returned:
		if !errors.Is(err, want) {
			t.Fatalf("cluster error was lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("controller did not join canceled founder")
	}
}

func TestStopJoinsInFlightFounder(t *testing.T) {
	shortFounderBackoff(t)
	founderRunning := make(chan struct{})
	founderReturned := make(chan struct{})
	_, stop, err := superviseFounderAndWaitCluster(t.Context(), func(context.Context) error {
		<-founderRunning
		return nil
	}, func(ctx context.Context) error {
		close(founderRunning)
		<-ctx.Done()
		close(founderReturned)
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	stop()
	select {
	case <-founderReturned:
	default:
		t.Fatal("stop returned before the in-flight founder")
	}
	stop()
}
