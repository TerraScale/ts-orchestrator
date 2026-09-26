package app

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestFounderStartsWhileRegionalClusterIsWaiting(t *testing.T) {
	clusterWaiting := make(chan struct{})
	founderStarted := make(chan struct{})
	err := waitForFounderAndCluster(t.Context(), func(ctx context.Context) error {
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
}

func TestFounderFailureCancelsClusterWait(t *testing.T) {
	want := errors.New("selected founder ledger held")
	clusterCanceled := make(chan struct{})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	err := waitForFounderAndCluster(ctx, func(ctx context.Context) error {
		<-ctx.Done()
		close(clusterCanceled)
		return ctx.Err()
	}, func(context.Context) error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("founder failure was not propagated: %v", err)
	}
	select {
	case <-clusterCanceled:
	case <-time.After(time.Second):
		t.Fatal("cluster wait was not canceled after founder hold")
	}
}

func TestClusterFailureWaitsForCanceledFounderBeforeReturn(t *testing.T) {
	founderStarted := make(chan struct{})
	founderCanceled := make(chan struct{})
	releaseFounder := make(chan struct{})
	returned := make(chan error, 1)
	want := errors.New("regional cluster failed")
	go func() {
		returned <- waitForFounderAndCluster(t.Context(), func(context.Context) error {
			<-founderStarted
			return want
		}, func(ctx context.Context) error {
			close(founderStarted)
			<-ctx.Done()
			close(founderCanceled)
			<-releaseFounder
			return ctx.Err()
		})
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
