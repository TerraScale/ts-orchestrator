package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// A containerd restart (unattended upgrade, 2026-10-27 06:15Z on gru) broke
// every wait stream with Unavailable while the shims kept the processes
// running. Failing those tasks orphaned live containers that held their host
// ports and blocked every replacement.
func TestFollowExitReattachesWhileContainerdRestarts(t *testing.T) {
	lost := fmt.Errorf("wait: %w", grpcstatus.Error(codes.Unavailable, "error reading from server: EOF"))
	exited := time.Unix(1, 0)
	attempts, serves, unserves := 0, 0, 0
	code, at, err := followExit(context.Background(), func(following func()) (uint32, time.Time, error) {
		attempts++
		following()
		if attempts < 3 {
			return 0, time.Time{}, lost
		}
		return 7, exited, nil
	}, func() func() {
		serves++
		return func() { unserves++ }
	})
	if err != nil || code != 7 || !at.Equal(exited) {
		t.Fatalf("followExit = %d %v %v, want the exit after re-attaching", code, at, err)
	}
	if attempts != 3 || serves != 1 || unserves != 1 {
		t.Fatalf("attempts %d serves %d unserves %d, want 3 1 1", attempts, serves, unserves)
	}
}

func TestFollowExitReturnsOtherErrorsAndKeepsServing(t *testing.T) {
	gone := fmt.Errorf("load task: %w", errdefs.ErrNotFound)
	unserves := 0
	_, _, err := followExit(context.Background(), func(following func()) (uint32, time.Time, error) {
		following()
		return 0, time.Time{}, gone
	}, func() func() { return func() { unserves++ } })
	if !errors.Is(err, errdefs.ErrNotFound) || unserves != 0 {
		t.Fatalf("err %v unserves %d, want the error and serving kept for stopTask", err, unserves)
	}
}

func TestFollowExitStopsReattachingWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	_, _, err := followExit(ctx, func(func()) (uint32, time.Time, error) {
		cancel()
		return 0, time.Time{}, errdefs.ErrUnavailable
	}, func() func() { return func() {} })
	if !errors.Is(err, errdefs.ErrUnavailable) && !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v, want the wait to end on cancel", err)
	}
}

func TestFailWithoutExitStopsTheProcessOfAFailedTask(t *testing.T) {
	gone := fmt.Errorf("load task: %w", errdefs.ErrNotFound)
	stops := 0
	err := failWithoutExit(context.Background(), gone, func(ctx context.Context) error {
		stops++
		if ctx.Err() != nil {
			t.Fatal("stop must outlive the failed wait")
		}
		return nil
	})
	if !errors.Is(err, errdefs.ErrNotFound) || stops != 1 {
		t.Fatalf("err %v stops %d, want the wait error after one stop", err, stops)
	}

	err = failWithoutExit(context.Background(), gone, func(context.Context) error { return errdefs.ErrFailedPrecondition })
	if !errors.Is(err, errdefs.ErrNotFound) || !errors.Is(err, errdefs.ErrFailedPrecondition) {
		t.Fatalf("err %v, want both the wait and the stop error", err)
	}
}

func TestFailWithoutExitLeavesACanceledWaitToShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stops := 0
	err := failWithoutExit(ctx, context.Canceled, func(context.Context) error { stops++; return nil })
	if !errors.Is(err, context.Canceled) || stops != 0 {
		t.Fatalf("err %v stops %d, want the cancel and no stop", err, stops)
	}
	if err := failWithoutExit(context.Background(), errdefs.ErrNotFound, nil); !errors.Is(err, errdefs.ErrNotFound) {
		t.Fatalf("err %v, want the error when no stop applies", err)
	}
}
