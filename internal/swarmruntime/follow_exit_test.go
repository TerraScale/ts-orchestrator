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
