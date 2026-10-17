//go:build linux

package swarmruntime

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestManagementObservationBlockedSend(t *testing.T) {
	for _, reason := range []string{"overflow", "caller canceled", "authority revoked"} {
		t.Run(reason, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			closed := make(chan struct{})
			release := make(chan struct{})
			started := make(chan struct{})
			finished := make(chan struct{})
			result := make(chan error, 1)
			var revoked atomic.Bool
			go func() {
				result <- sendManagementObservation(ctx, closed, func() error {
					if revoked.Load() {
						return denied()
					}
					return nil
				}, func() error {
					defer close(finished)
					close(started)
					<-release
					return nil
				})
			}()
			defer close(release)
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("send did not start")
			}
			switch reason {
			case "overflow":
				close(closed)
			case "caller canceled":
				cancel()
			case "authority revoked":
				revoked.Store(true)
			}
			select {
			case err := <-result:
				if reason == "overflow" && status.Code(err) != codes.OutOfRange || reason == "caller canceled" && !errors.Is(err, context.Canceled) || reason == "authority revoked" && status.Code(err) != codes.PermissionDenied {
					t.Fatalf("blocked send did not invalidate on %s: %v", reason, err)
				}
			case <-time.After(time.Second):
				t.Fatalf("blocked send retained handler after %s", reason)
			}
			// Emulate gRPC releasing its send when the handler has returned.
			release <- struct{}{}
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("sender did not exit after transport released it")
			}
		})
	}
}
