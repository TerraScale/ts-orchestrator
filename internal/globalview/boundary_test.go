package globalview

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func followedTestView(t *testing.T, local string, cells func() []string, now func() time.Time) (*View, *nats.Conn) {
	t.Helper()
	conn, _ := startNATS(t)
	view := NewView(local, cells, now)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- view.Follow(ctx, conn) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("follow: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("rollup follower did not stop")
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for conn.NumSubscriptions() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("rollup subscriber did not start")
		}
		time.Sleep(time.Millisecond)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	return view, conn
}
