package mesh

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// A region whose ts-orch restarted lost the apply (sjc and fra, 2026-10-28
// 16:22Z); the re-published request reaches it, and a duplicate answer from
// another region does not replace its first one.
func TestCollectRepublishesToARestartedReceiver(t *testing.T) {
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)

	var seen atomic.Int32
	if _, err := conn.Subscribe("test.apply", func(m *nats.Msg) {
		// The first copy arrives while this receiver is "restarting".
		if seen.Add(1) > 1 {
			_ = m.Respond([]byte(`{"region":"sjc","result":"applied"}`))
		}
	}); err != nil {
		t.Fatal(err)
	}
	var answers int
	err = collectAgain(t.Context(), conn, "test.apply", nil, 1, 5*time.Second, 100*time.Millisecond, func([]byte) bool {
		answers++
		return true
	})
	if err != nil || answers != 1 || seen.Load() < 2 {
		t.Fatalf("answers = %d after %d copies: %v", answers, seen.Load(), err)
	}
}
