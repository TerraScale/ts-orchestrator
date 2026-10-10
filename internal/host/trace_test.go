package host

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// TestHostRequestSendsTheTraceparent checks the agent side of the round trip:
// the request reaches the controller's subject with the caller's trace. A
// raw subscriber stands in for the controller, which never answers, so the
// request ends when the test cancels it.
func TestHostRequestSendsTheTraceparent(t *testing.T) {
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

	ctx, cancel := context.WithCancel(observability.StartTrace(t.Context()))
	defer cancel()
	subject, err := protocol.AgentObservationSubject("gru", testNATSUserKey("node-a"), "desired")
	if err != nil {
		t.Fatal(err)
	}
	traceparents := make(chan string, 1)
	sub, err := conn.Subscribe(subject, func(msg *nats.Msg) {
		traceparents <- msg.Header.Get("traceparent")
		cancel()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	var out any
	if err := exchange(ctx, conn, "gru", nil, request{Operation: "desired", NATSUserPublicKey: testNATSUserKey("node-a")}, &out); err == nil {
		t.Fatal("request returned without a controller reply")
	}
	if got := <-traceparents; len(got) != 55 || got[3:35] != observability.TraceID(ctx) {
		t.Fatalf("request traceparent = %q, want trace %q", got, observability.TraceID(ctx))
	}
}
