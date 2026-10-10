package decisionlog

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// traceSource reports the trace ID each query arrives with.
type traceSource struct{ traces chan string }

func (source traceSource) Query(ctx context.Context, _ Query) (Result, error) {
	source.traces <- observability.TraceID(ctx)
	return Result{}, nil
}

func (source traceSource) Chain(context.Context, string) (Chain, error) {
	return Chain{}, ErrNotFound
}

func TestQueryTraceReachesTheResponder(t *testing.T) {
	conn := startJetStream(t)
	traces := make(chan string, 2)
	if _, err := ServeQueries(t.Context(), conn, "gru", traceSource{traces}); err != nil {
		t.Fatal(err)
	}
	subject, err := protocol.ObservabilitySubject("gru", QueryLeaf)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(remoteRequest{Version: wireVersion})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(observability.StartTrace(t.Context()), 5*time.Second)
	defer cancel()
	if _, err := conn.RequestMsgWithContext(ctx, &nats.Msg{Subject: subject, Data: data, Header: observability.TraceHeader(ctx, nil)}); err != nil {
		t.Fatal(err)
	}
	if got := <-traces; got != observability.TraceID(ctx) {
		t.Fatalf("responder trace = %q, want the requester's %q", got, observability.TraceID(ctx))
	}
	// A request without a traceparent starts a new trace on the responder.
	if _, err := conn.RequestMsgWithContext(ctx, &nats.Msg{Subject: subject, Data: data}); err != nil {
		t.Fatal(err)
	}
	if got := <-traces; got == "" || got == observability.TraceID(ctx) {
		t.Fatalf("responder trace = %q, want a new trace", got)
	}
}
