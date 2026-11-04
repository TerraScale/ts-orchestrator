package app

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// recordedDecisions keeps every decision recorded through the process recorder.
type recordedDecisions struct {
	mu        sync.Mutex
	decisions []decisionlog.Decision
}

func (r *recordedDecisions) Record(_ context.Context, decision decisionlog.Decision) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.decisions = append(r.decisions, decision)
	return decision.ID
}

// startEmbeddedNATS runs an embedded JetStream server and connects to it.
func startEmbeddedNATS(t *testing.T) *nats.Conn {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true,
		StoreDir: filepath.Join(t.TempDir(), "jetstream")})
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
	return conn
}

// startGlobalHome runs an embedded NATS and makes this member the global leader of a
// home region, returning its global control, the connection it runs on and its JetStream.
func startGlobalHome(t *testing.T, ctx context.Context) (*globalControl, *nats.Conn, jetstream.JetStream) {
	t.Helper()
	conn := startEmbeddedNATS(t)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	control, err := authority.Start(ctx, js, authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scope: protocol.GlobalScope, CandidateID: "0000000000F2D374M7NMRHJJQT", Replicas: 1,
		LeaseDuration: 5 * time.Second, RenewInterval: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	for !control.Current().CanMutate() {
		if ctx.Err() != nil {
			t.Fatal("global authority never became leader")
		}
		time.Sleep(20 * time.Millisecond)
	}
	writer, err := globalcontrol.OpenHome(ctx, js, "gru", nil, 1, control)
	if err != nil {
		t.Fatal(err)
	}
	return &globalControl{authority: control, writer: writer, reader: &writer.Reader}, conn, js
}
