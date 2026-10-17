package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func TestNetBirdReadOpenFollowerStaysSilent(t *testing.T) {
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("read-open broker did not start")
	}
	conn, err := nats.Connect(broker.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var cfg Config
	cfg.NATS.Cell = "gru"
	done := make(chan error, 1)
	go func() { done <- runNetBirdIntentProducer(ctx, cfg, conn, new(authority.Runtime), new(rootoci.Client)) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("follower producer exit: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("follower producer did not stop")
		}
	})
	deadline := time.After(time.Second)
	for conn.NumSubscriptions() == 0 {
		select {
		case <-deadline:
			t.Fatal("follower did not subscribe to read-open")
		case <-time.After(time.Millisecond):
		}
	}
	proof := rootoci.NetBirdReadOpen{Schema: 1, Cell: "GRU", Nonce: entityid.New(), ExpiresAt: time.Now().Add(time.Minute), Signature: make([]byte, 64)}
	wire, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Request(netBirdReadOpenSubject("gru"), wire, 100*time.Millisecond); !errors.Is(err, nats.ErrTimeout) {
		t.Fatalf("follower answered read-open: %v", err)
	}
}
