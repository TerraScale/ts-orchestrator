package regionlink

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func TestLinksRegionsAndRequests(t *testing.T) {
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
	if _, err := conn.Subscribe("ts.orch.v1.gru.obs.ping", func(message *nats.Msg) {
		_ = message.Respond(append([]byte("pong:"), message.Data...))
	}); err != nil {
		t.Fatal(err)
	}
	links, err := New("GRU", conn, []string{"sfo", "FRA", "global", "bad region"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := links.Regions(); !slices.Equal(got, []string{"gru", "fra", "sfo"}) {
		t.Fatalf("regions = %v", got)
	}
	reply, err := links.Request(t.Context(), "GRU", "ping", []byte("x"))
	if err != nil || string(reply) != "pong:x" {
		t.Fatalf("reply = %q err=%v", reply, err)
	}
	if _, err := links.Request(t.Context(), "sfo", "ping", nil); !errors.Is(err, ErrNotLinked) {
		t.Fatalf("unlinked err = %v", err)
	}
	if _, err := links.Request(t.Context(), "mia", "ping", nil); !errors.Is(err, ErrUnknownRegion) {
		t.Fatalf("unknown err = %v", err)
	}
	if err := links.Link("mia", conn); err != nil || !links.Linked("mia") {
		t.Fatalf("link err = %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if _, err := links.Request(ctx, "mia", "ping", nil); err == nil {
		t.Fatal("a region with no responder must fail")
	}
	if err := links.Link("mia", nil); err != nil || links.Linked("mia") {
		t.Fatal("unlink failed")
	}
	if err := links.Link("global", conn); err == nil {
		t.Fatal("the global scope is not a region")
	}
}

// A caller deadline later than the link timeout does not stretch it.
func TestLinkTimeoutAppliesUnderALaterCallerDeadline(t *testing.T) {
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
	if _, err := conn.Subscribe("ts.orch.v1.gru.obs.slow", func(message *nats.Msg) {
		time.Sleep(2 * time.Second)
		_ = message.Respond(nil)
	}); err != nil {
		t.Fatal(err)
	}
	links, err := New("gru", conn, nil, 150*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	started := time.Now()
	if _, err := links.Request(ctx, "gru", "slow", nil); err == nil {
		t.Fatal("a slow region answered")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("the request took %s under a 150ms link timeout", elapsed)
	}
}

func TestUnlinkDropsOnlyPeerRegions(t *testing.T) {
	t.Parallel()
	links, err := New("gru", nil, []string{"sfo", "fra"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	links.Unlink("GRU")
	links.Unlink("mia")
	if got := links.Regions(); !slices.Equal(got, []string{"gru", "fra", "sfo"}) {
		t.Fatalf("local or unknown unlink changed regions = %v", got)
	}
	conn := &nats.Conn{}
	if err := links.Link("sfo", conn); err != nil || !links.Linked("sfo") {
		t.Fatalf("link sfo: %v", err)
	}
	links.Unlink("SFO")
	if got := links.Regions(); !slices.Equal(got, []string{"gru", "fra"}) || links.Linked("sfo") {
		t.Fatalf("after unlink regions = %v, linked %v", got, links.Linked("sfo"))
	}
}
