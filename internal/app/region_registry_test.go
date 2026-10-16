package app

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/atlas"
	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/regionlink"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// TestRegionRegistryBuildsAndFollowsRoster has the home keep the roster from
// heartbeats that match their subject, and a peer region follow the roster
// into its links.
func TestRegionRegistryBuildsAndFollowsRoster(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
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
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	global, err := authority.Start(ctx, js, authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scope: protocol.GlobalScope, CandidateID: entityid.Derive("test-controller", protocol.GlobalScope), Replicas: 1,
		LeaseDuration: 5 * time.Second, RenewInterval: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = global.Close() })
	waitRegistry(ctx, t, "global authority leader", global.Current().CanMutate)
	writer, err := globalcontrol.OpenHome(ctx, js, "gru", nil, 1, global)
	if err != nil {
		t.Fatal(err)
	}
	home := &globalControl{authority: global, writer: writer, reader: &writer.Reader}

	keeper := newRosterKeeper(home, "gru", time.Now())
	sub, err := conn.Subscribe(protocol.AnyRegionHealthSubject(), func(message *nats.Msg) {
		keeper.record(message, time.Now())
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := sendHeartbeat(conn, "gru", "sa-saopaulo-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := sendHeartbeat(conn, "sfo", "us-sanjose-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	// A heartbeat claiming sfo, published on fra's subject, is dropped.
	spoofed, err := protocol.EncodeJSON(globalcontrol.Heartbeat{Version: 1, Cell: "sfo", OCIRegion: "us-sanjose-1", SentAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Publish(protocol.RegionHealthSubject("fra"), spoofed); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	heard := func() int {
		keeper.mu.Lock()
		defer keeper.mu.Unlock()
		return len(keeper.seen)
	}
	waitRegistry(ctx, t, "heartbeats of gru and sfo", func() bool { return heard() == 2 })

	if err := keeper.refresh(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	roster, _, err := writer.Roster(ctx)
	if err != nil || roster.Generation != 1 || len(roster.Regions) != 2 || !roster.Active("sfo") || roster.Active("fra") {
		t.Fatalf("roster = %+v, %v", roster, err)
	}
	if err := keeper.refresh(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if again, _, err := writer.Roster(ctx); err != nil || again.Generation != 1 {
		t.Fatalf("unchanged roster = %+v, %v", again, err)
	}

	peers := &rosterPeers{}
	links, err := regionlink.New("sfo", conn, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	linkRoster(links, conn, peers)
	followCtx, stopFollow := context.WithCancel(ctx)
	followed := make(chan struct{})
	go func() {
		defer close(followed)
		followRoster(followCtx, &writer.Reader, "sfo", peers.apply)
	}()
	waitRegistry(ctx, t, "gru as the only peer of sfo", func() bool {
		return slices.Equal(peers.current(), []string{"gru"}) && links.Linked("gru")
	})
	stopFollow()
	<-followed
}

// waitRegistry polls cond until it holds or ctx ends.
func waitRegistry(ctx context.Context, t *testing.T, what string, cond func() bool) {
	t.Helper()
	for !cond() {
		if ctx.Err() != nil {
			t.Fatalf("%s: %v", what, ctx.Err())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The Atlas loop lists the local cell and the live roster peers, keeps the
// spec's entry for a listed region, and falls back to the spec when the roster
// names a region the catalog cannot describe.
func TestAtlasRosterListsTheLiveRoster(t *testing.T) {
	spec := &atlas.Config{Regions: []atlas.Region{{ID: "gru-1", Name: "Sao Paulo (reviewed)",
		API: "https://gru.api.terrascale.tech", Auth: "https://gru.auth.terrascale.tech"}}}
	peers := &rosterPeers{}
	config := atlasRoster(func() *atlas.Config { return spec }, "gru", peers)
	ids := func(c *atlas.Config) []string {
		var ids []string
		for _, region := range c.Regions {
			ids = append(ids, region.ID)
		}
		return ids
	}
	if got := config(); got != spec {
		t.Fatalf("before the first roster the spec's regions must stay: %+v", got.Regions)
	}
	peers.apply(nil)
	if got := config(); !slices.Equal(ids(got), []string{"gru-1"}) || got.Regions[0].Name != "Sao Paulo (reviewed)" {
		t.Fatalf("alone: %+v", got.Regions)
	}
	peers.apply([]string{"sfo", "fra"})
	if got := config(); !slices.Equal(ids(got), []string{"gru-1", "sfo-1", "fra-1"}) || got.Regions[0].Name != "Sao Paulo (reviewed)" {
		t.Fatalf("with roster: %+v", got.Regions)
	}
	peers.apply([]string{"zzz"})
	if got := config(); got != spec {
		t.Fatalf("unlistable roster must keep the spec: %+v", got.Regions)
	}
	if got := atlasRoster(func() *atlas.Config { return nil }, "gru", peers)(); got != nil {
		t.Fatal("no spec section must publish nothing")
	}
}
