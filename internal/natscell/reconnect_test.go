package natscell

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/tier"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestReconnectInterRegionRejectsUnavailableRuntime(t *testing.T) {
	broker, err := server.NewServer(&server.Options{DontListen: true, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, runtime := range []*Runtime{nil, {}, {server: broker}} {
		kicked, err := runtime.ReconnectInterRegion(t.Context())
		if kicked != 0 || err == nil {
			t.Fatalf("unavailable runtime reconnect = %d, %v", kicked, err)
		}
		if runtime != nil && runtime.server != nil && !errors.Is(err, ErrEmbeddedServerStopped) {
			t.Fatalf("stopped broker error = %v", err)
		}
	}
	if kicked, err := (*Runtime)(nil).ReconnectInterRegion(nil); kicked != 0 || err == nil {
		t.Fatalf("nil context reconnect = %d, %v", kicked, err)
	}
}

func TestReconnectInterRegionRepairsLeavesWithoutRestartingRegionalState(t *testing.T) {
	tier.Integration(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	topology := HubAndSpoke("gru", []string{"sfo"})
	leafTLS := testTLSFor(t, filepath.Join(root, "leaf-tls"))
	gru := newTestRegion(t, filepath.Join(root, "gru"), "gru", topology)
	sfo := newTestRegion(t, filepath.Join(root, "sfo"), "sfo", topology)
	brokers := []string{"broker-a", "broker-b", "broker-c"}
	ports := freeClientPorts(t, 9)
	routes := make([]string, len(brokers))
	for index := range brokers {
		routes[index] = fmt.Sprintf("nats-route://127.0.0.1:%d", ports[3+index])
	}
	routeSecret := filepath.Join(root, "route.secret")
	if err := os.WriteFile(routeSecret, []byte("reconnect-test-route-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	hub := net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[6]))
	private, fallback := newTCPProxy(t, hub), newTCPProxy(t, hub)
	defer private.Close()
	defer fallback.Close()
	sfo.cfg.Embedded.InterRegion.Remotes = []LeafRemote{{
		Peer: "gru", URLs: []string{"nats-leaf://" + private.Addr(), "nats-leaf://" + fallback.Addr()},
		ServerName: testLeafServerName, TLS: leafTLS, PeerAccount: gru.interregionID,
		CredentialsFile: gru.childLeafCredentials(t, "sfo-leaf.creds", "sfo"),
	}}
	var runtimes []*Runtime
	var configs []Config
	t.Cleanup(func() {
		for _, runtime := range runtimes {
			_ = runtime.Close()
		}
	})
	for index := range brokers {
		cfg := gru.cfg
		embedded, interregion := *cfg.Embedded, *cfg.Embedded.InterRegion
		cfg.Embedded, embedded.InterRegion = &embedded, &interregion
		cfg.Instance, cfg.Replicas = brokers[index], 3
		embedded.Port, embedded.RouteHost, embedded.RoutePort = ports[index], "127.0.0.1", ports[3+index]
		embedded.Routes, embedded.BrokerIDs = PeerRoutes(routes, routes[index]), brokers
		embedded.RouteUser, embedded.RoutePasswordFile = "reconnect-test", routeSecret
		embedded.StoreDir = filepath.Join(root, "gru", brokers[index])
		interregion.Listen = &LeafListen{Host: "0.0.0.0", Port: ports[6+index], TLS: leafTLS}
		runtime, err := Start(ctx, cfg)
		if err != nil {
			t.Fatalf("start gru %s: %v", cfg.Instance, err)
		}
		runtimes, configs = append(runtimes, runtime), append(configs, cfg)
	}
	for _, runtime := range runtimes {
		waitUntil(t, ctx, "regional R3 quorum", func() bool { return runtime.FullClusterReady(3) })
	}
	sfoRuntime, err := Start(ctx, sfo.cfg)
	if err != nil {
		t.Fatalf("start sfo: %v", err)
	}
	runtimes, configs = append(runtimes, sfoRuntime), append(configs, sfo.cfg)
	gruRuntime := runtimes[0]
	subject := protocol.Regional("sfo", "query", "status")
	query, err := sfoRuntime.Conn().Subscribe(subject, func(msg *nats.Msg) { _ = msg.Respond([]byte("sfo-ok")) })
	if err != nil {
		t.Fatal(err)
	}
	defer query.Unsubscribe()
	if err := sfoRuntime.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	probe := func(ctx context.Context) {
		t.Helper()
		if reply := requestUntil(ctx, t, gruRuntime.Conn(), subject); string(reply.Data) != "sfo-ok" {
			t.Fatalf("authenticated contract reply = %q", reply.Data)
		}
	}
	leaf := func(runtime *Runtime) *server.LeafInfo {
		t.Helper()
		leafz, err := runtime.server.Leafz(&server.LeafzOptions{Account: runtime.resolver.interregion})
		if err != nil || len(leafz.Leafs) != 1 {
			t.Fatalf("interregion leaf = %+v, %v", leafz, err)
		}
		return leafz.Leafs[0]
	}
	waitLeafCount(ctx, t, gruRuntime, 1)
	waitLeafCount(ctx, t, sfoRuntime, 1)
	probe(ctx)

	// These snapshots expose a repair that restarts a broker, route or client,
	// or replaces the persisted regional store instead of reconnecting its leaf.
	type snapshot struct {
		serverID, owner string
		node            nodeIdentity
		routeIDs        []uint64
		reconnects      uint64
	}
	observe := func(index int) snapshot {
		t.Helper()
		runtime := runtimes[index]
		owner, err := os.ReadFile(filepath.Join(configs[index].Embedded.StoreDir, storeIdentityFile))
		if err != nil {
			t.Fatal(err)
		}
		routez, err := runtime.server.Routez(nil)
		if err != nil {
			t.Fatal(err)
		}
		var ids []uint64
		for _, route := range routez.Routes {
			ids = append(ids, route.Rid)
		}
		slices.Sort(ids)
		return snapshot{runtime.server.ID(), string(owner), readNodeIdentity(t, configs[index].Embedded.StoreDir), ids,
			runtime.Conn().Stats().Reconnects}
	}
	before := make([]snapshot, len(runtimes))
	streams := make([]jetstream.Stream, len(runtimes))
	for index, runtime := range runtimes {
		before[index] = observe(index)
		if index < 3 && len(before[index].routeIDs) == 0 {
			t.Fatal("regional route preservation needs live routes")
		}
		name := fmt.Sprintf("RECONNECT_%d", index)
		streams[index], err = runtime.JetStream().CreateStream(ctx, jetstream.StreamConfig{
			Name: name, Subjects: []string{name}, Storage: jetstream.FileStorage, Replicas: configs[index].Replicas,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runtime.JetStream().Publish(ctx, name, []byte("retained")); err != nil {
			t.Fatal(err)
		}
	}
	assertPreserved := func() {
		t.Helper()
		for index, runtime := range runtimes {
			got, want := observe(index), before[index]
			if !runtime.Ready() || got.serverID != want.serverID || got.owner != want.owner || got.node != want.node ||
				got.reconnects != want.reconnects || !slices.Equal(got.routeIDs, want.routeIDs) {
				t.Fatalf("regional broker %d changed during leaf repair: %+v, want %+v", index, got, want)
			}
			message, err := streams[index].GetMsg(ctx, 1)
			if err != nil || string(message.Data) != "retained" {
				t.Fatalf("regional stored message %d = %+v, %v", index, message, err)
			}
		}
	}

	canceled, stop := context.WithCancel(ctx)
	stop()
	canceledID := leaf(sfoRuntime).ID
	if kicked, err := sfoRuntime.ReconnectInterRegion(canceled); kicked != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reconnect = %d, %v", kicked, err)
	}
	if leaf(sfoRuntime).ID != canceledID {
		t.Fatal("canceled reconnect changed the leaf")
	}
	for _, resolver := range []*accountResolver{nil, {}} {
		unpinned := &Runtime{server: gruRuntime.server, resolver: resolver}
		if kicked, err := unpinned.ReconnectInterRegion(ctx); kicked != 0 || err == nil {
			t.Fatalf("unpinned account reconnect = %d, %v", kicked, err)
		}
	}
	inboundID := leaf(gruRuntime).ID
	if kicked, err := gruRuntime.ReconnectInterRegion(ctx); kicked != 1 || err != nil {
		t.Fatalf("inbound leaf reconnect = %d, %v", kicked, err)
	}
	waitUntil(t, ctx, "inbound leaf native retry", func() bool {
		leafz, _ := gruRuntime.server.Leafz(nil)
		return len(leafz.Leafs) == 1 && leafz.Leafs[0].ID != inboundID
	})
	probe(ctx)
	assertPreserved()

	// Select whichever URL native retry chose, then silently break that path.
	active, healthy := private, fallback
	if connected := leaf(sfoRuntime); net.JoinHostPort(connected.IP, strconv.Itoa(connected.Port)) == fallback.Addr() {
		active, healthy = fallback, private
	}
	outboundID := leaf(sfoRuntime).ID
	active.Blackhole()
	probeCtx, probeCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	_, err = gruRuntime.Conn().RequestWithContext(probeCtx, subject, []byte("q"))
	probeCancel()
	if err == nil {
		t.Fatal("contract probe succeeded through a blackholed leaf")
	}
	if leaf(sfoRuntime).ID != outboundID {
		t.Fatal("stale leaf disappeared before the reconnect API ran")
	}
	if kicked, err := sfoRuntime.ReconnectInterRegion(ctx); kicked != 1 || err != nil {
		t.Fatalf("stale outbound leaf reconnect = %d, %v", kicked, err)
	}
	repaired, repairedCancel := context.WithTimeout(ctx, 10*time.Second)
	defer repairedCancel()
	waitUntil(t, repaired, "stale leaf retry over the healthy URL", func() bool {
		leafz, _ := sfoRuntime.server.Leafz(nil)
		return len(leafz.Leafs) == 1 && leafz.Leafs[0].ID != outboundID &&
			net.JoinHostPort(leafz.Leafs[0].IP, strconv.Itoa(leafz.Leafs[0].Port)) == healthy.Addr()
	})
	probe(repaired)
	assertPreserved()

	// With both paths closed there is nothing to kick. Healing a path must
	// still recover through the existing remote's retry, without reconfiguring it.
	private.Close()
	fallback.Close()
	waitLeafCount(ctx, t, sfoRuntime, 0)
	if kicked, err := sfoRuntime.ReconnectInterRegion(ctx); kicked != 0 || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("absent leaf reconnect = %d, %v", kicked, err)
	}
	healthy.Reopen(t)
	waitLeafCount(ctx, t, sfoRuntime, 1)
	probe(ctx)
	assertPreserved()
}
