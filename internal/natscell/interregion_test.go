package natscell

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalcontrol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

func TestLeafTopologyIsARootedTree(t *testing.T) {
	t.Parallel()

	topology := HubAndSpoke("gru", []string{"sfo", "fra"})
	if err := topology.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := topology.Regions(); strings.Join(got, ",") != "gru,fra,sfo" {
		t.Fatalf("regions = %v", got)
	}
	if got := topology.Children("gru"); strings.Join(got, ",") != "fra,sfo" {
		t.Fatalf("hub children = %v", got)
	}
	if parent, ok := topology.Parent("sfo"); !ok || parent != "gru" {
		t.Fatalf("sfo parent = %q, %v", parent, ok)
	}
	if _, ok := topology.Parent("gru"); ok {
		t.Fatal("hub dials a parent")
	}
	if got := topology.Peers("sfo"); strings.Join(got, ",") != "fra,gru" {
		t.Fatalf("sfo peers = %v", got)
	}
	// FRA prefers a direct spoke link to SFO; the graph stays a tree.
	direct := topology.WithSpokeParent("fra", "sfo")
	if err := direct.Validate(); err != nil {
		t.Fatal(err)
	}
	if topology.Parents["fra"] != "gru" {
		t.Fatal("WithSpokeParent mutated the original topology")
	}
	if direct.Links("sfo") != 2 || direct.Links("gru") != 1 || direct.Links("fra") != 1 {
		t.Fatalf("links = sfo:%d gru:%d fra:%d", direct.Links("sfo"), direct.Links("gru"), direct.Links("fra"))
	}
	for name, invalid := range map[string]LeafTopology{
		"cycle":          direct.WithSpokeParent("sfo", "fra"),
		"self":           topology.WithSpokeParent("sfo", "sfo"),
		"unknown parent": topology.WithSpokeParent("sfo", "iad"),
		"hub dials":      topology.WithSpokeParent("gru", "sfo"),
		"bad hub":        HubAndSpoke("GRU", []string{"sfo"}),
		"bad spoke":      HubAndSpoke("gru", []string{"s.fo"}),
	} {
		if err := invalid.Validate(); err == nil {
			t.Errorf("%s topology validated", name)
		}
	}
}

func TestInterRegionContractIsExplicitAndExact(t *testing.T) {
	t.Parallel()

	region := newTestRegionKeys(t)
	contract := InterRegionContract{Cell: "gru", Peers: []string{"fra", "sfo"}}
	system, cell, interregion := region.claims(contract, 2)
	if err := contract.verify(system, cell, interregion, 2); err != nil {
		t.Fatal(err)
	}
	for _, export := range cell.Exports {
		if !strings.HasPrefix(string(export.Subject), "ts.orch.v1.gru.") {
			t.Fatalf("cell exports a non-local subject %q", export.Subject)
		}
	}
	for _, imported := range cell.Imports {
		if imported.Account != interregion.Subject || strings.HasPrefix(string(imported.Subject), "ts.orch.v1.gru.") ||
			strings.Contains(string(imported.Subject), "*") {
			t.Fatalf("cell import %q is not a per-peer interregion import", imported.Subject)
		}
	}
	mutations := map[string]func(system, cell, interregion *jwt.AccountClaims){
		"cell allows leafnodes":   func(_, cell, _ *jwt.AccountClaims) { cell.Limits.LeafNodeConn = -1 },
		"system allows leafnodes": func(system, _, _ *jwt.AccountClaims) { system.Limits.LeafNodeConn = 1 },
		"cell exports control": func(_, cell, _ *jwt.AccountClaims) {
			cell.Exports.Add(&jwt.Export{Subject: jwt.Subject(protocol.Control("gru", ">")), Type: jwt.Stream})
		},
		"interregion imports placement": func(_, cell, interregion *jwt.AccountClaims) {
			interregion.Imports.Add(&jwt.Import{Account: cell.Subject, Subject: jwt.Subject(protocol.PlacementApplySubject("gru")), Type: jwt.Service})
		},
		"interregion exports wildcard": func(_, _, interregion *jwt.AccountClaims) {
			interregion.Exports[0].Subject = jwt.Subject(protocol.Regional("sfo", ">"))
		},
		"interregion has JetStream": func(_, _, interregion *jwt.AccountClaims) {
			interregion.Limits.JetStreamLimits = jwt.JetStreamLimits{DiskStorage: 1 << 20, Streams: 1}
		},
		"interregion unbounded leafs": func(_, _, interregion *jwt.AccountClaims) { interregion.Limits.LeafNodeConn = -1 },
		"import remapped": func(_, cell, _ *jwt.AccountClaims) {
			cell.Imports[0].LocalSubject = jwt.RenamingSubject(protocol.PlacementApplySubject("gru"))
		},
		"leaf defaults missing": func(_, _, interregion *jwt.AccountClaims) {
			interregion.DefaultPermissions = jwt.Permissions{}
		},
		"leaf defaults widened": func(_, _, interregion *jwt.AccountClaims) {
			interregion.DefaultPermissions.Pub.Allow.Add(protocol.PlacementApplySubject("gru"))
		},
		"leaf defaults wildcard": func(_, _, interregion *jwt.AccountClaims) {
			interregion.DefaultPermissions.Sub.Allow.Add(">")
		},
		"leaf defaults with deny": func(_, _, interregion *jwt.AccountClaims) {
			interregion.DefaultPermissions.Pub.Deny.Add("x")
		},
		"leaf defaults with responses": func(_, _, interregion *jwt.AccountClaims) {
			interregion.DefaultPermissions.Resp = &jwt.ResponsePermission{MaxMsgs: 100}
		},
	}
	for name, mutate := range mutations {
		system, cell, interregion := region.claims(contract, 2)
		mutate(system, cell, interregion)
		if err := contract.verify(system, cell, interregion, 2); err == nil {
			t.Errorf("%s: widened contract verified", name)
		}
	}
}

// TestGlobalMirrorContractExportsNoConsumerCreation pins the home region's
// JetStream surface: per peer, exactly one fixed delivery subject, the reset
// verb of that peer's own consumer, and its flow-control replies. No consumer
// create, stream, account or wildcard JetStream subject is ever exported, and
// the leaf defaults are the same subjects and nothing else.
func TestGlobalMirrorContractExportsNoConsumerCreation(t *testing.T) {
	t.Parallel()

	home := InterRegionContract{Cell: "gru", Peers: []string{"fra", "sfo"}, GlobalHome: "gru"}
	spoke := InterRegionContract{Cell: "sfo", Peers: []string{"fra", "gru"}, GlobalHome: "gru"}
	var homeJS []string
	for _, export := range home.CellExports() {
		subject := string(export.Subject)
		if strings.Contains(subject, "CREATE") || strings.Contains(subject, ".STREAM.") ||
			strings.HasSuffix(subject, "$JS.API.>") || strings.Contains(subject, "INFO") {
			t.Errorf("home exports JetStream API %q", subject)
		}
		if strings.HasPrefix(subject, "$JS.") {
			homeJS = append(homeJS, subject)
		}
	}
	wantJS := []string{
		"$JS.API.CONSUMER.RESET.TS_GLOBAL_CONTROL.global-mirror-fra",
		"$JS.API.CONSUMER.RESET.TS_GLOBAL_CONTROL.global-mirror-sfo",
		"$JS.FC.TS_GLOBAL_CONTROL.global-mirror-fra.*",
		"$JS.FC.TS_GLOBAL_CONTROL.global-mirror-sfo.*",
	}
	slices.Sort(homeJS)
	if !slices.Equal(homeJS, wantJS) {
		t.Fatalf("home JetStream exports = %v, want %v", homeJS, wantJS)
	}
	// Peers see the reset verb only under the link prefix.
	var linked []string
	for _, imported := range home.InterRegionImports("ACELL") {
		if imported.LocalSubject != "" {
			linked = append(linked, string(imported.LocalSubject))
		}
	}
	slices.Sort(linked)
	if !slices.Equal(linked, []string{
		"ts.interregion.v1.gru.jsapi.CONSUMER.RESET.TS_GLOBAL_CONTROL.global-mirror-fra",
		"ts.interregion.v1.gru.jsapi.CONSUMER.RESET.TS_GLOBAL_CONTROL.global-mirror-sfo",
	}) {
		t.Fatalf("home linked JetStream subjects = %v", linked)
	}
	// SFO imports only its own mirror's subjects, never another peer's.
	var spokeImports []string
	for _, imported := range spoke.CellImports("AINTER") {
		spokeImports = append(spokeImports, string(imported.Subject))
	}
	for _, want := range []string{
		"ts.interregion.v1.sfo.global",
		"ts.interregion.v1.gru.jsapi.CONSUMER.RESET.TS_GLOBAL_CONTROL.global-mirror-sfo",
		"$JS.FC.TS_GLOBAL_CONTROL.global-mirror-sfo.*",
	} {
		if !slices.Contains(spokeImports, want) {
			t.Errorf("spoke lacks mirror import %q in %v", want, spokeImports)
		}
	}
	for _, subject := range spokeImports {
		if strings.Contains(subject, "global-mirror-fra") || strings.Contains(subject, "fra.global") ||
			strings.Contains(subject, "CREATE") {
			t.Errorf("spoke imports %q outside its own mirror", subject)
		}
	}
	// Deny by default: the leaf permissions are link subjects of the roster's
	// contracts (transit through a spoke included) plus the reply namespace.
	fra := InterRegionContract{Cell: "fra", Peers: []string{"gru", "sfo"}, GlobalHome: "gru"}
	var links []string
	for _, contract := range []InterRegionContract{home, spoke, fra} {
		for _, flow := range append(contract.inbound(), contract.outbound()...) {
			links = append(links, flow.linkSubject)
		}
	}
	for name, contract := range map[string]InterRegionContract{"home": home, "spoke": spoke} {
		permissions := contract.LeafPermissions()
		if len(permissions.Pub.Deny) != 0 || len(permissions.Sub.Deny) != 0 || permissions.Resp != nil {
			t.Errorf("%s leaf defaults carry deny or response lists", name)
		}
		for _, grant := range append(append(jwt.StringList{}, permissions.Pub.Allow...), permissions.Sub.Allow...) {
			if grant != leafReplyGrant && !slices.Contains(links, grant) {
				t.Errorf("%s leaf default %q is not a contract subject", name, grant)
			}
			if grant == ">" || strings.HasPrefix(grant, "$JS.API") || strings.Contains(grant, "CREATE") {
				t.Errorf("%s leaf default %q widens the contract", name, grant)
			}
		}
	}
	homeDefaults := home.LeafPermissions()
	if !slices.Contains(homeDefaults.Sub.Allow, "ts.interregion.v1.sfo.global") ||
		slices.Contains(homeDefaults.Pub.Allow, "ts.interregion.v1.sfo.global") {
		t.Fatal("a peer may publish onto another peer's mirror feed")
	}
	if !slices.Contains(homeDefaults.Pub.Allow, protocol.RegionHealthSubject("sfo")) ||
		slices.Contains(homeDefaults.Pub.Allow, protocol.RegionHealthSubject("gru")) {
		t.Fatal("home leaf defaults let a peer impersonate the home health stream")
	}
	if slices.Contains(homeDefaults.Sub.Allow, protocol.Regional("gru", "query", ">")) ||
		slices.Contains(homeDefaults.Sub.Allow, protocol.JSConsumerResetSubject(protocol.InterRegionJSAPIPrefix("gru"),
			protocol.GlobalControlStream, protocol.GlobalMirrorConsumer("sfo"))) {
		t.Fatal("home leaf defaults let a peer take the home's own requests")
	}
	// A spoke with a child (FRA dialing SFO) relays FRA's traffic to and from
	// GRU, but its child can never speak for SFO or GRU, nor feed a mirror.
	spokeDefaults := spoke.LeafPermissions()
	ownReset := protocol.JSConsumerResetSubject(protocol.InterRegionJSAPIPrefix("gru"), protocol.GlobalControlStream,
		protocol.GlobalMirrorConsumer("sfo"))
	childReset := protocol.JSConsumerResetSubject(protocol.InterRegionJSAPIPrefix("gru"), protocol.GlobalControlStream,
		protocol.GlobalMirrorConsumer("fra"))
	for _, denied := range []string{
		protocol.RegionHealthSubject("sfo"), protocol.RegionHealthSubject("gru"), ownReset,
		protocol.InterRegionGlobalDeliverSubject("fra"), protocol.InterRegionGlobalDeliverSubject("sfo"),
	} {
		if slices.Contains(spokeDefaults.Pub.Allow, denied) {
			t.Errorf("spoke child may publish %q", denied)
		}
	}
	for _, relayed := range []string{protocol.RegionHealthSubject("fra"), childReset, protocol.Regional("gru", "query", ">")} {
		if !slices.Contains(spokeDefaults.Pub.Allow, relayed) {
			t.Errorf("spoke cannot relay %q up from its child", relayed)
		}
	}
	for _, relayed := range []string{protocol.InterRegionGlobalDeliverSubject("fra"), protocol.RegionHealthSubject("gru"), protocol.Regional("fra", "query", ">")} {
		if !slices.Contains(spokeDefaults.Sub.Allow, relayed) {
			t.Errorf("spoke cannot relay %q down to its child", relayed)
		}
	}
	if slices.Contains(spokeDefaults.Sub.Allow, protocol.InterRegionGlobalDeliverSubject("sfo")) ||
		slices.Contains(spokeDefaults.Sub.Allow, protocol.Regional("sfo", "query", ">")) {
		t.Error("spoke hands its own feed or requests to a child")
	}
}

// TestInterRegionLeafnodeCarriesOnlyContractSubjects links two production
// regions, each with its own operator, through a leafnode bound to their
// interregion accounts. Only the contract subjects cross; each region keeps
// serving JetStream while the link is down, and the link recovers.
func TestInterRegionLeafnodeCarriesOnlyContractSubjects(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	topology := HubAndSpoke("gru", []string{"sfo"})
	leafTLS := testBridgeTLS(t, filepath.Join(root, "leaf-tls"))
	gru := newTestRegion(t, filepath.Join(root, "gru"), "gru", topology)
	sfo := newTestRegion(t, filepath.Join(root, "sfo"), "sfo", topology)

	leafPort := freeClientPort(t)
	gru.cfg.Embedded.InterRegion.Listen = &LeafListen{Host: "127.0.0.1", Port: leafPort, TLS: leafTLS}
	proxy := newTCPProxy(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(leafPort)))
	defer proxy.Close()
	sfo.cfg.Embedded.InterRegion.Remotes = []LeafRemote{{
		Peer: "gru", URLs: []string{"nats-leaf://" + proxy.Addr()},
		CredentialsFile: gru.leafCredentials(t, "sfo-leaf.creds"), PeerAccount: gru.interregionID, TLS: leafTLS,
	}}

	gruRuntime, err := Start(ctx, gru.cfg)
	if err != nil {
		t.Fatalf("start gru: %v", err)
	}
	defer gruRuntime.Close()
	sfoRuntime, err := Start(ctx, sfo.cfg)
	if err != nil {
		t.Fatalf("start sfo: %v", err)
	}
	defer sfoRuntime.Close()

	for name, runtime := range map[string]*Runtime{"gru": gruRuntime, "sfo": sfoRuntime} {
		info, err := runtime.JetStream().AccountInfo(ctx)
		if err != nil || info.Domain != name {
			t.Fatalf("%s JetStream domain = %+v, %v", name, info, err)
		}
	}

	// Everything SFO's cell publishes under its own regional root that reaches
	// GRU's cell is captured here; only the health stream may arrive.
	received := make(chan *nats.Msg, 64)
	crossing, err := gruRuntime.Conn().ChanSubscribe(protocol.Regional("sfo", ">"), received)
	if err != nil {
		t.Fatal(err)
	}
	gruCommands := make(chan *nats.Msg, 8)
	gruPlacement, err := gruRuntime.Conn().ChanSubscribe(protocol.PlacementApplySubject("gru"), gruCommands)
	if err != nil {
		t.Fatal(err)
	}
	defer gruPlacement.Unsubscribe()
	gruControl := make(chan *nats.Msg, 8)
	gruControlSub, err := gruRuntime.Conn().ChanSubscribe(protocol.Control("gru", ">"), gruControl)
	if err != nil {
		t.Fatal(err)
	}
	defer gruControlSub.Unsubscribe()
	if err := gruRuntime.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	sfoQuery, err := sfoRuntime.Conn().Subscribe(protocol.Regional("sfo", "query", "status"), func(msg *nats.Msg) {
		_ = msg.Respond([]byte("sfo-ok"))
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sfoQuery.Unsubscribe()
	sfoPlacement, err := sfoRuntime.Conn().Subscribe(protocol.PlacementApplySubject("sfo"), func(msg *nats.Msg) {
		_ = msg.Respond([]byte("must-not-cross"))
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sfoPlacement.Unsubscribe()
	if err := sfoRuntime.Conn().Flush(); err != nil {
		t.Fatal(err)
	}

	awaitHealth(ctx, t, sfoRuntime.Conn(), received, "first")
	forbidden := []string{
		protocol.AgentObservation("sfo", "agent-a", "status"),
		protocol.PlacementApplySubject("sfo"),
		protocol.Regional("sfo", "inbox", "user", "x"),
		protocol.PlacementApplySubject("gru"),
		protocol.Control("gru", "lease"),
		protocol.Control("sfo", "lease"),
		protocol.Broker("sfo", "ticket", "x"),
	}
	for _, subject := range forbidden {
		if err := sfoRuntime.Conn().Publish(subject, []byte("forbidden")); err != nil {
			t.Fatal(err)
		}
	}
	awaitHealth(ctx, t, sfoRuntime.Conn(), received, "after-forbidden")
	drainAllowed(t, received)
	select {
	case msg := <-gruCommands:
		t.Fatalf("spoke reached hub command subject %q", msg.Subject)
	case msg := <-gruControl:
		t.Fatalf("spoke reached hub control subject %q", msg.Subject)
	default:
	}

	// GRU's own requests below match its capture subscription locally.
	if err := crossing.Unsubscribe(); err != nil {
		t.Fatal(err)
	}
	reply := requestUntil(ctx, t, gruRuntime.Conn(), protocol.Regional("sfo", "query", "status"))
	if string(reply.Data) != "sfo-ok" {
		t.Fatalf("cross-region query reply = %q", reply.Data)
	}
	requestCtx, requestCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	if msg, err := gruRuntime.Conn().RequestWithContext(requestCtx, protocol.PlacementApplySubject("sfo"), []byte("x")); err == nil {
		t.Fatalf("hub reached spoke placement command: %q", msg.Data)
	}
	requestCancel()

	// The home region's global stream is mirrored read-only into the spoke
	// through the durable consumer GRU created for SFO: only its fixed
	// delivery subject, its reset verb and its flow-control replies cross.
	home, err := gruRuntime.JetStream().CreateStream(ctx, globalcontrol.HomeStreamConfig(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := home.CreatePushConsumer(ctx, globalcontrol.MirrorConsumerConfig("sfo", 1)); err != nil {
		t.Fatalf("home mirror consumer: %v", err)
	}
	if _, err := gruRuntime.JetStream().Publish(ctx, protocol.GlobalState("roster", "current"), []byte("r1")); err != nil {
		t.Fatal(err)
	}
	// OpenMirror also verifies the server's view of the mirror config.
	if _, err := globalcontrol.OpenMirror(ctx, sfoRuntime.JetStream(), "gru", "sfo", 1); err != nil {
		t.Fatalf("open global mirror: %v", err)
	}
	mirror, err := sfoRuntime.JetStream().Stream(ctx, globalcontrol.StreamName)
	if err != nil {
		t.Fatal(err)
	}
	waitStreamMessages(ctx, t, mirror, 1)
	if _, err := sfoRuntime.JetStream().Publish(ctx, protocol.GlobalState("roster", "current"), []byte("forged")); err == nil {
		t.Fatal("spoke wrote into the read-only global mirror")
	}
	assertPeerCannotSteerHomeDelivery(ctx, t, sfoRuntime.Conn(), home, gruCommands)
	assertRawLeafPeerIsDenyByDefault(ctx, t, gru, gruRuntime.Conn(), sfoRuntime.Conn(), home, proxy.Addr(), leafTLS, gruCommands)

	// A leaf user of GRU's cell account is refused: the cell account allows
	// no leafnode connections, so only the interregion account is linkable.
	rogue := newTestRegion(t, filepath.Join(root, "fra"), "fra", HubAndSpoke("gru", []string{"sfo", "fra"}))
	rogue.cfg.Embedded.InterRegion.Remotes = []LeafRemote{{
		Peer: "gru", URLs: []string{"nats-leaf://" + proxy.Addr()},
		CredentialsFile: gru.leafCredentialsFor(t, "rogue-leaf.creds", gru.cell, gru.cellID), PeerAccount: gru.cellID, TLS: leafTLS,
	}}
	rogueRuntime, err := Start(ctx, rogue.cfg)
	if err != nil {
		t.Fatalf("start rogue spoke: %v", err)
	}
	defer rogueRuntime.Close()
	time.Sleep(1500 * time.Millisecond)
	if leafs := gruRuntime.server.NumLeafNodes(); leafs != 1 || rogueRuntime.server.NumLeafNodes() != 0 {
		t.Fatalf("hub leafnodes = %d, rogue leafnodes = %d; cell-account leaf was admitted", leafs, rogueRuntime.server.NumLeafNodes())
	}
	_ = rogueRuntime.Close()

	// Partition the link. Both regions keep full regional JetStream service.
	proxy.Close()
	waitLeafCount(ctx, t, gruRuntime, 0)
	waitLeafCount(ctx, t, sfoRuntime, 0)
	for name, runtime := range map[string]*Runtime{"gru": gruRuntime, "sfo": sfoRuntime} {
		bucket, err := runtime.JetStream().CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "PARTITION_" + strings.ToUpper(name)})
		if err != nil {
			t.Fatalf("%s JetStream during partition: %v", name, err)
		}
		if _, err := bucket.Put(ctx, "probe", []byte(name)); err != nil {
			t.Fatalf("%s KV during partition: %v", name, err)
		}
		local := make(chan *nats.Msg, 1)
		sub, err := runtime.Conn().ChanSubscribe(protocol.HostRegisterSubject(name), local)
		if err != nil {
			t.Fatal(err)
		}
		if err := runtime.Conn().Publish(protocol.HostRegisterSubject(name), []byte("local")); err != nil {
			t.Fatal(err)
		}
		select {
		case <-local:
		case <-ctx.Done():
			t.Fatalf("%s local messaging stopped during partition", name)
		}
		_ = sub.Unsubscribe()
	}

	// Heal the link; the spoke redials and the contract subjects flow again.
	healed := make(chan *nats.Msg, 64)
	healedSub, err := gruRuntime.Conn().ChanSubscribe(protocol.Regional("sfo", ">"), healed)
	if err != nil {
		t.Fatal(err)
	}
	defer healedSub.Unsubscribe()
	if _, err := home.Info(ctx); err != nil {
		t.Fatalf("home global stream during partition: %v", err)
	}
	if _, err := gruRuntime.JetStream().Publish(ctx, protocol.GlobalState("roster", "current"), []byte("r2")); err != nil {
		t.Fatalf("home global write during partition: %v", err)
	}
	if _, err := mirror.GetLastMsgForSubject(ctx, protocol.GlobalState("roster", "current")); err != nil {
		t.Fatalf("spoke cannot read its mirror during partition: %v", err)
	}
	proxy.Reopen(t)
	awaitHealth(ctx, t, sfoRuntime.Conn(), healed, "after-heal")
	waitStreamMessages(ctx, t, mirror, 2)
}

func awaitHealth(ctx context.Context, t *testing.T, publisher *nats.Conn, received chan *nats.Msg, marker string) {
	t.Helper()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := publisher.Publish(protocol.RegionHealthSubject("sfo"), []byte(marker)); err != nil {
			t.Fatal(err)
		}
		select {
		case msg := <-received:
			if msg.Subject != protocol.RegionHealthSubject("sfo") {
				t.Fatalf("non-contract subject crossed the leafnode: %q", msg.Subject)
			}
			if string(msg.Data) == marker {
				return
			}
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("health %q did not cross the leafnode", marker)
		}
	}
}

func drainAllowed(t *testing.T, received chan *nats.Msg) {
	t.Helper()
	for {
		select {
		case msg := <-received:
			if msg.Subject != protocol.RegionHealthSubject("sfo") {
				t.Fatalf("non-contract subject crossed the leafnode: %q", msg.Subject)
			}
		default:
			return
		}
	}
}

func requestUntil(ctx context.Context, t *testing.T, conn *nats.Conn, subject string) *nats.Msg {
	t.Helper()
	for {
		requestCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		msg, err := conn.RequestWithContext(requestCtx, subject, []byte("q"))
		cancel()
		if err == nil {
			return msg
		}
		if ctx.Err() != nil {
			t.Fatalf("request %q never crossed: %v", subject, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func waitStreamMessages(ctx context.Context, t *testing.T, stream jetstream.Stream, want uint64) {
	t.Helper()
	for {
		info, err := stream.Info(ctx)
		if err == nil && info.State.Msgs == want {
			return
		}
		if ctx.Err() != nil {
			t.Fatalf("mirror never reached %d messages: %+v, %v", want, info, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func waitLeafCount(ctx context.Context, t *testing.T, runtime *Runtime, want int) {
	t.Helper()
	for runtime.server.NumLeafNodes() != want {
		if ctx.Err() != nil {
			t.Fatalf("leafnode count = %d, want %d", runtime.server.NumLeafNodes(), want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type testRegionKeys struct {
	operator, system, cell, interregion nkeys.KeyPair
	operatorID, systemID, cellID        string
	interregionID                       string
}

func newTestRegionKeys(t *testing.T) testRegionKeys {
	t.Helper()
	var keys testRegionKeys
	var err error
	if keys.operator, err = nkeys.CreateOperator(); err != nil {
		t.Fatal(err)
	}
	for _, account := range []*nkeys.KeyPair{&keys.system, &keys.cell, &keys.interregion} {
		if *account, err = nkeys.CreateAccount(); err != nil {
			t.Fatal(err)
		}
	}
	keys.operatorID, _ = keys.operator.PublicKey()
	keys.systemID, _ = keys.system.PublicKey()
	keys.cellID, _ = keys.cell.PublicKey()
	keys.interregionID, _ = keys.interregion.PublicKey()
	return keys
}

func (keys testRegionKeys) claims(contract InterRegionContract, links int) (*jwt.AccountClaims, *jwt.AccountClaims, *jwt.AccountClaims) {
	system := jwt.NewAccountClaims(keys.systemID)
	system.Limits.LeafNodeConn = 0
	cell := jwt.NewAccountClaims(keys.cellID)
	cell.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 64 << 20, DiskStorage: 256 << 20, Streams: 20, Consumer: 20}
	contract.ApplyCell(cell, keys.interregionID)
	interregion := jwt.NewAccountClaims(keys.interregionID)
	contract.ApplyInterRegion(interregion, keys.cellID, links)
	return system, cell, interregion
}

type testRegion struct {
	testRegionKeys
	cfg Config
}

func newTestRegion(t *testing.T, root, cell string, topology LeafTopology) *testRegion {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	keys := newTestRegionKeys(t)
	peers := topology.Peers(cell)
	contract := InterRegionContract{Cell: cell, Peers: peers, GlobalHome: topology.Hub}
	links := topology.Links(cell)
	if len(topology.Children(cell)) != 0 {
		links = len(peers)
	}
	system, cellClaim, interregion := keys.claims(contract, links)
	operator := jwt.NewOperatorClaims(keys.operatorID)
	operator.SystemAccount = keys.systemID
	write := func(name, data string) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	encode := func(name string, claim interface {
		Encode(nkeys.KeyPair) (string, error)
	},
	) string {
		t.Helper()
		raw, err := claim.Encode(keys.operator)
		if err != nil {
			t.Fatal(err)
		}
		return write(name, raw)
	}
	systemUser, _ := nkeys.CreateUser()
	systemUserID, _ := systemUser.PublicKey()
	tlsFiles := testBridgeTLS(t, filepath.Join(root, "tls"))
	cfg := Config{
		Cell: cell, Instance: "broker-a", Replicas: 1, TLS: tlsFiles,
		CredentialsFile: testJWTUserCredentials(t, root, "controller.creds", keys.cell, keys.cellID, nil, nil),
		Embedded: &Embedded{
			Host: "127.0.0.1", Port: freeClientPort(t), StoreDir: filepath.Join(root, "store"),
			TLS: tlsFiles, RouteTLS: tlsFiles,
			OperatorJWTFile: encode("operator.jwt", operator),
			SystemJWTFile:   encode("system.jwt", system),
			CellJWTFile:     encode("cell.jwt", cellClaim),
			SystemCredentialsFile: testJWTUserCredentialsWithKey(t, root, "system.creds", keys.system, keys.systemID, systemUser,
				[]string{"$SYS.REQ.ACCOUNT." + keys.cellID + ".CLAIMS.UPDATE"}, []string{inboxPrefix(cell, systemUserID) + ".>"}),
			TicketPublicKeyFile: write("ticket.pub", "unused"),
			BrokerIDs:           []string{"broker-a"},
			InterRegion: &InterRegion{
				Enabled: true, Peers: peers, AccountJWTFile: encode("interregion.jwt", interregion),
				GlobalHome: topology.Hub,
			},
		},
	}
	return &testRegion{testRegionKeys: keys, cfg: cfg}
}

// leafCredentials issues a leafnode-only user of this region's interregion
// account for a child region; it is signed under this region's operator.
func (region *testRegion) leafCredentials(t *testing.T, name string) string {
	t.Helper()
	return region.leafCredentialsFor(t, name, region.interregion, region.interregionID)
}

// leafCredentialsWith issues a leafnode-only user after mutate adjusts its
// claims, so tests can prove permission-carrying leaf users are refused.
func (region *testRegion) leafCredentialsWith(t *testing.T, name string, account nkeys.KeyPair, accountID string,
	mutate func(*jwt.UserClaims),
) string {
	t.Helper()
	user, _ := nkeys.CreateUser()
	userID, _ := user.PublicKey()
	claim := jwt.NewUserClaims(userID)
	claim.IssuerAccount = accountID
	claim.AllowedConnectionTypes = jwt.StringList{jwt.ConnectionTypeLeafnode}
	mutate(claim)
	raw, err := claim.Encode(account)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := user.Seed()
	creds, err := jwt.FormatUserConfig(raw, seed)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, creds, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// leafCredentialsFor issues a leafnode-only user of any account in this
// region, so tests can prove the server refuses non-interregion leaf users.
func (region *testRegion) leafCredentialsFor(t *testing.T, name string, account nkeys.KeyPair, accountID string) string {
	t.Helper()
	user, _ := nkeys.CreateUser()
	userID, _ := user.PublicKey()
	claim := jwt.NewUserClaims(userID)
	claim.IssuerAccount = accountID
	claim.AllowedConnectionTypes = jwt.StringList{jwt.ConnectionTypeLeafnode}
	raw, err := claim.Encode(account)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := user.Seed()
	creds, err := jwt.FormatUserConfig(raw, seed)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, creds, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// tcpProxy models the private DRG/RPC path so the test can partition and heal
// the link without stopping either region's broker.
type tcpProxy struct {
	target   string
	addr     string
	mu       sync.Mutex
	listener net.Listener
	conns    []net.Conn
}

func newTCPProxy(t *testing.T, target string) *tcpProxy {
	t.Helper()
	proxy := &tcpProxy{target: target}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy.addr = listener.Addr().String()
	proxy.serve(listener)
	return proxy
}

func (p *tcpProxy) Addr() string { return p.addr }

func (p *tcpProxy) serve(listener net.Listener) {
	p.mu.Lock()
	p.listener = listener
	p.mu.Unlock()
	go func() {
		for {
			inbound, err := listener.Accept()
			if err != nil {
				return
			}
			outbound, err := net.Dial("tcp", p.target)
			if err != nil {
				_ = inbound.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, inbound, outbound)
			p.mu.Unlock()
			go func() { _, _ = io.Copy(outbound, inbound); _ = outbound.Close() }()
			go func() { _, _ = io.Copy(inbound, outbound); _ = inbound.Close() }()
		}
	}()
}

func (p *tcpProxy) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener != nil {
		_ = p.listener.Close()
		p.listener = nil
	}
	for _, conn := range p.conns {
		_ = conn.Close()
	}
	p.conns = nil
}

func (p *tcpProxy) Reopen(t *testing.T) {
	t.Helper()
	var listener net.Listener
	var err error
	for range 50 {
		if listener, err = net.Listen("tcp", p.addr); err == nil {
			break
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	p.serve(listener)
}
