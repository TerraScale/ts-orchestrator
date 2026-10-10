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
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/tier"
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
		"import legacy prefix": func(_, cell, _ *jwt.AccountClaims) {
			cell.Imports[0].To = jwt.Subject(protocol.PlacementApplySubject("gru"))
		},
		"cell maps query onto placement": func(_, cell, _ *jwt.AccountClaims) {
			cell.Mappings = jwt.Mapping{jwt.Subject(protocol.Regional("gru", "query", "admin")): {
				{Subject: jwt.Subject(protocol.PlacementApplySubject("gru")), Weight: 100},
			}}
		},
		"interregion mapping": func(_, _, interregion *jwt.AccountClaims) {
			interregion.Mappings = jwt.Mapping{"peer.relay": {{Subject: "ts.orch.v1.sfo.health", Weight: 100}}}
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
		"bearer leaf users allowed": func(_, _, interregion *jwt.AccountClaims) {
			interregion.Limits.DisallowBearer = false
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
		"$JS.gru.API.CONSUMER.RESET.TS_GLOBAL_CONTROL.global-mirror-fra",
		"$JS.gru.API.CONSUMER.RESET.TS_GLOBAL_CONTROL.global-mirror-sfo",
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
		"$JS.gru.API.CONSUMER.RESET.TS_GLOBAL_CONTROL.global-mirror-sfo",
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
		slices.Contains(homeDefaults.Sub.Allow, protocol.JSConsumerResetSubject(protocol.JSDomainAPIPrefix("gru"),
			protocol.GlobalControlStream, protocol.GlobalMirrorConsumer("sfo"))) {
		t.Fatal("home leaf defaults let a peer take the home's own requests")
	}
	// A spoke with a child (FRA dialing SFO) relays FRA's traffic to and from
	// GRU, but its child can never speak for SFO or GRU, nor feed a mirror.
	spokeDefaults := spoke.LeafPermissions()
	ownReset := protocol.JSConsumerResetSubject(protocol.JSDomainAPIPrefix("gru"), protocol.GlobalControlStream,
		protocol.GlobalMirrorConsumer("sfo"))
	childReset := protocol.JSConsumerResetSubject(protocol.JSDomainAPIPrefix("gru"), protocol.GlobalControlStream,
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

// TestInterRegionLeafFailsOverToTheNextURLInOrder dials the hub over two
// paths, each an IP URL through its own proxy: the private peering first,
// NetBird second. The hub's certificate names only the pinned server_name,
// not the IP. The link comes up over the first URL; when that path goes
// silent, pings close it within about 40 s and the remote moves to the next.
func TestInterRegionLeafFailsOverToTheNextURLInOrder(t *testing.T) {
	tier.Integration(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	topology := HubAndSpoke("gru", []string{"sfo"})
	leafTLS := testTLSFor(t, filepath.Join(root, "leaf-tls"))
	gru := newTestRegion(t, filepath.Join(root, "gru"), "gru", topology)
	sfo := newTestRegion(t, filepath.Join(root, "sfo"), "sfo", topology)
	leafPort := freeClientPort(t)
	gru.cfg.Embedded.InterRegion.Listen = &LeafListen{Host: "0.0.0.0", Port: leafPort, TLS: leafTLS}
	hub := net.JoinHostPort("127.0.0.1", strconv.Itoa(leafPort))
	private, netbird := newTCPProxy(t, hub), newTCPProxy(t, hub)
	defer private.Close()
	defer netbird.Close()
	remote := LeafRemote{
		Peer: "gru", URLs: []string{"nats-leaf://" + private.Addr(), "nats-leaf://" + netbird.Addr()},
		CredentialsFile: gru.childLeafCredentials(t, "sfo-leaf.creds", "sfo"), PeerAccount: gru.interregionID, TLS: leafTLS,
	}
	for _, name := range []string{"", "127.0.0.1"} {
		remote.ServerName = name
		sfo.cfg.Embedded.InterRegion.Remotes = []LeafRemote{remote}
		if err := sfo.cfg.validate(); err == nil {
			t.Fatalf("remote with server_name %q accepted", name)
		}
	}
	remote.ServerName = testLeafServerName
	sfo.cfg.Embedded.InterRegion.Remotes = []LeafRemote{remote}

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
	sfoQuery, err := sfoRuntime.Conn().Subscribe(protocol.Regional("sfo", "query", "status"), func(msg *nats.Msg) {
		_ = msg.Respond([]byte("sfo-ok"))
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sfoQuery.Unsubscribe()
	if err := sfoRuntime.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	// linkedThrough waits until SFO's only leaf connection goes through proxy.
	linkedThrough := func(ctx context.Context, proxy *tcpProxy) {
		t.Helper()
		for {
			leafz, err := sfoRuntime.server.Leafz(nil)
			if err == nil && len(leafz.Leafs) == 1 &&
				net.JoinHostPort(leafz.Leafs[0].IP, strconv.Itoa(leafz.Leafs[0].Port)) == proxy.Addr() {
				return
			}
			if ctx.Err() != nil {
				t.Fatalf("leaf never linked through %s: %+v, %v", proxy.Addr(), leafz, err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	linkedThrough(ctx, private)
	if reply := requestUntil(ctx, t, gruRuntime.Conn(), protocol.Regional("sfo", "query", "status")); string(reply.Data) != "sfo-ok" {
		t.Fatalf("query over the private path = %q", reply.Data)
	}

	cut := time.Now()
	private.Blackhole()
	failover, failoverCancel := context.WithTimeout(ctx, 50*time.Second)
	defer failoverCancel()
	linkedThrough(failover, netbird)
	t.Logf("failed over to the second URL %v after the first went silent", time.Since(cut).Round(time.Second))
	// The hub saw no close either; its own pings or the new connection
	// retire the old one.
	waitLeafCount(failover, t, gruRuntime, 1)
	if reply := requestUntil(failover, t, gruRuntime.Conn(), protocol.Regional("sfo", "query", "status")); string(reply.Data) != "sfo-ok" {
		t.Fatalf("query over the NetBird path = %q", reply.Data)
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
	// children holds each child region's scoped signing key of the
	// interregion account, created on first use.
	children map[string]nkeys.KeyPair
	t        *testing.T
}

// childKey returns child's scoped signing key, creating it once.
func (keys testRegionKeys) childKey(t *testing.T, child string) nkeys.KeyPair {
	t.Helper()
	if key, ok := keys.children[child]; ok {
		return key
	}
	key, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	keys.children[child] = key
	return key
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
	keys.children = map[string]nkeys.KeyPair{}
	keys.t = t
	return keys
}

func (keys testRegionKeys) claims(contract InterRegionContract, links int) (*jwt.AccountClaims, *jwt.AccountClaims, *jwt.AccountClaims) {
	childKeys := map[string]string{}
	for child := range contract.Subtrees {
		childKeys[child], _ = keys.childKey(keys.t, child).PublicKey()
	}
	system := jwt.NewAccountClaims(keys.systemID)
	system.Limits.LeafNodeConn = 0
	cell := jwt.NewAccountClaims(keys.cellID)
	cell.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 64 << 20, DiskStorage: 256 << 20, Streams: 20, Consumer: 20}
	contract.ApplyCell(cell, keys.interregionID)
	interregion := jwt.NewAccountClaims(keys.interregionID)
	contract.ApplyInterRegion(interregion, keys.cellID, links, childKeys)
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
	subtrees := topology.Subtrees(cell)
	contract := InterRegionContract{Cell: cell, Peers: peers, GlobalHome: topology.Hub, Subtrees: subtrees}
	links := topology.Links(cell)
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
				Peers: peers, AccountJWTFile: encode("interregion.jwt", interregion),
				GlobalHome: topology.Hub, Subtrees: subtrees,
			},
		},
	}
	return &testRegion{testRegionKeys: keys, cfg: cfg}
}

// leafCredentials issues a user of this region's interregion account signed
// by the account identity key rather than a child's scoped key. The hub gives
// it the account's deny-all defaults.
func (region *testRegion) leafCredentials(t *testing.T, name string) string {
	t.Helper()
	return region.leafCredentialsWith(t, name, region.interregion, region.interregionID, func(claim *jwt.UserClaims) {
		claim.NatsLimits = jwt.NatsLimits{Subs: jwt.NoLimit, Data: jwt.NoLimit, Payload: jwt.NoLimit}
		claim.AllowedConnectionTypes = jwt.StringList{jwt.ConnectionTypeLeafnode}
	})
}

// childLeafCredentials issues a leafnode-only user for child through child's
// scoped signing key, so the hub applies child's leaf permissions to it.
func (region *testRegion) childLeafCredentials(t *testing.T, name, child string) string {
	t.Helper()
	return region.leafCredentialsFor(t, name, region.childKey(t, child), region.interregionID)
}

// leafCredentialsWith issues a user of accountID signed by signer, without
// permissions or limits (as a scoped signing key requires), after mutate
// adjusts its claims, so tests can prove permission-carrying users are refused.
func (region *testRegion) leafCredentialsWith(t *testing.T, name string, signer nkeys.KeyPair, accountID string,
	mutate func(*jwt.UserClaims),
) string {
	t.Helper()
	user, _ := nkeys.CreateUser()
	userID, _ := user.PublicKey()
	claim := jwt.NewUserClaims(userID)
	claim.UserPermissionLimits = jwt.UserPermissionLimits{}
	claim.IssuerAccount = accountID
	mutate(claim)
	raw, err := claim.Encode(signer)
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

// leafCredentialsFor issues a user of accountID signed by signer, so tests
// can prove the server refuses leaf users of other accounts or signers.
func (region *testRegion) leafCredentialsFor(t *testing.T, name string, signer nkeys.KeyPair, accountID string) string {
	t.Helper()
	return region.leafCredentialsWith(t, name, signer, accountID, func(*jwt.UserClaims) {})
}

// tcpProxy models the private DRG/RPC path so the test can partition and heal
// the link without stopping either region's broker.
type tcpProxy struct {
	target   string
	addr     string
	mu       sync.Mutex
	listener net.Listener
	conns    []net.Conn
	silent   atomic.Bool
}

// Blackhole drops all traffic from now on without closing anything, as a
// silently failed network path does.
func (p *tcpProxy) Blackhole() { p.silent.Store(true) }

// forward copies src to dst, then closes dst unless the proxy is
// black-holed: a dead path delivers neither data nor the close.
func (p *tcpProxy) forward(dst, src net.Conn) {
	_, _ = io.Copy(proxyWriter{p, dst}, src)
	if !p.silent.Load() {
		_ = dst.Close()
	}
}

// proxyWriter forwards to w until its proxy is black-holed.
type proxyWriter struct {
	proxy *tcpProxy
	w     io.Writer
}

func (p proxyWriter) Write(b []byte) (int, error) {
	if p.proxy.silent.Load() {
		return len(b), nil
	}
	return p.w.Write(b)
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
			go p.forward(outbound, inbound)
			go p.forward(inbound, outbound)
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
