package natscell

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// newLinkRegion is a region with its own operator, system and cell accounts
// whose cell account carries the link signer. It has no interregion account.
func newLinkRegion(t *testing.T, root, cell, signer string) *testRegion {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	keys := newTestRegionKeys(t)
	operator := jwt.NewOperatorClaims(keys.operatorID)
	operator.SystemAccount = keys.systemID
	cellClaim := jwt.NewAccountClaims(keys.cellID)
	cellClaim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 64 << 20, DiskStorage: 256 << 20, Streams: 20, Consumer: 20}
	ApplyLink(cellClaim, signer)
	write := func(name string, claim interface {
		Encode(nkeys.KeyPair) (string, error)
	},
	) string {
		t.Helper()
		raw, err := claim.Encode(keys.operator)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	systemUser, _ := nkeys.CreateUser()
	systemUserID, _ := systemUser.PublicKey()
	tlsFiles := testBridgeTLS(t, filepath.Join(root, "tls"))
	cfg := Config{
		Cell: cell, Instance: "broker-a", Replicas: 1, TLS: tlsFiles,
		Embedded: &Embedded{
			Host: "127.0.0.1", Port: freeClientPort(t), StoreDir: filepath.Join(root, "store"),
			TLS: tlsFiles, RouteTLS: tlsFiles,
			OperatorJWTFile: write("operator.jwt", operator),
			SystemJWTFile:   write("system.jwt", jwt.NewAccountClaims(keys.systemID)),
			CellJWTFile:     write("cell.jwt", cellClaim),
			SystemCredentialsFile: testJWTUserCredentialsWithKey(t, root, "system.creds", keys.system, keys.systemID, systemUser,
				[]string{"$SYS.REQ.ACCOUNT." + keys.cellID + ".CLAIMS.UPDATE"}, []string{inboxPrefix(cell, systemUserID) + ".>"}),
			TicketPublicKeyFile: filepath.Join(root, "ticket.pub"),
			BrokerIDs:           []string{"broker-a"},
		},
	}
	if err := os.WriteFile(cfg.Embedded.TicketPublicKeyFile, []byte("unused"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &testRegion{testRegionKeys: keys, cfg: cfg}
}

// linkUserCredentials issues cell's link user through signer for the home
// account, as the home's material does for a spoke.
func linkUserCredentials(t *testing.T, root, name string, signer nkeys.KeyPair, homeAccount, cell string) string {
	t.Helper()
	now := time.Now()
	creds, err := IssueLinkUser(signer, homeAccount, cell, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, creds, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// linkControllerCredentials is a controller's user in region: the publish and
// subscribe surface a controller serves, the observability and query services
// of the cross-region contract, one response per request.
func linkControllerCredentials(t *testing.T, root, name string, region *testRegion) string {
	t.Helper()
	cell := region.cfg.Cell
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	userID, _ := user.PublicKey()
	claim := jwt.NewUserClaims(userID)
	claim.IssuerAccount = region.cellID
	claim.Pub.Allow = append(ControllerPublishes(cell),
		protocol.SubjectRoot+".*.obs."+protocol.ObservabilityRegionLeaf, protocol.SubjectRoot+".*.obs."+protocol.ObservabilityDecisionsLeaf,
		protocol.SubjectRoot+".*.query.>")
	claim.Sub.Allow = append(jwt.StringList(ControllerSubscriptions(cell)), protocol.ObservabilityGrant(cell),
		protocol.SubjectRoot+"."+cell+".query.>", protocol.SubjectRoot+".*.region.health", protocol.InboxGrant(cell, userID))
	claim.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: time.Minute}
	raw, err := claim.Encode(region.cell)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := user.Seed()
	creds, err := jwt.FormatUserConfig(raw, seed)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, creds, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// useLinkListener points the home's listener and every spoke's remote at a
// local port with the test certificate, restoring the production values after.
func useLinkListener(t *testing.T, port int) {
	t.Helper()
	listenPort, urls, serverName := linkListenPort, linkHomeURLs, linkServerName
	t.Cleanup(func() { linkListenPort, linkHomeURLs, linkServerName = listenPort, urls, serverName })
	linkListenPort = port
	linkHomeURLs = []string{"nats-leaf://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
	linkServerName = testLeafServerName
}

// awaitEveryBroadcast publishes each region's broadcast on subject(region)
// until every region has received every region's on grant.
func awaitEveryBroadcast(ctx context.Context, t *testing.T, runtimes map[string]*Runtime, names []string,
	subject func(string) string, grant string,
) {
	t.Helper()
	received := map[string]chan *nats.Msg{}
	for _, name := range names {
		ch := make(chan *nats.Msg, 64)
		sub, err := runtimes[name].Conn().ChanSubscribe(grant, ch)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sub.Unsubscribe() })
		received[name] = ch
	}
	seen := map[string]map[string]bool{}
	for _, name := range names {
		seen[name] = map[string]bool{}
	}
	for {
		for _, name := range names {
			if err := runtimes[name].Conn().Publish(subject(name), []byte(name)); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(50 * time.Millisecond)
		for receiver, ch := range received {
			for len(ch) > 0 {
				seen[receiver][string((<-ch).Data)] = true
			}
		}
		complete := true
		for _, receiver := range names {
			complete = complete && len(seen[receiver]) == len(names)
		}
		if complete {
			return
		}
		if ctx.Err() != nil {
			t.Fatalf("health did not reach every region: %v", seen)
		}
	}
}

// TestLinkStarRelaysEveryRegionThroughTheHome proves the link role across three
// regions, each with its own operator: requests and observability in every
// direction, queries answered by their own region, health of every region, and
// a spoke's leaf unable to take another region's traffic or publish outside
// its own subjects.
func TestLinkStarRelaysEveryRegionThroughTheHome(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	signer, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	signerID, _ := signer.PublicKey()
	names := []string{"gru", "sfo", "fra"}
	regions := map[string]*testRegion{}
	for _, name := range names {
		regions[name] = newLinkRegion(t, filepath.Join(root, name), name, signerID)
	}
	tlsFiles := testBridgeTLS(t, filepath.Join(root, "link-tls"))
	port := freeClientPort(t)
	useLinkListener(t, port)
	regions["gru"].cfg.Embedded.Link = &Link{TLS: tlsFiles}
	spokeCreds := map[string]string{}
	for _, name := range []string{"sfo", "fra"} {
		spokeCreds[name] = linkUserCredentials(t, root, name+"-link.creds", signer, regions["gru"].cellID, name)
		regions[name].cfg.Embedded.Link = &Link{CredentialsFile: spokeCreds[name], TLS: tlsFiles}
	}
	runtimes := map[string]*Runtime{}
	for _, name := range names {
		regions[name].cfg.CredentialsFile = linkControllerCredentials(t, root, name+"-controller.creds", regions[name])
		runtime, err := Start(ctx, regions[name].cfg)
		if err != nil {
			t.Fatalf("start %s: %v", name, err)
		}
		t.Cleanup(func() { _ = runtime.Close() })
		runtimes[name] = runtime
	}
	waitLeafCount(ctx, t, runtimes["gru"], 2)

	// a: observability requests in all six directions.
	for _, name := range names {
		_, err := runtimes[name].Conn().Subscribe(protocol.InterRegionObservabilitySubject(name, protocol.ObservabilityRegionLeaf),
			func(msg *nats.Msg) { _ = msg.Respond([]byte(name + "/region")) })
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := runtimes["gru"].Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	for _, from := range names {
		for _, to := range names {
			if from == to {
				continue
			}
			subject := protocol.InterRegionObservabilitySubject(to, protocol.ObservabilityRegionLeaf)
			if reply := requestUntil(ctx, t, runtimes[from].Conn(), subject); string(reply.Data) != to+"/region" {
				t.Fatalf("%s -> %s region reply = %q", from, to, reply.Data)
			}
		}
	}

	// b: a query from SFO is answered by FRA alone.
	if _, err := runtimes["fra"].Conn().Subscribe(protocol.SubjectRoot+".fra.query.>",
		func(msg *nats.Msg) { _ = msg.Respond([]byte("fra-query")) }); err != nil {
		t.Fatal(err)
	}
	if err := runtimes["fra"].Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	if reply := requestUntil(ctx, t, runtimes["sfo"].Conn(), protocol.Regional("fra", "query", "terrabase-wan", "x")); string(reply.Data) != "fra-query" {
		t.Fatalf("query from sfo answered by %q", reply.Data)
	}

	// c: every region receives every region's health.
	awaitEveryBroadcast(ctx, t, runtimes, names, protocol.RegionHealthSubject, protocol.SubjectRoot+".*.region.health")
	awaitEveryBroadcast(ctx, t, runtimes, names, protocol.RegionRollupSubject, protocol.RegionRollupGrant)

	// d: a raw leaf with SFO's link user cannot receive FRA's requests and
	// cannot publish outside its own region.
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	spoke := dialRawLeaf(ctx, t, addr, tlsFiles, spokeCreds["sfo"])
	defer spoke.close()
	spoke.subscribe(t, protocol.SubjectRoot+".fra.>")
	time.Sleep(200 * time.Millisecond)
	// Requests only: SFO's leaf does receive FRA's health, which it may.
	for range 5 {
		requestCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		_, _ = runtimes["gru"].Conn().RequestWithContext(requestCtx, protocol.Regional("fra", "query", "terrabase-wan", "raw"), []byte("q"))
		cancel()
	}
	if subject, got := spoke.awaitMessage(t, protocol.SubjectRoot+".fra.query.", 300*time.Millisecond); got {
		t.Fatalf("SFO's leaf received FRA's request %q", subject)
	}
	for _, forbidden := range []string{protocol.RegionHealthSubject("fra"), protocol.HostRegisterSubject(LinkHome), "$KV.TS_X.k"} {
		intruder := dialRawLeaf(ctx, t, addr, tlsFiles, spokeCreds["sfo"])
		intruder.publish(t, forbidden, "", []byte("forged"))
		if reason := intruder.awaitClose(t); !strings.Contains(reason, "Permissions Violation for Publish") {
			t.Fatalf("SFO's leaf published %q; link closed with %q", forbidden, reason)
		}
	}

	// e: a command published in GRU never reaches SFO. The admin user is
	// test-only: a controller may not publish another region's commands.
	admin := linkAdminConnection(t, root, runtimes["gru"], regions["gru"])
	commands := make(chan *nats.Msg, 8)
	commandSub, err := runtimes["sfo"].Conn().ChanSubscribe(protocol.HostRegisterSubject("sfo"), commands)
	if err != nil {
		t.Fatal(err)
	}
	defer commandSub.Unsubscribe()
	if err := runtimes["sfo"].Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if err := admin.Publish(protocol.HostRegisterSubject("sfo"), []byte("command")); err != nil {
			t.Fatal(err)
		}
	}
	if err := admin.Flush(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if len(commands) != 0 {
		t.Fatalf("a command published in GRU reached SFO: %d messages", len(commands))
	}
}

// linkAdminConnection is a test-only, unrestricted GRU client: the one source
// of a command addressed to another region.
func linkAdminConnection(t *testing.T, root string, runtime *Runtime, region *testRegion) *nats.Conn {
	t.Helper()
	creds := testJWTUserCredentials(t, root, "admin.creds", region.cell, region.cellID, nil, nil)
	conn, err := nats.Connect("", nats.InProcessServer(runtime.server), nats.UserCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	return conn
}
