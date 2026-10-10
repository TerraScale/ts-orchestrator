package natscell

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
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

// awaitEveryHealth publishes each region's heartbeat until every region has
// received every region's.
func awaitEveryHealth(ctx context.Context, t *testing.T, runtimes map[string]*Runtime, names []string) {
	t.Helper()
	received := map[string]chan *nats.Msg{}
	for _, name := range names {
		ch := make(chan *nats.Msg, 64)
		sub, err := runtimes[name].Conn().ChanSubscribe(protocol.SubjectRoot+".*.region.health", ch)
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
			if err := runtimes[name].Conn().Publish(protocol.RegionHealthSubject(name), []byte(name)); err != nil {
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
	awaitEveryHealth(ctx, t, runtimes, names)

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

// TestLinkScopeIsOneTemplateForEveryRegion pins what a link user may send and
// receive, so widening the link is a visible test change.
func TestLinkScopeIsOneTemplateForEveryRegion(t *testing.T) {
	signer, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	signerID, _ := signer.PublicKey()
	scope := LinkScope(signerID)
	if scope.Key != signerID || scope.Role != "link" {
		t.Fatalf("link scope key/role = %q/%q", scope.Key, scope.Role)
	}
	for _, subject := range []string{"ts.orch.v1.*.query.>", "ts.orch.v1.*.obs.region", "ts.orch.v1.*.obs.decisions",
		"ts.orch.v1.{{tag(cell)}}.region.health",
		"$JS.gru.API.CONSUMER.RESET.TS_GLOBAL_CONTROL.global-mirror-{{tag(cell)}}",
		"$JS.FC.TS_GLOBAL_CONTROL.global-mirror-{{tag(cell)}}.*"} {
		if !slices.Contains(scope.Template.Pub.Allow, subject) {
			t.Fatalf("link may not send %q", subject)
		}
	}
	for _, subject := range []string{"ts.orch.v1.{{tag(cell)}}.query.>", "ts.orch.v1.{{tag(cell)}}.obs.region",
		"ts.orch.v1.{{tag(cell)}}.obs.decisions", "ts.orch.v1.*.region.health", "ts.interregion.v1.{{tag(cell)}}.global",
		"ts.orch.v1.{{tag(cell)}}.inbox.>", "_INBOX.>", "$JSC.R.>"} {
		if !slices.Contains(scope.Template.Sub.Allow, subject) {
			t.Fatalf("link may not receive %q", subject)
		}
	}
	for _, subject := range scope.Template.Pub.Allow {
		if strings.Contains(subject, "host.register") || strings.HasPrefix(subject, "$KV") || strings.HasPrefix(subject, "ts.control") {
			t.Fatalf("link may send regional-only subject %q", subject)
		}
	}
	if scope.Template.Resp == nil || scope.Template.Resp.MaxMsgs != 1 || scope.Template.Resp.Expires != time.Minute {
		t.Fatalf("link responses = %+v", scope.Template.Resp)
	}
	if !slices.Equal(scope.Template.AllowedConnectionTypes, jwt.StringList{jwt.ConnectionTypeLeafnode}) {
		t.Fatalf("link connection types = %v", scope.Template.AllowedConnectionTypes)
	}
}

func TestIssueLinkUserCarriesOnlyTheLinkClaim(t *testing.T) {
	signer, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	signerID, _ := signer.PublicKey()
	home, _ := nkeys.CreateAccount()
	homeID, _ := home.PublicKey()
	now := time.Now()
	creds, err := IssueLinkUser(signer, homeID, "sfo", now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := nkeys.ParseDecoratedJWT(creds)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		t.Fatal(err)
	}
	if claim.IssuerAccount != homeID || claim.Issuer != signerID || !slices.Equal(claim.Tags, jwt.TagList{"cell:sfo"}) ||
		!claim.HasEmptyPermissions() {
		t.Fatalf("link user claim = %+v", claim)
	}
	if err := validateLinkCredentials(writeTempFile(t, creds), "sfo"); err != nil {
		t.Fatalf("issued link user rejected: %v", err)
	}
	if _, err := IssueLinkUser(signer, homeID, "SFO", now, now.Add(time.Hour)); err == nil {
		t.Fatal("noncanonical cell accepted")
	}
	if _, err := IssueLinkUser(signer, signerID+"x", "sfo", now, now.Add(time.Hour)); err == nil {
		t.Fatal("invalid home account accepted")
	}
}

// TestLinkValidationRefusesMisconfiguredRegions covers the startup checks: both
// blocks set, a spoke without or with another cell's link user, a home with
// link credentials, and a home whose cell account lacks the link signer.
func TestLinkValidationRefusesMisconfiguredRegions(t *testing.T) {
	signer, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	signerID, _ := signer.PublicKey()
	root := t.TempDir()
	gru := newLinkRegion(t, filepath.Join(root, "gru"), "gru", signerID)
	tlsFiles := testBridgeTLS(t, filepath.Join(root, "tls"))
	gru.cfg.CredentialsFile = "controller.creds"
	gru.cfg.Embedded.Link = &Link{TLS: tlsFiles}
	if err := gru.cfg.validate(); err != nil {
		t.Fatalf("home link rejected: %v", err)
	}
	both := gru.cfg
	both.Embedded = &Embedded{}
	*both.Embedded = *gru.cfg.Embedded
	both.Embedded.InterRegion = &InterRegion{AccountJWTFile: "x"}
	if err := both.validate(); err == nil {
		t.Fatal("interregion and link accepted together")
	}
	withCreds := gru.cfg
	withCreds.Embedded = &Embedded{}
	*withCreds.Embedded = *gru.cfg.Embedded
	withCreds.Embedded.Link = &Link{CredentialsFile: "x", TLS: tlsFiles}
	if err := withCreds.validate(); err == nil {
		t.Fatal("home with link credentials accepted")
	}
	spoke := newLinkRegion(t, filepath.Join(root, "sfo"), "sfo", signerID)
	spoke.cfg.CredentialsFile = "controller.creds"
	spoke.cfg.Embedded.Link = &Link{TLS: tlsFiles}
	if err := spoke.cfg.validate(); err == nil {
		t.Fatal("spoke without link credentials accepted")
	}
	fraCreds := linkUserCredentials(t, root, "fra.creds", signer, gru.cellID, "fra")
	if err := validateLinkCredentials(fraCreds, "sfo"); err == nil {
		t.Fatal("link user for another cell accepted")
	}
	sfoCreds := linkUserCredentials(t, root, "sfo.creds", signer, gru.cellID, "sfo")
	if err := validateLinkCredentials(sfoCreds, "fra"); err == nil {
		t.Fatal("link user tagged for sfo accepted by fra")
	}
	if err := VerifyLinkScope(jwt.NewAccountClaims(gru.cellID)); err == nil {
		t.Fatal("home cell account without the link signer accepted")
	}
	mutated := jwt.NewAccountClaims(gru.cellID)
	ApplyLink(mutated, signerID)
	scope := mutated.SigningKeys[signerID].(*jwt.UserScope)
	scope.Template.Sub.Allow = append(scope.Template.Sub.Allow, "ts.control.>")
	if err := VerifyLinkScope(mutated); err == nil {
		t.Fatal("link template with regional-only subjects accepted")
	}
}

// writeTempFile stores data in a fresh file and returns its path.
func writeTempFile(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "creds")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
