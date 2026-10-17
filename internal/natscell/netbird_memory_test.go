package natscell

import (
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func TestNetBirdSingleMemoryLeaseUsesActualTLSBridgeAndEndsOnFence(t *testing.T) {
	keys := newTestRegionKeys(t)
	signer, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Wipe()
	signerID, err := signer.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	account := jwt.NewAccountClaims(keys.cellID)
	account.SigningKeys.Add(signerID)
	accountWire, err := account.Encode(keys.operator)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &server.MemAccResolver{}
	if err := resolver.Store(keys.cellID, accountWire); err != nil {
		t.Fatal(err)
	}
	s, err := server.NewServer(&server.Options{DontListen: true, NoLog: true, NoSigs: true, TrustedKeys: []string{keys.operatorID}, AccountResolver: resolver})
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	t.Cleanup(s.Shutdown)
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("broker did not start")
	}
	files := testBridgeTLS(t, t.TempDir())
	serverTLS, err := loadTLS(files, true)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := loadTLS(files, false)
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := startBridge(s, "127.0.0.1:0", serverTLS, keys.cellID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bridge.Close)
	deadline := time.Now().Truncate(time.Second).Add(time.Minute)
	if err := bridge.OpenUntil(1, accountWire, deadline); err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	public, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	claim := jwt.NewUserClaims(public)
	claim.Name, claim.IssuerAccount, claim.Expires = "netbird-manager-read", keys.cellID, deadline.Unix()
	claim.Pub.Allow = NetBirdReaderPublishes("gru")
	claim.Sub.Allow = jwt.StringList{protocol.InboxGrant("gru", public)}
	claim.AllowedConnectionTypes = jwt.StringList{jwt.ConnectionTypeInProcess}
	wire, err := claim.Encode(signer)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := user.Seed()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	creds, err := jwt.FormatUserConfig(wire, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(creds)
	conn, lease, err := ConnectMemorySingleLease(t.Context(), "gru", "tls://"+bridge.Addr().String(), creds, clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	if conn.Opts.AllowReconnect || !conn.Opts.IgnoreDiscoveredServers {
		t.Fatal("single delivery may reconnect or adopt advertised endpoints")
	}
	if _, err := conn.SubscribeSync(protocol.InboxGrant("gru", public)); err != nil {
		t.Fatal(err)
	}
	if err := conn.Publish(protocol.Regional("gru", "netbird", "read-open"), []byte("nonce")); err != nil {
		t.Fatal(err)
	}
	if err := conn.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	denied := make(chan error, 8)
	conn.SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { denied <- err })
	for _, subject := range []string{"$JS.API.STREAM.MSG.GET.KV_TS_TRUST_ROOTS", "$JS.API.CONSUMER.CREATE.TS_CONTROL_LOG.OTHER", "$JS.API.CONSUMER.DELETE.TS_CONTROL_LOG.NET_ACCOUNT_READ"} {
		if err := conn.Publish(subject, nil); err != nil {
			t.Fatal(err)
		}
		if err := conn.FlushTimeout(time.Second); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-denied:
			if !strings.Contains(err.Error(), "Permissions Violation") {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("closed read ACL allowed protected API")
		}
	}
	bridge.Fence()
	select {
	case <-lease.Done():
	case <-time.After(time.Second):
		t.Fatal("bridge loss retained original credential context")
	}
	if err := bridge.OpenUntil(1, accountWire, deadline); err != nil {
		t.Fatal(err)
	}
	if !conn.IsClosed() || lease.Err() == nil {
		t.Fatal("reopening bridge revived the original delivery")
	}
}
