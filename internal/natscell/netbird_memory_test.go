package natscell

import (
	"context"
	"crypto/tls"
	"errors"
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
	t.Run("cancel-pending-info", func(t *testing.T) {
		listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		operation, cancelOperation := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancelOperation()
		ready := make(chan error, 1)
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				ready <- err
				cancelOperation()
				return
			}
			defer conn.Close()
			t.Cleanup(func() { conn.Close() })
			err = conn.(*tls.Conn).HandshakeContext(t.Context())
			ready <- err
			cancelOperation()
			var wire [1]byte
			conn.Read(wire[:])
		}()
		started := time.Now()
		conn, _, err := ConnectMemorySingleLeaseForOperation(operation, t.Context(), "gru", "tls://"+listener.Addr().String(), creds, clientTLS)
		if conn != nil {
			conn.Close()
		}
		if err == nil || time.Since(started) >= 3*time.Second {
			t.Fatal("canceled initial INFO wait retained the connection budget", err)
		}
		select {
		case err := <-ready:
			if err != nil {
				t.Fatal("initial TLS handshake failed before cancellation", err)
			}
		case <-time.After(time.Second):
			t.Fatal("connection did not reach the initial TLS handshake")
		}
	})
	if conn, _, err := ConnectMemorySingleLease(t.Context(), "gru", "tls://first:4222,tls://second:4222", creds, clientTLS); err == nil {
		conn.Close()
		t.Fatal("finite reader accepted an internal endpoint fallback list")
	}
	// A rejected issuer still consumes the one nonce-signing attempt.
	otherSigner, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	defer otherSigner.Wipe()
	rejectedJWT, err := claim.Encode(otherSigner)
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := jwt.FormatUserConfig(rejectedJWT, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(rejected)
	if conn, _, err := ConnectMemorySingleLease(t.Context(), "gru", "tls://"+bridge.Addr().String(), rejected, clientTLS); !errors.Is(err, ErrMemorySessionLost) {
		if conn != nil {
			conn.Close()
		}
		t.Fatal("signed authentication attempt allowed endpoint fallback", err)
	}
	operation, cancelOperation := context.WithCancel(t.Context())
	conn, lease, err := ConnectMemorySingleLeaseForOperation(operation, t.Context(), "gru", "tls://"+bridge.Addr().String(), creds, clientTLS)
	cancelOperation()
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
