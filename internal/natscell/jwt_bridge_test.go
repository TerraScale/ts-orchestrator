package natscell

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func TestProductionJWTBridgeClosedApplyOpenAndFence(t *testing.T) {
	root := t.TempDir()
	operatorKey, _ := nkeys.CreateOperator()
	systemKey, _ := nkeys.CreateAccount()
	cellKey, _ := nkeys.CreateAccount()
	operatorID, _ := operatorKey.PublicKey()
	systemID, _ := systemKey.PublicKey()
	cellID, _ := cellKey.PublicKey()
	op := jwt.NewOperatorClaims(operatorID)
	op.SystemAccount = systemID
	opRaw, err := op.Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	sys := jwt.NewAccountClaims(systemID)
	sysRaw, err := sys.Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	cell := jwt.NewAccountClaims(cellID)
	cell.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 64 << 20, DiskStorage: 256 << 20, Streams: 10, Consumer: 10}
	cellRaw, err := cell.Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	ticketPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, data string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	controllerCredentials := testJWTUserCredentials(t, root, "controller.creds", cellKey, cellID, nil, nil)
	hostCredentials := testJWTUserCredentials(t, root, "host.creds", cellKey, cellID, nil, nil)
	hostClaim, hostUserID, err := credentialUser(hostCredentials)
	if err != nil || hostClaim == nil {
		t.Fatal(err)
	}
	systemUser, _ := nkeys.CreateUser()
	systemUserID, _ := systemUser.PublicKey()
	systemInbox := inboxPrefix("gru", systemUserID) + ".>"
	systemCredentials := testJWTUserCredentialsWithKey(t, root, "system.creds", systemKey, systemID, systemUser,
		[]string{"$SYS.REQ.ACCOUNT." + cellID + ".CLAIMS.UPDATE"}, []string{systemInbox})
	tlsFiles := testBridgeTLS(t, root)
	cfg := Config{Cell: "gru", Instance: "broker-a", Replicas: 1, CredentialsFile: controllerCredentials, TLS: tlsFiles,
		Embedded: &Embedded{Host: "127.0.0.1", Port: freeClientPort(t), StoreDir: filepath.Join(root, "store"),
			TLS: tlsFiles, RouteTLS: tlsFiles, OperatorJWTFile: write("operator.jwt", opRaw, 0o600),
			SystemJWTFile: write("system.jwt", sysRaw, 0o600), CellJWTFile: write("cell.jwt", cellRaw, 0o600),
			SystemCredentialsFile: systemCredentials}}
	cfg.Embedded.TicketPublicKeyFile = write("ticket.pub", base64.StdEncoding.EncodeToString(ticketPublic), 0o600)
	cfg.Embedded.BrokerIDs = []string{"broker-a"}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	r, err := Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if r.server.Addr() != nil {
		t.Fatal("production NATS unexpectedly opened its own client listener")
	}
	if _, err := net.DialTimeout("tcp", r.ClientAddress().String(), time.Second); err != nil {
		t.Fatal(err)
	}
	if err := r.ApplyCellClaim(ctx, 1, cellRaw); err != nil {
		t.Fatal(err)
	}
	hostConfig := Config{Cell: "gru", Instance: "host-a", Replicas: 1, ClientRole: "host",
		URL: r.URL(), CredentialsFile: hostCredentials, TLS: tlsFiles}
	meshListener, err := r.bridge.listen("127.0.0.1:0", r.brokerTLS.ServerConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer meshListener.Close()
	meshConfig := hostConfig
	meshConfig.URL = "tls://" + meshListener.Addr().String()
	if _, err := Start(ctx, meshConfig); err == nil {
		t.Fatal("second listener bypassed the closed production bridge")
	}
	for _, address := range []string{"0.0.0.0", "127.0.0.1", "10.251.0.11", "8.8.8.8", "fd00::1"} {
		if listener, err := r.ListenNetBird(netip.MustParseAddr(address)); err == nil {
			listener.Close()
			t.Fatalf("mesh listener accepted non-mesh address %s", address)
		}
	}
	if _, err := Start(ctx, hostConfig); err == nil {
		t.Fatal("closed production bridge admitted a client")
	}
	if err := r.Bridge().OpenUntil(1, cellRaw, time.Now().Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	client, err := Start(ctx, hostConfig)
	if err != nil {
		t.Fatalf("real TLS-first JWT client: %v", err)
	}
	defer client.Close()
	credentials, err := os.ReadFile(hostCredentials)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(credentials)
	clientTLS, err := loadTLS(tlsFiles, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"tls", "info", "pong"} {
		t.Run("cancel-acquisition-"+phase, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			operation, cancelOperation := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancelOperation()
			peerDone := make(chan error, 1)
			go func() {
				raw, err := listener.Accept()
				if err != nil {
					peerDone <- err
					return
				}
				defer raw.Close()
				if err := raw.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
					peerDone <- err
					return
				}
				var conn net.Conn = raw
				if phase == "tls" {
					var hello [1]byte
					_, err = io.ReadFull(raw, hello[:])
				} else {
					secure := tls.Server(raw, r.brokerTLS.ServerConfig())
					err = secure.HandshakeContext(operation)
					conn = secure
					if err == nil && phase == "pong" {
						_, err = conn.Write([]byte("INFO {\"server_id\":\"stalled\",\"version\":\"2.15.0\",\"proto\":1,\"nonce\":\"test-nonce\"}\r\n"))
						reader := bufio.NewReader(conn)
						for err == nil {
							var line string
							line, err = reader.ReadString('\n')
							if line == "PING\r\n" {
								break
							}
						}
					}
				}
				cancelOperation()
				if err == nil {
					_, drainErr := io.Copy(io.Discard, conn)
					if networkErr, ok := errors.AsType[net.Error](drainErr); ok && networkErr.Timeout() {
						err = drainErr
					}
				}
				peerDone <- err
			}()
			connection, lease, err := ConnectMemoryLeaseForOperation(t.Context(), operation, "gru", "tls://"+listener.Addr().String(), credentials, clientTLS)
			if connection != nil {
				connection.Close()
			}
			if err == nil || lease != nil || operation.Err() == nil {
				t.Fatalf("canceled %s acquisition returned a lease: %v", phase, err)
			}
			select {
			case err := <-peerDone:
				if err != nil {
					t.Fatalf("%s peer did not finish after socket cancellation: %v", phase, err)
				}
			case <-time.After(time.Second):
				t.Fatal("acquisition returned without joining canceled socket work")
			}
		})
	}
	t.Run("acquisition-detaches-original-lifetime-remains", func(t *testing.T) {
		original, cancelOriginal := context.WithCancel(t.Context())
		defer cancelOriginal()
		operation, cancelOperation := context.WithTimeout(t.Context(), time.Second)
		defer cancelOperation()
		connection, lease, err := ConnectMemoryLeaseForOperation(original, operation, "gru", r.URL(), credentials, clientTLS)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		cancelOperation()
		if lease.Err() != nil || connection.FlushTimeout(time.Second) != nil {
			t.Fatal("completed acquisition cancellation revoked the original lease")
		}
		reconnected := make(chan struct{}, 1)
		connection.SetReconnectHandler(func(*nats.Conn) {
			select {
			case reconnected <- struct{}{}:
			default:
			}
		})
		if err := connection.ForceReconnect(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-reconnected:
		case <-time.After(time.Second):
			t.Fatal("completed acquisition cancellation blocked reconnect under the original lease")
		}
		if lease.Err() != nil || connection.FlushTimeout(time.Second) != nil {
			t.Fatal("reconnected session lost the original lease")
		}

		cancelOriginal()
		select {
		case <-lease.Done():
		case <-time.After(time.Second):
			t.Fatal("original authority cancellation retained the lease")
		}
		deadline := time.Now().Add(time.Second)
		for !connection.IsClosed() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if !connection.IsClosed() {
			t.Fatal("original authority cancellation retained its connection")
		}
	})

	meshClient, err := Start(ctx, meshConfig)
	if err != nil {
		t.Fatalf("authenticated second listener failed: %v", err)
	}
	defer meshClient.Close()
	if err := meshClient.Conn().FlushWithContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := meshListener.Close(); err != nil {
		t.Fatal(err)
	}
	for meshClient.Conn().IsConnected() {
		if ctx.Err() != nil {
			t.Fatal("closing mesh listener left its accepted session alive")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := client.Conn().FlushWithContext(ctx); err != nil {
		t.Fatalf("closing mesh listener interrupted the OCI session: %v", err)
	}
	meshListener, err = r.bridge.listen("127.0.0.1:0", r.brokerTLS.ServerConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer meshListener.Close()
	meshConfig.URL = "tls://" + meshListener.Addr().String()
	meshClient, err = Start(ctx, meshConfig)
	if err != nil {
		t.Fatalf("replacement mesh listener did not admit its authenticated client: %v", err)
	}
	defer meshClient.Close()
	if !client.Conn().IsConnected() {
		t.Fatal("TLS-first client disconnected")
	}
	plain, err := net.DialTimeout("tcp", r.ClientAddress().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = plain.Write([]byte("CONNECT {}\r\n"))
	_ = plain.SetReadDeadline(time.Now().Add(time.Second))
	var byteBuffer [1]byte
	if _, err := plain.Read(byteBuffer[:]); err == nil {
		t.Fatal("plaintext client was accepted by mTLS bridge")
	}
	_ = plain.Close()
	badTLS := testBridgeTLS(t, filepath.Join(root, "wrong-ca"))
	wrongCA := hostConfig
	wrongCA.TLS = badTLS
	if _, err := Start(ctx, wrongCA); err == nil {
		t.Fatal("untrusted TLS peer connected")
	}
	wrongCA.URL = meshConfig.URL
	if _, err := Start(ctx, wrongCA); err == nil {
		t.Fatal("second listener bypassed mutual TLS")
	}
	// NATS uses second-resolution iat; a replacement must be issued later.
	time.Sleep(time.Until(time.Unix(cell.IssuedAt+1, 0)))
	cell.Revoke(hostUserID)
	revokedRaw, err := cell.Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ApplyCellClaim(ctx, 2, revokedRaw); err != nil {
		t.Fatal(err)
	}
	if err := r.Bridge().OpenUntil(2, revokedRaw, time.Now().Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	for client.Conn().IsConnected() || meshClient.Conn().IsConnected() {
		if ctx.Err() != nil {
			t.Fatal("fence did not close live client")
		}
		time.Sleep(10 * time.Millisecond)
	}
	newUser := testJWTUserCredentials(t, root, "new-user.creds", cellKey, cellID, nil, nil)
	newConfig := hostConfig
	newConfig.CredentialsFile = newUser
	newConfig.Instance = "host-b"
	reconnected, err := Start(ctx, newConfig)
	if err != nil {
		t.Fatalf("non-revoked TLS-first client did not reconnect: %v", err)
	}
	defer reconnected.Close()
	r.Bridge().FenceClaim(3)
	if err := r.Bridge().OpenUntil(2, revokedRaw, time.Now().Add(time.Second)); err == nil {
		t.Fatal("old claim ticket reopened fenced bridge")
	}
	r.Bridge().Close()
	if _, err := r.bridge.listen("127.0.0.1:0", r.brokerTLS.ServerConfig()); !errors.Is(err, ErrBridgeClosed) {
		t.Fatalf("closed bridge did not return its shutdown sentinel: %v", err)
	}
	if connection, err := net.DialTimeout("tcp", meshListener.Addr().String(), time.Second); err == nil {
		connection.Close()
		t.Fatal("bridge close left second listener serving")
	}
}

func testJWTUserCredentials(t *testing.T, root, name string, account nkeys.KeyPair, accountID string, publish, subscribe []string) string {
	t.Helper()
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	return testJWTUserCredentialsWithKey(t, root, name, account, accountID, user, publish, subscribe)
}

func testJWTUserCredentialsWithKey(t *testing.T, root, name string, account nkeys.KeyPair, accountID string, user nkeys.KeyPair, publish, subscribe []string) string {
	t.Helper()
	userID, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	claim := jwt.NewUserClaims(userID)
	claim.IssuerAccount = accountID
	if publish != nil {
		claim.Pub.Allow = publish
	}
	if subscribe != nil {
		claim.Sub.Allow = subscribe
	}
	raw, err := claim.Encode(account)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := user.Seed()
	if err != nil {
		t.Fatal(err)
	}
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

// testLeafServerName is the DNS name of testBridgeTLS's certificate, the
// server_name test leaf remotes pin.
const testLeafServerName = "leaf.interregion.test"

// testBridgeTLS is a CA and a peer certificate for 127.0.0.1 and
// testLeafServerName.
func testBridgeTLS(t *testing.T, root string) TLSFiles {
	t.Helper()
	return testTLSFor(t, root, net.ParseIP("127.0.0.1"))
}

// testTLSFor is testBridgeTLS for testLeafServerName and the given IPs only.
func testTLSFor(t *testing.T, root string, ips ...net.IP) TLSFiles {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test peer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), DNSNames: []string{testLeafServerName}, IPAddresses: ips, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	return TLSFiles{CAFile: write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		CertFile: write("peer.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		KeyFile:  write("peer-key.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))}
}
