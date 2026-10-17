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
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
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
	membershipUser, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer membershipUser.Wipe()
	membershipUserID, err := membershipUser.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	membershipCredentials := testJWTUserCredentialsWithKey(t, root, "membership.creds", systemKey, systemID, membershipUser,
		[]string{MembershipMetaStepdownSubject, MembershipServerRemoveSubject}, []string{inboxPrefix("gru", membershipUserID) + ".>"})
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
	controllerWire, err := os.ReadFile(controllerCredentials)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(controllerWire)
	controllerUser, err := nkeys.ParseDecoratedUserNKey(controllerWire)
	if err != nil {
		t.Fatal(err)
	}
	defer controllerUser.Wipe()
	otherControllerJWT := testJWTUserCredentialsWithKey(t, root, "controller-other-jwt.creds", cellKey, cellID, controllerUser,
		[]string{">"}, []string{">"})
	for _, next := range []struct {
		name, path string
		allowed    bool
	}{
		{"original", controllerCredentials, true},
		{"same-account-other-user", hostCredentials, true},
		{"same-user-other-jwt", otherControllerJWT, true},
		{"system", systemCredentials, false},
		{"membership", membershipCredentials, false},
	} {
		t.Run("repeated-connect/"+next.name, func(t *testing.T) {
			secured, reader, nonce := testBridgeProtocolConnection(t, ctx, tlsFiles, r.ClientAddress().String())
			writeBridgeConnect(t, secured, controllerCredentials, nonce)
			if line, err := reader.ReadString('\n'); err != nil || line != "PONG\r\n" {
				t.Fatalf("original controller authentication: %q %v", line, err)
			}
			writeBridgeConnect(t, secured, next.path, nonce)
			line, err := reader.ReadString('\n')
			if next.allowed {
				if err != nil || line != "PONG\r\n" {
					t.Fatalf("public bridge rejected same-account repeated CONNECT: %q %v", line, err)
				}
				return
			}
			if timeout, ok := errors.AsType[net.Error](err); ok && timeout.Timeout() {
				t.Fatal("privileged repeated CONNECT was not rejected before the protocol deadline")
			}
			if ctx.Err() != nil || !r.Bridge().Status().Open {
				t.Fatal("privileged repeated CONNECT ended after its context or public gate expired")
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("privileged repeated CONNECT failed without a native rejection: %v", err)
				}
			} else if !strings.HasPrefix(line, "-ERR ") {
				t.Fatalf("public bridge accepted privileged repeated CONNECT: %q", line)
			}
		})
	}
	admin, err := r.OpenMembershipAdmin(membershipCredentials)
	if err != nil {
		t.Fatalf("root's scoped membership handle failed: %v", err)
	}
	if err := admin.conn.FlushWithContext(ctx); err != nil {
		t.Fatal(err)
	}
	admin.Close()
	if err := r.systemConn.FlushWithContext(ctx); err != nil {
		t.Fatalf("root's SYSTEM handle failed: %v", err)
	}
	client, err := Start(ctx, hostConfig)
	if err != nil {
		t.Fatalf("real TLS-first JWT client: %v", err)
	}
	defer client.Close()
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

func testBridgeProtocolConnection(t *testing.T, ctx context.Context, files TLSFiles, address string) (*tls.Conn, *bufio.Reader, string) {
	t.Helper()
	config, err := loadTLS(files, false)
	if err != nil {
		t.Fatal(err)
	}
	config.ServerName = testLeafServerName
	raw, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	secured := tls.Client(raw, config)
	t.Cleanup(func() { _ = secured.Close() })
	if err := secured.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := secured.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(secured)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "INFO ") {
		t.Fatalf("native INFO: %q %v", line, err)
	}
	var info struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "INFO "))), &info); err != nil || info.Nonce == "" {
		t.Fatalf("native nonce: %v", err)
	}
	return secured, reader, info.Nonce
}

func writeBridgeConnect(t *testing.T, conn net.Conn, path, nonce string) {
	t.Helper()
	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	raw, err := jwt.ParseDecoratedJWT(wire)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := nkeys.ParseDecoratedUserNKey(wire)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Wipe()
	signature, err := pair.Sign([]byte(nonce))
	if err != nil {
		t.Fatal(err)
	}
	connect, err := json.Marshal(struct {
		JWT     string `json:"jwt"`
		Sig     string `json:"sig"`
		Verbose bool   `json:"verbose"`
	}{JWT: raw, Sig: base64.RawURLEncoding.EncodeToString(signature)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s\r\nPING\r\n", connect); err != nil {
		t.Fatal(err)
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
