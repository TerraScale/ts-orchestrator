package natscell

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
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
	for client.Conn().IsConnected() {
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

func testBridgeTLS(t *testing.T, root string) TLSFiles {
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
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test peer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
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
