package natscell

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func productionPreflightFixture(t *testing.T) (Config, nkeys.KeyPair, nkeys.KeyPair, *jwt.UserClaims) {
	t.Helper()
	root := t.TempDir()
	operatorKey, _ := nkeys.CreateOperator()
	systemKey, _ := nkeys.CreateAccount()
	cellKey, _ := nkeys.CreateAccount()
	operatorID, _ := operatorKey.PublicKey()
	systemID, _ := systemKey.PublicKey()
	cellID, _ := cellKey.PublicKey()
	operator := jwt.NewOperatorClaims(operatorID)
	operator.SystemAccount = systemID
	operatorRaw, err := operator.Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	systemRaw, err := jwt.NewAccountClaims(systemID).Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	cellRaw, err := jwt.NewAccountClaims(cellID).Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	systemUser, _ := nkeys.CreateUser()
	systemUserID, _ := systemUser.PublicKey()
	systemCreds := testJWTUserCredentialsWithKey(t, root, "system.creds", systemKey, systemID, systemUser,
		[]string{"$SYS.REQ.ACCOUNT." + cellID + ".CLAIMS.UPDATE"},
		[]string{inboxPrefix("gru", systemUserID) + ".>"})
	controllerUser, _ := nkeys.CreateUser()
	controllerID, _ := controllerUser.PublicKey()
	controller := jwt.NewUserClaims(controllerID)
	controller.IssuerAccount = cellID
	controller.Pub.Allow = jwt.StringList{"ts.broker.gru.ticket.>", "ts.broker.gru.fence.>"}
	controller.Sub.Allow = jwt.StringList{
		inboxPrefix("gru", controllerID) + ".>", "ts.broker.gru.ticket.>",
		"ts.broker.gru.fence.broker-a", "ts.orch.v1.gru.broker.claim.apply",
	}
	controller.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second}
	controllerCreds := writeControllerPreflightCredentials(t, root, controller, cellKey, controllerUser)
	tlsFiles := testBridgeTLS(t, filepath.Join(root, "tls"))
	ticketPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Cell: "gru", Instance: "broker-a", Replicas: 1, CredentialsFile: controllerCreds,
		TLS: tlsFiles, Embedded: &Embedded{
			Host: "127.0.0.1", Port: 4222, StoreDir: filepath.Join(root, "store"),
			TLS: tlsFiles, RouteTLS: tlsFiles, OperatorJWTFile: write("operator.jwt", operatorRaw),
			SystemJWTFile: write("system.jwt", systemRaw), CellJWTFile: write("cell.jwt", cellRaw),
			SystemCredentialsFile: systemCreds, TicketPublicKeyFile: write("ticket.pub", base64.StdEncoding.EncodeToString(ticketPublic)),
			BrokerIDs: []string{"broker-a"},
		}}
	return cfg, cellKey, controllerUser, controller
}

func writeControllerPreflightCredentials(t *testing.T, root string, claim *jwt.UserClaims, account, user nkeys.KeyPair) string {
	t.Helper()
	raw, err := claim.Encode(account)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := user.Seed()
	if err != nil {
		t.Fatal(err)
	}
	content, err := jwt.FormatUserConfig(raw, seed)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "controller.creds")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProductionCredentialPreflightIsReadOnlyAndCurrent(t *testing.T) {
	cfg, cellKey, controllerUser, controller := productionPreflightFixture(t)
	if err := ValidateProductionCredentials(cfg); err != nil {
		t.Fatalf("current credentials: %v", err)
	}
	if _, err := os.Stat(cfg.Embedded.StoreDir); !os.IsNotExist(err) {
		t.Fatalf("read-only preflight created broker state: %v", err)
	}
	controller.Expires = time.Now().Add(-time.Minute).Unix()
	writeControllerPreflightCredentials(t, filepath.Dir(cfg.CredentialsFile), controller, cellKey, controllerUser)
	if err := ValidateProductionCredentials(cfg); err == nil {
		t.Fatal("expired controller JWT accepted")
	}
}

func TestProductionCredentialPreflightRejectsUntrustedTLS(t *testing.T) {
	cfg, _, _, _ := productionPreflightFixture(t)
	other := testBridgeTLS(t, filepath.Join(t.TempDir(), "other-tls"))
	cfg.TLS.CAFile = other.CAFile
	if err := ValidateProductionCredentials(cfg); err == nil {
		t.Fatal("client certificate with unrelated CA accepted")
	}
}

func TestProductionCredentialPreflightEnforcesTLSKeyPurposes(t *testing.T) {
	tests := []struct {
		name      string
		role      string
		usages    []x509.ExtKeyUsage
		wantError bool
	}{
		{name: "server-only listener accepted", role: "listener", usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{name: "client-only listener rejected", role: "listener", usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, wantError: true},
		{name: "server-only client rejected", role: "client", usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, wantError: true},
		{name: "server-only route rejected", role: "route", usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, wantError: true},
		{name: "client-only route rejected", role: "route", usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, _, _, _ := productionPreflightFixture(t)
			files := testPreflightTLSWithUsages(t, filepath.Join(t.TempDir(), "tls"), test.usages...)
			switch test.role {
			case "client":
				cfg.TLS = files
			case "listener":
				cfg.Embedded.TLS = files
			case "route":
				cfg.Embedded.RouteTLS = files
			default:
				t.Fatalf("invalid test TLS role %q", test.role)
			}

			err := ValidateProductionCredentials(cfg)
			if test.wantError && err == nil {
				t.Fatal("certificate with the wrong key purpose was accepted")
			}
			if !test.wantError && err != nil {
				t.Fatalf("trusted certificate with the expected key purpose was rejected: %v", err)
			}
		})
	}
}

func testPreflightTLSWithUsages(t *testing.T, root string, usages ...x509.ExtKeyUsage) TLSFiles {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "preflight test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "preflight test peer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	return TLSFiles{
		CAFile:   write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		CertFile: write("peer.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		KeyFile:  write("peer-key.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
	}
}
