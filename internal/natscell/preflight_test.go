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
	"slices"
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
		"ts.orch.v1.gru.terminal.>",
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

func TestControllerCredentialsRequireScopedTerminalSubscription(t *testing.T) {
	cfg, cellKey, controllerUser, controller := productionPreflightFixture(t)
	if err := ValidateBrokerControllerCredentials(cfg.CredentialsFile, "gru", "broker-a"); err != nil {
		t.Fatalf("current controller grants rejected: %v", err)
	}
	original := slices.Clone(controller.Sub.Allow)
	for _, test := range []struct {
		name  string
		grant string
	}{
		{name: "missing"},
		{name: "broad wildcard", grant: "ts.orch.v1.gru.>"},
	} {
		t.Run(test.name, func(t *testing.T) {
			controller.Sub.Allow = slices.Clone(original[:len(original)-1])
			if test.grant != "" {
				controller.Sub.Allow = append(controller.Sub.Allow, test.grant)
			}
			writeControllerPreflightCredentials(t, filepath.Dir(cfg.CredentialsFile), controller, cellKey, controllerUser)
			if err := ValidateBrokerControllerCredentials(cfg.CredentialsFile, "gru", "broker-a"); err == nil {
				t.Fatal("controller credentials without exact terminal subscription accepted")
			}
		})
	}
}

func TestOperatorCredentialsRequireExactTerminalPublishes(t *testing.T) {
	root := t.TempDir()
	cellKey, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	cellID, _ := cellKey.PublicKey()
	operatorUser, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	operatorID, _ := operatorUser.PublicKey()
	claim := jwt.NewUserClaims(operatorID)
	claim.IssuerAccount = cellID
	claim.Sub.Allow = jwt.StringList{inboxPrefix("gru", operatorID) + ".>"}
	claim.Pub.Allow = jwt.StringList{
		"ts.orch.v1.gru.broker.claim.apply", "$JS.API.INFO",
		"$JS.API.STREAM.INFO.TS_CONTROL_LOG", "$JS.API.STREAM.MSG.GET.TS_CONTROL_LOG",
		"ts.orch.v1.gru.terminal.plan", "ts.orch.v1.gru.terminal.apply", "ts.orch.v1.gru.terminal.status",
	}
	path := testJWTUserCredentialsWithKey(t, root, "operator.creds", cellKey, cellID,
		operatorUser, claim.Pub.Allow, claim.Sub.Allow)
	if err := ValidateBrokerOperatorCredentials(path, "gru"); err != nil {
		t.Fatalf("current operator grants rejected: %v", err)
	}
	for _, missing := range []string{"terminal.plan", "terminal.apply", "terminal.status"} {
		t.Run(missing, func(t *testing.T) {
			allowed := make(jwt.StringList, 0, len(claim.Pub.Allow))
			for _, subject := range claim.Pub.Allow {
				if subject != "ts.orch.v1.gru."+missing {
					allowed = append(allowed, subject)
				}
			}
			testJWTUserCredentialsWithKey(t, root, "operator.creds", cellKey, cellID,
				operatorUser, allowed, claim.Sub.Allow)
			if err := ValidateBrokerOperatorCredentials(path, "gru"); err == nil {
				t.Fatal("operator credentials without exact terminal publish accepted")
			}
		})
	}
	for _, unscoped := range []string{"ts.orch.v1.gru.terminal.>", "ts.orch.v1.gru.>", "ts.orch.v1.gru.terminal.delete"} {
		t.Run(unscoped, func(t *testing.T) {
			allowed := append(slices.Clone(claim.Pub.Allow), unscoped)
			testJWTUserCredentialsWithKey(t, root, "operator.creds", cellKey, cellID,
				operatorUser, allowed, claim.Sub.Allow)
			if err := ValidateBrokerOperatorCredentials(path, "gru"); err == nil {
				t.Fatal("operator credentials with unscoped terminal publish accepted")
			}
		})
	}
	t.Run("unscoped subscription", func(t *testing.T) {
		subscribe := append(slices.Clone(claim.Sub.Allow), "ts.orch.v1.gru.>")
		testJWTUserCredentialsWithKey(t, root, "operator.creds", cellKey, cellID,
			operatorUser, claim.Pub.Allow, subscribe)
		if err := ValidateBrokerOperatorCredentials(path, "gru"); err == nil {
			t.Fatal("operator credentials with an unscoped subscription accepted")
		}
	})
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
