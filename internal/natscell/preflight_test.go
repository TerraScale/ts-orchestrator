package natscell

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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
		"ts.orch.v1.gru.managed-update.prepare",
		"ts.orch.v1.gru.backup.operation",
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
