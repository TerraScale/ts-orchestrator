package natscell

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func writeExpiringUserCredentials(t *testing.T, path string, account nkeys.KeyPair, accountID string,
	user nkeys.KeyPair, expires time.Time,
) {
	t.Helper()
	userID, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	claim := jwt.NewUserClaims(userID)
	claim.IssuerAccount = accountID
	claim.Expires = expires.Unix()
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
	if err := os.WriteFile(path, creds, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestClientMaterialSourceRejectsAnotherUserKey(t *testing.T) {
	root := t.TempDir()
	account, _ := nkeys.CreateAccount()
	accountID, _ := account.PublicKey()
	user, _ := nkeys.CreateUser()
	userID, _ := user.PublicKey()
	other, _ := nkeys.CreateUser()
	startup := filepath.Join(root, "startup.creds")
	renewed := filepath.Join(root, "renewed.creds")
	foreign := filepath.Join(root, "foreign.creds")
	later := time.Now().Add(time.Hour)
	writeExpiringUserCredentials(t, startup, account, accountID, user, later)
	writeExpiringUserCredentials(t, renewed, account, accountID, user, later)
	writeExpiringUserCredentials(t, foreign, account, accountID, other, later)
	tlsFiles := testBridgeTLS(t, filepath.Join(root, "tls"))
	next := renewed
	source := newClientMaterialSource(Config{CredentialsFile: startup, TLS: tlsFiles,
		ReloadClientMaterial: func() (ClientMaterial, error) {
			return ClientMaterial{CredentialsFile: next, TLS: tlsFiles}, nil
		}}, userID)
	if got := source.current().CredentialsFile; got != renewed {
		t.Fatalf("renewed credentials for the same key were not used: %s", got)
	}
	next = foreign
	if got := source.current().CredentialsFile; got != startup {
		t.Fatalf("credentials for a different NATS user were accepted: %s", got)
	}
	next = filepath.Join(root, "missing.creds")
	if got := source.current().CredentialsFile; got != startup {
		t.Fatalf("missing reloaded credentials did not fall back: %s", got)
	}
	if _, err := source.tlsConfig(); err != nil {
		t.Fatal(err)
	}
	static := newClientMaterialSource(Config{CredentialsFile: startup, TLS: tlsFiles}, userID)
	if got := static.current().CredentialsFile; got != startup {
		t.Fatal(got)
	}
}

// A renewed host JWT must be picked up on the reconnect the broker forces at
// the old credential's expiry, without restarting the client process.
func TestHostClientPresentsRenewedCredentialsAfterExpiry(t *testing.T) {
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
	sysRaw, err := jwt.NewAccountClaims(systemID).Encode(operatorKey)
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
	write := func(name, data string) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	controllerCredentials := testJWTUserCredentials(t, root, "controller.creds", cellKey, cellID, nil, nil)
	systemUser, _ := nkeys.CreateUser()
	systemUserID, _ := systemUser.PublicKey()
	systemCredentials := testJWTUserCredentialsWithKey(t, root, "system.creds", systemKey, systemID, systemUser,
		[]string{"$SYS.REQ.ACCOUNT." + cellID + ".CLAIMS.UPDATE"}, []string{inboxPrefix("gru", systemUserID) + ".>"})
	tlsFiles := testBridgeTLS(t, root)
	cfg := Config{Cell: "gru", Instance: "broker-a", Replicas: 1, CredentialsFile: controllerCredentials, TLS: tlsFiles,
		Embedded: &Embedded{Host: "127.0.0.1", Port: freeClientPort(t), StoreDir: filepath.Join(root, "store"),
			TLS: tlsFiles, RouteTLS: tlsFiles, OperatorJWTFile: write("operator.jwt", opRaw),
			SystemJWTFile: write("system.jwt", sysRaw), CellJWTFile: write("cell.jwt", cellRaw),
			SystemCredentialsFile: systemCredentials}}
	cfg.Embedded.TicketPublicKeyFile = write("ticket.pub", base64.StdEncoding.EncodeToString(ticketPublic))
	cfg.Embedded.BrokerIDs = []string{"broker-a"}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	r, err := Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if err := r.ApplyCellClaim(ctx, 1, cellRaw); err != nil {
		t.Fatal(err)
	}
	if err := r.Bridge().OpenUntil(1, cellRaw, time.Now().Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	hostUser, _ := nkeys.CreateUser()
	startup := filepath.Join(root, "host-startup.creds")
	renewed := filepath.Join(root, "host-renewed.creds")
	writeExpiringUserCredentials(t, startup, cellKey, cellID, hostUser, time.Now().Add(3*time.Second))
	var renewedReady atomic.Bool
	hostConfig := Config{Cell: "gru", Instance: "host-a", Replicas: 1, ClientRole: "host",
		URL: r.URL(), CredentialsFile: startup, TLS: tlsFiles,
		ReloadClientMaterial: func() (ClientMaterial, error) {
			if !renewedReady.Load() {
				return ClientMaterial{CredentialsFile: startup, TLS: tlsFiles}, nil
			}
			return ClientMaterial{CredentialsFile: renewed, TLS: tlsFiles}, nil
		}}
	client, err := Start(ctx, hostConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	reconnected := make(chan struct{}, 4)
	client.Conn().SetReconnectHandler(func(*nats.Conn) { reconnected <- struct{}{} })
	writeExpiringUserCredentials(t, renewed, cellKey, cellID, hostUser, time.Now().Add(time.Hour))
	renewedReady.Store(true)
	select {
	case <-reconnected:
	case <-ctx.Done():
		t.Fatal("host client did not reconnect after its startup credential expired")
	}
	time.Sleep(500 * time.Millisecond)
	if !client.Conn().IsConnected() {
		t.Fatalf("host client is not connected with renewed credentials: %v", client.Conn().Status())
	}
}
