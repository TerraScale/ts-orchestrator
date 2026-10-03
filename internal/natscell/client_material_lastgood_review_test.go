package natscell

import (
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

// After a renewal is accepted the startup material may already be expired, so
// a later failed reload keeps presenting the last accepted renewal while it is
// still usable, and falls back to the startup files only when it is not
// (#127 12130).
func TestClientMaterialSourceKeepsTheLastAcceptedRenewal(t *testing.T) {
	root := t.TempDir()
	account, _ := nkeys.CreateAccount()
	accountID, _ := account.PublicKey()
	user, _ := nkeys.CreateUser()
	userID, _ := user.PublicKey()
	startup := filepath.Join(root, "startup.creds")
	renewed := filepath.Join(root, "renewed.creds")
	writeExpiringUserCredentials(t, startup, account, accountID, user, time.Now().Add(time.Hour))
	writeExpiringUserCredentials(t, renewed, account, accountID, user, time.Now().Add(48*time.Hour))
	next := ClientMaterial{CredentialsFile: renewed}
	var failure error
	source := newClientMaterialSource(Config{CredentialsFile: startup, ReloadClientMaterial: func() (ClientMaterial, error) {
		return next, failure
	}}, userID)
	if got := source.current().CredentialsFile; got != renewed {
		t.Fatalf("renewal not accepted: %s", got)
	}
	failure = errors.New("host.json is being rewritten")
	if got := source.current().CredentialsFile; got != renewed {
		t.Fatalf("a failed config read reverted to %s", got)
	}
	failure, next = nil, ClientMaterial{CredentialsFile: filepath.Join(root, "missing.creds")}
	if got := source.current().CredentialsFile; got != renewed {
		t.Fatalf("an unusable renewal reverted to %s", got)
	}
	if err := os.Remove(renewed); err != nil {
		t.Fatal(err)
	}
	if got := source.current().CredentialsFile; got != startup {
		t.Fatalf("a vanished renewal was kept: %s", got)
	}
}

// The TLS path keeps the last renewed certificate that loaded instead of the
// startup certificate (#127 12130).
func TestClientMaterialSourceKeepsTheLastRenewedCertificate(t *testing.T) {
	root := t.TempDir()
	startupTLS := testBridgeTLS(t, filepath.Join(root, "startup"))
	renewedTLS := testBridgeTLS(t, filepath.Join(root, "renewed"))
	next := renewedTLS
	source := newClientMaterialSource(Config{TLS: startupTLS, ReloadClientMaterial: func() (ClientMaterial, error) {
		return ClientMaterial{TLS: next}, nil
	}}, "")
	if _, err := source.tlsConfig(); err != nil {
		t.Fatal(err)
	}
	next.KeyFile = filepath.Join(root, "renewed-missing.key")
	config, err := source.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	want, err := tls.LoadX509KeyPair(renewedTLS.CertFile, renewedTLS.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Certificates) != 1 || string(config.Certificates[0].Certificate[0]) != string(want.Certificate[0]) {
		t.Fatal("an unusable reload reverted to the startup certificate")
	}
}
