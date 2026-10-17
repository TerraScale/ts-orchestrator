package natscell

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func TestMemoryClientRejectsExpiredAndMismatchedCredentials(t *testing.T) {
	root := t.TempDir()
	files := testBridgeTLS(t, root)
	config, err := loadTLS(files, false)
	if err != nil {
		t.Fatal(err)
	}
	account, _ := nkeys.CreateAccount()
	defer account.Wipe()
	accountID, _ := account.PublicKey()
	user, _ := nkeys.CreateUser()
	defer user.Wipe()
	path := filepath.Join(root, "expired.creds")
	writeExpiringUserCredentials(t, path, account, accountID, user, time.Now().Add(-time.Hour))
	expired, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(expired)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if conn, lease, err := ConnectMemoryLease(t.Context(), "gru", "tls://127.0.0.1:1", expired, config); conn != nil || lease != nil || err == nil || !strings.Contains(err.Error(), "authority expired") {
		t.Fatal("expired JWT reached a dial attempt", err)
	}
	public, _ := user.PublicKey()
	claim := jwt.NewUserClaims(public)
	claim.Expires = time.Now().Add(time.Hour).Unix()
	raw, err := claim.Encode(account)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := nkeys.CreateUser()
	defer other.Wipe()
	seed, _ := other.Seed()
	defer clear(seed)
	mismatch, err := jwt.FormatUserConfig(raw, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(mismatch)
	if conn, err := ConnectMemory(t.Context(), "gru", "tls://127.0.0.1:1", mismatch, config); conn != nil || err == nil || !strings.Contains(err.Error(), "seed and user JWT differ") {
		t.Fatal("another seed was accepted", err)
	}
}
