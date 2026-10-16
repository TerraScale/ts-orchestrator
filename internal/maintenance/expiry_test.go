package maintenance

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func certificatePEM(t *testing.T, name string, serial int64, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: notAfter.Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// userCredentials returns a NATS credentials file and its seed.
func userCredentials(t *testing.T, expires time.Time) ([]byte, []byte) {
	t.Helper()
	account, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	public, _ := user.PublicKey()
	claim := jwt.NewUserClaims(public)
	if !expires.IsZero() {
		claim.Expires = expires.Unix()
	}
	token, err := claim.Encode(account)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := user.Seed()
	creds, err := jwt.FormatUserConfig(token, seed)
	if err != nil {
		t.Fatal(err)
	}
	return creds, seed
}

func accountJWT(t *testing.T, expires time.Time) string {
	t.Helper()
	operator, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	account, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	public, _ := account.PublicKey()
	claim := jwt.NewAccountClaims(public)
	claim.Expires = expires.Unix()
	token, err := claim.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func write(t *testing.T, dir, name string, body []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanReadsCertificatesAndNATSJWTs(t *testing.T) {
	dir := t.TempDir()
	expires := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	// Parsing never checks validity: an expired credential is the one that
	// most needs reporting.
	expired := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	leaf := write(t, dir, "tls.pem", certificatePEM(t, "gru-1-ctl-1", 1, expired))
	// During a CA rotation the trust file holds the old and the new CA
	// under one subject; each must stay its own credential.
	ca := "TerraScale gru controller CA"
	bundle := write(t, dir, "ca.pem", bytes.Join([][]byte{certificatePEM(t, ca, 0xabcdef0123, expires),
		certificatePEM(t, ca, 0x77, expires.AddDate(1, 0, 0)), certificatePEM(t, "", 9, expires)}, nil))
	creds, seed := userCredentials(t, expired)
	credsPath := write(t, dir, "controller.creds", creds)
	account := write(t, dir, "cell.jwt", []byte(accountJWT(t, expires)+"\n"))
	forever, _ := userCredentials(t, time.Time{})
	foreverPath := write(t, dir, "forever.creds", forever)

	got, err := Scan([]CredentialFile{{Name: "nats server tls", Path: leaf}, {Name: "nats server ca", Path: bundle},
		{Name: "nats route ca", Path: bundle}, {Name: "nats client credentials", Path: credsPath},
		{Name: "nats cell account jwt", Path: account}, {Name: "nats system credentials", Path: foreverPath},
		{Name: "unset", Path: ""}})
	if err != nil {
		t.Fatal(err)
	}
	want := []observability.CredentialView{
		{Name: "nats server tls", Kind: "tls", NotAfter: expired},
		{Name: "nats server ca (TerraScale gru controller CA serial abcdef01)", Kind: "tls", NotAfter: expires},
		{Name: "nats server ca (TerraScale gru controller CA serial 77)", Kind: "tls", NotAfter: expires.AddDate(1, 0, 0)},
		{Name: "nats server ca (serial 9)", Kind: "tls", NotAfter: expires},
		{Name: "nats client credentials", Kind: "nats-jwt", NotAfter: expired},
		{Name: "nats cell account jwt", Kind: "nats-jwt", NotAfter: expires}}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for index := range want {
		issued := got[index].NotBefore
		got[index].NotBefore = time.Time{}
		if got[index] != want[index] || issued.IsZero() {
			t.Fatalf("credential %d: got %+v issued %s, want %+v", index, got[index], issued, want[index])
		}
	}
	for _, credential := range got {
		if strings.Contains(credential.Name, string(seed)) {
			t.Fatal("a credential name carries the seed")
		}
	}
}

// One unreadable, tampered or oversized file is reported by role and path
// without hiding the expiry of the files that could be read, and without
// echoing file content.
func TestScanReportsBadFilesAndKeepsTheRest(t *testing.T) {
	dir := t.TempDir()
	expires := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	leaf := write(t, dir, "tls.pem", certificatePEM(t, "leaf", 1, expires))
	creds, seed := userCredentials(t, expires)
	// A payload with a raised expiry under the original signature must fail
	// verification instead of being believed.
	token, _ := jwt.ParseDecoratedJWT(creds)
	parts := strings.Split(token, ".")
	claims, _ := jwt.DecodeUserClaims(token)
	claims.Expires = expires.AddDate(10, 0, 0).Unix()
	other, _ := nkeys.CreateAccount()
	forged, _ := claims.Encode(other)
	parts[1] = strings.Split(forged, ".")[1]
	tampered := bytes.Replace(creds, []byte(token), []byte(strings.Join(parts, ".")), 1)
	files := []CredentialFile{
		{Name: "missing", Path: filepath.Join(dir, "absent.pem")},
		{Name: "tampered", Path: write(t, dir, "tampered.creds", tampered)},
		{Name: "garbage", Path: write(t, dir, "garbage", []byte("not a credential "+string(seed)))},
		{Name: "broken pem", Path: write(t, dir, "broken.pem", []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))},
		{Name: "huge", Path: write(t, dir, "huge.pem", bytes.Repeat([]byte("x"), maxCredentialBytes+1))},
		{Name: "leaf", Path: leaf}}
	got, err := Scan(files)
	if len(got) != 1 || got[0].Name != "leaf" || !got[0].NotAfter.Equal(expires) {
		t.Fatalf("the readable file must still be reported: %+v", got)
	}
	if err == nil {
		t.Fatal("bad files must be reported")
	}
	message := err.Error()
	for _, name := range []string{"missing", "tampered", "garbage", "broken pem", "huge"} {
		if !strings.Contains(message, name+" credential ") {
			t.Fatalf("error does not name %q: %v", name, err)
		}
	}
	if strings.Contains(message, string(seed)) || strings.Contains(message, "not a credential S") {
		t.Fatalf("error echoes file content: %v", err)
	}
}
