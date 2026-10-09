package hostenroll_test

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
)

// During a CA rollover the bundle holds the old and the new CA, and the host
// issuer may already be the new CA's. A bundle root or a self-signed issuer
// is never accepted as the online host issuer.
func TestParseTLSIssuerAcrossARolloverBundle(t *testing.T) {
	now := time.Now()
	year := now.AddDate(1, 0, 0)
	old, _, _ := generationtest.Certificate(t, generationtest.CA("old CA", now, year), nil)
	next, _, _ := generationtest.Certificate(t, generationtest.CA("new CA", now, year), nil)
	issuer, cert, key := generationtest.Certificate(t, generationtest.HostIssuer(now, year), &next)
	roots := []*x509.Certificate{old.Certificate, next.Certificate}
	if _, parsed, signer, err := hostenroll.ParseTLSIssuer(key, cert, roots); err != nil ||
		!parsed.Equal(issuer.Certificate) || !signer.Equal(next.Certificate) {
		t.Fatalf("an issuer of the bundle's second CA: %v", err)
	}
	if _, _, _, err := hostenroll.ParseTLSIssuer(key, cert, roots[:1]); err == nil {
		t.Fatal("an issuer of a CA outside the bundle was accepted")
	}
	self, selfCert, selfKey := generationtest.Certificate(t, generationtest.HostIssuer(now, year), nil)
	if _, _, _, err := hostenroll.ParseTLSIssuer(selfKey, selfCert, append(roots, self.Certificate)); err == nil {
		t.Fatal("a self-signed issuer in the bundle was accepted")
	}
	if _, _, _, err := hostenroll.ParseTLSIssuer(selfKey, selfCert, roots); err == nil {
		t.Fatal("a self-signed issuer was accepted")
	}
}

// The regional root file may hold only certificates.
func TestLoadIssuerRefusesTrailingRootData(t *testing.T) {
	now := time.Now()
	year := now.AddDate(1, 0, 0)
	root, rootPEM, _ := generationtest.Certificate(t, generationtest.CA("cell CA", now, year), nil)
	_, cert, key := generationtest.Certificate(t, generationtest.HostIssuer(now, year), &root)
	issuer, _ := nkeys.CreateAccount()
	seed, _ := issuer.Seed()
	cell, _ := nkeys.CreateAccount()
	cellID, _ := cell.PublicKey()
	dir := t.TempDir()
	write := func(name string, content []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	seedPath, keyPath, certPath := write("0000000000SF1REEJJX6TC691V", seed), write("key.pem", key), write("cert.pem", cert)
	if _, err := hostenroll.LoadIssuer("gru", cellID, seedPath, keyPath, certPath, rootPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := hostenroll.LoadIssuer("gru", cellID, seedPath, keyPath, certPath,
		append(append([]byte(nil), rootPEM...), "tampered"...)); err == nil {
		t.Fatal("a root file with trailing data was accepted")
	}
}
