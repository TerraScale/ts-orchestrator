package bootstrapstart

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func TestCurrentCredentialBoundUsesEarliestInstalledJWTOrTLSExpiry(t *testing.T) {
	check, expected := credentialPathFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	write := func(name string, wire []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(check.directory, name), wire, 0o600); err != nil {
			t.Fatal(err)
		}
		expected[name] = digest(wire)
	}
	operatorKey, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	systemKey, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	cellKey, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	systemUserKey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	controllerUserKey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	operatorID, _ := operatorKey.PublicKey()
	systemID, _ := systemKey.PublicKey()
	cellID, _ := cellKey.PublicKey()
	systemUserID, _ := systemUserKey.PublicKey()
	controllerUserID, _ := controllerUserKey.PublicKey()
	operator := jwt.NewOperatorClaims(operatorID)
	operator.Expires = now.Add(6 * time.Hour).Unix()
	operatorRaw, err := operator.Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	write("operator.jwt", []byte(operatorRaw))
	system := jwt.NewAccountClaims(systemID)
	system.Expires = now.Add(5 * time.Hour).Unix()
	systemRaw, err := system.Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	write("system.jwt", []byte(systemRaw))
	cell := jwt.NewAccountClaims(cellID)
	cell.Expires = now.Add(4 * time.Hour).Unix()
	cellRaw, err := cell.Encode(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	write("cell.jwt", []byte(cellRaw))
	systemUser := jwt.NewUserClaims(systemUserID)
	systemUser.Expires = now.Add(3 * time.Hour).Unix()
	writeDecoratedBoundUser(t, write, "system.creds", systemUser, systemKey, systemUserKey)
	controller := jwt.NewUserClaims(controllerUserID)
	controller.Expires = now.Add(2 * time.Hour).Unix()
	writeDecoratedBoundUser(t, write, "controller.creds", controller, cellKey, controllerUserKey)
	leafExpiry := now.Add(90 * time.Minute)
	write("cert.pem", boundTestCertificate(t, now, leafExpiry))

	bound, err := check.CurrentCredentialBound(expected, peerCredentialManifest, nil, "")
	if err != nil {
		t.Fatalf("derive bound from installed credentials: %v", err)
	}
	wantDigest, err := bootstrap.InstallContinuityCredentialDigest(expected)
	if err != nil {
		t.Fatal(err)
	}
	if bound.SHA256 != wantDigest || !bound.ValidUntil.Equal(leafExpiry) {
		t.Fatalf("TLS leaf should be first expiry: bound=%+v digest=%s", bound, wantDigest)
	}
	fixture := newFounderSignerFixture(t)
	seed, err := verifiedFounderManifest(fixture.current, fixture.accepted.Slot, fixture.baked.Roots, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string][]byte{
		"founder-peer.key": fixture.peerKey, "founder-ledger.key": fixture.ledgerKey,
	} {
		write(name, key)
		expected[name] = fixture.accepted.MaterialSHA256[name]
	}
	seedBound, err := check.CurrentCredentialBound(expected, seed.Manifest(), nil, "")
	if err != nil || !seedBound.ValidUntil.Equal(leafExpiry) || seedBound.SHA256 == wantDigest {
		t.Fatalf("seed signer material did not preserve credential cutoff and bind inventory: bound=%+v err=%v", seedBound, err)
	}
	for _, name := range []string{"founder-peer.key", "founder-ledger.key"} {
		if err := os.Remove(filepath.Join(check.directory, name)); err != nil {
			t.Fatal(err)
		}
		delete(expected, name)
	}

	controller.Expires = now.Add(30 * time.Minute).Unix()
	writeDecoratedBoundUser(t, write, "controller.creds", controller, cellKey, controllerUserKey)
	bound, err = check.CurrentCredentialBound(expected, peerCredentialManifest, nil, "")
	if err != nil || !bound.ValidUntil.Equal(now.Add(30*time.Minute)) || bound.SHA256 == wantDigest {
		t.Fatalf("earlier current user JWT did not replace TLS cutoff and inventory: bound=%+v err=%v", bound, err)
	}
	if err := os.Remove(filepath.Join(check.directory, "system.jwt")); err != nil {
		t.Fatal(err)
	}
	if _, err := check.CurrentCredentialBound(expected, peerCredentialManifest, nil, ""); err == nil {
		t.Fatal("missing pinned JWT produced a current credential bound")
	}
	write("system.jwt", []byte(systemRaw))
	if err := os.WriteFile(filepath.Join(check.directory, "extra.key"), []byte("unpinned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := check.CurrentCredentialBound(expected, peerCredentialManifest, nil, ""); err == nil {
		t.Fatal("extra installed material produced a current credential bound")
	}
	if err := os.Remove(filepath.Join(check.directory, "extra.key")); err != nil {
		t.Fatal(err)
	}
	controller.Expires = now.Add(-time.Minute).Unix()
	writeDecoratedBoundUser(t, write, "controller.creds", controller, cellKey, controllerUserKey)
	if _, err := check.CurrentCredentialBound(expected, peerCredentialManifest, nil, ""); !errors.Is(err, ErrLiveCredentials) {
		t.Fatalf("expired but digest-pinned user JWT produced a current bound: %v", err)
	}
}

func writeDecoratedBoundUser(t *testing.T, write func(string, []byte), name string,
	claim *jwt.UserClaims, signer, user nkeys.KeyPair,
) {
	t.Helper()
	raw, err := claim.Encode(signer)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := user.Seed()
	if err != nil {
		t.Fatal(err)
	}
	seed = bytes.Clone(seed)
	defer clear(seed)
	wire, err := jwt.FormatUserConfig(raw, seed)
	if err != nil {
		t.Fatal(err)
	}
	write(name, wire)
	clear(wire)
}

func boundTestCertificate(t *testing.T, now, expiry time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:   pkix.Name{CommonName: "continuity cutoff test"},
		NotBefore: now.Add(-time.Hour), NotAfter: expiry,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
