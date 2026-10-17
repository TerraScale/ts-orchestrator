package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/roleidentity"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func TestHostAndRoleIssuersReadCurrentNativeAccount(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	auth := newAuthenticatedNATS(t, "gru")
	responsePublic, responseKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(responseKey)
	bundle, material, _ := testHostEnrollmentTLSMaterial(t, responsePublic)
	hostPublic, err := material.NATSKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	roleSigner, err := roleidentity.Signer(material.NATSKey)
	if err != nil {
		t.Fatal(err)
	}
	rolePublic, err := roleSigner.PublicKey()
	roleSigner.Wipe()
	if err != nil {
		t.Fatal(err)
	}
	operator, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	defer operator.Wipe()
	operatorPublic, err := operator.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	systemWire, err := os.ReadFile(auth.systemFile)
	if err != nil {
		t.Fatal(err)
	}
	system, err := jwt.DecodeAccountClaims(string(systemWire))
	if err != nil {
		t.Fatal(err)
	}
	operatorClaim := jwt.NewOperatorClaims(operatorPublic)
	operatorClaim.SystemAccount = system.Subject
	operatorJWT, err := operatorClaim.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	systemJWT, err := system.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := jwt.DecodeAccountClaims(auth.cellJWT)
	if err != nil {
		t.Fatal(err)
	}
	claim.SigningKeys.AddScopedSigner(bootstrapmaterial.HostScope("gru", hostPublic))
	claim.SigningKeys.AddScopedSigner(roleidentity.Scope(rolePublic))
	auth.cellJWT, err = claim.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	for path, raw := range map[string]string{auth.operatorFile: operatorJWT, auth.systemFile: systemJWT, auth.cellFile: auth.cellJWT} {
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ca, err := os.ReadFile(auth.tls.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auth.tls.CAFile, append(bytes.Clone(ca), []byte(bundle.CAPEM)...), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{NATS: auth.config(t, natscell.Config{Cell: "gru", Embedded: &natscell.Embedded{}})}
	write := func(name string, wire []byte) string {
		t.Helper()
		path := filepath.Join(auth.root, name)
		if err := os.WriteFile(path, wire, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	seed, err := material.NATSKey.Seed()
	if err != nil {
		t.Fatal(err)
	}
	seed = bytes.Clone(seed)
	cfg.Controller.HostNATSIssuerSeedFile = write("host-issuer.seed", seed)
	clear(seed)
	tlsKey, ok := material.TLSKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("host fixture TLS issuer is not an EC key")
	}
	keyDER, err := x509.MarshalECPrivateKey(tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cfg.Controller.HostTLSIssuerKeyFile = write("host-issuer.key", keyPEM)
	clear(keyDER)
	clear(keyPEM)
	cfg.Controller.HostTLSIssuerCertFile = write("host-issuer.pem", material.TLSCertPEM)
	root, err := auth.start(t, ctx, cfg.NATS)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := auth.start(t, ctx, natscell.Config{Cell: "gru", URL: root.URL()})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := loadHostIssuer(ctx, cfg, fixtureBrokerNative{root})
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.NATSKey.Wipe()
	if issuer.CellAccount != auth.cellID {
		t.Fatal("host issuer lost the native regional account")
	}
	if _, err := loadHostIssuer(ctx, cfg, fixtureBrokerNative{transport}); err == nil {
		t.Fatal("a transport-only runtime provided host issuer account state")
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	userPublic, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, new(x509.CertificateRequest), clientKey)
	if err != nil {
		t.Fatal(err)
	}
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	issue := roleIdentityIssuer(issuer, transport, fixtureBrokerNative{root}, 1)
	raw, chain, err := issue(ctx, "terrabase", "gru-1-db-1", userPublic, csr)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := jwt.DecodeUserClaims(raw)
	if err != nil || issued.Subject != userPublic || issued.IssuerAccount != auth.cellID || issued.Issuer != rolePublic || len(chain) == 0 {
		t.Fatal("role issuance lost the native account or role/TLS identity", err)
	}
	if _, err := transport.JetStream().KeyValue(ctx, "terrabase_backup_leases"); err != nil {
		t.Fatal("role bucket was not created through the ordinary transport", err)
	}
	if _, _, err := roleIdentityIssuer(issuer, transport, fixtureBrokerNative{transport}, 1)(ctx, "terrabase", "gru-1-db-1", userPublic, csr); err == nil {
		t.Fatal("a transport-only runtime provided role issuer account state")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := loadHostIssuer(canceled, cfg, fixtureBrokerNative{root}); !errors.Is(err, context.Canceled) {
		t.Fatal("host issuer ignored cancellation", err)
	}
	if _, _, err := issue(canceled, "terrabase", "gru-1-db-1", userPublic, csr); !errors.Is(err, context.Canceled) {
		t.Fatal("role issuer ignored cancellation", err)
	}
	// The resolver accepts only claims issued after its current second.
	for time.Now().Unix() <= claim.IssuedAt {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	claim.SigningKeys = jwt.SigningKeys{}
	revoked, err := claim.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.ApplyCellClaim(ctx, 2, revoked); err != nil {
		t.Fatal(err)
	}
	if _, err := loadHostIssuer(ctx, cfg, fixtureBrokerNative{root}); err == nil {
		t.Fatal("host issuer reused a revoked native host signer")
	}
	if raw, chain, err := issue(ctx, "terrabase", "gru-1-db-1", userPublic, csr); err == nil || raw != "" || chain != nil {
		t.Fatal("role issuer reused a revoked native role signer", err)
	}
}
