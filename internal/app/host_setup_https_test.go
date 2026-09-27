package app

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/nats-io/nkeys"
)

func testHostEnrollmentTLSMaterial(t *testing.T, controllerPublic ed25519.PublicKey) (
	hostenroll.PublicBundle, *hostenroll.Issuer, tls.Certificate,
) {
	t.Helper()
	now := time.Now().UTC()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:   pkix.Name{CommonName: "host enrollment test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(96 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject:   pkix.Name{CommonName: "host enrollment test client issuer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(23 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, root, &issuerKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issuerCert, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(3),
		Subject:   pkix.Name{CommonName: "host enrollment test server"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(23 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("10.251.0.11")},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, root, &serverKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	serverCertificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER}))
	if err != nil {
		t.Fatal(err)
	}
	account, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(account.Wipe)
	accountPublic, err := account.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	bundle := hostenroll.PublicBundle{SchemaVersion: 1, Cell: "gru", Region: "GRU",
		ControllerEndpoints: []string{"10.251.0.11:8443", "10.251.0.12:8443", "10.251.0.13:8443"},
		NATSURLs:            []string{"tls://10.251.0.11:4222", "tls://10.251.0.12:4222", "tls://10.251.0.13:4222"},
		CAPEM:               string(rootPEM), ControllerResponsePublicKey: base64.StdEncoding.EncodeToString(controllerPublic),
		CellAccountNKey: accountPublic, Environment: "production",
		InstallRoot: filepath.Join(base, "install"), StateRoot: filepath.Join(base, "state"),
		ManagedRuntimeRoot: filepath.Join(base, "managed"), WorkloadUID: 2000, WorkloadGID: 2000}
	if err := bundle.Validate(); err != nil {
		t.Fatal(err)
	}
	issuer := &hostenroll.Issuer{CellAccount: accountPublic, Cell: "gru", NATSKey: account,
		TLSKey: issuerKey, TLSCert: issuerCert,
		TLSCertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER}), Root: root}
	return bundle, issuer, serverCertificate
}
