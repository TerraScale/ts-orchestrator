package bootstrapmaterial

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{Environment: "production", Region: "sa-saopaulo-1", Cell: "gru",
		DeploymentID: "alpha-20260927", ClusterID: "alpha-gru", SubnetCIDR: "10.251.0.0/24",
		Slots:         []Slot{{"controller-a", "10.251.0.10"}, {"controller-b", "10.251.0.11"}, {"controller-c", "10.251.0.12"}},
		ValidityHours: 48}
}

func TestMaterialConfigUsesMappedCellRegion(t *testing.T) {
	for _, test := range []struct{ cell, region string }{
		{"gru", "sa-saopaulo-1"}, {"sfo", "us-sanjose-1"}, {"fra", "eu-frankfurt-1"},
	} {
		t.Run(test.cell, func(t *testing.T) {
			cfg := testConfig()
			cfg.Cell, cfg.Region = test.cell, test.region
			if err := cfg.Validate(); err != nil {
				t.Fatalf("mapped material rejected: %v", err)
			}
			directory := filepath.Join(t.TempDir(), "material")
			record, err := Generate(directory, cfg, time.Now().UTC().Truncate(time.Second))
			if err != nil || ValidateLive(directory, record) != nil {
				t.Fatalf("mapped material did not survive live validation: %v", err)
			}
			cfg.Region = "sa-saopaulo-1"
			if test.cell != "gru" && cfg.Validate() == nil {
				t.Fatal("cell with another OCI region accepted")
			}
		})
	}
	for _, cell := range []string{"GRU", "unknown", "sfo-extra"} {
		cfg := testConfig()
		cfg.Cell = cell
		if cfg.Validate() == nil {
			t.Fatalf("unsupported or noncanonical material cell accepted: %s", cell)
		}
	}
}

func TestGenerateStableAndProductionValid(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "material")
	now := time.Now().UTC().Truncate(time.Second)
	first, err := Generate(directory, testConfig(), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateLive(directory, first); err != nil {
		t.Fatal(err)
	}
	second, err := Generate(directory, testConfig(), now.Add(time.Minute))
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("rerun changed material: %v", err)
	}
	if len(first.Files) != 32 || first.Public.PeerSignerPublicKey == first.Public.LedgerSignerPublicKey {
		t.Fatal("incomplete or reused signing identities")
	}
	for _, name := range expectedNames() {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s is not owner-only: %v", name, err)
		}
	}
}

func TestHostIssuerConstraintsAndOfflineOperatorFiles(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "material")
	now := time.Now().UTC().Truncate(time.Second)
	record, err := Generate(directory, testConfig(), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"operator.creds", "operator-tls-cert.pem", "operator-tls-key.pem"} {
		file := findRecordFile(record, name)
		if file.Purpose != "owner-only" || file.Slot != "" {
			t.Fatalf("%s is not excluded from controller publication", name)
		}
	}
	parseCertificate := func(name string) *x509.Certificate {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		block, rest := pem.Decode(body)
		if block == nil || len(rest) != 0 {
			t.Fatalf("%s has invalid PEM", name)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	root := parseCertificate("ca.pem")
	issuer := parseCertificate("host-tls-issuer-cert.pem")
	keyWire, err := os.ReadFile(filepath.Join(directory, "host-tls-issuer-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, rest := pem.Decode(keyWire)
	clear(keyWire)
	if keyBlock == nil || len(rest) != 0 {
		t.Fatal("invalid host issuer key PEM")
	}
	issuerKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(issuer)
	makeLeaf := func(dnsName, uriHost string) *x509.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		uri := &url.URL{Scheme: "spiffe", Host: uriHost, Path: "/instances/ocid1.instance.oc1.sa-saopaulo-1.test"}
		template := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "host"},
			NotBefore: now, NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, DNSNames: []string{dnsName}, URIs: []*url.URL{uri}}
		der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return leaf
	}
	verify := func(cert *x509.Certificate) error {
		_, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		return err
	}
	if err := verify(makeLeaf("node-a.hosts.gru.terrascale.internal", "hosts.gru.terrascale.internal")); err != nil {
		t.Fatalf("valid host leaf rejected: %v", err)
	}
	if err := verify(makeLeaf("node-a.hosts.other.terrascale.internal", "hosts.gru.terrascale.internal")); err == nil {
		t.Fatal("foreign host DNS SAN passed intermediate constraint")
	}
	if err := verify(makeLeaf("node-a.hosts.gru.terrascale.internal", "hosts.other.terrascale.internal")); err == nil {
		t.Fatal("foreign host URI SAN passed intermediate constraint")
	}
}

func findRecordFile(record Record, name string) File {
	for _, file := range record.Files {
		if file.Name == name {
			return file
		}
	}
	return File{}
}

func TestGenerateSharesControllerResponseKey(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "material")
	record, err := Generate(directory, testConfig(), time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	public, err := base64.StdEncoding.Strict().DecodeString(record.Public.ControllerResponsePublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		t.Fatal("invalid exported controller response public key")
	}
	var firstWire []byte
	for _, slot := range record.Config.Slots {
		wire, err := os.ReadFile(filepath.Join(directory, slot.Name+"-response.key"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(string(wire), "\n") {
			t.Fatalf("%s response key lacks a trailing newline", slot.Name)
		}
		private, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSuffix(string(wire), "\n"))
		if err != nil || len(private) != ed25519.PrivateKeySize {
			t.Fatalf("%s response key is invalid: %v", slot.Name, err)
		}
		message := []byte("reply from " + slot.Name)
		if !ed25519.Verify(public, message, ed25519.Sign(private, message)) {
			t.Fatalf("%s signature does not verify with the exported key", slot.Name)
		}
		if firstWire == nil {
			firstWire = wire
		} else if !bytes.Equal(firstWire, wire) {
			t.Fatalf("%s response key differs from the regional key", slot.Name)
		}
		clear(private)
	}
	record.Public.ControllerResponsePublicKey = ""
	if err := ValidateLive(directory, record); err == nil {
		t.Fatal("response keys accepted without their registered public key")
	}
}

func TestGenerateHoldsIncompleteAndTamperedSource(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "material")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(directory, testConfig(), time.Now()); err == nil {
		t.Fatal("incomplete directory was regenerated")
	}
	if err := os.Remove(directory); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(directory, testConfig(), time.Now()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "ticket.key")
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(directory); err == nil {
		t.Fatal("tampered source loaded")
	}
	if _, err := Generate(directory, testConfig(), time.Now()); err == nil {
		t.Fatal("tampered source was regenerated")
	}
}

func TestLoadRejectsWorldReadableOrLinkedMaterial(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "material")
	if _, err := Generate(directory, testConfig(), time.Now()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "ticket.key")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(directory); err == nil {
		t.Fatal("world-readable private key loaded")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(t.TempDir(), "linked-key")
	if err := os.Link(path, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(directory); err == nil {
		t.Fatal("hard-linked private key loaded")
	}
}
