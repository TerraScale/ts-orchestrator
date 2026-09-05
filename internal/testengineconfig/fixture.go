// Package testengineconfig supplies isolated identities only to tests.
package testengineconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"
)

func Declaration(t testing.TB, bindings []vmengineconfig.Binding, artifact, release string) (vmengineconfig.Declaration, string) {
	t.Helper()
	root := t.TempDir()
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caFile := write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	d := vmengineconfig.Declaration{Version: 1, Contract: vmengineconfig.Contract, ArtifactSHA256: artifact, Release: release, Environment: "qualification", Cluster: fmt.Sprintf("%026d", 100), Generation: 1, Epoch: 1,
		Databases: []vmengineconfig.Database{{Tenant: fmt.Sprintf("%026d", 200), Project: fmt.Sprintf("%026d", 201), Database: fmt.Sprintf("%026d", 202), Region: bindings[0].Region, EncryptionKey: fmt.Sprintf("%026d", 203), MaxStorageBytes: 1 << 20, MaxDocuments: 100, MaxInflight: 8}},
		Limits:    vmengineconfig.Limits{MaxMessageBytes: 1 << 20, MaxInflight: 32, RequestTimeoutMillis: 5000, TLSHandshakeTimeoutMillis: 5000, ShutdownGraceMillis: 5000},
	}
	seen := map[string]bool{}
	for _, binding := range bindings {
		if !seen[binding.Region] {
			d.Databases[0].AllowedRegions = append(d.Databases[0].AllowedRegions, binding.Region)
			seen[binding.Region] = true
		}
	}
	for i, binding := range bindings {
		member := fmt.Sprintf("%026d", i+1)
		uri, err := url.Parse("spiffe://terrascale.tech/qualification/terrabase-member/" + d.Cluster + "/" + member)
		if err != nil {
			t.Fatal(err)
		}
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), URIs: []*url.URL{uri}, IPAddresses: []net.IP{net.ParseIP(binding.Address)}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalPKCS8PrivateKey(leafKey)
		if err != nil {
			t.Fatal(err)
		}
		d.Hosts = append(d.Hosts, vmengineconfig.Host{NodeID: binding.NodeID, Member: member, CertificateFile: write(fmt.Sprintf("%d.crt", i), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), PrivateKeyFile: write(fmt.Sprintf("%d.key", i), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), CAFile: caFile})
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return d, write("declaration.json", raw)
}
