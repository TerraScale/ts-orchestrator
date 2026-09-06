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
	"github.com/nats-io/nkeys"
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
	return declaration(t, bindings, artifact, release, false, false)
}
func ControlDeclaration(t testing.TB, bindings []vmengineconfig.Binding, artifact, release string) (vmengineconfig.Declaration, string) {
	t.Helper()
	return declaration(t, bindings, artifact, release, true, false)
}
func DatabaseDeclaration(t testing.TB, bindings []vmengineconfig.Binding, artifact, release string) (vmengineconfig.Declaration, string) {
	t.Helper()
	return declaration(t, bindings, artifact, release, true, true)
}
func declaration(t testing.TB, bindings []vmengineconfig.Binding, artifact, release string, control, database bool) (vmengineconfig.Declaration, string) {
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
		Databases: []vmengineconfig.Database{{Tenant: fmt.Sprintf("%026d", 200), Project: fmt.Sprintf("%026d", 201), Database: fmt.Sprintf("%026d", 202), Region: bindings[0].Region, SelectedRegions: []string{bindings[0].Region}, EncryptionKey: fmt.Sprintf("%026d", 203), MaxStorageBytes: 1 << 20, MaxDocuments: 100, MaxInflight: 8}},
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
		observerIdentity := "spiffe://terrascale.tech/qualification/engine-observer/" + binding.NodeID
		observerURI, err := url.Parse(observerIdentity)
		if err != nil {
			t.Fatal(err)
		}
		observerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		observerLeaf := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 100)), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), URIs: []*url.URL{observerURI}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		observerDER, err := x509.CreateCertificate(rand.Reader, observerLeaf, ca, &observerKey.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		observerPrivate, err := x509.MarshalPKCS8PrivateKey(observerKey)
		if err != nil {
			t.Fatal(err)
		}
		host := vmengineconfig.Host{ObserverIdentity: observerIdentity, ObserverDatabase: d.Databases[0].Database, ObserverCertificateFile: write(fmt.Sprintf("%d-observer.crt", i), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: observerDER})), ObserverPrivateKeyFile: write(fmt.Sprintf("%d-observer.key", i), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: observerPrivate})), NodeID: binding.NodeID, Member: member, CertificateFile: write(fmt.Sprintf("%d.crt", i), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), PrivateKeyFile: write(fmt.Sprintf("%d.key", i), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), CAFile: caFile}
		if control {
			issue := func(suffix, identity string, serial int64) (string, string) {
				t.Helper()
				clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				clientURI, err := url.Parse(identity)
				if err != nil {
					t.Fatal(err)
				}
				cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), URIs: []*url.URL{clientURI}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
				raw, err := x509.CreateCertificate(rand.Reader, cert, ca, &clientKey.PublicKey, key)
				if err != nil {
					t.Fatal(err)
				}
				secret, err := x509.MarshalPKCS8PrivateKey(clientKey)
				if err != nil {
					t.Fatal(err)
				}
				return write(fmt.Sprintf("%d-%s.crt", i, suffix), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})), write(fmt.Sprintf("%d-%s.key", i, suffix), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: secret}))
			}
			identity := "spiffe://terrascale.tech/qualification/orchestrator-control/" + binding.NodeID
			certificate, private := issue("control", identity, int64(300+i))
			natsCertificate, natsPrivate := issue("nats-control", "spiffe://terrascale.tech/qualification/nats-placement/"+binding.NodeID, int64(600+i))
			pair, err := nkeys.CreateUser()
			if err != nil {
				t.Fatal(err)
			}
			seed, err := pair.Seed()
			if err != nil {
				t.Fatal(err)
			}
			nkey := write(fmt.Sprintf("%d-placement.nkey", i), seed)
			clear(seed)
			pair.Wipe()
			host.OrchestratorPrincipals = []string{identity}
			host.EngineControl = &vmengineconfig.EngineControlCredentials{Identity: identity, CertificateFile: certificate, PrivateKeyFile: private, NATSURL: "tls://" + bindings[0].Address + ":4222", NATSAccount: "$G", NKeyFile: nkey, NATSCertificateFile: natsCertificate, NATSPrivateKeyFile: natsPrivate, NATSCAFile: caFile}
			if database {
				dbCert, dbKey := issue("nats-database", "spiffe://terrascale.tech/qualification/nats-database/"+binding.NodeID, int64(900+i))
				newSeed := func(suffix string) string {
					pair, err := nkeys.CreateUser()
					if err != nil {
						t.Fatal(err)
					}
					defer pair.Wipe()
					seed, err := pair.Seed()
					if err != nil {
						t.Fatal(err)
					}
					defer clear(seed)
					return write(fmt.Sprintf("%d-%s.nkey", i, suffix), seed)
				}
				host.DatabaseHost = &vmengineconfig.DatabaseHostCredentials{DataRoot: "/var/lib/terrascale/terrabase/member", NATSURL: host.EngineControl.NATSURL, NATSAccount: "$G", NKeyFile: newSeed("database"), LifecycleNKeyFile: newSeed("lifecycle"), CertificateFile: dbCert, PrivateKeyFile: dbKey, CAFile: caFile, CatalogPath: "/var/lib/terrascale/orchestrator/keys/catalog.json", EngineSocket: "/run/terrascale-database/engine.sock", IngressSocket: "/var/lib/terrascale/orchestrator/database/ingress.sock", IngressUID: 62013}
			}

		}
		d.Hosts = append(d.Hosts, host)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return d, write("declaration.json", raw)
}
