package testengineconfig

// This file is deliberately independent of testing.TB. It prepares the
// private material used by the stopped Firecracker qualification guests.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

// PrivateFixture is a complete, private qualification declaration and its
// locally generated credential root. The root contains test secrets and must
// only be handed to the isolated qualification run.
type PrivateFixture struct {
	Root            string
	DeclarationPath string
	Declaration     vmengineconfig.Declaration
	Bindings        []vmengineconfig.Binding
}

// Prepare creates the six guest declaration required by the production
// loader: two members each in GRU, SFO, and FRA. artifact and release are the
// exact TerraBase artifact identity that the run will load.
func Prepare(artifact, release string) (PrivateFixture, error) {
	return prepareAt("", artifact, release)
}

// PrepareAt is the CLI-facing variant. parent must be an existing private
// directory; a uniquely named child is created below it.
func PrepareAt(parent, artifact, release string) (PrivateFixture, error) {
	return prepareAt(parent, artifact, release)
}

func prepareAt(parent, artifact, release string) (PrivateFixture, error) {
	bindings := []vmengineconfig.Binding{
		{NodeID: "gru-member-1", Region: "GRU", Address: "10.77.0.10"}, {NodeID: "gru-member-2", Region: "GRU", Address: "10.77.0.11"},
		{NodeID: "sfo-member-1", Region: "SFO", Address: "10.77.1.10"}, {NodeID: "sfo-member-2", Region: "SFO", Address: "10.77.1.11"},
		{NodeID: "fra-member-1", Region: "FRA", Address: "10.77.2.10"}, {NodeID: "fra-member-2", Region: "FRA", Address: "10.77.2.11"},
	}
	root, err := os.MkdirTemp(parent, "terrascale-vm-qualification-")
	if err != nil {
		return PrivateFixture{}, fmt.Errorf("create private fixture root: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		_ = os.RemoveAll(root)
		return PrivateFixture{}, err
	}
	f := PrivateFixture{Root: root, Bindings: bindings}
	removeOnError := true
	defer func() {
		if removeOnError {
			_ = os.RemoveAll(root)
		}
	}()
	write := func(name string, data []byte) (string, error) {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return "", err
		}
		return path, nil
	}
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return PrivateFixture{}, err
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return PrivateFixture{}, err
	}
	caFile, err := write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	if err != nil {
		return PrivateFixture{}, err
	}
	d := vmengineconfig.Declaration{Version: 1, Contract: vmengineconfig.Contract, ArtifactSHA256: artifact, Release: release, Environment: "qualification", Cluster: fmt.Sprintf("%026d", 100), Generation: 1, Epoch: 1,
		Databases: []vmengineconfig.Database{{Tenant: fmt.Sprintf("%026d", 200), Project: fmt.Sprintf("%026d", 201), Database: fmt.Sprintf("%026d", 202), Region: "GRU", AllowedRegions: []string{"GRU", "SFO", "FRA"}, SelectedRegions: []string{"GRU", "SFO", "FRA"}, EncryptionKey: fmt.Sprintf("%026d", 203), MaxStorageBytes: 1 << 20, MaxDocuments: 100, MaxInflight: 8}},
		Limits:    vmengineconfig.Limits{MaxMessageBytes: 1 << 20, MaxInflight: 32, RequestTimeoutMillis: 5000, TLSHandshakeTimeoutMillis: 5000, ShutdownGraceMillis: 5000}}
	issue := func(name, identity string, serial int64, usages []x509.ExtKeyUsage, address net.IP) (string, string, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", "", err
		}
		u, err := url.Parse(identity)
		if err != nil {
			return "", "", err
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), URIs: []*url.URL{u}, IPAddresses: []net.IP{address}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
		if address == nil {
			cert.IPAddresses = nil
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
		if err != nil {
			return "", "", err
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return "", "", err
		}
		certPath, err := write(name+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		if err != nil {
			return "", "", err
		}
		keyPath, err := write(name+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
		return certPath, keyPath, err
	}
	seed := func(name string) (string, error) {
		pair, err := nkeys.CreateUser()
		if err != nil {
			return "", err
		}
		defer pair.Wipe()
		raw, err := pair.Seed()
		if err != nil {
			return "", err
		}
		defer clear(raw)
		return write(name+".nkey", raw)
	}
	for i, b := range bindings {
		gateway, err := regionGateway(b.Region)
		if err != nil {
			return PrivateFixture{}, err
		}
		member := fmt.Sprintf("%026d", i+1)
		memberID := "spiffe://terrascale.tech/qualification/terrabase-member/" + d.Cluster + "/" + member
		memberCert, memberKey, err := issue(fmt.Sprintf("%d-member", i), memberID, int64(i+2), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, net.ParseIP(b.Address))
		if err != nil {
			return PrivateFixture{}, err
		}
		observerID := "spiffe://terrascale.tech/qualification/engine-observer/" + b.NodeID
		observerCert, observerKey, err := issue(fmt.Sprintf("%d-observer", i), observerID, int64(i+100), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
		if err != nil {
			return PrivateFixture{}, err
		}
		controlID := "spiffe://terrascale.tech/qualification/orchestrator-control/" + b.NodeID
		controlCert, controlKey, err := issue(fmt.Sprintf("%d-control", i), controlID, int64(i+300), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
		if err != nil {
			return PrivateFixture{}, err
		}
		natsCert, natsKey, err := issue(fmt.Sprintf("%d-nats-control", i), "spiffe://terrascale.tech/qualification/nats-placement/"+b.NodeID, int64(i+600), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
		if err != nil {
			return PrivateFixture{}, err
		}
		hostNKey, err := seed(fmt.Sprintf("%d-placement", i))
		if err != nil {
			return PrivateFixture{}, err
		}
		dbCert, dbKey, err := issue(fmt.Sprintf("%d-nats-database", i), "spiffe://terrascale.tech/qualification/nats-database/"+b.NodeID, int64(i+900), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
		if err != nil {
			return PrivateFixture{}, err
		}
		dbNKey, err := seed(fmt.Sprintf("%d-database", i))
		if err != nil {
			return PrivateFixture{}, err
		}
		lifecycleNKey, err := seed(fmt.Sprintf("%d-lifecycle", i))
		if err != nil {
			return PrivateFixture{}, err
		}
		natsURL := "tls://" + gateway + ":4222"
		h := vmengineconfig.Host{NodeID: b.NodeID, Member: member, ObserverIdentity: observerID, ObserverDatabase: d.Databases[0].Database, ObserverCertificateFile: observerCert, ObserverPrivateKeyFile: observerKey, CertificateFile: memberCert, PrivateKeyFile: memberKey, CAFile: caFile, OrchestratorPrincipals: []string{controlID}, EngineControl: &vmengineconfig.EngineControlCredentials{Identity: controlID, CertificateFile: controlCert, PrivateKeyFile: controlKey, NATSURL: natsURL, NATSAccount: "$G", NKeyFile: hostNKey, NATSCertificateFile: natsCert, NATSPrivateKeyFile: natsKey, NATSCAFile: caFile}, DatabaseHost: &vmengineconfig.DatabaseHostCredentials{DataRoot: "/var/lib/terrascale/terrabase/member", NATSURL: natsURL, NATSAccount: "$G", NKeyFile: dbNKey, LifecycleNKeyFile: lifecycleNKey, CertificateFile: dbCert, PrivateKeyFile: dbKey, CAFile: caFile, CatalogPath: "/var/lib/terrascale/orchestrator/keys/catalog.json", EngineSocket: "/run/terrascale-database/engine.sock", IngressSocket: "/var/lib/terrascale/orchestrator/database/ingress.sock", IngressUID: 62013}}
		d.Hosts = append(d.Hosts, h)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return PrivateFixture{}, err
	}
	f.DeclarationPath, err = write("declaration.json", raw)
	if err != nil {
		return PrivateFixture{}, err
	}
	f.Declaration = d
	if _, err := vmengineconfig.Load(f.DeclarationPath, artifact, release, bindings); err != nil {
		return PrivateFixture{}, fmt.Errorf("generated declaration rejected by vmengineconfig.Load: %w", err)
	}
	removeOnError = false
	return f, nil
}

func regionGateway(region string) (string, error) {
	switch region {
	case "GRU", "SFO", "FRA":
		return vmnet.StableGateway(vmnet.RegionCode(region)), nil
	default:
		return "", fmt.Errorf("unsupported qualification region %q", region)
	}
}

// Remove deletes only the private root created by Prepare.
func (f PrivateFixture) Remove() error {
	if f.Root == "" {
		return errors.New("empty fixture root")
	}
	root := filepath.Clean(f.Root)
	if filepath.Dir(root) != filepath.Clean(os.TempDir()) || len(filepath.Base(root)) <= len("terrascale-vm-qualification-") || filepath.Base(root)[:len("terrascale-vm-qualification-")] != "terrascale-vm-qualification-" {
		return errors.New("refusing to remove an unowned fixture root")
	}
	return os.RemoveAll(root)
}
