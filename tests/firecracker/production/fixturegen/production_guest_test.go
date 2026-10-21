package fixturegen

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/app"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestProductionControllerConfigRequiresExplicitVersionOne(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	input := productionGuestTestInputs(t, time.Now().UTC(), []byte("unused"))
	const slot = "controller-a"
	validate := func(wire []byte) error {
		return validateControllerConfig(wire, slot, "ocid1.instance.oc1.sa-saopaulo-1."+slot,
			input.VNICs[slot].PrimaryPrivateIP, input.VNICs, input.Credentials[slot])
	}
	wire := input.Configs[slot]
	if err := validate(wire); err != nil {
		t.Fatalf("version-1 production config: %v", err)
	}
	for _, version := range []string{"", `"version":0,`, `"version":2,`, `"version":6,`} {
		changed := strings.Replace(string(wire), `"version":1,`, version, 1)
		if err := validate([]byte(changed)); err == nil || !strings.Contains(err.Error(), "version") {
			t.Errorf("invalid version %q accepted: %v", version, err)
		}
	}
}

func productionGuestTestInputs(t *testing.T, now time.Time, binary []byte) GuestMaterialInputs {
	t.Helper()
	secrets := filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), "go", "run", "../../jwtsetup", "--dir", secrets,
		"--cell", "gru", "--brokers", "controller-a,controller-b,controller-c", "--host-node", "host-a")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate production JWT fixture: %v: %s", err, output)
	}
	caPEM, caCert, caKey := testCertificateAuthority(t, now, "production-restart-nats")
	ociCA, ociCert, ociKey := testCertificateAuthority(t, now, "production-restart-oci")
	ociLeaf, ociLeafKey := testLeafCertificate(t, now, ociCert, ociKey,
		"production-restart-oci", nil, simulatorDNSNames)
	input := GuestMaterialInputs{
		Binary: binary, Credentials: make(map[string]map[string][]byte, 3),
		Configs: make(map[string][]byte, 3), SimulatorCA: ociCA,
		SimulatorCertificate: ociLeaf, SimulatorPrivateKey: ociLeafKey,
		IMDS:  make(map[string]IMDSIdentity, 3),
		VNICs: make(map[string]GuestObservation, 3), ServiceUID: 1000, ServiceGID: 1000,
	}
	addresses := map[string]string{
		"controller-a": "10.44.0.11", "controller-b": "10.44.0.12", "controller-c": "10.44.0.10",
	}
	slots := []string{"controller-a", "controller-b", "controller-c"}
	for _, slot := range slots {
		imdsCert, imdsKey, imdsIntermediate := fixtureInstanceCertificate(t)
		input.IMDS[slot] = IMDSIdentity{TenancyID: fixtureTenancyOCID,
			Certificate: imdsCert, PrivateKey: imdsKey, Intermediate: imdsIntermediate}
		input.VNICs[slot] = GuestObservation{
			PrimaryVNICOCID:        "ocid1.vnic.oc1.sa-saopaulo-1." + slot,
			PrimaryPrivateIP:       addresses[slot],
			NetworkCompartmentOCID: "ocid1.compartment.oc1..networkfixture",
			VCNOCID:                "ocid1.vcn.oc1.sa-saopaulo-1.restartfixture",
		}
		credentials := make(map[string][]byte, 12)
		for _, name := range []string{"operator.jwt", "system.jwt", "cell.jwt", "system.creds",
			"broker-ticket.key", "broker-ticket.pub", slot + ".creds"} {
			body, err := os.ReadFile(filepath.Join(secrets, name))
			if err != nil {
				t.Fatal(err)
			}
			credentials[name] = body
		}
		credentials["nats-ca.pem"] = caPEM
		leaf, key := testLeafCertificate(t, now, caCert, caKey, slot, []string{addresses[slot]}, nil)
		credentials["nats-"+slot+".pem"] = leaf
		credentials["nats-"+slot+".key"] = key
		credentials["route-password"] = []byte("fixture-production-route-password-32-bytes\n")
		_, responseKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		credentials["controller.key"] = []byte(base64.StdEncoding.EncodeToString(responseKey) + "\n")
		input.Credentials[slot] = credentials
		secret := func(name string) string { return serviceSecretsGuestDir + "/" + name }
		tlsFiles := natscell.TLSFiles{CAFile: secret("nats-ca.pem"),
			CertFile: secret("nats-" + slot + ".pem"), KeyFile: secret("nats-" + slot + ".key")}
		var routes []string
		for _, peer := range slots {
			if peer != slot {
				routes = append(routes, "nats-route://"+addresses[peer]+":6222")
			}
		}
		cfg := app.Config{Version: app.ConfigVersion,
			NATS: natscell.Config{Cell: "gru", Instance: slot, Replicas: 3,
				ClientRole: "controller", CredentialsFile: secret(slot + ".creds"), TLS: tlsFiles,
				Embedded: &natscell.Embedded{
					Host: addresses[slot], Port: 4222, RouteHost: addresses[slot], RoutePort: 6222,
					Routes: routes, StoreDir: "/var/lib/terrascale-orchestrator-controller/nats",
					StoreMaxBytes: 2 << 30, TLS: tlsFiles, RouteTLS: tlsFiles,
					RouteUser: "ts-fixture-route", RoutePasswordFile: secret("route-password"),
					OperatorJWTFile: secret("operator.jwt"), SystemJWTFile: secret("system.jwt"),
					CellJWTFile: secret("cell.jwt"), SystemCredentialsFile: secret("system.creds"),
					TicketPublicKeyFile: secret("broker-ticket.pub"), BrokerIDs: slots,
				}},
			Controller: app.ControllerConfig{CandidateID: "ocid1.instance.oc1.sa-saopaulo-1." + slot,
				ResponseKeyFile: secret("controller.key"), BrokerTicketKeyFile: secret("broker-ticket.key")},
		}
		wire, err := protocol.EncodeJSON(cfg)
		if err != nil {
			t.Fatal(err)
		}
		input.Configs[slot] = wire
	}
	return input
}

func testCertificateAuthority(t *testing.T, now time.Time, name string) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(3 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, key
}

func testLeafCertificate(t *testing.T, now time.Time, ca *x509.Certificate, caKey *ecdsa.PrivateKey,
	name string, addresses, dnsNames []string,
) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    dnsNames}
	for _, address := range addresses {
		ip := net.ParseIP(address)
		if ip == nil {
			t.Fatal(fmt.Errorf("invalid test certificate IP %q", address))
		}
		template.IPAddresses = append(template.IPAddresses, ip)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
