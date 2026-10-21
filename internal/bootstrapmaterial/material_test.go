package bootstrapmaterial

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func testConfig() Config {
	return Config{Environment: "production", Region: "sa-saopaulo-1", Cell: "gru",
		DeploymentID: "0000000000XXVM2FA4QBBHZBKD", ClusterID: "00000000000C2KQX35BT9P1FFG", SubnetCIDR: "10.251.0.0/24",
		Slots:         []Slot{{"controller-a", "10.251.0.10"}, {"controller-b", "10.251.0.11"}, {"controller-c", "10.251.0.12"}},
		ValidityHours: 48}
}

func TestMaterialValidityAllowsOneYear(t *testing.T) {
	cfg := testConfig()
	cfg.ValidityHours = 365 * 24
	if err := cfg.Validate(); err != nil {
		t.Fatalf("one-year material rejected: %v", err)
	}
	cfg.ValidityHours++
	if cfg.Validate() == nil {
		t.Fatal("material longer than one year accepted")
	}
}

func TestMaterialConfigUsesMappedCellRegion(t *testing.T) {
	for _, test := range []struct{ cell, region string }{
		{"gru", "sa-saopaulo-1"}, {"sjc", "us-sanjose-1"}, {"fra", "eu-frankfurt-1"},
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
	for _, cell := range []string{"GRU", "unknown", "sjc-extra"} {
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
	if len(first.Files) != 37 || first.Public.PeerSignerPublicKey == first.Public.LedgerSignerPublicKey {
		t.Fatal("incomplete or reused signing identities")
	}
	for _, name := range expectedNames() {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s is not owner-only: %v", name, err)
		}
	}
	t.Run("prospective attestor data format only", func(t *testing.T) {
		cfg := testConfig()
		authorization := testAdmissionAuthorization(t, cfg)
		path := filepath.Join(t.TempDir(), "candidate")
		record, err := GenerateAdmissionCandidate(path, cfg, authorization, now)
		if err != nil || len(record.Files) != len(first.Files)+3 || !dedicatedAdmissionKey(record.Public) || ValidateLive(path, record) != nil {
			t.Fatalf("dedicated candidate format: %v", err)
		}
		metadata, err := os.ReadFile(filepath.Join(path, metadataName))
		if err != nil {
			t.Fatal(err)
		}
		for _, slot := range cfg.Slots {
			if !slices.ContainsFunc(record.Files, func(file File) bool {
				return file.Name == slot.Name+"-admission.key" && file.Purpose == bootstrap.SecretController && file.Slot == slot.Name
			}) {
				t.Fatalf("missing exact dedicated private slot %s", slot.Name)
			}
		}
		replayed, err := GenerateAdmissionCandidate(path, cfg, authorization, now.Add(time.Minute))
		actual, readErr := os.ReadFile(filepath.Join(path, metadataName))
		if err != nil || readErr != nil || !reflect.DeepEqual(record, replayed) || !bytes.Equal(actual, metadata) {
			t.Fatalf("candidate replay changed original bytes: %v %v", err, readErr)
		}
		changed := authorization
		changed.SourceRegistrationSHA256 = strings.Repeat("b", 64)
		if _, err := GenerateAdmissionCandidate(path, cfg, changed, now); err == nil {
			t.Fatal("different authorization adopted the original candidate")
		}
		noncanonical := record
		noncanonical.Public.AdmissionAttestor.PublicKey = record.Public.LedgerSignerPublicKey[:8] + "\n" + record.Public.LedgerSignerPublicKey[8:]
		if noncanonical.Public.AdmissionAttestor.Validate() == nil || dedicatedAdmissionKey(noncanonical.Public) || ValidateAdmissionInventory(noncanonical) == nil {
			t.Fatal("noncanonical reused ledger key passed public-only inventory checks")
		}
		reused := record.Public
		reused.AdmissionAttestor.PublicKey = record.Public.LedgerSignerPublicKey
		reused.LedgerSignerPublicKey = record.Public.LedgerSignerPublicKey[:8] + "\r\n" + record.Public.LedgerSignerPublicKey[8:]
		if dedicatedAdmissionKey(reused) {
			t.Fatal("different encodings of the same issuer key defeated separation")
		}
		for name, mutate := range map[string]func(*testing.T, string, *Record){
			"missing public descriptor": func(_ *testing.T, _ string, r *Record) {
				r.Public.AdmissionAttestor = release.AdmissionAttestorMaterial{}
			},
			"partial public descriptor": func(_ *testing.T, _ string, r *Record) { r.Public.AdmissionAttestor.AuthorizationSHA256 = "" },
			"reused public key": func(_ *testing.T, _ string, r *Record) {
				r.Public.AdmissionAttestor.PublicKey = r.Public.LedgerSignerPublicKey
			},
			"missing private file": func(t *testing.T, p string, r *Record) {
				if err := os.Remove(filepath.Join(p, "controller-b-admission.key")); err != nil {
					t.Fatal(err)
				}
				r.Files = slices.DeleteFunc(r.Files, func(file File) bool { return file.Name == "controller-b-admission.key" })
			},
			"wrong private key with matching digest": func(t *testing.T, p string, r *Record) {
				wire, err := os.ReadFile(filepath.Join(p, "controller-a-response.key"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(p, "controller-a-admission.key"), wire, 0o600); err != nil {
					t.Fatal(err)
				}
				for index := range r.Files {
					if r.Files[index].Name == "controller-a-admission.key" {
						r.Files[index].SHA256 = digest(wire)
						r.Files[index].MaxBytes = int64(len(wire))
					}
				}
			},
			"foreign private slot": func(_ *testing.T, _ string, r *Record) {
				for index := range r.Files {
					if r.Files[index].Name == "controller-a-admission.key" {
						r.Files[index].Slot = "controller-b"
					}
				}
			},
		} {
			t.Run(name, func(t *testing.T) {
				copyPath := t.TempDir()
				entries, err := os.ReadDir(path)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					wire, err := os.ReadFile(filepath.Join(path, entry.Name()))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(copyPath, entry.Name()), wire, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				candidate := record
				candidate.Files = slices.Clone(record.Files)
				mutate(t, copyPath, &candidate)
				wire, err := json.Marshal(candidate)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(copyPath, metadataName), wire, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(copyPath, readyName), []byte(digest(wire)+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if _, err := Load(copyPath); err == nil {
					t.Fatal("invalid dedicated material loaded")
				}
			})
		}
	})
}

func testAdmissionAuthorization(t *testing.T, cfg Config) release.AdmissionAttestorAuthorization {
	t.Helper()
	wire, err := json.Marshal(cfg, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return release.AdmissionAttestorAuthorization{Schema: release.AdmissionAttestorAuthorizationSchema, Domain: "terrascale.release.container-admission", Action: "reserve", SourceBinding: "original-source-inventory.v1", TenancyID: "ocid1.tenancy.oc1..test", InstallationID: "0000000000YTR4D9RJ6W8NG1HC", DeploymentID: cfg.DeploymentID, ClusterID: cfg.ClusterID, Cell: strings.ToUpper(cfg.Cell), Environment: cfg.Environment, Generation: 1,
		ControllerSlots: [3]string{"controller-a", "controller-b", "controller-c"}, Roles: [3]string{"function-worker", "terrabase", "ts-auth"}, PlanSHA256: digest(wire), WorkloadGenesisSHA256: strings.Repeat("a", 64), SourceRegistrationSHA256: strings.Repeat("c", 64), SourceNamespace: "ns", SourceBucket: "gru-1-head", SourceObject: "bootstrap/bootstrap/v2/material-source/" + strings.Repeat("d", 64) + ".json"}
}

// Every controller receives the cell's C# TerraBase member CA as host-issuer
// material, written owner-only so terrabase.LoadCA accepts it.
func TestGenerateDistributesTerraBaseMemberCA(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "material")
	now := time.Now().UTC().Truncate(time.Second)
	record, err := Generate(directory, testConfig(), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"terrabase-member-ca.pem", "terrabase-member-ca.key"} {
		if !slices.ContainsFunc(record.Files, func(file File) bool {
			return file.Name == name && file.Purpose == bootstrap.SecretHostIssuer && file.Slot == ""
		}) {
			t.Fatalf("%s is not host-issuer material: %+v", name, record.Files)
		}
	}
	ca, err := terrabase.LoadCA(filepath.Join(directory, "terrabase-member-ca.pem"),
		filepath.Join(directory, "terrabase-member-ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(ca.CertificatePEM())
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || certificate.Subject.CommonName != "TerraBase member CA gru-1" {
		t.Fatalf("member CA is not the gru-1 cell CA: %v %v", certificate.Subject, err)
	}
	peers, err := terrabase.ParsePeers("gru-1-db-1=10.251.0.21:9443")
	if err != nil {
		t.Fatal(err)
	}
	_, csr, err := terrabase.NewMemberKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Issue(csr, peers[0], now); err != nil {
		t.Fatalf("material member CA cannot issue: %v", err)
	}
}

// Controllers use JetStream through the cell account; in operator mode the
// account JWT alone decides whether JetStream is enabled.
func TestGeneratedCellAccountEnablesJetStream(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "material")
	if _, err := Generate(directory, testConfig(), time.Now().UTC().Truncate(time.Second)); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(filepath.Join(directory, "cell.jwt"))
	if err != nil {
		t.Fatal(err)
	}
	claim, err := jwt.DecodeAccountClaims(string(wire))
	if err != nil {
		t.Fatal(err)
	}
	if !claim.Limits.IsJSEnabled() {
		t.Fatalf("generated cell account disables JetStream: %+v", claim.Limits.JetStreamLimits)
	}
}

func TestGeneratedTerminalCredentialGrants(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "material")
	_, err := Generate(directory, testConfig(), time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	readClaim := func(name string) *jwt.UserClaims {
		t.Helper()
		wire, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := nkeys.ParseDecoratedJWT(wire)
		if err != nil {
			t.Fatal(err)
		}
		claim, err := jwt.DecodeUserClaims(raw)
		if err != nil {
			t.Fatal(err)
		}
		return claim
	}
	operator := readClaim("operator.creds")
	if err := natscell.ValidateBrokerOperatorCredentials(filepath.Join(directory, "operator.creds"), "gru"); err != nil {
		t.Fatalf("generated operator JWT rejected: %v", err)
	}
	for _, subject := range []string{"ts.orch.v1.gru.managed-update.prepare", "ts.orch.v1.gru.backup.operation", "ts.orch.v1.gru.terminal.plan", "ts.orch.v1.gru.terminal.apply", "ts.orch.v1.gru.terminal.status"} {
		if !slices.Contains(operator.Pub.Allow, subject) {
			t.Fatalf("generated operator JWT lacks %s", subject)
		}
	}
	if slices.Contains(operator.Pub.Allow, "ts.orch.v1.gru.terminal.>") {
		t.Fatal("generated operator JWT has wildcard terminal publish")
	}
	for _, slot := range testConfig().Slots {
		claim := readClaim(slot.Name + ".creds")
		if err := natscell.ValidateBrokerControllerCredentials(filepath.Join(directory, slot.Name+".creds"), "gru", slot.Name); err != nil {
			t.Fatalf("generated %s JWT rejected: %v", slot.Name, err)
		}
		if !slices.Contains(claim.Sub.Allow, "ts.orch.v1.gru.managed-update.prepare") ||
			!slices.Contains(claim.Sub.Allow, "ts.orch.v1.gru.backup.operation") ||
			!slices.Contains(claim.Sub.Allow, "ts.orch.v1.gru.terminal.>") ||
			slices.Contains(claim.Sub.Allow, "ts.orch.v1.gru.>") {
			t.Fatalf("generated %s JWT has invalid terminal subscription", slot.Name)
		}
	}
}

// Every standalone cell is its own global home and always receives telemetry.
func TestControllerMaterialAlwaysGrantsTelemetryWithBoundGlobalHome(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, cell := range catalog.Entries() {
		t.Run(cell.Name(), func(t *testing.T) {
			cfg := testConfig()
			cfg.Cell, cfg.Region = cell.Name(), cell.OCIRegion
			directory := filepath.Join(t.TempDir(), "material")
			record, err := Generate(directory, cfg, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateLive(directory, record); err != nil {
				t.Fatal(err)
			}
			if again, err := Generate(directory, cfg, now); err != nil || !reflect.DeepEqual(again, record) {
				t.Fatalf("immutable source reuse: %v", err)
			}
			for _, slot := range cfg.Slots {
				path := filepath.Join(directory, slot.Name+".creds")
				if err := natscell.ValidateBrokerControllerCredentials(path, cfg.Cell, slot.Name); err != nil {
					t.Fatal(err)
				}
				wire, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := nkeys.ParseDecoratedJWT(wire)
				if err != nil {
					t.Fatal(err)
				}
				claim, err := jwt.DecodeUserClaims(raw)
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Contains(claim.Sub.Allow, protocol.ObservabilityGrant(cfg.Cell)) {
					t.Fatalf("%s lacks telemetry grants", slot.Name)
				}
				err = natscell.ValidateGlobalControllerPermissions(natscell.Config{Cell: cfg.Cell, CredentialsFile: path})
				if err != nil {
					t.Fatalf("home %s lacks global grants: %v", slot.Name, err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			path := func(name string) string { return filepath.Join(directory, name) }
			tlsFiles := natscell.TLSFiles{CAFile: path("ca.pem"), CertFile: path("controller-a-tls-cert.pem"), KeyFile: path("controller-a-tls-key.pem")}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			brokerConfig := natscell.Config{Cell: cfg.Cell, Instance: "controller-a", Replicas: 1, CredentialsFile: path("controller-a.creds"), TLS: tlsFiles,
				Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: port, StoreDir: filepath.Join(t.TempDir(), "broker"),
					TLS: tlsFiles, RouteTLS: tlsFiles, RouteUser: "integration-route", OperatorJWTFile: path("operator.jwt"),
					SystemJWTFile: path("system.jwt"), CellJWTFile: path("cell.jwt"), SystemCredentialsFile: path("system.creds"),
					TicketPublicKeyFile: path("ticket.pub"), BrokerIDs: []string{"controller-a"}}}
			if err := natscell.ValidateProductionCredentials(brokerConfig); err != nil {
				t.Fatalf("generated controller preflight: %v", err)
			}
			broker, err := natscell.Start(ctx, brokerConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer broker.Close()
			if err := broker.ApplyCellClaim(ctx, 1, broker.InitialCellJWT()); err != nil {
				t.Fatal(err)
			}
			if err := broker.Bridge().OpenUntil(1, broker.InitialCellJWT(), time.Now().Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			certificate, err := tls.LoadX509KeyPair(tlsFiles.CertFile, tlsFiles.KeyFile)
			if err != nil {
				t.Fatal(err)
			}
			ca, err := os.ReadFile(tlsFiles.CAFile)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(ca) {
				t.Fatal("generated CA is invalid")
			}
			client, err := nats.Connect(broker.URL(), nats.UserCredentials(brokerConfig.CredentialsFile),
				nats.SetCustomDialer(&tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: &tls.Config{
					MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate}, ServerName: "controller-a"}}))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			requests, err := broker.Conn().SubscribeSync(protocol.GlobalBudgetSetSubject())
			if err != nil {
				t.Fatal(err)
			}
			defer requests.Unsubscribe()
			if err := broker.Conn().FlushWithContext(ctx); err != nil {
				t.Fatal(err)
			}
			if err := client.Publish(protocol.GlobalBudgetSetSubject(), []byte("budget")); err != nil {
				t.Fatal(err)
			}
			if _, err := requests.NextMsg(time.Second); err != nil {
				t.Fatalf("generated controller cannot publish and receive global budget requests: %v", err)
			}
		})
	}
}

func TestControllerMaterialRejectsRetiredGrantSwitches(t *testing.T) {
	for _, field := range []string{`"globalHome":true`, `"globalHome":false`, `"grantVersion":1`, `"grantVersion":2`} {
		directory := filepath.Join(t.TempDir(), "material")
		if _, err := Generate(directory, testConfig(), time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, metadataName)
		wire, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		changed := bytes.Replace(wire, []byte(`"config":{`), []byte(`"config":{`+field+`,`), 1)
		if bytes.Equal(changed, wire) {
			t.Fatal("fixture config was not changed")
		}
		wire = changed
		if err := os.WriteFile(path, wire, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, readyName), []byte(digest(wire)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(directory); !errors.Is(err, ErrMaterial) {
			t.Fatalf("retired %s accepted: %v", field, err)
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

	t.Run("one-year validity survives immutable source publication", func(t *testing.T) {
		cfg := testConfig()
		cfg.ValidityHours = 365 * 24
		if err := cfg.Validate(); err != nil {
			t.Fatalf("one-year material rejected: %v", err)
		}
		parent := t.TempDir()
		directory := filepath.Join(parent, "material")
		now := time.Now().UTC().Truncate(time.Second)
		if _, err := Generate(directory, cfg, now); err != nil {
			t.Fatalf("one-year material generation: %v", err)
		}
		persisted, err := Load(directory)
		if err != nil {
			t.Fatalf("one-year material readback: %v", err)
		}
		if err := ValidateLive(directory, persisted); err != nil {
			t.Fatalf("one-year material live validation: %v", err)
		}
		deadline := now.Add(365 * 24 * time.Hour)
		if !reflect.DeepEqual(persisted.Config, cfg) || !persisted.IssuedAt.Equal(now) || !persisted.ExpiresAt.Equal(deadline) {
			t.Fatalf("persisted one-year material has different config or validity: %+v", persisted)
		}
		wire, err := os.ReadFile(filepath.Join(directory, "ca.pem"))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(wire)
		if block == nil {
			t.Fatal("persisted one-year CA is not PEM")
		}
		ca, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if !ca.NotAfter.Equal(deadline) {
			t.Fatalf("persisted CA expiry = %v, want %v", ca.NotAfter, deadline)
		}

		cfg.ValidityHours++
		if cfg.Validate() == nil {
			t.Fatal("material longer than one year accepted")
		}
		rejected := filepath.Join(parent, "too-long")
		if _, err := os.Lstat(rejected); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rejected material path was not absent: %v", err)
		}
		before, err := os.ReadDir(parent)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Generate(rejected, cfg, now); !errors.Is(err, ErrMaterial) {
			t.Fatalf("material longer than one year generation = %v, want ErrMaterial", err)
		}
		if _, err := os.Lstat(rejected); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rejected material created an artifact: %v", err)
		}
		after, err := os.ReadDir(parent)
		if err != nil || len(after) != len(before) {
			t.Fatalf("rejected generation changed parent entries: %v", err)
		}
		for index, entry := range before {
			if after[index].Name() != entry.Name() {
				t.Fatal("rejected generation changed parent entry names")
			}
		}
		unchanged, err := Load(directory)
		if err != nil || !reflect.DeepEqual(unchanged, persisted) {
			t.Fatalf("rejected generation changed existing material: %v", err)
		}
	})
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

// legacyMaterial removes only the optional member CA pair from generated
// material, retaining every currently mandatory file.
func legacyMaterial(t *testing.T, directory string, record Record) Record {
	t.Helper()
	record.Files = slices.DeleteFunc(slices.Clone(record.Files), func(file File) bool {
		return slices.Contains(memberCANames[:], file.Name)
	})
	for _, name := range memberCANames {
		if err := os.Remove(filepath.Join(directory, name)); err != nil {
			t.Fatal(err)
		}
	}
	metadata, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{metadataName: metadata, readyName: []byte(digest(metadata) + "\n")} {
		if err := os.WriteFile(filepath.Join(directory, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return record
}

// Material generated before the member CA existed still loads, resumes and
// validates; half a CA pair does not.
func TestLegacyMaterialWithoutMemberCAStillLoads(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "material")
	now := time.Now().UTC().Truncate(time.Second)
	generated, err := Generate(directory, testConfig(), now)
	if err != nil {
		t.Fatal(err)
	}
	legacy := legacyMaterial(t, directory, generated)
	if len(legacy.Files) != 35 || legacy.HasMemberCA() || !generated.HasMemberCA() {
		t.Fatalf("legacy fixture has %d files", len(legacy.Files))
	}
	loaded, err := Load(directory)
	if err != nil || !reflect.DeepEqual(loaded, legacy) {
		t.Fatalf("legacy material did not load: %v", err)
	}
	if resumed, err := Generate(directory, testConfig(), now.Add(time.Hour)); err != nil || !reflect.DeepEqual(resumed, legacy) {
		t.Fatalf("legacy material did not resume: %v", err)
	}
	if err := ValidateLive(directory, legacy); err != nil {
		t.Fatalf("legacy material failed live validation: %v", err)
	}
	legacyMetadata, err := os.ReadFile(filepath.Join(directory, metadataName))
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Public.AdmissionAttestor != (release.AdmissionAttestorMaterial{}) {
		t.Fatal("legacy archive acquired attestor public material")
	}
	if _, err := GenerateAdmissionCandidate(directory, testConfig(), testAdmissionAuthorization(t, testConfig()), now); err == nil {
		t.Fatal("legacy archive upgraded with a new attestor")
	}
	after, err := os.ReadFile(filepath.Join(directory, metadataName))
	if err != nil || !bytes.Equal(legacyMetadata, after) {
		t.Fatal("refused legacy upgrade changed original bytes")
	}
	half := filepath.Join(t.TempDir(), "material")
	record, err := Generate(half, testConfig(), now)
	if err != nil {
		t.Fatal(err)
	}
	record.Files = slices.DeleteFunc(record.Files, func(file File) bool { return file.Name == memberCANames[1] })
	if err := os.Remove(filepath.Join(half, memberCANames[1])); err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(half, metadataName), metadata, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(half, readyName), []byte(digest(metadata)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(half); err == nil {
		t.Fatal("loaded material with half a member CA pair")
	}
}

// New material's cell account carries the role signer (TS-663); material
// generated before still validates, and a role signer with any other scope
// does not.
func TestCellAccountRoleSignerIsExactOrAbsent(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "material")
	record, err := Generate(directory, testConfig(), time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, "cell.jwt"))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := os.ReadFile(filepath.Join(directory, "issuer-operator.seed"))
	if err != nil {
		t.Fatal(err)
	}
	operator, err := nkeys.FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*jwt.AccountClaims, string){
		"before TS-663": func(claim *jwt.AccountClaims, role string) { delete(claim.SigningKeys, role) },
		"wider scope": func(claim *jwt.AccountClaims, role string) {
			claim.SigningKeys[role].(*jwt.UserScope).Template.Pub.Allow.Add(">")
		},
	} {
		claim, err := jwt.DecodeAccountClaims(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		var role string
		for key := range claim.SigningKeys {
			if key != record.Public.HostNATSIssuerNKey && key != record.Public.ControllerAccountSignerNKey {
				role = key
			}
		}
		edit(claim, role)
		wire, err := claim.Encode(operator)
		if err != nil {
			t.Fatal(err)
		}
		edited := slices.Clone(record.Files)
		for i, file := range edited {
			if file.Name == "cell.jwt" {
				edited[i].SHA256, edited[i].MaxBytes = digest([]byte(wire)), int64(len(wire))
			}
		}
		changed := record
		changed.Files = edited
		metadata, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		for file, body := range map[string][]byte{"cell.jwt": []byte(wire), metadataName: metadata,
			readyName: []byte(digest(metadata) + "\n")} {
			if err := os.WriteFile(filepath.Join(directory, file), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := ValidateLive(directory, changed); (err == nil) != (name == "before TS-663") {
			t.Fatalf("%s: live validation = %v", name, err)
		}
	}
}

func TestMaterialLinkSignerIsOptionalAndValidated(t *testing.T) {
	signer, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	signerID, _ := signer.PublicKey()
	cfg := testConfig()
	cfg.LinkSigner = "not-an-account-key"
	if cfg.Validate() == nil {
		t.Fatal("invalid link signer accepted")
	}
	cfg.LinkSigner = signerID
	directory := filepath.Join(t.TempDir(), "material")
	record, err := Generate(directory, cfg, time.Now().UTC().Truncate(time.Second))
	if err != nil || ValidateLive(directory, record) != nil {
		t.Fatalf("material with a link signer did not survive live validation: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, "cell.jwt"))
	if err != nil {
		t.Fatal(err)
	}
	claim, err := jwt.DecodeAccountClaims(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := claim.SigningKeys[signerID]; !ok {
		t.Fatal("cell account does not carry the link signer")
	}
}
