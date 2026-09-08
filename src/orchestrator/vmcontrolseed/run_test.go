package vmcontrolseed

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
)

func runAdmissionFixture(t *testing.T) (Material, hostmanifest.HostManifest, RunAdmission, map[string][]byte) {
	t.Helper()
	member, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&member.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(member)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateDER)
	guest := Guest{ID: "gru-member-1", Address: "10.77.0.10", MembershipPublicKey: base64.StdEncoding.EncodeToString(publicDER)}
	pins, err := json.Marshal(map[string]string{guest.ID: guest.MembershipPublicKey}, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	dependencies := map[string][]byte{MembershipKeyPath: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), MembershipPinsPath: pins, "/etc/terrascale/database/host.json": []byte(`{"version":1}`)}
	t.Cleanup(func() {
		for _, raw := range dependencies {
			clear(raw)
		}
	})
	seeds, err := GenerateGRU("run-admission", []Guest{guest})
	if err != nil {
		t.Fatal(err)
	}
	seed := seeds[guest.ID]
	t.Cleanup(seed.Clear)
	ca, issue, closeIssuer, err := newCertificateIssuer("production-run")
	if err != nil {
		t.Fatal(err)
	}
	defer closeIssuer()
	admission := RunAdmission{HostID: guest.ID, Generation: 9, Settings: map[string]string{"TS_ORCH_PROVIDER": "oci", "TS_ORCH_REPLICAS": "3", "TS_ORCH_PRODUCTION_RUNTIME_FILE": "/etc/terrascale/run/runtime.json", "TS_ORCH_NATS_SERVER_CONFIG_FILE": "/etc/terrascale/run/broker.conf"}, Files: map[string]RunFile{}}
	files := map[string][]byte{"/etc/terrascale/run/runtime.json": []byte(`{"version":1}`), "/etc/terrascale/run/broker.conf": []byte(`{"server_name":"admitted-r3-gru"}`)}
	connection := func(role string) RunConnection {
		t.Helper()
		g := guest
		g.ID += "-" + role
		cert, key, err := issue(g, false)
		if err != nil {
			t.Fatal(err)
		}
		root := "/etc/terrascale/run/" + role
		files[root+".pem"], files[root+".key"], files[root+"-ca.pem"] = cert, key, ca
		c, err := newUser(files, root+".seed", initialgrant.TLSFiles{CAFile: root + "-ca.pem", CASHA256: digest(ca), CertificateFile: root + ".pem", CertificateSHA256: digest(cert), KeyFile: root + ".key"})
		if err != nil {
			t.Fatal(err)
		}
		return RunConnection{Endpoint: "tls://10.77.0.10:4222", ServerName: "admitted-r3-gru", Account: role, Connection: c}
	}
	admission.Regional = connection("regional")
	admission.Global = new(connection("global"))
	dir := t.TempDir()
	for target, data := range files {
		path := filepath.Join(dir, filepath.Base(target))
		if err := os.WriteFile(path, data, 0400); err != nil {
			t.Fatal(err)
		}
		admission.Files[target] = RunFile{Source: path, SHA256: digest(data)}
	}
	base := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{{Name: "orchestrator", Version: "1.0.0", Sha256: strings.Repeat("a", 64), ArtifactURL: "https://releases.terrascale.tech/releases/orchestrator/1.0.0/orchestrator", SignatureURL: "https://releases.terrascale.tech/releases/orchestrator/1.0.0/orchestrator.sig", User: ServiceUser, DataVolume: "/var/lib/terrascale/orchestrator", CPUWeight: 100, MemoryMaxBytes: 128 << 20, IOWeight: 100, Arguments: RunArguments, Configuration: `{"TS_ORCH_DATABASE_HOST_FILE":"/etc/terrascale/database/host.json"}`}}}
	return seed, base, admission, dependencies
}

func TestRunManifestPreservesCallbacksAndBindsInitialPredecessor(t *testing.T) {
	seed, base, admission, dependencies := runAdmissionFixture(t)
	run, err := seed.RunManifest(base, admission, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	defer run.Clear()
	var settings map[string]string
	if err := json.Unmarshal([]byte(run.Manifest.Components[0].Configuration), &settings); err != nil {
		t.Fatal(err)
	}
	if settings["TS_ORCH_DATABASE_HOST_FILE"] != "/etc/terrascale/database/host.json" || settings["TS_ORCH_NATS_NKEY_FILE"] != admission.Regional.Connection.NKeySeedFile {
		t.Fatal("full host callback configuration or admitted run identity lost")
	}
	raw, err := hostmanifest.CanonicalHostManifestJSON(base)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := seed.LaunchManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := run.ValidateStage(seed, initial); err != nil {
		t.Fatal(err)
	}
	clone := run.Clone()
	defer clone.Clear()
	clone.Files[admission.Regional.Connection.NKeySeedFile][0] ^= 1
	if clone.ValidateStage(seed, initial) == nil {
		t.Fatal("mutated protected credential accepted")
	}
	clone = run.Clone()
	defer clone.Clear()
	clone.Manifest.Components[0].Configuration = "{}"
	if clone.ValidateStage(seed, initial) == nil {
		t.Fatal("mutated final configuration accepted")
	}
}

func TestRunManifestRefusesMissingAdmissionAndInitialCredentials(t *testing.T) {
	for _, name := range []string{"generation", "initial key", "initial tls", "R1", "provider", "missing runtime", "changed digest", "callback conflict", "shell target", "writable material volume", "unbound runtime reference", "unbound broker reference", "missing callback dependency"} {
		t.Run(name, func(t *testing.T) {
			seed, base, admission, dependencies := runAdmissionFixture(t)
			replace := func(target string, data []byte) {
				path := filepath.Join(t.TempDir(), "replacement")
				if err := os.WriteFile(path, data, 0400); err != nil {
					t.Fatal(err)
				}
				admission.Files[target] = RunFile{Source: path, SHA256: digest(data)}
			}
			switch name {
			case "unbound runtime reference":
				replace(admission.Settings["TS_ORCH_PRODUCTION_RUNTIME_FILE"], []byte(`{"version":1,"serviceKeyFile":"/etc/terrascale/not-admitted.key"}`))
			case "unbound broker reference":
				replace(admission.Settings["TS_ORCH_NATS_SERVER_CONFIG_FILE"], []byte(`{"tls":{"cert_file":"/etc/terrascale/not-admitted.pem"}}`))
			case "missing callback dependency":
				delete(dependencies, "/etc/terrascale/database/host.json")
			case "writable material volume":
				base.Components[0].DataVolume = "/etc/terrascale"
			case "shell target":
				admission.Files["/etc/terrascale/run/a;touch${IFS}/tmp/injected"] = admission.Files[admission.Regional.Connection.NKeySeedFile]
			case "generation":
				admission.Generation = 0
			case "initial key":
				replace(admission.Regional.Connection.NKeySeedFile, seed.Files[NKeyPath])
				c, _ := initialgrant.ParseConfig([]byte(seed.Settings))
				admission.Regional.Connection.PublicNKey = c.Regional.Runtime.PublicNKey
			case "initial tls":
				replace(admission.Regional.Connection.TLS.KeyFile, seed.Files[PrivateKeyPath])
				replace(admission.Regional.Connection.TLS.CertificateFile, seed.Files[CertificatePath])
				replace(admission.Regional.Connection.TLS.CAFile, seed.Files[CAPath])
				admission.Regional.Connection.TLS.CertificateSHA256 = digest(seed.Files[CertificatePath])
				admission.Regional.Connection.TLS.CASHA256 = digest(seed.Files[CAPath])
			case "R1":
				admission.Settings["TS_ORCH_REPLICAS"] = "1"
			case "provider":
				delete(admission.Settings, "TS_ORCH_PROVIDER")
			case "missing runtime":
				delete(admission.Files, admission.Settings["TS_ORCH_PRODUCTION_RUNTIME_FILE"])
			case "changed digest":
				file := admission.Files[admission.Regional.Connection.NKeySeedFile]
				file.SHA256 = strings.Repeat("b", 64)
				admission.Files[admission.Regional.Connection.NKeySeedFile] = file
			case "callback conflict":
				admission.Settings["TS_ORCH_DATABASE_HOST_FILE"] = "/etc/terrascale/foreign.json"
			}
			if material, err := seed.RunManifest(base, admission, dependencies); err == nil {
				material.Clear()
				t.Fatal("unsafe production run admission accepted")
			}
		})
	}
}

func TestFreshRegionalRunRequiresOwnMembershipAndNoGlobalRole(t *testing.T) {
	seed, base, admission, dependencies := runAdmissionFixture(t)
	initial, err := initialgrant.ParseConfig([]byte(seed.Settings))
	if err != nil {
		t.Fatal(err)
	}
	admission.HostID = "sfo-member-2"
	global := admission.Global.Connection
	for _, path := range []string{global.NKeySeedFile, global.TLS.CAFile, global.TLS.CertificateFile, global.TLS.KeyFile} {
		delete(admission.Files, path)
	}
	admission.Global = nil
	pins, err := json.Marshal(map[string]string{admission.HostID: initial.Membership.PublicKey}, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	dependencies[MembershipPinsPath] = pins
	membership := initial.Membership
	membership.PinsSHA256 = digest(pins)
	host := RunHost{HostID: admission.HostID, Cell: "sfo", Membership: membership, InitialFiles: seed.Files}
	material, err := PrepareRunManifest(base, admission, dependencies, host)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Clear()
	if material.ExpectedManifestSHA != "" {
		t.Fatal("fresh ordinary member fabricated a predecessor")
	}
	if err := material.ValidateManifest(host.HostID, material.Manifest); err != nil {
		t.Fatal(err)
	}
	if material.ValidatePredecessor(host.HostID, material.Manifest) == nil {
		t.Fatal("ordinary finite grant treated as staged CAS")
	}
	host.Membership.PublicKey = membershipPublic(t)
	if _, err := PrepareRunManifest(base, admission, dependencies, host); err == nil {
		t.Fatal("foreign membership admitted")
	}
}

func TestRunDeclarationRefusesSharedProductionIdentities(t *testing.T) {
	_, _, first, _ := runAdmissionFixture(t)
	_, _, second, _ := runAdmissionFixture(t)
	second.HostID, second.Global = "sfo-member-2", nil
	for _, scenario := range []string{"distinct", "nkey", "certificate"} {
		t.Run(scenario, func(t *testing.T) {
			other := second
			switch scenario {
			case "nkey":
				other.Regional.Connection.PublicNKey = first.Regional.Connection.PublicNKey
			case "certificate":
				other.Regional.Connection.TLS.CertificateSHA256 = first.Regional.Connection.TLS.CertificateSHA256
			}
			raw, err := json.Marshal(RunDeclaration{Version: 1, Hosts: []RunAdmission{first, other}})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "run.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			_, err = LoadRunDeclaration(path)
			if (err == nil) != (scenario == "distinct") {
				t.Fatalf("identity admission result: %v", err)
			}
		})
	}
}
