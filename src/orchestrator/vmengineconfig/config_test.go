package vmengineconfig_test

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/internal/testengineconfig"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"
)

var bindings = []vmengineconfig.Binding{{NodeID: "gru-member-1", Region: "GRU", Address: "10.77.0.10"}, {NodeID: "gru-member-2", Region: "GRU", Address: "10.77.0.11"}}

func manifest(t *testing.T, m *vmengineconfig.Material) hostmanifest.HostManifest {
	t.Helper()
	base := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{{Name: "terrabase", Version: "1.0.0", Sha256: strings.Repeat("a", 64), ArtifactURL: "https://releases.terrascale.tech:8443/releases/terrabase/1.0.0/terrabase", SignatureURL: "https://releases.terrascale.tech:8443/releases/terrabase/1.0.0/terrabase.sig", User: vmengineconfig.ServiceUser, DataVolume: "/var/lib/terrascale/terrabase", CPUWeight: 100, MemoryMaxBytes: 128<<20, IOWeight: 100}}}
	planned, err := m.Apply(base)
	if err != nil { t.Fatal(err) }
	planned, err = bootstrap.PlanControlLaunchManifest(planned)
	if err != nil { t.Fatal(err) }
	return planned
}

func TestDeclaredProductionConfigBindsIdentityArtifactAndTLS(t *testing.T) {
	d, path := testengineconfig.Declaration(t, bindings, strings.Repeat("a", 64), "1.0.0")
	materials, err := vmengineconfig.Load(path, d.ArtifactSHA256, d.Release, bindings)
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { for _, m := range materials { m.Clear() } })
	for i, binding := range bindings {
		m := materials[binding.NodeID]
		planned := manifest(t, m)
		if err := m.ValidateManifest(binding.NodeID, binding.Address, planned); err != nil { t.Fatal(err) }
		config := planned.Components[0].Configuration
		for _, required := range []string{"mode = \"production\"", "member = \""+d.Hosts[i].Member+"\"", "endpoint = \""+bindings[1-i].Address+":8422\"", "encryption_provider = \"oci-vault\"", "tbep_listen = \"127.0.0.1:8421\""} {
			if !strings.Contains(config, required) { t.Fatalf("missing production field %s", required) }
		}
		if strings.Count(config, "[[transport.peers]]") != 1 || strings.Contains(config, "PRIVATE KEY") || strings.Contains(config, "local-development") { t.Fatal("unexpected peers, secret, or runtime mode") }
		if err := m.ValidateManifest("foreign", binding.Address, planned); err == nil { t.Fatal("wrong host accepted") }
		planned.Components[0].Configuration += "\n"
		if err := m.ValidateManifest(binding.NodeID, binding.Address, planned); err == nil { t.Fatal("changed signed configuration accepted") }
		copy := m.Clone()
		files := copy.Files()
		copy.Clear()
		if len(files[vmengineconfig.PrivateKeyPath]) == 0 || len(m.Files()[vmengineconfig.PrivateKeyPath]) == 0 { t.Fatal("material copies shared private buffers") }
	}
	original := manifest(t, materials[bindings[0].NodeID]).Components[0]
	slices.Reverse(d.Hosts)
	raw, err := json.Marshal(d)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, raw, 0600); err != nil { t.Fatal(err) }
	reordered, err := vmengineconfig.Load(path, d.ArtifactSHA256, d.Release, bindings)
	if err != nil { t.Fatal(err) }
	defer func() { for _, m := range reordered { m.Clear() } }()
	if next := manifest(t, reordered[bindings[0].NodeID]).Components[0]; next.Configuration != original.Configuration || next.Version != original.Version { t.Fatal("declaration ordering changed immutable launch") }
}

func TestDeclarationRejectsUnprovenInputs(t *testing.T) {
	for _, test := range []struct { name string; change func(*vmengineconfig.Declaration) }{
		{"contract", func(d *vmengineconfig.Declaration) { d.Contract = "unpublished-other" }},
		{"artifact", func(d *vmengineconfig.Declaration) { d.ArtifactSHA256 = strings.Repeat("b", 64) }},
		{"release", func(d *vmengineconfig.Declaration) { d.Release = "2.0.0" }},
		{"missing-databases", func(d *vmengineconfig.Declaration) { d.Databases = nil }},
		{"missing-member", func(d *vmengineconfig.Declaration) { d.Hosts = d.Hosts[:1] }},
		{"duplicate-member", func(d *vmengineconfig.Declaration) { d.Hosts[1].Member = d.Hosts[0].Member }},
		{"wrong-host", func(d *vmengineconfig.Declaration) { d.Hosts[0].NodeID = "foreign" }},
		{"wrong-certificate", func(d *vmengineconfig.Declaration) { d.Hosts[0].CertificateFile = d.Hosts[1].CertificateFile; d.Hosts[0].PrivateKeyFile = d.Hosts[1].PrivateKeyFile }},
		{"epoch", func(d *vmengineconfig.Declaration) { d.Epoch = 0 }},
		{"undeclared-residency", func(d *vmengineconfig.Declaration) { d.Databases[0].Region = "FRA" }},
		{"quota", func(d *vmengineconfig.Declaration) { d.Databases[0].MaxStorageBytes = 0 }},
		{"key-version", func(d *vmengineconfig.Declaration) { d.Databases[0].EncryptionKey = "ocid1.key.wrong-kind" }},
		{"timeout", func(d *vmengineconfig.Declaration) { d.Limits.RequestTimeoutMillis = 0 }},
		{"output-bound", func(d *vmengineconfig.Declaration) { base := d.Databases[0]; for i := range 200 { next := base; next.Database = fmt.Sprintf("%026d", 1000+i); d.Databases = append(d.Databases, next) } }},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, path := testengineconfig.Declaration(t, bindings, strings.Repeat("a", 64), "1.0.0")
			test.change(&d)
			raw, err := json.Marshal(d)
			if err != nil { t.Fatal(err) }
			if err := os.WriteFile(path, raw, 0600); err != nil { t.Fatal(err) }
			if _, err := vmengineconfig.Load(path, strings.Repeat("a", 64), "1.0.0", bindings); err == nil { t.Fatal("unproven production input accepted") }
		})
	}
}

func TestDeclarationJSONAndPrivateFileBoundaries(t *testing.T) {
	d, path := testengineconfig.Declaration(t, bindings, strings.Repeat("a", 64), "1.0.0")
	raw, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	for _, invalid := range [][]byte{append(bytes.Clone(raw), []byte(" {}")...), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"privateKey":"no-inline-secret"`), 1)} {
		if err := os.WriteFile(path, invalid, 0600); err != nil { t.Fatal(err) }
		if _, err := vmengineconfig.Load(path, d.ArtifactSHA256, d.Release, bindings); err == nil { t.Fatal("ambiguous or unknown JSON accepted") }
	}
	if err := os.WriteFile(path, raw, 0600); err != nil { t.Fatal(err) }
	if err := os.Chmod(d.Hosts[0].PrivateKeyFile, 0644); err != nil { t.Fatal(err) }
	if _, err := vmengineconfig.Load(path, d.ArtifactSHA256, d.Release, bindings); err == nil { t.Fatal("publicly readable private key accepted") }
}
