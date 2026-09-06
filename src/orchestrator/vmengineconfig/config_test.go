package vmengineconfig_test

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"math"
	"os"
	"slices"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/internal/testengineconfig"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"
)

var bindings = []vmengineconfig.Binding{{NodeID: "gru-member-1", Region: "GRU", Address: "10.77.0.10"}, {NodeID: "gru-member-2", Region: "GRU", Address: "10.77.0.11"}}

func manifest(t *testing.T, m *vmengineconfig.Material) hostmanifest.HostManifest {
	t.Helper()
	base := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{{Name: "terrabase", Version: "1.0.0", Sha256: strings.Repeat("a", 64), ArtifactURL: "https://releases.terrascale.tech:8443/releases/terrabase/1.0.0/terrabase", SignatureURL: "https://releases.terrascale.tech:8443/releases/terrabase/1.0.0/terrabase.sig", User: vmengineconfig.ServiceUser, DataVolume: "/var/lib/terrascale/terrabase", CPUWeight: 100, MemoryMaxBytes: 128 << 20, IOWeight: 100}}}
	planned, err := m.Apply(base)
	if err != nil {
		t.Fatal(err)
	}
	planned, err = bootstrap.PlanControlLaunchManifest(planned)
	if err != nil {
		t.Fatal(err)
	}
	return planned
}

func TestDeclaredProductionConfigBindsIdentityArtifactAndTLS(t *testing.T) {
	d, path := testengineconfig.Declaration(t, bindings, strings.Repeat("a", 64), "1.0.0")
	materials, err := vmengineconfig.Load(path, d.ArtifactSHA256, d.Release, bindings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, m := range materials {
			m.Clear()
		}
	})
	for i, binding := range bindings {
		m := materials[binding.NodeID]
		planned := manifest(t, m)
		if err := m.ValidateManifest(binding.NodeID, binding.Address, planned); err != nil {
			t.Fatal(err)
		}
		config := planned.Components[0].Configuration
		for _, required := range []string{"mode = \"production\"", "member = \"" + d.Hosts[i].Member + "\"", "endpoint = \"" + bindings[1-i].Address + ":8422\"", "encryption_provider = \"oci-vault\"", "selected_regions = [\"GRU\"]", "tbep_listen = \"127.0.0.1:8421\""} {
			if !strings.Contains(config, required) {
				t.Fatalf("missing production field %s", required)
			}
		}
		if strings.Count(config, "[[transport.peers]]") != 1 || strings.Contains(config, "PRIVATE KEY") || strings.Contains(config, "local-development") {
			t.Fatal("unexpected peers, secret, or runtime mode")
		}
		if err := m.ValidateManifest("foreign", binding.Address, planned); err == nil {
			t.Fatal("wrong host accepted")
		}
		planned.Components[0].Configuration += "\n"
		if err := m.ValidateManifest(binding.NodeID, binding.Address, planned); err == nil {
			t.Fatal("changed signed configuration accepted")
		}
		copy := m.Clone()
		files := copy.Files()
		copy.Clear()
		if len(files[vmengineconfig.PrivateKeyPath]) == 0 || len(m.Files()[vmengineconfig.PrivateKeyPath]) == 0 {
			t.Fatal("material copies shared private buffers")
		}
	}
	original := manifest(t, materials[bindings[0].NodeID]).Components[0]
	slices.Reverse(d.Hosts)
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	reordered, err := vmengineconfig.Load(path, d.ArtifactSHA256, d.Release, bindings)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, m := range reordered {
			m.Clear()
		}
	}()
	if next := manifest(t, reordered[bindings[0].NodeID]).Components[0]; next.Configuration != original.Configuration || next.Version != original.Version {
		t.Fatal("declaration ordering changed immutable launch")
	}
}

func TestRenderedDatabaseResidencyIncludesDisabledControlDeclarations(t *testing.T) {
	mixedBindings := []vmengineconfig.Binding{
		{NodeID: "gru-member-1", Region: "GRU", Address: "10.77.0.10"},
		{NodeID: "gru-member-2", Region: "GRU", Address: "10.77.0.11"},
		{NodeID: "sfo-member-1", Region: "SFO", Address: "10.77.1.10"},
		{NodeID: "sfo-member-2", Region: "SFO", Address: "10.77.1.11"},
	}
	d, path := testengineconfig.Declaration(t, mixedBindings, strings.Repeat("a", 64), "1.0.0")
	d.Databases[0].SelectedRegions = []string{"GRU", "SFO"}
	d.Databases = append(d.Databases, vmengineconfig.Database{
		Tenant: d.Databases[0].Tenant, Project: d.Databases[0].Project, Database: "000000000000000000000000CB",
		Region: "GRU", SelectedRegions: []string{"GRU"}, AllowedRegions: []string{"GRU"},
		EncryptionKey: "000000000000000000000000CC", MaxStorageBytes: 1 << 20, MaxDocuments: 100, MaxInflight: 8,
	})
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	materials, err := vmengineconfig.Load(path, d.ArtifactSHA256, d.Release, mixedBindings)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, material := range materials {
			material.Clear()
		}
	}()
	for _, binding := range mixedBindings {
		config := manifest(t, materials[binding.NodeID]).Components[0].Configuration
		if !strings.Contains(config, "region = \""+binding.Region+"\"") {
			t.Fatalf("%s config does not bind its local Region", binding.Region)
		}
		if got := strings.Count(config, "[[databases]]"); got != 2 {
			t.Fatalf("%s rendered %d databases, want 2", binding.Region, got)
		}
		if binding.Region == "SFO" {
			if !strings.Contains(config, "region = \"GRU\"\nselected_regions = [\"GRU\"]") || !strings.Contains(config, "enabled = false") {
				t.Fatal("SFO config omitted disabled GRU control declaration")
			}
		}
	}
}

func TestPendingHostRequiresDatabaseAdmission(t *testing.T) {
	mixedBindings := []vmengineconfig.Binding{
		{NodeID: "gru-member-1", Region: "GRU", Address: "10.77.0.10"},
		{NodeID: "gru-member-2", Region: "GRU", Address: "10.77.0.11"},
		{NodeID: "sfo-member-1", Region: "SFO", Address: "10.77.1.10"},
		{NodeID: "sfo-member-2", Region: "SFO", Address: "10.77.1.11"},
	}
	d, path := testengineconfig.DatabaseDeclaration(t, mixedBindings, strings.Repeat("a", 64), "1.0.0")
	for i := 2; i < len(d.Hosts); i++ {
		d.Hosts[i].ObserverDatabase = ""
		d.Hosts[i].DatabaseHost = nil
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := vmengineconfig.Load(path, d.ArtifactSHA256, d.Release, mixedBindings); err == nil {
		t.Fatal("pending host without database admission accepted")
	}
}

func TestPendingHostMayOmitObserverDatabase(t *testing.T) {
	mixedBindings := []vmengineconfig.Binding{
		{NodeID: "gru-member-1", Region: "GRU", Address: "10.77.0.10"},
		{NodeID: "gru-member-2", Region: "GRU", Address: "10.77.0.11"},
		{NodeID: "sfo-member-1", Region: "SFO", Address: "10.77.1.10"},
		{NodeID: "sfo-member-2", Region: "SFO", Address: "10.77.1.11"},
	}
	d, path := testengineconfig.DatabaseDeclaration(t, mixedBindings, strings.Repeat("a", 64), "1.0.0")
	for i := 2; i < len(d.Hosts); i++ {
		d.Hosts[i].ObserverDatabase = ""
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	m, err := vmengineconfig.Load(path, d.ArtifactSHA256, d.Release, mixedBindings)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, material := range m {
			material.Clear()
		}
	}()
	for _, nodeID := range []string{"sfo-member-1", "sfo-member-2"} {
		if got := m[nodeID].Observation(); got != (tbep.FileConfig{}) {
			t.Fatalf("pending host %s has fabricated observation scope: %#v", nodeID, got)
		}
	}
}

func TestDeclarationRejectsUnprovenInputs(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*vmengineconfig.Declaration)
	}{
		{"contract", func(d *vmengineconfig.Declaration) { d.Contract = "unpublished-other" }},
		{"artifact", func(d *vmengineconfig.Declaration) { d.ArtifactSHA256 = strings.Repeat("b", 64) }},
		{"release", func(d *vmengineconfig.Declaration) { d.Release = "2.0.0" }},
		{"missing-databases", func(d *vmengineconfig.Declaration) { d.Databases = nil }},
		{"missing-member", func(d *vmengineconfig.Declaration) { d.Hosts = d.Hosts[:1] }},
		{"duplicate-member", func(d *vmengineconfig.Declaration) { d.Hosts[1].Member = d.Hosts[0].Member }},
		{"wrong-host", func(d *vmengineconfig.Declaration) { d.Hosts[0].NodeID = "foreign" }},
		{"wrong-certificate", func(d *vmengineconfig.Declaration) {
			d.Hosts[0].CertificateFile = d.Hosts[1].CertificateFile
			d.Hosts[0].PrivateKeyFile = d.Hosts[1].PrivateKeyFile
		}},
		{"writer-reuses-observer", func(d *vmengineconfig.Declaration) {
			d.Hosts[0].OrchestratorPrincipals = []string{d.Hosts[1].ObserverIdentity}
		}},
		{"observer-scope", func(d *vmengineconfig.Declaration) { d.Hosts[0].ObserverDatabase = d.Databases[0].Tenant }},
		{"observer-identity", func(d *vmengineconfig.Declaration) { d.Hosts[0].ObserverIdentity = d.Hosts[1].ObserverIdentity }},
		{"observer-server-key", func(d *vmengineconfig.Declaration) {
			d.Hosts[0].ObserverCertificateFile = d.Hosts[0].CertificateFile
			d.Hosts[0].ObserverPrivateKeyFile = d.Hosts[0].PrivateKeyFile
		}},
		{"observer-foreign-key", func(d *vmengineconfig.Declaration) {
			d.Hosts[0].ObserverPrivateKeyFile = d.Hosts[1].ObserverPrivateKeyFile
		}},
		{"epoch", func(d *vmengineconfig.Declaration) { d.Epoch = 0 }},
		{"toml-integer-overflow", func(d *vmengineconfig.Declaration) { d.Epoch = math.MaxUint64 }},
		{"undeclared-residency", func(d *vmengineconfig.Declaration) { d.Databases[0].Region = "FRA" }},
		{"missing-residency-lock", func(d *vmengineconfig.Declaration) { d.Databases[0].AllowedRegions = nil }},
		{"cross-residency-placement", func(d *vmengineconfig.Declaration) { d.Databases[0].AllowedRegions = []string{"FRA"} }},
		{"duplicate-residency-region", func(d *vmengineconfig.Declaration) { d.Databases[0].AllowedRegions = []string{"GRU", "GRU"} }},
		{"missing-selected-regions", func(d *vmengineconfig.Declaration) { d.Databases[0].SelectedRegions = nil }},
		{"duplicate-selected-region", func(d *vmengineconfig.Declaration) { d.Databases[0].SelectedRegions = []string{"GRU", "GRU"} }},
		{"selected-region-outside-lock", func(d *vmengineconfig.Declaration) { d.Databases[0].SelectedRegions = []string{"FRA"} }},
		{"quota", func(d *vmengineconfig.Declaration) { d.Databases[0].MaxStorageBytes = 0 }},
		{"key-version", func(d *vmengineconfig.Declaration) { d.Databases[0].EncryptionKey = "ocid1.key.wrong-kind" }},
		{"timeout", func(d *vmengineconfig.Declaration) { d.Limits.RequestTimeoutMillis = 0 }},
		{"output-bound", func(d *vmengineconfig.Declaration) {
			base := d.Databases[0]
			for i := range 200 {
				next := base
				next.Database = fmt.Sprintf("%026d", 1000+i)
				d.Databases = append(d.Databases, next)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, path := testengineconfig.Declaration(t, bindings, strings.Repeat("a", 64), "1.0.0")
			test.change(&d)
			raw, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := vmengineconfig.Load(path, strings.Repeat("a", 64), "1.0.0", bindings); err == nil {
				t.Fatal("unproven production input accepted")
			}
		})
	}
}

func TestDeclarationJSONAndPrivateFileBoundaries(t *testing.T) {
	d, path := testengineconfig.Declaration(t, bindings, strings.Repeat("a", 64), "1.0.0")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{append(bytes.Clone(raw), []byte(" {}")...), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"privateKey":"no-inline-secret"`), 1)} {
		if err := os.WriteFile(path, invalid, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := vmengineconfig.Load(path, d.ArtifactSHA256, d.Release, bindings); err == nil {
			t.Fatal("ambiguous or unknown JSON accepted")
		}
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d.Hosts[0].PrivateKeyFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := vmengineconfig.Load(path, d.ArtifactSHA256, d.Release, bindings); err == nil {
		t.Fatal("publicly readable private key accepted")
	}
}
