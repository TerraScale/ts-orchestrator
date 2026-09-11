package testengineconfig

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"
)

func TestPrepareCreatesLoadableSixGuestFixture(t *testing.T) {
	f, err := Prepare(strings.Repeat("a", 64), "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Remove() })
	if len(f.Bindings) != 6 || len(f.Declaration.Hosts) != 6 {
		t.Fatalf("fixture has %d bindings and %d hosts, want six", len(f.Bindings), len(f.Declaration.Hosts))
	}
	if len(f.Peers) != 6 {
		t.Fatalf("fixture has %d transport peers, want six", len(f.Peers))
	}
	if info, err := os.Stat(f.Root); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("private root mode = %v, err = %v", info, err)
	}
	if _, err := vmengineconfig.Load(f.DeclarationPath, f.Declaration.ArtifactSHA256, f.Declaration.Release, f.Bindings); err != nil {
		t.Fatalf("prepared declaration failed Load: %v", err)
	}
	destination := f.Declaration.Databases[0].Backup.Destinations[0]
	if destination.Provider != "tigris" || destination.Endpoint != "https://fly.storage.tigris.dev" || destination.VerifiedGeography != "BR" || len(destination.PermittedGeographies) != 1 || destination.PermittedGeographies[0] != "BR" {
		t.Fatalf("backup destination is not the approved qualification target: %+v", destination)
	}
	for _, path := range []string{destination.AccessKeyFile, destination.SecretKeyFile} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 || info.Size() == 0 {
			t.Fatalf("backup credential %q is not a private nonempty file: %v", path, err)
		}
	}
	wantGateway := map[string]string{"GRU": "10.77.0.1", "SFO": "10.77.1.1", "FRA": "10.77.2.1"}
	for _, host := range f.Declaration.Hosts {
		want := "tls://" + wantGateway[hostRegion(f.Bindings, host.NodeID)] + ":4222"
		if host.EngineControl.NATSURL != want || host.DatabaseHost.NATSURL != want {
			t.Errorf("%s NATS URLs = %q and %q, want %q", host.NodeID, host.EngineControl.NATSURL, host.DatabaseHost.NATSURL, want)
		}
	}
}

func TestPrepareRendersCompletePeerAdmissionComposition(t *testing.T) {
	bindings := []vmengineconfig.Binding{
		{NodeID: "gru-member-1", Region: "GRU", Address: "10.77.0.10"}, {NodeID: "gru-member-2", Region: "GRU", Address: "10.77.0.11"},
		{NodeID: "sfo-member-1", Region: "SFO", Address: "10.77.1.10"}, {NodeID: "sfo-member-2", Region: "SFO", Address: "10.77.1.11"},
		{NodeID: "fra-member-1", Region: "FRA", Address: "10.77.2.10"}, {NodeID: "fra-member-2", Region: "FRA", Address: "10.77.2.11"},
	}
	d, path := Declaration(t, bindings, strings.Repeat("a", 64), "1.0.0")
	materials, err := vmengineconfig.Load(path, d.ArtifactSHA256, d.Release, bindings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, material := range materials {
			material.Clear()
		}
	})
	for _, binding := range bindings {
		material := materials[binding.NodeID]
		manifest := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{{Name: "terrabase", Version: d.Release, Sha256: d.ArtifactSHA256, ArtifactURL: "https://releases.terrascale.tech/releases/terrabase/1.0.0/terrabase", SignatureURL: "https://releases.terrascale.tech/releases/terrabase/1.0.0/terrabase.sig", User: vmengineconfig.ServiceUser, DataVolume: "/var/lib/terrascale/terrabase", CPUWeight: 100, MemoryMaxBytes: 128 << 20, IOWeight: 100}}}
		manifest, err = material.Apply(manifest)
		if err != nil {
			t.Fatalf("%s apply: %v", binding.NodeID, err)
		}
		manifest = mustPlanManifest(t, manifest)
		config := manifest.Components[0].Configuration
		if strings.Count(config, "[[transport.peers]]") != 5 {
			t.Fatalf("%s has %d peers, want five", binding.NodeID, strings.Count(config, "[[transport.peers]]"))
		}
		for i, peer := range d.Hosts {
			if peer.NodeID == binding.NodeID {
				continue
			}
			for _, expected := range []string{
				"member = \"" + peer.Member + "\"",
				"endpoint = \"" + bindings[i].Address + ":8422\"",
				"spiffe_identity = \"spiffe://terrascale.tech/qualification/terrabase-member/" + d.Cluster + "/" + peer.Member + "\"",
			} {
				if !strings.Contains(config, expected) {
					t.Fatalf("%s missing peer field %s", binding.NodeID, expected)
				}
			}
		}
		if !strings.Contains(config, "generation = "+itoa(d.Generation)+"\n") || !strings.Contains(config, "epoch = "+itoa(d.Epoch)+"\n") {
			t.Fatalf("%s missing placement generation/epoch", binding.NodeID)
		}
		if !strings.Contains(config, "[databases.backup]\n") {
			t.Fatalf("%s missing explicit database backup declaration", binding.NodeID)
		}
	}
}

func mustPlanManifest(t *testing.T, manifest hostmanifest.HostManifest) hostmanifest.HostManifest {
	t.Helper()
	planned, err := bootstrap.PlanControlLaunchManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return planned
}

func itoa(value uint64) string {
	return fmt.Sprintf("%d", value)
}

func hostRegion(bindings []vmengineconfig.Binding, nodeID string) string {
	for _, binding := range bindings {
		if binding.NodeID == nodeID {
			return binding.Region
		}
	}
	return ""
}
