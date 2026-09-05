package vmqualbootstrap

import (
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"testing"
)

func TestInitialActivationRefusesForeignOrUninstalledState(t *testing.T) {
	manifest := hostagent.HostManifest{Components: []hostagent.ComponentSpec{{Name: "orchestrator", Version: "1.0.0"}, {Name: "terrabase", Version: "2.0.0"}}}
	report := hostagent.NodeStatusReport{Facts: hostagent.HostFacts{ManifestSha256: "admitted", Components: []hostagent.ComponentFact{
		{Name: "orchestrator", Desired: "1.0.0", Installed: true}, {Name: "terrabase", Desired: "2.0.0", Installed: true},
	}}}
	if ready, err := initialActivationStatus(report, manifest, "admitted"); err != nil || !ready {
		t.Fatalf("initial: %v %v", ready, err)
	}
	report.Facts.Components[0].Version = "1.0.0"
	if ready, err := initialActivationStatus(report, manifest, "admitted"); err != nil || !ready {
		t.Fatalf("partial recovery: %v %v", ready, err)
	}
	report.Facts.Components[1].Installed = false
	if ready, err := initialActivationStatus(report, manifest, "admitted"); err != nil || ready {
		t.Fatalf("uninstalled: %v %v", ready, err)
	}
	report.Facts.Components[0].Version = "9.0.0"
	if _, err := initialActivationStatus(report, manifest, "admitted"); err == nil {
		t.Fatal("foreign serving release accepted")
	}
	report.Facts.Components[0].Version = ""
	if _, err := initialActivationStatus(report, manifest, "foreign"); err == nil {
		t.Fatal("foreign manifest accepted")
	}
	report.Facts.Components[1] = report.Facts.Components[0]
	if _, err := initialActivationStatus(report, manifest, "admitted"); err == nil {
		t.Fatal("duplicate component evidence accepted")
	}
}
