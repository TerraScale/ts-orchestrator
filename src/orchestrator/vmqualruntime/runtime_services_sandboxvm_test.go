//go:build sandboxvm

package vmqualruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

func TestInstallQualificationControlSourceRequiresCompleteRunAdmissions(t *testing.T) {
	source := &qualificationAdmittedControlSource{}
	services := &qualificationRuntimeServices{
		controlAdmission: &qualificationControlAdmission{source: source},
		controlSeeds:     map[string]vmcontrolseed.Material{"gru-member-1": {}},
	}

	services.installQualificationControlSource()
	if services.controlSource != nil {
		t.Fatal("installed control source without an admitted run")
	}

	services.runAdmissions = map[string]vmcontrolseed.RunAdmission{
		"gru-member-1": {HostID: "gru-member-1", Generation: 1},
	}
	services.installQualificationControlSource()
	if services.controlSource != source {
		t.Fatal("did not install control source after complete run admission")
	}
}

func TestQualificationServicesRejectBackupBeforeStartingServices(t *testing.T) {
	plan, err := vmnet.Plan(QualificationNetworkConfig(true, true, 1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	declarationPath := filepath.Join(root, "declaration.json")
	if err := os.WriteFile(declarationPath, []byte(`{"databases":[{"backup":null}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	config := vmqual.DefaultConfig()
	config.StateRoot = filepath.Join(root, "state")
	config.NetworkPlan = plan
	config.TerraBaseDeclarationFile = declarationPath

	services, err := newQualificationServices(config, plan, vmimage.AMD64)
	if services != nil {
		_ = services.Close(t.Context())
		t.Fatal("invalid backup declaration started qualification services")
	}
	if err == nil || !strings.Contains(err.Error(), "requires backup policy") {
		t.Fatalf("early backup preflight error = %v", err)
	}
	if _, statErr := os.Stat(config.StateRoot); !os.IsNotExist(statErr) {
		t.Fatalf("service state root was created before backup preflight: %v", statErr)
	}
}
