//go:build sandboxvm

package vmqualruntime

import (
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
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
