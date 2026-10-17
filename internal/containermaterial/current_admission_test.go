//go:build linux

package containermaterial

import (
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/host"
)

func TestCurrentMaterialAdmissionsRequireActualSources(t *testing.T) {
	if err := (Admission{}).Guard(t.Context()); err == nil {
		t.Fatal("zero material proof granted delivery")
	}
	if err := (GenerationAdmission{}).Guard(t.Context()); err == nil {
		t.Fatal("zero generation proof granted metadata observation")
	}
	if _, err := AdmitMaterialTask(t.Context(), CurrentTaskSources{}, CurrentTask{}, nil); err == nil {
		t.Fatal("missing original signed host request was admitted")
	}
	if _, err := AdmitGenerationTask(t.Context(), CurrentTaskSources{}, CurrentTask{}, nil, host.ContainerMaterialBinding{}); err == nil {
		t.Fatal("missing actual host session was admitted")
	}
}
