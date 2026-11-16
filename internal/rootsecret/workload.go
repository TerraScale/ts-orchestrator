//go:build linux

package rootsecret

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// MaterialService accepts independently verified opaque root admissions, never
// caller-selected Vault references or secret identifiers.
type MaterialService struct {
	AdmitContainer  func(context.Context, rootoci.Call, host.ContainerMaterialEvidence) (containermaterial.Admission, error)
	AdmitGeneration func(context.Context, rootoci.Call, string) (containermaterial.GenerationAdmission, error)
}
