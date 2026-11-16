package materialsource

import (
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

// StartupProjection is render-only until exact house-rendered config bytes are
// committed to the source CAS. Only recovered, verified source may bind them.
type StartupProjection struct {
	template bootstrap.VerifiedStartupTemplate
	material VerifiedColdStartMaterial
	manifest bootstrap.Manifest
	link     *bootstrap.VerifiedStartupLink
}
