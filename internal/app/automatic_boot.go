package app

import (
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart/materialsource"
)

// VerifiedAutomaticInstall retains only a house-rendered installation tied to
// the same signed startup template, owned host and exact durable source.
type VerifiedAutomaticInstall struct {
	template bootstrap.VerifiedStartupTemplate
	material materialsource.VerifiedColdStartMaterial
	link     bootstrap.VerifiedStartupLink
	founder  bootstrapstart.VerifiedSourceFounder
	manifest bootstrap.Manifest
	configs  map[string][]byte
}
