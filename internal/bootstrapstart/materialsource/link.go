package materialsource

import (
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

// LinkSource retains the recovered founder-only Link signer and its durable publication.
type LinkSource struct {
	source *ColdStartMaterial
	record bootstrapmaterial.LinkRecord
}

type VerifiedLinkMaterial struct {
	material VerifiedColdStartMaterial
	record   bootstrapmaterial.LinkRecord
}

type linkInputs struct {
	recipient                                  *bootstrap.LinkRecipient
	recipientGrant                             region.VerifiedBootstrapMaterial
	regional, home                             *ColdStartMaterial
	homeLink                                   *LinkSource
	regionalDigest, homeDigest, homeLinkDigest string
}
