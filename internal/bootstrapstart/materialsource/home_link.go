package materialsource

import (
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
)

var ErrLinkDeliveryPending = errors.New("home has not published this region's Link delivery")

type VerifiedRegionalLink struct {
	regional    VerifiedColdStartMaterial
	proof       bootstrap.VerifiedStartupLink
	directory   string
	record      bootstrapmaterial.LinkRecord
	publication bootstrapmaterial.Publication
}
