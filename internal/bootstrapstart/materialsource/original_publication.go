package materialsource

import (
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

type originalMaterialPublicationState struct {
	Scope   region.OriginalMaterialPublicationScope `json:"scope"`
	Journal []byte                                  `json:"journal,omitempty"`
	Result  *bootstrapmaterial.Publication          `json:"result,omitempty"`
}
