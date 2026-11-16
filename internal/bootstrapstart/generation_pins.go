package bootstrapstart

import (
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
)

// MaterialGenerationsFile is the controller's adopted material generation
// chain (TS-568), kept in the credential directory beside the files it pins.
const MaterialGenerationsFile = "material-generations.json"

// MaterialPins is what restart admission expects in the credential directory.
// The complete accepted baseline is overlaid by the verified newest generation.
// Local issued files may retain their baseline bytes or satisfy that generation's
// issuance rules. Shared and nonrenewable baseline files remain pinned.
type MaterialPins struct {
	Digests map[string]string
	// Issued maps each issued file to its accepted baseline digest; empty before a
	// generation with controller issuers is adopted.
	Issued         map[string]string
	Generation     *bootstrap.VerifiedMaterialGeneration
	slot           string
	acceptance     string
	acceptedSHA256 string
	references     []bootstrap.SecretReference
	identity       bootstrapmaterial.LeafIdentity
	target         GenerationTarget
	// config is the loaded controller config, which a v1 generation
	// pins as controller-<slot>.json (TS-668).
	config []byte
}
