package foundation

import (
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// Record projects a verified foundation's non-secret provider references.
// It is not an authority or admission proof; the owning durable operation
// supplies its authenticated identity and generation separately.
type Record struct {
	Cell        string             `json:"cell"`
	Region      string             `json:"region"`
	HomeRegion  string             `json:"home_region"`
	ResourceIDs map[string]string  `json:"resource_ids"`
	Vault       vaultsecret.Target `json:"vault"`
	Buckets     map[string]string  `json:"buckets"`
}
