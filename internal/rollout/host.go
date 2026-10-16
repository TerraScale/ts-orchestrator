package rollout

import "github.com/TerraScale/ts-orchestrator/internal/entityid"

// HostMembership binds a joined host to the registered key it proved with.
// Replacing that key requires the host to join again with a fresh proof.
type HostMembership struct {
	Node      string `json:"node"`
	PublicKey string `json:"public_key"`
}

func HostMembershipKey(node string) string { return entityid.Derive("rollout-host", node) }
