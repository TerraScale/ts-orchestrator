package rollout

// HostMembership binds a joined host to the registered key it proved with.
// Replacing that key requires the host to join again with a fresh proof.
type HostMembership struct {
	Node      string `json:"node"`
	PublicKey string `json:"public_key"`
}
