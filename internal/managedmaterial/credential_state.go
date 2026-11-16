package managedmaterial

// CredentialState is the root-owned overlay consumed by TerraBase. The
// immutable initial registry and manifest remain the generation-one fallback.
// The signature uses a deliberately simple cross-language byte grammar.
type CredentialState struct {
	Version              uint64 `json:"version"`
	Generation           uint64 `json:"generation"`
	InitialReceiptSHA256 string `json:"initial_receipt_sha256"`
	RegistrySHA256       string `json:"registry_sha256"`
	Registry             []byte `json:"registry"`
	Signature            string `json:"signature"`
}

type CredentialReceipt struct {
	Version         uint64            `json:"version"`
	DatabaseID      string            `json:"database_id"`
	PartitionID     string            `json:"partition_id"`
	RequestSHA256   string            `json:"request_sha256"`
	PreviousSHA256  string            `json:"previous_sha256"`
	State           CredentialState   `json:"state"`
	Customer        *CustomerEnvelope `json:"customer,omitempty"`
	ControllerKeyID string            `json:"controller_key_id"`
	Signature       string            `json:"signature"`
}
