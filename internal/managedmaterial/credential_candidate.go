package managedmaterial

// CredentialCandidate contains public proposed CAS bytes and their exact
// predecessor. It grants no authority before the actual Runtime commits it.
type CredentialCandidate struct {
	Reply             CredentialReply `json:"reply"`
	ExpectedSequence  uint64          `json:"expected_sequence"`
	CommittedSequence uint64          `json:"committed_sequence,omitzero"`
}
