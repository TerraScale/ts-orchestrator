package authority

// IdentityResetGlobalLease pins the home region's opaque global predecessor.
// Its root-signed replacement uses the same transaction and deployment.
type IdentityResetGlobalLease struct {
	PreviousSequence uint64 `json:"previous_sequence"`
	PreviousSHA256   string `json:"previous_sha256"`
	EpochFloor       uint64 `json:"epoch_floor"`
	Epoch            uint64 `json:"epoch"`
}
