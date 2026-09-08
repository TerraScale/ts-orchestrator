package vmqual

// LaunchTransitionObservation carries exact finite owner admission and chained
// guest receipts. Consumers verify these bytes before advancing a launch stage.
type LaunchTransitionObservation struct {
	OwnerPublicKey     []byte   `json:"ownerPublicKey"`
	SignedPlan         []byte   `json:"signedPlan"`
	PreliminaryScope   []byte   `json:"preliminaryScope"`
	CandidateReceipts  [][]byte `json:"candidateReceipts"`
	SourceStateReceipt []byte   `json:"sourceStateReceipt"`
	CutReceipt         []byte   `json:"cutReceipt"`
	CaptureReceipt     []byte   `json:"captureReceipt"`
	RestoreReceipt     []byte   `json:"restoreReceipt"`
	JournalPath        string   `json:"journalPath"`
}
