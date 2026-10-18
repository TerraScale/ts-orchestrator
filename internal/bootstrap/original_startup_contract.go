package bootstrap

const OriginalStartupAdmissionPurpose = "original-controller-startup/v1"

// OriginalStartupAdmissionIntent is covered by its parent foundation grant.
type OriginalStartupAdmissionIntent struct {
	Purpose               string `json:"purpose"`
	ProducerIntentSHA256  string `json:"producerIntentSha256"`
	LedgerRetentionRuleID string `json:"ledgerRetentionRuleId"`
}
