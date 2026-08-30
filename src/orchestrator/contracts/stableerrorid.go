// Port of src/TerraScale.Orchestrator/Contracts/StableIdentifiers/StableErrorId.cs.
package contracts

// StableErrorId is a permanent stable-error identifier from the GOAL.md
// "Stable contract identifiers" table. Identifiers form a closed set: only
// values registered in StableIdentifierRegistry construct successfully, the
// canonical text of a live identifier never changes in place, and a
// replacement decision marks the retired identifier superseded and adds a new
// identifier instead of editing either one. Code is the wire error-code string
// surface (for example ERR-ORCH-OUTCOME-UNKNOWN) so code sites can adopt the
// typed identifier incrementally wherever a raw error string is emitted today.
type StableErrorId struct {
	Value string
}

// Code is the stable error code string surface, equal to Value.
func (i StableErrorId) Code() string { return i.Value }

// IsRegistered reports whether this value is one of the registered stable errors.
func (i StableErrorId) IsRegistered() bool {
	_, ok := StableIdentifierRegistry.tryGetStableErrorText(i)
	return ok
}

// CanonicalText returns the verbatim GOAL.md text; it panics for an
// unregistered identifier, mirroring the C# InvalidOperationException.
func (i StableErrorId) CanonicalText() string {
	if text, ok := StableIdentifierRegistry.tryGetStableErrorText(i); ok {
		return text
	}

	panic("Stable error " + i.Value + " is not registered.")
}

// TryGetText mirrors StableIdentifierRegistry.TryGetText(StableErrorId, out text).
func (i StableErrorId) TryGetText() (string, bool) {
	return StableIdentifierRegistry.tryGetStableErrorText(i)
}

// StableErrorIdTryCreate mirrors StableErrorId.TryCreate: only registered values pass.
func StableErrorIdTryCreate(value string) (StableErrorId, bool) {
	if _, ok := StableIdentifierRegistry.tryGetStableErrorText(StableErrorId{Value: value}); ok {
		return StableErrorId{Value: value}, true
	}

	return StableErrorId{}, false
}

// StableErrorIdTryCreateFromCode resolves a wire error code such as
// ERR-ORCH-OUTCOME-UNKNOWN.
func StableErrorIdTryCreateFromCode(code string) (StableErrorId, bool) {
	return StableErrorIdTryCreate(code)
}

// SupersededBy mirrors StableIdentifierRegistry.SupersededBy(StableErrorId).
func (i StableErrorId) SupersededBy() (StableErrorId, bool) {
	return StableIdentifierRegistry.supersededStableError(i)
}

func (i StableErrorId) String() string { return i.Code() }

// The registered stable-error identifiers (C# static properties).
var (
	StableErrorIdAuthorityUnavailable      = StableErrorId{Value: "ERR-ORCH-AUTHORITY-UNAVAILABLE"}
	StableErrorIdStaleTerm                 = StableErrorId{Value: "ERR-ORCH-STALE-TERM"}
	StableErrorIdGenerationConflict        = StableErrorId{Value: "ERR-ORCH-GENERATION-CONFLICT"}
	StableErrorIdRegionIsolated            = StableErrorId{Value: "ERR-ORCH-REGION-ISOLATED"}
	StableErrorIdOutcomeUnknown            = StableErrorId{Value: "ERR-ORCH-OUTCOME-UNKNOWN"}
	StableErrorIdOwnershipMismatch         = StableErrorId{Value: "ERR-ORCH-OWNERSHIP-MISMATCH"}
	StableErrorIdEvidenceIncomplete        = StableErrorId{Value: "ERR-ORCH-EVIDENCE-INCOMPLETE"}
	StableErrorIdCapacityUnavailable       = StableErrorId{Value: "ERR-ORCH-CAPACITY-UNAVAILABLE"}
	StableErrorIdBudgetApprovalRequired    = StableErrorId{Value: "ERR-ORCH-BUDGET-APPROVAL-REQUIRED"}
	StableErrorIdProviderLimit             = StableErrorId{Value: "ERR-ORCH-PROVIDER-LIMIT"}
	StableErrorIdTerraBaseHold             = StableErrorId{Value: "ERR-ORCH-TERRABASE-HOLD"}
	StableErrorIdArtifactDenied            = StableErrorId{Value: "ERR-ORCH-ARTIFACT-DENIED"}
	StableErrorIdRegionNotQualified        = StableErrorId{Value: "ERR-ORCH-REGION-NOT-QUALIFIED"}
	StableErrorIdRestoreGenerationConflict = StableErrorId{Value: "ERR-ORCH-RESTORE-GENERATION-CONFLICT"}
	StableErrorIdCandidateNotReady         = StableErrorId{Value: "ERR-ORCH-CANDIDATE-NOT-READY"}
	StableErrorIdWorkloadQuarantined       = StableErrorId{Value: "ERR-ORCH-WORKLOAD-QUARANTINED"}
	StableErrorIdDeletionBlocked           = StableErrorId{Value: "ERR-ORCH-DELETION-BLOCKED"}
	StableErrorIdWatchExpired              = StableErrorId{Value: "ERR-ORCH-WATCH-EXPIRED"}
)
