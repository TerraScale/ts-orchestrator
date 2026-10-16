package bootstrap

import (
	"crypto/ed25519"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// SlotRetirementDisposition is the only disposition a managed controller slot
// replacement accepts: the prior instance is gone and cannot rejoin.
const SlotRetirementDisposition = "instance-retired"

// MaxSlotRetirementLifetime bounds a signed retirement. The ledger accepts the
// general manifest lifetime; replacement evidence must be acted on promptly.
const MaxSlotRetirementLifetime = 24 * time.Hour

// SlotRetirementCandidate returns the unsigned retirement evidence that must
// be reviewed and root-signed before a completed managed peer slot may advance
// to its next attempt. It binds the exact prior attempt, result and instance.
// The founder's delegated ledger key cannot sign this domain, so replacement
// always needs offline root authority for the specific instance it retires.
func SlotRetirementCandidate(state SlotState, observedEvidenceDigest, fencingAuthority string,
	observedAt time.Time,
) (RetirementEvidence, error) {
	if state.Result == nil || state.ResultRecord == nil || state.Head.ResultDigest == "" ||
		state.Head.ResultDigest != state.ResultRecord.SHA256 || state.Intent.Mode != IntentModeManaged ||
		state.Intent.SchemaVersion != 1 || state.Head.SchemaVersion != 1 || state.Result.SchemaVersion != 1 ||
		state.Head.Attempt != state.Intent.Attempt ||
		state.Result.InstanceOCID == "" || !validDigest(observedEvidenceDigest) || fencingAuthority == "" ||
		len(fencingAuthority) > 256 || !validFounderNow(observedAt) {
		return RetirementEvidence{}, fmt.Errorf("%w: only a completed managed peer attempt can be retired", ErrRetirementInvalid)
	}
	return RetirementEvidence{SchemaVersion: 1, DeploymentID: state.Intent.DeploymentID, Cell: state.Intent.Cell,
		Environment: state.Intent.Environment, Role: roleController, Slot: state.Intent.Slot,
		PreviousAttempt: state.Head.Attempt, PreviousGeneration: state.Head.Generation,
		PreviousResultDigest: state.Head.ResultDigest, PriorInstanceOCID: state.Result.InstanceOCID,
		PriorCreateKey: state.Intent.CreateKey, Disposition: SlotRetirementDisposition,
		ObservedEvidenceDigest: observedEvidenceDigest, FencingAuthority: fencingAuthority,
		ObservedAt: observedAt.Round(0).UTC().Truncate(time.Second)}, nil
}

// ValidateSlotRetirementCandidate checks the structural invariants that the
// ledger later re-verifies with the signature and the exact current HEAD.
func ValidateSlotRetirementCandidate(evidence RetirementEvidence) error {
	if evidence.SchemaVersion != 1 || evidence.Role != roleController || evidence.Slot == "" ||
		!ledgerIDPattern.MatchString(evidence.Slot) || evidence.DeploymentID == "" || evidence.Cell == "" ||
		evidence.Environment == "" || evidence.PreviousAttempt == 0 || evidence.PreviousGeneration == 0 ||
		!validDigest(evidence.PreviousResultDigest) || !isOCID(evidence.PriorInstanceOCID, "instance") ||
		evidence.PriorCreateKey == "" || evidence.Disposition != SlotRetirementDisposition ||
		evidence.CoordinatorHandoffDigest != "" || !validDigest(evidence.ObservedEvidenceDigest) ||
		evidence.FencingAuthority == "" || !validFounderNow(evidence.ObservedAt) {
		return fmt.Errorf("%w: retirement candidate is incomplete", ErrRetirementInvalid)
	}
	return nil
}

// SignSlotRetirement signs reviewed managed-slot retirement evidence with the
// offline root key in the exact ledger scope.
func SignSlotRetirement(evidence RetirementEvidence, issuedAt, expiresAt time.Time,
	rootPrivateKey ed25519.PrivateKey,
) (trust.Envelope, error) {
	if err := ValidateSlotRetirementCandidate(evidence); err != nil {
		return trust.Envelope{}, err
	}
	issuedAt = issuedAt.Round(0).UTC()
	expiresAt = expiresAt.Round(0).UTC()
	if !validFounderNow(issuedAt) || !expiresAt.After(issuedAt) || issuedAt.Before(evidence.ObservedAt) ||
		expiresAt.Sub(issuedAt) > MaxSlotRetirementLifetime {
		return trust.Envelope{}, fmt.Errorf("%w: retirement signing interval is invalid", ErrRetirementInvalid)
	}
	payload, err := trust.EncodePayload(evidence)
	if err != nil {
		return trust.Envelope{}, err
	}
	return trust.Sign(payload, trust.Scope{Domain: domainSlotRetirement, DeploymentID: evidence.DeploymentID,
		Cell: evidence.Cell, Environment: evidence.Environment, Role: roleController, Slot: evidence.Slot},
		issuedAt, expiresAt, rootPrivateKey)
}

// DecodeSlotRetirementCandidate decodes, without verifying, the payload of a
// signed retirement envelope so a caller can route it to the matching slot.
// Only Ledger.AdvanceSlot authorizes it.
func DecodeSlotRetirementCandidate(wire []byte) (RetirementEvidence, error) {
	if len(wire) == 0 || len(wire) > maxLedgerRecordBytes {
		return RetirementEvidence{}, ErrRetirementInvalid
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil || envelope.Scope.Domain != domainSlotRetirement {
		return RetirementEvidence{}, ErrRetirementInvalid
	}
	var evidence RetirementEvidence
	if err := decodeCanonicalPayload(envelope.Payload, &evidence); err != nil {
		return RetirementEvidence{}, ErrRetirementInvalid
	}
	if err := ValidateSlotRetirementCandidate(evidence); err != nil {
		return RetirementEvidence{}, err
	}
	if envelope.Scope != (trust.Scope{Domain: domainSlotRetirement, DeploymentID: evidence.DeploymentID,
		Cell: evidence.Cell, Environment: evidence.Environment, Role: roleController, Slot: evidence.Slot}) {
		return RetirementEvidence{}, ErrRetirementInvalid
	}
	return evidence, nil
}

// ReplacementManagedPeerIntent returns the next-attempt managed intent for a
// completed peer slot whose prior instance has root-signed retirement
// evidence. It pins the same founder plan row, private IP, slot and node name
// as attempt one, so the replacement keeps the controller's NATS server name
// and raft identity. Its create key and OCI retry token are fresh per attempt.
func (verified VerifiedFounderPlan) ReplacementManagedPeerIntent(slot string, previous SlotState,
	retirementWire []byte, createdAt time.Time,
) (Intent, error) {
	return replacementManagedPeerIntent(verified, slot, previous, retirementWire, createdAt)
}

func replacementManagedPeerIntent(verified FounderPlanAuthority, slot string, previous SlotState, retirementWire []byte, createdAt time.Time) (Intent, error) {
	if !verified.IsVerified() || !validFounderNow(createdAt) || len(retirementWire) == 0 {
		return Intent{}, ErrFounderPeerAuthorization
	}
	if previous.Intent.Slot != slot || previous.Head.ResultDigest == "" || previous.Result == nil ||
		previous.Intent.SchemaVersion != 1 || previous.Head.SchemaVersion != 1 || previous.Result.SchemaVersion != 1 ||
		previous.Head.Attempt == 0 || previous.Head.Attempt == ^uint64(0) ||
		previous.Head.Generation == ^uint64(0) || previous.Intent.Mode != IntentModeManaged {
		return Intent{}, fmt.Errorf("%w: only a completed managed slot can be replaced", ErrFounderPeerAuthorization)
	}
	intent, err := verified.InitialManagedPeerIntent(slot, createdAt)
	if err != nil {
		return Intent{}, err
	}
	attempt := previous.Head.Attempt + 1
	// Replacement tokens live in their own "replace-" namespace. Reusing the
	// initial "founder-<slot>-" form would let slot "b" at attempt 2 render
	// exactly the attempt-one token of a slot named "b-a2" under the same
	// plan. Read from the right, "-a<attempt>-<digest>" is unambiguous.
	token := "replace-" + slot + "-a" + strconv.FormatUint(attempt, 10) + "-" + verified.Digest()[:24]
	if !createTokenPattern.MatchString(token) {
		return Intent{}, fmt.Errorf("%w: replacement create key is unbounded", ErrFounderPeerAuthorization)
	}
	intent.Attempt, intent.Generation = attempt, previous.Head.Generation+1
	intent.RetirementDigest = objectDigest(retirementWire)
	intent.CreateKey, intent.RetryToken = token, token
	intent.NetworkSecurityGroupIDs = slices.Clone(intent.NetworkSecurityGroupIDs)
	return intent, nil
}

// ReplacementSlotHead returns the unsigned successor HEAD that AdvanceSlot
// requires for intentWire after the completed previous attempt.
func ReplacementSlotHead(previous SlotState, intent Intent, intentWire, retirementWire []byte) (SlotHead, error) {
	if intent.SchemaVersion != 1 || previous.Intent.SchemaVersion != 1 || previous.Head.SchemaVersion != 1 ||
		previous.Head.ResultDigest == "" || intent.Attempt != previous.Head.Attempt+1 ||
		intent.Generation != previous.Head.Generation+1 || len(intentWire) == 0 || len(retirementWire) == 0 {
		return SlotHead{}, fmt.Errorf("%w: successor head does not follow the completed attempt", ErrRetirementInvalid)
	}
	previousCandidate := ""
	if previous.Intent.Mode == IntentModeManaged {
		if !validDigest(previous.Head.CandidateDigest) {
			return SlotHead{}, fmt.Errorf("%w: completed managed predecessor requires its candidate pin", ErrRetirementInvalid)
		}
		previousCandidate = previous.Head.CandidateDigest
	}
	return SlotHead{SchemaVersion: 1, DeploymentID: intent.DeploymentID, Cell: intent.Cell,
		Environment: intent.Environment, Role: intent.Role, Slot: intent.Slot, Attempt: intent.Attempt,
		Generation: intent.Generation, IntentDigest: objectDigest(intentWire),
		PreviousAttempt: previous.Head.Attempt, PreviousGeneration: previous.Head.Generation,
		PreviousIntentDigest: previous.Head.IntentDigest, PreviousResultDigest: previous.Head.ResultDigest,
		PreviousCandidateDigest: previousCandidate, RetirementDigest: objectDigest(retirementWire)}, nil
}
