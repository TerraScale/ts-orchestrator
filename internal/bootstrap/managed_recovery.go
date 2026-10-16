package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const managedPeerProgressLifetime = 5 * time.Minute

// RecordManagedPeerCandidate pins the exact instance returned from the
// idempotent launch before the caller observes it or writes peer proofs. Once
// this fixed key exists, this attempt can never receive another launch token.
func (ledger *Ledger) RecordManagedPeerCandidate(ctx context.Context, scope BootstrapScope,
	candidateWire []byte, signProgress ManagedPeerProgressSigner, refresh ManagedPeerRecoveryRefresh,
) error {
	if err := ledger.validateAnchorScope(scope); err != nil {
		return err
	}
	baseline, err := ledger.readSlotForManagedPeerRecovery(ctx, scope)
	if err != nil {
		return err
	}
	if baseline.Intent.Mode != IntentModeManaged || baseline.Intent.SchemaVersion != 1 || baseline.Head.SchemaVersion != 1 {
		return ErrFounderPlanRequired
	}
	candidate, candidateEnvelope, err := ledger.decodeManagedPeerCandidate(scope, candidateWire, true)
	if err != nil {
		return err
	}
	if err := validateManagedPeerCandidateForIntent(candidate, baseline.Intent, baseline.IntentRecord.SHA256,
		baseline.Intent.FounderPlanSHA256, baseline.Intent.PeerRowDigest, baseline.Intent.ManifestDigest); err != nil {
		return err
	}
	if err := ledger.validateCurrentAuthority(); err != nil {
		return err
	}
	peer, err := ledger.refreshManagedPeer(ctx, scope, baseline, refresh)
	if err != nil {
		return err
	}
	if peer.recovery.phase != ManagedPeerRecoveryClean && peer.recovery.phase != ManagedPeerRecoveryManifestOnly &&
		peer.recovery.phase != ManagedPeerRecoveryCandidateOnly {
		return ErrRecordAuthorization
	}
	if peer.recovery.phase == ManagedPeerRecoveryCandidateOnly {
		stored := peer.recovery.state.CandidateRecord
		if stored == nil || !bytes.Equal(stored.Bytes, candidateWire) {
			return ErrImmutableConflict
		}
		if progressRecord := peer.recovery.state.ProgressRecord; progressRecord != nil {
			return nil
		}
	}
	if !peer.recovery.AuthorizationTime().Before(candidateEnvelope.ExpiresAt) {
		return fmt.Errorf("%w: candidate signature is not current at the refreshed recovery clock", ErrRecordAuthorization)
	}
	candidateRecord, err := ledger.createOrRead(ctx, scope, baseline.Head.Attempt, ledgerCandidate, candidateWire)
	if err != nil {
		return err
	}
	if err := validateStoredInterval(candidateRecord, candidateEnvelope); err != nil {
		return err
	}
	if err := ledger.validateStoredBeforeAnchorExpiry(candidateRecord); err != nil {
		return err
	}
	baseline.Candidate = &candidate
	baseline.CandidateRecord = &candidateRecord
	_, progress, err := ledger.readManagedPeerProgress(ctx, scope, baseline.Head.Attempt, false)
	if err == nil {
		if progress.CandidateDigest != candidateRecord.SHA256 {
			return ErrImmutableConflict
		}
		return nil
	}
	if !errors.Is(err, ErrRecordMissing) {
		return err
	}
	peer, err = ledger.refreshManagedPeer(ctx, scope, baseline, refresh)
	if err != nil {
		return err
	}
	if peer.recovery.phase != ManagedPeerRecoveryCandidateOnly || peer.recovery.state.CandidateRecord == nil ||
		peer.recovery.state.CandidateRecord.SHA256 != candidateRecord.SHA256 {
		return ErrRecordAuthorization
	}
	progress = ManagedPeerProgress{
		SchemaVersion: 1, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
		Environment: ledger.config.Environment, Role: roleController, Slot: scope.Slot,
		Attempt: baseline.Head.Attempt, Generation: baseline.Head.Generation, Sequence: 1,
		CandidateDigest: candidateRecord.SHA256, Phase: ManagedPeerProgressCandidate,
	}
	progressWire, progressEnvelope, err := ledger.signManagedPeerProgress(peer, progress, signProgress)
	if err != nil {
		return err
	}
	peer, err = ledger.refreshManagedPeer(ctx, scope, baseline, refresh)
	if err != nil {
		return err
	}
	if err := ensureCandidateAndProgressBaseline(peer, candidateRecord.SHA256, 0, ""); err != nil {
		return err
	}
	effectCtx, cancel, err := managedPeerEffectContext(ctx, peer, time.Time{}, progressEnvelope.ExpiresAt)
	if err != nil {
		return err
	}
	defer cancel()
	_, _, err = ledger.writeManagedPeerProgress(effectCtx, scope, baseline.Head.Attempt, "", progress, progressWire, progressEnvelope)
	return err
}

func (ledger *Ledger) signManagedPeerProgress(peer VerifiedFounderPeer, progress ManagedPeerProgress,
	signer ManagedPeerProgressSigner,
) ([]byte, trust.Envelope, error) {
	if signer == nil || !peer.IsVerified() || peer.recovery == nil || !peer.recovery.verified {
		return nil, trust.Envelope{}, ErrRecordAuthorization
	}
	issuedAt := peer.recovery.serverDate.UTC()
	expiresAt := earlierTime(issuedAt.Add(managedPeerProgressLifetime), peer.EffectDeadline())
	if !ledger.config.AnchorExpiresAt.IsZero() {
		expiresAt = earlierTime(expiresAt, ledger.config.AnchorExpiresAt)
	}
	if !issuedAt.Before(expiresAt) {
		return nil, trust.Envelope{}, ErrFounderPlanExpired
	}
	wire, err := signer(progress, issuedAt, expiresAt)
	if err != nil {
		return nil, trust.Envelope{}, err
	}
	envelope, payload, err := ledger.signedPayload(wire, peer.recovery.scope, domainBootstrapProgress, true)
	if err != nil {
		return nil, trust.Envelope{}, err
	}
	var signedProgress ManagedPeerProgress
	if err := decodeCanonicalPayload(payload, &signedProgress); err != nil || !sameManagedPeerProgress(progress, signedProgress) ||
		!envelope.IssuedAt.Equal(issuedAt) || !envelope.ExpiresAt.Equal(expiresAt) {
		return nil, trust.Envelope{}, fmt.Errorf("%w: progress signer returned bytes outside the requested scope, sequence, or time bounds", ErrRecordAuthorization)
	}
	if _, _, err := ledger.decodeManagedPeerProgress(peer.recovery.scope, wire, true); err != nil {
		return nil, trust.Envelope{}, err
	}
	return bytes.Clone(wire), envelope, nil
}

func sameManagedPeerProgress(left, right ManagedPeerProgress) bool {
	return left.SchemaVersion == right.SchemaVersion && left.DeploymentID == right.DeploymentID &&
		left.Cell == right.Cell && left.Environment == right.Environment && left.Role == right.Role &&
		left.Slot == right.Slot && left.Attempt == right.Attempt && left.Generation == right.Generation &&
		left.Sequence == right.Sequence && left.CandidateDigest == right.CandidateDigest && left.Phase == right.Phase &&
		left.PendingProofKind == right.PendingProofKind && left.PendingProofDigest == right.PendingProofDigest &&
		bytes.Equal(left.PendingProofWire, right.PendingProofWire)
}

func ensureCandidateAndProgressBaseline(peer VerifiedFounderPeer, candidateDigest string,
	sequence uint64, etag string,
) error {
	if !peer.IsVerified() || peer.recovery == nil || !peer.recovery.verified ||
		peer.recovery.state.CandidateRecord == nil || peer.recovery.state.CandidateRecord.SHA256 != candidateDigest {
		return ErrRecordAuthorization
	}
	progressRecord := peer.recovery.state.ProgressRecord
	if sequence == 0 {
		if progressRecord != nil {
			return ErrSlotHeadConflict
		}
		return nil
	}
	if progressRecord == nil || progressRecord.ETag != etag || peer.recovery.state.Progress == nil ||
		peer.recovery.state.Progress.Sequence != sequence || peer.recovery.state.Progress.CandidateDigest != candidateDigest {
		return ErrSlotHeadConflict
	}
	return nil
}

func (ledger *Ledger) stageManagedPeerProof(ctx context.Context, scope BootstrapScope, attempt uint64,
	candidateDigest string, phase ManagedPeerProgressPhase, proofKind string, proofWire []byte,
	signer ManagedPeerProgressSigner, refresh func() (VerifiedFounderPeer, error),
) error {
	if !validDigest(candidateDigest) || proofKind != "receipt" && proofKind != "result" ||
		phase != ManagedPeerProgressReceipt && phase != ManagedPeerProgressResult ||
		phase == ManagedPeerProgressReceipt && proofKind != "receipt" ||
		phase == ManagedPeerProgressResult && proofKind != "result" || len(proofWire) == 0 || len(proofWire) > ledger.maxRecord {
		return ErrInvalidRecord
	}
	proofDigest := objectDigest(proofWire)
	for {
		peer, err := refresh()
		if err != nil {
			return err
		}
		state := peer.recovery.state
		if state.CandidateRecord == nil || state.CandidateRecord.SHA256 != candidateDigest {
			return ErrRecordAuthorization
		}
		prior := state.Progress
		priorRecord := state.ProgressRecord
		if prior != nil && prior.Phase == phase && prior.PendingProofKind == proofKind &&
			prior.PendingProofDigest == proofDigest && bytes.Equal(prior.PendingProofWire, proofWire) {
			return nil
		}
		if prior == nil {
			candidateProgress := ManagedPeerProgress{
				SchemaVersion: 1, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
				Environment: ledger.config.Environment, Role: roleController, Slot: scope.Slot,
				Attempt: attempt, Generation: state.Intent.Generation, Sequence: 1,
				CandidateDigest: candidateDigest, Phase: ManagedPeerProgressCandidate,
			}
			candidateWire, candidateEnvelope, signErr := ledger.signManagedPeerProgress(peer, candidateProgress, signer)
			if signErr != nil {
				return signErr
			}
			fresh, refreshErr := refresh()
			if refreshErr != nil {
				return refreshErr
			}
			if err := ensureCandidateAndProgressBaseline(fresh, candidateDigest, 0, ""); err != nil {
				if errors.Is(err, ErrSlotHeadConflict) {
					continue
				}
				return err
			}
			effectCtx, cancel, effectErr := managedPeerEffectContext(ctx, fresh, time.Time{}, candidateEnvelope.ExpiresAt)
			if effectErr != nil {
				return effectErr
			}
			_, _, writeErr := ledger.writeManagedPeerProgress(effectCtx, scope, attempt, "", candidateProgress,
				candidateWire, candidateEnvelope)
			cancel()
			if writeErr != nil {
				if errors.Is(writeErr, ErrSlotHeadConflict) {
					continue
				}
				return writeErr
			}
			continue
		}
		if priorRecord == nil || prior.CandidateDigest != candidateDigest || prior.Attempt != attempt ||
			prior.Generation != state.Intent.Generation {
			return ErrRecordAuthorization
		}
		priorRank := managedPeerProgressRank(prior.Phase)
		nextRank := managedPeerProgressRank(phase)
		if priorRank == 0 || nextRank == 0 || nextRank > priorRank+1 || nextRank < priorRank && !state.quarantined {
			return ErrRecordAuthorization
		}
		if !state.quarantined && prior.Phase == phase {
			return ErrImmutableConflict
		}
		if prior.Sequence == ^uint64(0) {
			return fmt.Errorf("%w: managed-peer progress sequence is exhausted", ErrInvalidRecord)
		}
		progress := ManagedPeerProgress{
			SchemaVersion: 1, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
			Environment: ledger.config.Environment, Role: roleController, Slot: scope.Slot,
			Attempt: attempt, Generation: state.Intent.Generation, Sequence: prior.Sequence + 1,
			CandidateDigest: candidateDigest, Phase: phase, PendingProofKind: proofKind,
			PendingProofDigest: proofDigest, PendingProofWire: bytes.Clone(proofWire),
		}
		progressWire, progressEnvelope, signErr := ledger.signManagedPeerProgress(peer, progress, signer)
		if signErr != nil {
			return signErr
		}
		fresh, refreshErr := refresh()
		if refreshErr != nil {
			return refreshErr
		}
		if err := ensureCandidateAndProgressBaseline(fresh, candidateDigest, prior.Sequence, priorRecord.ETag); err != nil {
			if errors.Is(err, ErrSlotHeadConflict) {
				continue
			}
			return err
		}
		effectCtx, cancel, effectErr := managedPeerEffectContext(ctx, fresh, time.Time{}, progressEnvelope.ExpiresAt)
		if effectErr != nil {
			return effectErr
		}
		_, _, writeErr := ledger.writeManagedPeerProgress(effectCtx, scope, attempt, priorRecord.ETag,
			progress, progressWire, progressEnvelope)
		cancel()
		if errors.Is(writeErr, ErrSlotHeadConflict) {
			continue
		}
		return writeErr
	}
}

func managedPeerProgressRank(phase ManagedPeerProgressPhase) int {
	switch phase {
	case ManagedPeerProgressCandidate:
		return 1
	case ManagedPeerProgressReceipt:
		return 2
	case ManagedPeerProgressResult:
		return 3
	default:
		return 0
	}
}

func (ledger *Ledger) readManagedPeerProgress(ctx context.Context, scope BootstrapScope, attempt uint64,
	current bool,
) (StoredRecord, ManagedPeerProgress, error) {
	if err := validateLedgerScope(scope); err != nil {
		return StoredRecord{}, ManagedPeerProgress{}, err
	}
	record, err := ledger.readObject(ctx, ledger.config.HeadBucket, ledger.progressObjectName(scope, attempt))
	if err != nil {
		return StoredRecord{}, ManagedPeerProgress{}, err
	}
	progress, envelope, err := ledger.decodeManagedPeerProgress(scope, record.Bytes, current)
	if err != nil {
		return StoredRecord{}, ManagedPeerProgress{}, err
	}
	if progress.Attempt != attempt {
		return StoredRecord{}, ManagedPeerProgress{}, ErrRecordAuthorization
	}
	_ = envelope // The recovery reader classifies stale progress as quarantined.
	return record, progress, nil
}

func (ledger *Ledger) writeManagedPeerProgress(ctx context.Context, scope BootstrapScope, attempt uint64,
	ifMatch string, expected ManagedPeerProgress, body []byte, envelope trust.Envelope,
) (StoredRecord, ManagedPeerProgress, error) {
	if ledger.readOnly {
		return StoredRecord{}, ManagedPeerProgress{}, ErrRecordAuthorization
	}
	decoded, _, err := ledger.decodeManagedPeerProgress(scope, body, true)
	if err != nil || !sameManagedPeerProgress(decoded, expected) {
		return StoredRecord{}, ManagedPeerProgress{}, ErrRecordAuthorization
	}
	if err := ledger.validateCurrentAuthority(); err != nil {
		return StoredRecord{}, ManagedPeerProgress{}, err
	}
	objectName := ledger.progressObjectName(scope, attempt)
	length := int64(len(body))
	digest := sha256.Sum256(body)
	digestHeader := base64.StdEncoding.EncodeToString(digest[:])
	ifNoneMatch := "*"
	request := objectstorage.PutObjectRequest{
		NamespaceName: new(ledger.config.Namespace), BucketName: new(ledger.config.HeadBucket),
		ObjectName: new(objectName), PutObjectBody: io.NopCloser(bytes.NewReader(body)),
		ContentLength: &length, ContentType: new("application/json"), OpcSseKmsKeyId: new(ledger.config.HeadKMSKeyID),
		OpcChecksumAlgorithm: objectstorage.PutObjectOpcChecksumAlgorithmSha256, OpcContentSha256: &digestHeader,
	}
	if ifMatch == "" {
		request.IfNoneMatch = &ifNoneMatch
	} else {
		request.IfMatch = &ifMatch
	}
	if err := ctx.Err(); err != nil {
		return StoredRecord{}, ManagedPeerProgress{}, err
	}
	response, putErr, putAttempted := ledger.putObjectAfterTimestampBoundary(ctx, request, envelope)
	if putErr != nil && (!putAttempted || !shouldReadAfterPutError(putErr)) {
		return StoredRecord{}, ManagedPeerProgress{}, fmt.Errorf("write managed-peer progress CAS: %w", putErr)
	}
	stored, readErr := ledger.readObject(ctx, ledger.config.HeadBucket, objectName)
	if readErr != nil {
		return StoredRecord{}, ManagedPeerProgress{}, fmt.Errorf("%w: managed-peer progress write: %v; exact-key read: %w", ErrOutcomeUnknown, putErr, readErr)
	}
	progress, storedEnvelope, err := ledger.decodeManagedPeerProgress(scope, stored.Bytes, false)
	if err != nil || !sameManagedPeerProgress(progress, expected) || !bytes.Equal(stored.Bytes, body) {
		return StoredRecord{}, ManagedPeerProgress{}, ErrSlotHeadConflict
	}
	if putErr == nil && response.ETag != nil && *response.ETag != "" && stored.ETag != *response.ETag {
		return StoredRecord{}, ManagedPeerProgress{}, ErrSlotHeadConflict
	}
	if err := validateStoredInterval(stored, storedEnvelope); err != nil {
		return StoredRecord{}, ManagedPeerProgress{}, err
	}
	if err := ledger.validateStoredBeforeAnchorExpiry(stored); err != nil {
		return StoredRecord{}, ManagedPeerProgress{}, err
	}
	stored.Created = ifMatch == "" && putErr == nil
	return stored, progress, nil
}

func (ledger *Ledger) progressObjectName(scope BootstrapScope, attempt uint64) string {
	return ledger.managedPeerObjectName(scope, attempt, "progress.json")
}

func (ledger *Ledger) readManagedPeerState(ctx context.Context, scope BootstrapScope, state SlotState,
	allowQuarantine bool,
) (SlotState, error) {
	if !allowQuarantine && state.quarantined {
		return SlotState{}, ErrRecordAuthorization
	}
	manifestRecord, manifestErr := ledger.read(ctx, scope, state.Head.Attempt, ledgerManifest)
	if manifestErr != nil && !errors.Is(manifestErr, ErrRecordMissing) {
		return SlotState{}, manifestErr
	}
	if manifestErr == nil {
		manifest, envelope, err := ledger.verifyHistoricalIntentManifest(scope, state.Intent, manifestRecord.Bytes)
		if err != nil || manifestRecord.SHA256 != state.Intent.ManifestDigest {
			return SlotState{}, ErrRecordAuthorization
		}
		manifestValue := manifest.Manifest()
		state.Manifest = &manifestValue
		state.ManifestRecord = &manifestRecord
		if err := validateStoredInterval(manifestRecord, envelope); err != nil ||
			ledger.validateStoredBeforeAnchorExpiry(manifestRecord) != nil {
			state.quarantined = true
		}
	}

	candidateRecord, candidateErr := ledger.read(ctx, scope, state.Head.Attempt, ledgerCandidate)
	if candidateErr != nil && !errors.Is(candidateErr, ErrRecordMissing) {
		return SlotState{}, candidateErr
	}
	if candidateErr == nil {
		candidate, _, err := ledger.decodeManagedPeerCandidate(scope, candidateRecord.Bytes, false)
		if err != nil || validateManagedPeerCandidateForIntent(candidate, state.Intent, state.IntentRecord.SHA256,
			state.Intent.FounderPlanSHA256, state.Intent.PeerRowDigest, state.Intent.ManifestDigest) != nil {
			return SlotState{}, ErrRecordAuthorization
		}
		state.Candidate, state.CandidateRecord = &candidate, &candidateRecord
		if state.Head.CandidateDigest != "" && state.Head.CandidateDigest != candidateRecord.SHA256 {
			return SlotState{}, ErrRecordAuthorization
		}
	} else if state.Head.CandidateDigest != "" {
		return SlotState{}, fmt.Errorf("%w: HEAD candidate digest has no fixed candidate object", ErrRecordAuthorization)
	}

	progressRecord, progress, progressErr := ledger.readManagedPeerProgress(ctx, scope, state.Head.Attempt, false)
	if progressErr != nil && !errors.Is(progressErr, ErrRecordMissing) {
		return SlotState{}, progressErr
	}
	if progressErr == nil {
		if state.CandidateRecord == nil || progress.CandidateDigest != state.CandidateRecord.SHA256 ||
			progress.Generation != state.Intent.Generation {
			return SlotState{}, fmt.Errorf("%w: progress does not bind the fixed candidate and active intent", ErrRecordAuthorization)
		}
		state.Progress, state.ProgressRecord = &progress, &progressRecord
		progressEnvelope, err := trust.DecodeEnvelope(progressRecord.Bytes)
		completedResult := state.Head.ResultDigest != "" && progress.Phase == ManagedPeerProgressResult &&
			progress.PendingProofDigest == state.Head.ResultDigest
		if err != nil || validateStoredInterval(progressRecord, progressEnvelope) != nil ||
			!ledger.now().Before(progressEnvelope.ExpiresAt) && !completedResult {
			state.quarantined = true
		}
	}
	if state.Head.ResultDigest != "" && (state.CandidateRecord == nil || progressErr != nil) {
		return SlotState{}, fmt.Errorf("%w: completed HEAD is missing its signed candidate or progress proof", ErrRecordAuthorization)
	}

	var resultDigest string
	var resultWire []byte
	if progressErr == nil && progress.Phase == ManagedPeerProgressResult &&
		(state.Head.ResultDigest == "" || progress.PendingProofDigest != state.Head.ResultDigest) {
		resultDigest = progress.PendingProofDigest
		resultWire = bytes.Clone(progress.PendingProofWire)
		if state.Head.ResultDigest != "" {
			// The signed progress CAS proposes a replacement proof set for a
			// completed HEAD. It remains quarantined until fresh authority
			// reobserves the pinned instance and CASes the matching HEAD.
			state.quarantined = true
		}
	} else if state.Head.ResultDigest != "" {
		resultDigest = state.Head.ResultDigest
	}
	if resultDigest != "" {
		resultRecord, err := ledger.readContent(ctx, scope, state.Head.Attempt, ledgerResult, resultDigest)
		if err != nil && len(resultWire) == 0 {
			return SlotState{}, fmt.Errorf("read content-addressed managed result: %w", err)
		}
		resultStored := err == nil
		if err == nil && resultRecord.SHA256 != resultDigest {
			return SlotState{}, ErrRecordAuthorization
		}
		if err != nil {
			resultRecord = StoredRecord{Bytes: resultWire, SHA256: resultDigest}
		}
		resultEnvelope, envelopeErr := trust.DecodeEnvelope(resultRecord.Bytes)
		result, decodeErr := ledger.decodeResult(scope, resultRecord.Bytes, false)
		if envelopeErr != nil || decodeErr != nil || validateResultForIntent(result, state.Intent, state.IntentRecord.SHA256) != nil ||
			result.Mode != IntentModeManaged || result.SeedReceiptDigest != "" {
			return SlotState{}, fmt.Errorf("%w: content-addressed result does not match the active intent", ErrRecordAuthorization)
		}
		if resultStored {
			state.ResultRecord = &resultRecord
			if validateStoredInterval(resultRecord, resultEnvelope) != nil || ledger.validateStoredBeforeAnchorExpiry(resultRecord) != nil ||
				validateResultClock(result, resultRecord, ledger.config.TrustPolicy.ClockSkew) != nil {
				state.quarantined = true
			}
		} else if state.Head.ResultDigest != "" {
			state.quarantined = true
		}
		state.Result = &result
		if state.Head.ResultDigest != "" && state.Head.ResultDigest != resultDigest {
			state.quarantined = true
		}
	}

	var receiptDigest string
	var receiptWire []byte
	if state.Result != nil {
		receiptDigest = state.Result.PeerReceiptDigest
		if progressErr == nil && progress.Phase == ManagedPeerProgressReceipt &&
			progress.PendingProofDigest != receiptDigest {
			// A quarantined repair may stage a fresh receipt before its matching
			// replacement result. Do not pair that receipt with the old HEAD
			// result while recovery is in progress.
			state.Result = nil
			state.ResultRecord = nil
			state.quarantined = true
			receiptDigest = progress.PendingProofDigest
			receiptWire = bytes.Clone(progress.PendingProofWire)
		}
	} else if progressErr == nil && progress.Phase == ManagedPeerProgressReceipt {
		receiptDigest = progress.PendingProofDigest
		receiptWire = bytes.Clone(progress.PendingProofWire)
	}
	if receiptDigest != "" {
		receiptRecord, err := ledger.readContent(ctx, scope, state.Head.Attempt, ledgerPeerReceipt, receiptDigest)
		if err != nil && len(receiptWire) == 0 {
			return SlotState{}, fmt.Errorf("read content-addressed managed receipt: %w", err)
		}
		receiptStored := err == nil
		if err == nil && receiptRecord.SHA256 != receiptDigest {
			return SlotState{}, ErrRecordAuthorization
		}
		if err != nil {
			receiptRecord = StoredRecord{Bytes: receiptWire, SHA256: receiptDigest}
		}
		receiptEnvelope, err := trust.DecodeEnvelope(receiptRecord.Bytes)
		if err != nil {
			return SlotState{}, ErrRecordAuthorization
		}
		receipt, err := ReceiptPayload(receiptEnvelope.Payload)
		if err != nil || validatePeerReceiptForIntent(receipt, state.Intent, state.IntentRecord.SHA256) != nil {
			return SlotState{}, ErrRecordAuthorization
		}
		if state.Manifest != nil {
			facts, factsErr := instanceFactsFromReceipt(receipt, *state.Manifest)
			if factsErr != nil {
				return SlotState{}, ErrRecordAuthorization
			}
			historicalManifest, _, manifestErr := ledger.verifyHistoricalIntentManifest(scope, state.Intent, state.ManifestRecord.Bytes)
			if manifestErr != nil {
				return SlotState{}, ErrRecordAuthorization
			}
			if _, err := VerifyHistoricalPeerReceipt(receiptEnvelope, historicalManifest, facts, ledger.config.TrustPolicy); err != nil {
				return SlotState{}, ErrRecordAuthorization
			}
		}
		state.PeerReceipt = &receipt
		if receiptStored {
			state.PeerReceiptRecord = &receiptRecord
			if validateStoredInterval(receiptRecord, receiptEnvelope) != nil || ledger.validateStoredBeforeAnchorExpiry(receiptRecord) != nil {
				state.quarantined = true
			}
		}
		if state.Candidate != nil && receipt.InstanceOCID != state.Candidate.InstanceOCID {
			return SlotState{}, fmt.Errorf("%w: receipt identifies a different instance than the candidate pin", ErrRecordAuthorization)
		}
		if state.Result != nil && validatePeerReceiptForResult(receipt, *state.Result) != nil {
			return SlotState{}, ErrRecordAuthorization
		}
	}

	if state.Result != nil {
		if state.Manifest == nil || state.PeerReceipt == nil ||
			validatePeerReceiptForResult(*state.PeerReceipt, *state.Result) != nil {
			return SlotState{}, fmt.Errorf("%w: result lacks its exact manifest and receipt", ErrRecordAuthorization)
		}
		if state.ResultRecord != nil && state.PeerReceiptRecord != nil && state.ManifestRecord != nil {
			if err := validateCompletionWriteOrder(*state.ManifestRecord, *state.PeerReceiptRecord, *state.ResultRecord); err != nil {
				return SlotState{}, err
			}
			if validateResultStoredWithinProofs(*state.ManifestRecord, *state.PeerReceiptRecord, *state.ResultRecord,
				ledger.config.AnchorExpiresAt) != nil {
				state.quarantined = true
			}
		}
		if state.Head.ResultDigest != "" && state.Head.CandidateDigest != state.CandidateRecord.SHA256 {
			return SlotState{}, ErrRecordAuthorization
		}
		// A staged result is not yet durable positive evidence. It can be
		// resumed only while the exact pinned instance observation remains
		// fresh; persisted result-ready and complete states are replayable.
		if state.ResultRecord == nil && validateManagedPeerObservationFreshness(*state.Result, ledger.now().UTC()) != nil {
			state.quarantined = true
		}
	}
	if progressErr == nil && progress.Phase == ManagedPeerProgressReceipt && state.PeerReceiptRecord != nil &&
		progress.PendingProofDigest != state.PeerReceiptRecord.SHA256 {
		if !state.quarantined {
			return SlotState{}, ErrRecordAuthorization
		}
	}
	if progressErr == nil && progress.Phase == ManagedPeerProgressResult && state.ResultRecord != nil &&
		progress.PendingProofDigest != state.ResultRecord.SHA256 {
		if !state.quarantined {
			return SlotState{}, ErrRecordAuthorization
		}
	}
	if state.Candidate == nil && state.Head.CandidateDigest != "" {
		return SlotState{}, ErrRecordAuthorization
	}
	if !allowQuarantine && state.quarantined {
		return SlotState{}, ErrRecordAuthorization
	}
	if state.Progress == nil && state.CandidateRecord != nil {
		// A crash may occur after the immutable candidate PUT and before the
		// first progress CAS. The fixed candidate key is enough to forbid launch.
		return state, nil
	}
	if state.Progress == nil && (state.PeerReceiptRecord != nil || state.ResultRecord != nil) {
		state.quarantined = true
	}
	return state, nil
}

func (ledger *Ledger) managedPeerObjectName(scope BootstrapScope, attempt uint64, name string) string {
	identity := sha256.Sum256([]byte(scope.Cell + "\x00controller\x00" + scope.Slot))
	objectName := "bootstrap/v1/" + scope.DeploymentID + "/" + fmt.Sprintf("%x", identity[:]) +
		fmt.Sprintf("/attempt-%020d/%s", attempt, name)
	if ledger.config.Prefix != "" {
		return ledger.config.Prefix + "/" + objectName
	}
	return objectName
}
