package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync/atomic"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// LaunchAuthorization is an unforgeable in-process token returned only after
// the signed intent and signed stable-slot HEAD have been read back. Managed
// peer callers must bind it through VerifiedFounderPlan.AuthorizePeer before
// any pre-quorum OCI effect; the raw intent is deliberately not exposed.
type LaunchAuthorization struct {
	scope        BootstrapScope
	intent       Intent
	intentRecord StoredRecord
	head         SlotHead
	headRecord   StoredRecord
}

// ManagedPeerRecoveryPhase describes the exact durable stage of one managed
// peer attempt. It is intentionally independent of any selector generation.
type ManagedPeerRecoveryPhase string

const (
	ManagedPeerRecoveryClean         ManagedPeerRecoveryPhase = "clean"
	ManagedPeerRecoveryManifestOnly  ManagedPeerRecoveryPhase = "manifest-only"
	ManagedPeerRecoveryReceiptOnly   ManagedPeerRecoveryPhase = "receipt-only"
	ManagedPeerRecoveryCandidateOnly ManagedPeerRecoveryPhase = "candidate-only"
	ManagedPeerRecoveryProofStaged   ManagedPeerRecoveryPhase = "proof-staged"
	ManagedPeerRecoveryQuarantined   ManagedPeerRecoveryPhase = "quarantined"
	ManagedPeerRecoveryResultReady   ManagedPeerRecoveryPhase = "result-ready"
	ManagedPeerRecoveryComplete      ManagedPeerRecoveryPhase = "complete"
)

// ManagedPeerRecoveryAuthorization is an opaque, exact-byte view of a
// managed slot's current durable recovery state. It is minted only by the
// ledger after verifying its signed records and write order.
type ManagedPeerRecoveryAuthorization struct {
	scope      BootstrapScope
	phase      ManagedPeerRecoveryPhase
	state      SlotState
	serverDate time.Time
	observedAt time.Time
	readID     uint64
	verified   bool
}

var managedPeerRecoveryReadID atomic.Uint64

func (authorization ManagedPeerRecoveryAuthorization) Phase() ManagedPeerRecoveryPhase {
	if !authorization.verified {
		return ""
	}
	return authorization.phase
}

// State returns a defensive copy, including the exact persisted wire bytes.
func (authorization ManagedPeerRecoveryAuthorization) State() SlotState {
	if !authorization.verified {
		return SlotState{}
	}
	return cloneSlotState(authorization.state)
}

// Candidate returns the immutable candidate pin, when one has been verified.
func (authorization ManagedPeerRecoveryAuthorization) Candidate() (ManagedPeerCandidate, bool) {
	if !authorization.verified || authorization.state.Candidate == nil {
		return ManagedPeerCandidate{}, false
	}
	return *authorization.state.Candidate, true
}

// Progress returns a defensive copy of the current signed progress CAS value.
func (authorization ManagedPeerRecoveryAuthorization) Progress() (ManagedPeerProgress, bool) {
	if !authorization.verified || authorization.state.Progress == nil {
		return ManagedPeerProgress{}, false
	}
	progress := *authorization.state.Progress
	progress.PendingProofWire = bytes.Clone(progress.PendingProofWire)
	return progress, true
}

// ServerDate returns the OCI server clock from the final exact HEAD read that
// closed this recovery snapshot.
func (authorization ManagedPeerRecoveryAuthorization) ServerDate() time.Time {
	if !authorization.verified {
		return time.Time{}
	}
	return authorization.serverDate
}

// AuthorizationTime is a conservative UTC verification time derived from the
// final successful OCI read in this recovery snapshot plus local monotonic
// elapsed time. OCI Date headers have one-second precision, so it advances
// the observed value by one second before accounting for work after the read.
func (authorization ManagedPeerRecoveryAuthorization) AuthorizationTime() time.Time {
	if !authorization.verified || authorization.serverDate.IsZero() || authorization.observedAt.IsZero() {
		return time.Time{}
	}
	elapsed := time.Since(authorization.observedAt)
	if elapsed < 0 {
		return time.Time{}
	}
	return authorization.serverDate.Add(time.Second).Add(elapsed)
}

// ManagedPeerRecoveryRefresh must freshly select and verify the currently
// authoritative founder plan, then read and authorize the current ledger
// recovery state before each immutable write or HEAD compare-and-swap.
type ManagedPeerRecoveryRefresh func(context.Context) (VerifiedFounderPeer, error)

// ManagedPeerProgressSigner signs an exact progress value at caller-supplied
// bounds derived by the ledger from a fresh current recovery authorization.
type ManagedPeerProgressSigner func(ManagedPeerProgress, time.Time, time.Time) ([]byte, error)

func (authorization LaunchAuthorization) IntentDigest() string {
	return authorization.intentRecord.SHA256
}

// ServerDate is the OCI server clock observed while the intent was freshly
// read to issue this launch token.
func (authorization LaunchAuthorization) ServerDate() time.Time {
	return authorization.intentRecord.ServerDate
}

func (authorization LaunchAuthorization) HeadETag() string { return authorization.headRecord.ETag }

func (authorization LaunchAuthorization) Attempt() uint64 { return authorization.intent.Attempt }

// SlotState is a verified read-only view of the active slot. Stored bytes and
// nested slices are copied so callers cannot mutate ledger-owned state.
type SlotState struct {
	Head              SlotHead
	HeadRecord        StoredRecord
	Intent            Intent
	IntentRecord      StoredRecord
	Manifest          *Manifest
	ManifestRecord    *StoredRecord
	Result            *Result
	ResultRecord      *StoredRecord
	PeerReceipt       *Receipt
	PeerReceiptRecord *StoredRecord
	SeedReceipt       *Receipt
	SeedReceiptRecord *StoredRecord
	Candidate         *ManagedPeerCandidate
	CandidateRecord   *StoredRecord
	Progress          *ManagedPeerProgress
	ProgressRecord    *StoredRecord
	quarantined       bool
}

func cloneSlotState(state SlotState) SlotState {
	state.HeadRecord = cloneStoredRecord(state.HeadRecord)
	state.IntentRecord = cloneStoredRecord(state.IntentRecord)
	if state.Manifest != nil {
		manifest := cloneManifest(*state.Manifest)
		state.Manifest = &manifest
	}
	state.ManifestRecord = cloneStoredRecordPointer(state.ManifestRecord)
	if state.Result != nil {
		result := *state.Result
		state.Result = &result
	}
	state.ResultRecord = cloneStoredRecordPointer(state.ResultRecord)
	if state.PeerReceipt != nil {
		receipt := *state.PeerReceipt
		state.PeerReceipt = &receipt
	}
	state.PeerReceiptRecord = cloneStoredRecordPointer(state.PeerReceiptRecord)
	if state.SeedReceipt != nil {
		receipt := *state.SeedReceipt
		state.SeedReceipt = &receipt
	}
	state.SeedReceiptRecord = cloneStoredRecordPointer(state.SeedReceiptRecord)
	if state.Candidate != nil {
		candidate := *state.Candidate
		state.Candidate = &candidate
	}
	state.CandidateRecord = cloneStoredRecordPointer(state.CandidateRecord)
	if state.Progress != nil {
		progress := *state.Progress
		progress.PendingProofWire = bytes.Clone(progress.PendingProofWire)
		state.Progress = &progress
	}
	state.ProgressRecord = cloneStoredRecordPointer(state.ProgressRecord)
	return state
}

func cloneStoredRecord(record StoredRecord) StoredRecord {
	record.Bytes = bytes.Clone(record.Bytes)
	return record
}

func cloneStoredRecordPointer(record *StoredRecord) *StoredRecord {
	if record == nil {
		return nil
	}
	cloned := cloneStoredRecord(*record)
	return &cloned
}

func (state SlotState) IntentDigest() string { return state.IntentRecord.SHA256 }

func (state SlotState) Attempt() uint64 { return state.Head.Attempt }

func (state SlotState) HeadETag() string { return state.HeadRecord.ETag }

// ReserveSlot durably creates the first signed intent and stable slot HEAD,
// then returns its verified observation. Call ReadForLaunch separately when a
// managed OCI mutation needs an unforgeable authorization token.
func (ledger *Ledger) ReserveSlot(ctx context.Context, scope BootstrapScope, intentBytes, initialHeadBytes []byte) (SlotState, error) {
	if err := validateLedgerScope(scope); err != nil {
		return SlotState{}, err
	}
	if err := ledger.validateAnchorScope(scope); err != nil {
		return SlotState{}, err
	}
	intent, intentEnvelope, intentErr := ledger.decodeIntent(scope, intentBytes, true)
	if intentErr != nil {
		return SlotState{}, intentErr
	}
	if intent.Mode == IntentModeManaged && intent.SchemaVersion != 2 {
		return SlotState{}, ErrFounderPlanRequired
	}
	if intent.Attempt != 1 || intent.Generation != 1 {
		return SlotState{}, fmt.Errorf("%w: an initial reservation must begin at attempt and generation one", ErrInvalidRecord)
	}
	head, headErr := ledger.decodeHead(scope, initialHeadBytes, true)
	headAuthorizedNow := headErr == nil
	if headErr != nil {
		return SlotState{}, headErr
	}
	if intent.Mode == IntentModeManaged && head.SchemaVersion != 2 {
		return SlotState{}, fmt.Errorf("%w: managed schema-v2 attempts require a schema-v2 HEAD", ErrRecordAuthorization)
	}
	if head.Attempt != intent.Attempt || head.Generation != intent.Generation || head.IntentDigest != objectDigest(intentBytes) ||
		head.ResultDigest != "" || head.PreviousAttempt != 0 || head.RetirementDigest != "" {
		return SlotState{}, ErrSlotNotReserved
	}
	intentRecord, err := ledger.createOrRead(ctx, scope, intent.Attempt, ledgerIntent, intentBytes)
	if err != nil {
		return SlotState{}, err
	}
	clockErr := validIntentClock(intent, intentRecord, ledger.config.TrustPolicy.ClockSkew)
	if clockErr != nil {
		return SlotState{}, clockErr
	}
	if err := validateStoredInterval(intentRecord, intentEnvelope); err != nil {
		return SlotState{}, err
	}
	if err := ledger.validateStoredBeforeAnchorExpiry(intentRecord); err != nil {
		return SlotState{}, err
	}
	// Intent creation and HEAD admission are separate Object Storage calls. The
	// intent may expire while the HEAD write is in flight, so verify current
	// authority again immediately before admitting the initial HEAD.
	currentIntent, currentIntentRecord, err := ledger.refreshCurrentIntent(ctx, scope, intent, intentBytes)
	if err != nil {
		return SlotState{}, err
	}
	if !sameIntent(currentIntent, intent) || currentIntentRecord.SHA256 != intentRecord.SHA256 {
		return SlotState{}, ErrRecordAuthorization
	}
	intentRecord = currentIntentRecord
	if err := ledger.validateCurrentAuthority(); err != nil {
		return SlotState{}, err
	}
	_, headRecord, err := ledger.writeInitialHead(ctx, scope, head, initialHeadBytes, headAuthorizedNow)
	if err != nil {
		return SlotState{}, err
	}
	if err := validateStoredBeforeExpiry(headRecord, intentEnvelope.ExpiresAt); err != nil {
		return SlotState{}, err
	}
	if err := validateHeadWithinRetryWindow(headRecord, intentRecord); err != nil {
		return SlotState{}, err
	}
	if err := ledger.validateStoredBeforeAnchorExpiry(headRecord); err != nil {
		return SlotState{}, err
	}
	return ledger.ReadSlot(ctx, scope)
}

// ReadSlot returns a historically verified record view. It does not authorize
// a cloud mutation; use ReadForLaunch for a current signed, unexpired intent.
func (ledger *Ledger) ReadSlot(ctx context.Context, scope BootstrapScope) (SlotState, error) {
	state, err := ledger.readSlot(ctx, scope, false)
	if err == nil {
		return state, nil
	}
	// Schema-v2 managed peer records can be valid historical evidence whose
	// signed interval or exact proof timing is no longer current. Preserve that
	// distinction for read-only callers while keeping malformed or mismatched
	// records as hard errors.
	quarantined, recoveryErr := ledger.readSlotWithRecovery(ctx, scope, false, true)
	if recoveryErr == nil && quarantined.Intent.Mode == IntentModeManaged &&
		quarantined.Intent.SchemaVersion == 2 && quarantined.quarantined {
		return SlotState{}, fmt.Errorf("%w: slot %q", ErrManagedPeerProofQuarantined, scope.Slot)
	}
	return SlotState{}, err
}

// ReadForLaunch returns a launch token only when the current signed intent is
// the exact attempt referenced by HEAD, has no committed positive result, and
// remains inside the original OCI retry window.
func (ledger *Ledger) ReadForLaunch(ctx context.Context, scope BootstrapScope) (LaunchAuthorization, error) {
	if err := ledger.validateCurrentAuthority(); err != nil {
		return LaunchAuthorization{}, err
	}
	state, err := ledger.readSlot(ctx, scope, true)
	if err != nil {
		return LaunchAuthorization{}, err
	}
	if state.Head.ResultDigest != "" {
		return LaunchAuthorization{}, ErrSlotAlreadyComplete
	}
	if state.Intent.Mode == IntentModeExternalSeed {
		return LaunchAuthorization{}, ErrExternalSeedMode
	}
	if state.Intent.SchemaVersion != 2 {
		return LaunchAuthorization{}, ErrFounderPlanRequired
	}
	if state.Head.Attempt == ^uint64(0) {
		return LaunchAuthorization{}, fmt.Errorf("%w: slot attempt sequence is exhausted", ErrInvalidRecord)
	}
	if _, err := ledger.read(ctx, scope, state.Head.Attempt+1, ledgerIntent); err == nil {
		return LaunchAuthorization{}, ErrSlotAdvancePendingHead
	} else if !errors.Is(err, ErrRecordMissing) {
		return LaunchAuthorization{}, err
	}
	if state.CandidateRecord != nil {
		return LaunchAuthorization{}, ErrManagedPeerCandidatePinned
	}
	if _, err := ledger.read(ctx, scope, state.Head.Attempt, ledgerResult); err == nil {
		return LaunchAuthorization{}, ErrSlotResultPendingHead
	} else if !errors.Is(err, ErrRecordMissing) {
		return LaunchAuthorization{}, err
	}
	if err := CheckRetryWindow(state.IntentRecord); err != nil {
		return LaunchAuthorization{}, err
	}
	if state.ManifestRecord != nil || state.PeerReceiptRecord != nil {
		return LaunchAuthorization{}, ErrSlotResultPendingHead
	}
	if err := ledger.validateCurrentAuthority(); err != nil {
		return LaunchAuthorization{}, err
	}
	currentIntent, currentIntentRecord, err := ledger.refreshCurrentIntent(ctx, scope, state.Intent, state.IntentRecord.Bytes)
	if err != nil {
		return LaunchAuthorization{}, err
	}
	if !sameIntent(currentIntent, state.Intent) || currentIntentRecord.SHA256 != state.IntentRecord.SHA256 {
		return LaunchAuthorization{}, ErrRecordAuthorization
	}
	if err := ledger.validateCurrentAuthority(); err != nil {
		return LaunchAuthorization{}, err
	}
	return LaunchAuthorization{
		scope: scope, intent: currentIntent, intentRecord: currentIntentRecord,
		head: state.Head, headRecord: state.HeadRecord,
	}, nil
}

// ReadForManagedPeerRecovery returns the exact durable phase of a managed
// schema-v2 attempt. Unlike ReadForLaunch, it can authorize observing an
// already receipt-bound instance or finishing an already written result, but
// it never grants launch authority by itself.
func (ledger *Ledger) ReadForManagedPeerRecovery(
	ctx context.Context,
	scope BootstrapScope,
) (ManagedPeerRecoveryAuthorization, error) {
	if err := ledger.validateCurrentAuthority(); err != nil {
		return ManagedPeerRecoveryAuthorization{}, err
	}
	state, err := ledger.readSlotForManagedPeerRecovery(ctx, scope)
	if err != nil {
		return ManagedPeerRecoveryAuthorization{}, err
	}
	if state.Intent.Mode != IntentModeManaged {
		return ManagedPeerRecoveryAuthorization{}, ErrExternalSeedMode
	}
	if state.Intent.SchemaVersion != 2 {
		return ManagedPeerRecoveryAuthorization{}, ErrFounderPlanRequired
	}
	if state.Head.Attempt == ^uint64(0) {
		return ManagedPeerRecoveryAuthorization{}, fmt.Errorf("%w: slot attempt sequence is exhausted", ErrInvalidRecord)
	}
	if _, err := ledger.read(ctx, scope, state.Head.Attempt+1, ledgerIntent); err == nil {
		return ManagedPeerRecoveryAuthorization{}, ErrSlotAdvancePendingHead
	} else if !errors.Is(err, ErrRecordMissing) {
		return ManagedPeerRecoveryAuthorization{}, err
	}
	phase := ManagedPeerRecoveryClean
	if state.ManifestRecord != nil {
		phase = ManagedPeerRecoveryManifestOnly
	}
	if state.CandidateRecord != nil {
		phase = ManagedPeerRecoveryCandidateOnly
	}
	if state.PeerReceiptRecord != nil {
		phase = ManagedPeerRecoveryReceiptOnly
	}
	if state.ResultRecord != nil {
		phase = ManagedPeerRecoveryResultReady
	}
	if state.Head.ResultDigest != "" {
		phase = ManagedPeerRecoveryComplete
	}
	if state.Progress != nil &&
		(state.Progress.Phase == ManagedPeerProgressReceipt && state.PeerReceiptRecord == nil ||
			state.Progress.Phase == ManagedPeerProgressResult && state.ResultRecord == nil) {
		phase = ManagedPeerRecoveryProofStaged
	}
	if state.Intent.Mode == IntentModeManaged && state.Intent.SchemaVersion == 2 && state.Head.SchemaVersion != 2 {
		state.quarantined = true
	}
	if state.quarantined {
		phase = ManagedPeerRecoveryQuarantined
	}

	managedV2 := state.Intent.Mode == IntentModeManaged && state.Intent.SchemaVersion == 2 && state.Head.SchemaVersion == 2
	if state.Head.ResultDigest == "" && !managedV2 {
		resultRecord, resultErr := ledger.read(ctx, scope, state.Head.Attempt, ledgerResult)
		if resultErr == nil {
			if state.Manifest == nil || state.ManifestRecord == nil || state.PeerReceipt == nil || state.PeerReceiptRecord == nil {
				return ManagedPeerRecoveryAuthorization{}, fmt.Errorf("%w: result exists before its exact manifest and peer receipt", ErrRecordAuthorization)
			}
			result, decodeErr := ledger.decodeResult(scope, resultRecord.Bytes, false)
			if decodeErr != nil || validateResultForIntent(result, state.Intent, state.IntentRecord.SHA256) != nil ||
				result.Mode != IntentModeManaged || result.SeedReceiptDigest != "" ||
				result.PeerReceiptDigest != state.PeerReceiptRecord.SHA256 {
				return ManagedPeerRecoveryAuthorization{}, fmt.Errorf("%w: unattached result does not match the active managed proof", ErrRecordAuthorization)
			}
			if err := ledger.validateStoredResult(result, resultRecord); err != nil {
				return ManagedPeerRecoveryAuthorization{}, err
			}
			if err := validatePeerReceiptForIntent(*state.PeerReceipt, state.Intent, state.IntentRecord.SHA256); err != nil {
				return ManagedPeerRecoveryAuthorization{}, err
			}
			if err := validatePeerReceiptForResult(*state.PeerReceipt, result); err != nil {
				return ManagedPeerRecoveryAuthorization{}, err
			}
			if err := validateCompletionWriteOrder(*state.ManifestRecord, *state.PeerReceiptRecord, resultRecord); err != nil {
				return ManagedPeerRecoveryAuthorization{}, err
			}
			if err := validateResultStoredWithinProofs(*state.ManifestRecord, *state.PeerReceiptRecord, resultRecord, ledger.config.AnchorExpiresAt); err != nil {
				return ManagedPeerRecoveryAuthorization{}, err
			}
			facts, factsErr := instanceFactsFromReceipt(*state.PeerReceipt, *state.Manifest)
			if factsErr != nil || validateManagedFacts(ledger, facts, state.Intent, state.IntentRecord.SHA256, result) != nil {
				return ManagedPeerRecoveryAuthorization{}, ErrIdentityMismatch
			}
			state.Result = &result
			state.ResultRecord = &resultRecord
			phase = ManagedPeerRecoveryResultReady
		} else if !errors.Is(resultErr, ErrRecordMissing) {
			return ManagedPeerRecoveryAuthorization{}, resultErr
		}
	}
	if err := ledger.validateCurrentAuthority(); err != nil {
		return ManagedPeerRecoveryAuthorization{}, err
	}
	observedAt := time.Now()
	freshHeadRecord, err := ledger.readObject(ctx, ledger.config.HeadBucket, ledger.headObjectName(scope))
	if err != nil {
		return ManagedPeerRecoveryAuthorization{}, err
	}
	if freshHeadRecord.ETag != state.HeadRecord.ETag || !bytes.Equal(freshHeadRecord.Bytes, state.HeadRecord.Bytes) {
		return ManagedPeerRecoveryAuthorization{}, ErrSlotHeadConflict
	}
	latestReadDate := state.HeadRecord.ServerDate
	for _, record := range []*StoredRecord{
		&state.IntentRecord, state.ManifestRecord, state.PeerReceiptRecord, state.ResultRecord,
	} {
		if record != nil && record.ServerDate.After(latestReadDate) {
			latestReadDate = record.ServerDate
		}
	}
	if freshHeadRecord.ServerDate.Before(latestReadDate) {
		return ManagedPeerRecoveryAuthorization{}, fmt.Errorf("%w: final HEAD Date predates an earlier successful recovery read", ErrInvalidRetryClock)
	}
	state.HeadRecord = freshHeadRecord
	serverDate := freshHeadRecord.ServerDate
	if serverDate.IsZero() || state.IntentRecord.LastModified.IsZero() || serverDate.Before(state.IntentRecord.LastModified) {
		return ManagedPeerRecoveryAuthorization{}, ErrInvalidRetryClock
	}
	authorization := ManagedPeerRecoveryAuthorization{
		scope: scope, phase: phase, state: cloneSlotState(state), serverDate: serverDate,
		observedAt: observedAt, readID: managedPeerRecoveryReadID.Add(1), verified: true,
	}
	if state.Result != nil && state.ResultRecord == nil &&
		validateManagedPeerObservationFreshness(*state.Result, authorization.AuthorizationTime()) != nil {
		authorization.phase = ManagedPeerRecoveryQuarantined
		authorization.state.quarantined = true
	}
	return authorization, nil
}

func (ledger *Ledger) refreshCurrentIntent(
	ctx context.Context,
	scope BootstrapScope,
	expected Intent,
	expectedBytes []byte,
) (Intent, StoredRecord, error) {
	record, err := ledger.read(ctx, scope, expected.Attempt, ledgerIntent)
	if err != nil {
		return Intent{}, StoredRecord{}, err
	}
	if record.SHA256 != objectDigest(expectedBytes) || !bytes.Equal(record.Bytes, expectedBytes) {
		return Intent{}, StoredRecord{}, ErrImmutableConflict
	}
	intent, envelope, err := ledger.decodeIntent(scope, record.Bytes, true)
	if err != nil {
		return Intent{}, StoredRecord{}, err
	}
	if !sameIntent(intent, expected) {
		return Intent{}, StoredRecord{}, ErrRecordAuthorization
	}
	if err := validateStoredInterval(record, envelope); err != nil {
		return Intent{}, StoredRecord{}, err
	}
	if err := ledger.validateStoredBeforeAnchorExpiry(record); err != nil {
		return Intent{}, StoredRecord{}, err
	}
	if err := validIntentClock(intent, record, ledger.config.TrustPolicy.ClockSkew); err != nil {
		return Intent{}, StoredRecord{}, err
	}
	return intent, record, nil
}

func (ledger *Ledger) manifestExpectation(scope BootstrapScope, intent Intent) (ManifestExpectation, error) {
	if err := ledger.validateAnchorScope(scope); err != nil {
		return ManifestExpectation{}, err
	}
	if intent.DeploymentID != scope.DeploymentID || intent.Cell != scope.Cell || intent.Environment != ledger.config.Environment ||
		intent.Role != roleController || intent.Slot != scope.Slot || !validDigest(intent.ManifestDigest) || !isOCID(intent.ImageOCID, "image") {
		return ManifestExpectation{}, fmt.Errorf("%w: verified intent does not match the anchored manifest scope", ErrRecordAuthorization)
	}
	if intent.RegionIntentGeneration != ledger.config.InitialRegionIntentGeneration ||
		intent.RegionIntentDigest != ledger.config.InitialRegionIntentSHA256 {
		return ManifestExpectation{}, fmt.Errorf("%w: intent region proof differs from the trusted anchor", ErrRecordAuthorization)
	}
	expected := ManifestExpectation{
		DeploymentID: ledger.config.DeploymentID, Environment: ledger.config.Environment,
		ClusterID: ledger.config.ClusterID, Cell: ledger.config.Cell, Slot: scope.Slot,
		ImageOCID: intent.ImageOCID, StorageDomain: ledger.config.storageDomain(),
		ControllerSlots:  slices.Clone(ledger.config.ControllerSlots),
		IntentGeneration: ledger.config.InitialRegionIntentGeneration,
		IntentSHA256:     ledger.config.InitialRegionIntentSHA256,
	}
	if err := expected.validate(); err != nil {
		return ManifestExpectation{}, err
	}
	return expected, nil
}

func (ledger *Ledger) verifyCurrentIntentManifest(scope BootstrapScope, intent Intent, body []byte) (VerifiedManifest, trust.Envelope, error) {
	expected, err := ledger.manifestExpectation(scope, intent)
	if err != nil {
		return VerifiedManifest{}, trust.Envelope{}, err
	}
	envelope, err := trust.DecodeEnvelope(body)
	if err != nil {
		return VerifiedManifest{}, trust.Envelope{}, fmt.Errorf("%w: decode canonical managed manifest: %v", ErrInvalidRecord, err)
	}
	verified, err := VerifyManifest(envelope, ledger.config.TrustRoots, expected, ledger.now(), ledger.config.TrustPolicy)
	if err != nil {
		return VerifiedManifest{}, trust.Envelope{}, err
	}
	manifest := verified.Manifest()
	if verified.Digest() != intent.ManifestDigest || objectDigest(body) != intent.ManifestDigest ||
		validateManifestForIntent(manifest, scope, intent) != nil {
		return VerifiedManifest{}, trust.Envelope{}, fmt.Errorf("%w: root-signed manifest does not match the exact intent", ErrRecordAuthorization)
	}
	return verified, envelope, nil
}

func (ledger *Ledger) verifyHistoricalIntentManifest(scope BootstrapScope, intent Intent, body []byte) (HistoricalManifest, trust.Envelope, error) {
	expected, err := ledger.manifestExpectation(scope, intent)
	if err != nil {
		return HistoricalManifest{}, trust.Envelope{}, err
	}
	envelope, err := trust.DecodeEnvelope(body)
	if err != nil {
		return HistoricalManifest{}, trust.Envelope{}, fmt.Errorf("%w: decode canonical managed manifest: %v", ErrInvalidRecord, err)
	}
	verified, err := VerifyHistoricalManifest(envelope, ledger.config.TrustRoots, expected, ledger.config.TrustPolicy)
	if err != nil {
		return HistoricalManifest{}, trust.Envelope{}, err
	}
	manifest := verified.Manifest()
	if verified.Digest() != intent.ManifestDigest || objectDigest(body) != intent.ManifestDigest ||
		validateManifestForIntent(manifest, scope, intent) != nil {
		return HistoricalManifest{}, trust.Envelope{}, fmt.Errorf("%w: root-signed manifest does not match the exact intent", ErrRecordAuthorization)
	}
	return verified, envelope, nil
}

func validateManifestForIntent(manifest Manifest, scope BootstrapScope, intent Intent) error {
	profile, ok := manifestProfile(manifest, scope.Slot)
	if !ok || manifest.Slot != scope.Slot || manifest.DeploymentID != intent.DeploymentID ||
		string(manifest.Cell) != intent.Cell || manifest.Environment != intent.Environment ||
		manifest.ControllerRole != intent.Role || manifest.ImageOCID != intent.ImageOCID ||
		manifest.IntentSHA256 != intent.RegionIntentDigest || manifest.IntentGeneration != intent.RegionIntentGeneration ||
		!sameProfile(profile, launchProfileForIntent(intent)) {
		return fmt.Errorf("%w: manifest slot, image, region intent, or launch profile differs from the intent", ErrRecordAuthorization)
	}
	return nil
}

func launchProfileForIntent(intent Intent) LaunchProfile {
	return LaunchProfile{
		Slot: intent.Slot, CompartmentOCID: intent.CompartmentOCID, AvailabilityDomain: intent.AvailabilityDomain,
		FaultDomain: intent.FaultDomain, SubnetOCID: intent.SubnetOCID,
		NetworkSecurityGroupOCIDs: append([]string(nil), intent.NetworkSecurityGroupIDs...), Shape: intent.Shape,
	}
}

func validateManagedFacts(ledger *Ledger, facts InstanceFacts, intent Intent, intentDigest string, result Result) error {
	profile := launchProfileForIntent(intent)
	if facts.DeploymentID != ledger.config.DeploymentID || facts.Environment != ledger.config.Environment ||
		facts.ClusterID != ledger.config.ClusterID || facts.Cell != ledger.config.Cell || facts.Slot != intent.Slot ||
		facts.Role != intent.Role || facts.OCIRegion != intent.OCIRegion || facts.InstanceOCID != result.InstanceOCID ||
		facts.CompartmentOCID != intent.CompartmentOCID || facts.ImageOCID != intent.ImageOCID ||
		facts.CreateKey != intent.CreateKey || facts.IntentSHA256 != intentDigest || !sameProfile(facts.Profile, profile) ||
		result.OCIRegion != facts.OCIRegion || result.CompartmentOCID != facts.CompartmentOCID ||
		result.ImageOCID != facts.ImageOCID || result.Shape != facts.Profile.Shape || result.CreateKey != facts.CreateKey ||
		result.IntentDigest != facts.IntentSHA256 {
		return fmt.Errorf("%w: authenticated OCI facts do not match the exact intent and result", ErrIdentityMismatch)
	}
	return nil
}

func validatePeerReceiptForIntent(receipt Receipt, intent Intent, intentDigest string) error {
	if intent.Mode != IntentModeManaged || receipt.DeploymentID != intent.DeploymentID ||
		receipt.Environment != intent.Environment || string(receipt.Cell) != intent.Cell ||
		receipt.OCIRegion != intent.OCIRegion || receipt.Role != intent.Role || receipt.Slot != intent.Slot ||
		receipt.CompartmentOCID != intent.CompartmentOCID || receipt.ImageOCID != intent.ImageOCID ||
		receipt.CreateKey != intent.CreateKey || receipt.IntentSHA256 != intentDigest ||
		receipt.ManifestDigest != intent.ManifestDigest || receipt.ManifestIntentSHA256 != intent.RegionIntentDigest ||
		receipt.IntentGeneration != intent.RegionIntentGeneration || receipt.ProfileSHA256 != intent.LaunchRequestDigest {
		return fmt.Errorf("%w: delegated peer receipt does not match the exact intent", ErrInvalidRecord)
	}
	return nil
}

func validatePeerReceiptForResult(receipt Receipt, result Result) error {
	if receipt.InstanceOCID != result.InstanceOCID || receipt.CompartmentOCID != result.CompartmentOCID ||
		receipt.ImageOCID != result.ImageOCID || receipt.CreateKey != result.CreateKey ||
		receipt.OCIRegion != result.OCIRegion || receipt.ProfileSHA256 != result.ObservedProfileDigest {
		return fmt.Errorf("%w: positive result does not match delegated peer receipt facts", ErrInvalidRecord)
	}
	return nil
}

func instanceFactsFromReceipt(receipt Receipt, manifest Manifest) (InstanceFacts, error) {
	profile, ok := manifestProfile(manifest, receipt.Slot)
	if !ok {
		return InstanceFacts{}, ErrIdentityMismatch
	}
	return InstanceFacts{
		DeploymentID: receipt.DeploymentID, Environment: receipt.Environment, ClusterID: receipt.ClusterID,
		Cell: receipt.Cell, OCIRegion: receipt.OCIRegion, Role: receipt.Role, Slot: receipt.Slot,
		InstanceOCID: receipt.InstanceOCID, CompartmentOCID: receipt.CompartmentOCID,
		ImageOCID: receipt.ImageOCID, CreateKey: receipt.CreateKey, IntentSHA256: receipt.IntentSHA256,
		Profile: profile,
	}, nil
}

func validateStoredInterval(record StoredRecord, envelope trust.Envelope) error {
	if record.LastModified.IsZero() || record.ServerDate.IsZero() || record.ServerDate.Before(record.LastModified) {
		return ErrInvalidRetryClock
	}
	if record.LastModified.Before(envelope.IssuedAt) || !storedBeforeExpiry(record.LastModified, envelope.ExpiresAt) {
		return fmt.Errorf("%w: immutable proof was not durably stored while its signature was current", ErrRecordAuthorization)
	}
	return nil
}

// OCI exposes Object Storage Last-Modified timestamps with one-second
// precision. Treat the timestamp as the start of its whole second and require
// that second's exclusive upper boundary to be no later than the signed
// expiry. This rejects records created in an expiry second we cannot
// distinguish from records created at or after expiry.
func storedBeforeExpiry(lastModified, expiresAt time.Time) bool {
	if lastModified.IsZero() || expiresAt.IsZero() {
		return false
	}
	return !lastModified.UTC().Truncate(time.Second).Add(time.Second).After(expiresAt)
}

func validateStoredBeforeExpiry(record StoredRecord, expiresAt time.Time) error {
	if record.LastModified.IsZero() || record.ServerDate.IsZero() || record.ServerDate.Before(record.LastModified) {
		return ErrInvalidRetryClock
	}
	if !storedBeforeExpiry(record.LastModified, expiresAt) {
		return fmt.Errorf("%w: object was not durably stored before the authorization expired", ErrRecordAuthorization)
	}
	return nil
}

func validateHeadWithinRetryWindow(headRecord, intentRecord StoredRecord) error {
	if intentRecord.LastModified.IsZero() {
		return ErrInvalidRetryClock
	}
	if err := validateStoredBeforeExpiry(headRecord, intentRecord.LastModified.Add(maxRetryAge)); err != nil {
		if errors.Is(err, ErrRecordAuthorization) {
			return ErrRetryWindowExpired
		}
		return err
	}
	return nil
}

func (ledger *Ledger) validateStoredBeforeAnchorExpiry(record StoredRecord) error {
	if ledger.config.AnchorExpiresAt.IsZero() {
		return nil
	}
	return validateStoredBeforeExpiry(record, ledger.config.AnchorExpiresAt)
}

func validateResultStoredWithinProofs(manifest, receipt, result StoredRecord, anchorExpiresAt time.Time) error {
	manifestEnvelope, err := trust.DecodeEnvelope(manifest.Bytes)
	if err != nil {
		return fmt.Errorf("%w: decode persisted manifest envelope: %v", ErrInvalidRecord, err)
	}
	receiptEnvelope, err := trust.DecodeEnvelope(receipt.Bytes)
	if err != nil {
		return fmt.Errorf("%w: decode persisted receipt envelope: %v", ErrInvalidRecord, err)
	}
	resultEnvelope, err := trust.DecodeEnvelope(result.Bytes)
	if err != nil {
		return fmt.Errorf("%w: decode persisted result envelope: %v", ErrInvalidRecord, err)
	}
	if resultEnvelope.IssuedAt.Before(receiptEnvelope.IssuedAt) {
		return fmt.Errorf("%w: result was signed before its bound receipt", ErrRecordAuthorization)
	}
	if err := validateStoredInterval(manifest, manifestEnvelope); err != nil {
		return err
	}
	if err := validateStoredInterval(receipt, receiptEnvelope); err != nil {
		return err
	}
	if err := validateStoredBeforeExpiry(result, manifestEnvelope.ExpiresAt); err != nil {
		return err
	}
	if err := validateStoredBeforeExpiry(result, receiptEnvelope.ExpiresAt); err != nil {
		return err
	}
	if !anchorExpiresAt.IsZero() {
		if err := validateStoredBeforeExpiry(manifest, anchorExpiresAt); err != nil {
			return err
		}
		if err := validateStoredBeforeExpiry(receipt, anchorExpiresAt); err != nil {
			return err
		}
		if err := validateStoredBeforeExpiry(result, anchorExpiresAt); err != nil {
			return err
		}
	}
	return nil
}

// validateCompletionWriteOrder rejects timestamp evidence that contradicts the
// typed write sequence. OCI timestamps have whole-second precision, so this
// check cannot prove transaction order when records share a second.
func validateCompletionWriteOrder(manifest, receipt, result StoredRecord) error {
	if manifest.LastModified.IsZero() || receipt.LastModified.IsZero() || result.LastModified.IsZero() ||
		manifest.LastModified.After(receipt.LastModified) || receipt.LastModified.After(result.LastModified) {
		return fmt.Errorf("%w: manifest, receipt, and result were not persisted in transaction order", ErrRecordAuthorization)
	}
	return nil
}

func (ledger *Ledger) validateStoredResult(result Result, record StoredRecord) error {
	if err := validateResultClock(result, record, ledger.config.TrustPolicy.ClockSkew); err != nil {
		return err
	}
	envelope, err := trust.DecodeEnvelope(record.Bytes)
	if err != nil {
		return fmt.Errorf("%w: decode persisted result envelope: %v", ErrInvalidRecord, err)
	}
	if err := validateStoredInterval(record, envelope); err != nil {
		return err
	}
	return ledger.validateStoredBeforeAnchorExpiry(record)
}

// RecordResult writes a signed positive OCI observation for the current HEAD
// attempt, then CAS-updates HEAD to include its immutable result digest.
func (ledger *Ledger) RecordResult(ctx context.Context, scope BootstrapScope, resultBytes, headWithResultBytes []byte) (SlotState, error) {
	result, err := ledger.decodeResult(scope, resultBytes, false)
	if err != nil {
		return SlotState{}, err
	}
	if result.Mode == IntentModeManaged {
		return SlotState{}, ErrManagedPeerReceiptRequired
	}
	_, storedResultExists, err := ledger.readExistingExact(ctx, scope, result.Attempt, ledgerResult, resultBytes)
	if err != nil {
		return SlotState{}, err
	}
	if _, currentErr := ledger.decodeResult(scope, resultBytes, true); currentErr != nil && !storedResultExists {
		return SlotState{}, currentErr
	}
	state, err := ledger.readSlot(ctx, scope, false)
	if err != nil {
		return SlotState{}, err
	}
	if state.Intent.Mode == IntentModeExternalSeed {
		return SlotState{}, ErrExternalSeedMode
	}
	if state.Head.Attempt != result.Attempt || state.Head.Generation != result.Generation ||
		state.Head.IntentDigest != result.IntentDigest || state.Head.ResultDigest != "" {
		if state.Head.Attempt == result.Attempt && state.Head.IntentDigest == result.IntentDigest &&
			state.Head.ResultDigest == objectDigest(resultBytes) {
			return state, nil
		}
		return SlotState{}, ErrSlotHeadConflict
	}
	if err := validateResultForIntent(result, state.Intent, state.IntentRecord.SHA256); err != nil {
		return SlotState{}, err
	}
	resultRecord, err := ledger.createOrRead(ctx, scope, result.Attempt, ledgerResult, resultBytes)
	if err != nil {
		return SlotState{}, err
	}
	if err := validateResultClock(result, resultRecord, ledger.config.TrustPolicy.ClockSkew); err != nil {
		return SlotState{}, err
	}
	updatedHead, headErr := ledger.decodeHead(scope, headWithResultBytes, true)
	headAuthorizedNow := headErr == nil
	if headErr != nil {
		if !storedResultExists {
			return SlotState{}, headErr
		}
		updatedHead, err = ledger.decodeHead(scope, headWithResultBytes, false)
		if err != nil {
			return SlotState{}, err
		}
	}
	expectedHead := state.Head
	expectedHead.ResultDigest = resultRecord.SHA256
	if !sameHead(updatedHead, expectedHead) {
		return SlotState{}, ErrSlotHeadConflict
	}
	_, headRecord, err := ledger.writeHead(ctx, scope, state.HeadRecord.ETag, updatedHead, headWithResultBytes, headAuthorizedNow)
	if err != nil {
		return SlotState{}, err
	}
	state.Head = updatedHead
	state.HeadRecord = headRecord
	state.Result = &result
	state.ResultRecord = &resultRecord
	return state, nil
}

// RecordExternalSeed commits the root-signed manifest, root-signed seed
// receipt, and matching positive observation before advancing HEAD. Exact
// persisted proof bytes may repair a partial transition after expiry; a new
// manifest or receipt must be current when first stored.
func (ledger *Ledger) RecordExternalSeed(
	ctx context.Context,
	scope BootstrapScope,
	manifestBytes []byte,
	receiptBytes []byte,
	facts InstanceFacts,
	resultBytes []byte,
	headWithResultBytes []byte,
) (SlotState, error) {
	state, err := ledger.readSlot(ctx, scope, false)
	if err != nil {
		return SlotState{}, err
	}
	if state.Intent.Mode != IntentModeExternalSeed {
		return SlotState{}, ErrExternalSeedMode
	}
	if state.Head.ResultDigest != "" {
		if state.HeadRecord.SHA256 == objectDigest(headWithResultBytes) &&
			state.Head.ResultDigest == objectDigest(resultBytes) && state.ResultRecord != nil &&
			state.ResultRecord.SHA256 == objectDigest(resultBytes) && state.ManifestRecord != nil &&
			state.ManifestRecord.SHA256 == objectDigest(manifestBytes) && state.SeedReceiptRecord != nil &&
			state.SeedReceiptRecord.SHA256 == objectDigest(receiptBytes) {
			return state, nil
		}
		return SlotState{}, ErrSlotHeadConflict
	}
	result, err := ledger.decodeResult(scope, resultBytes, false)
	if err != nil {
		return SlotState{}, err
	}
	if result.Mode != IntentModeExternalSeed || result.Attempt != state.Head.Attempt || result.Generation != state.Head.Generation ||
		result.IntentDigest != state.IntentRecord.SHA256 || result.SeedReceiptDigest != objectDigest(receiptBytes) || result.PeerReceiptDigest != "" {
		return SlotState{}, ErrSlotHeadConflict
	}
	if err := validateResultForIntent(result, state.Intent, state.IntentRecord.SHA256); err != nil {
		return SlotState{}, err
	}
	if err := validateManagedFacts(ledger, facts, state.Intent, state.IntentRecord.SHA256, result); err != nil {
		return SlotState{}, err
	}
	manifestRecord, manifestExists, err := ledger.readExistingExact(ctx, scope, state.Head.Attempt, ledgerManifest, manifestBytes)
	if err != nil {
		return SlotState{}, err
	}
	receiptRecord, receiptExists, err := ledger.readExistingExact(ctx, scope, state.Head.Attempt, ledgerSeedReceipt, receiptBytes)
	if err != nil {
		return SlotState{}, err
	}
	resultRecord, resultExists, err := ledger.readExistingExact(ctx, scope, result.Attempt, ledgerResult, resultBytes)
	if err != nil {
		return SlotState{}, err
	}
	if resultExists && (!manifestExists || !receiptExists) {
		return SlotState{}, fmt.Errorf("%w: an existing result cannot authorize creating a missing manifest or receipt", ErrRecordAuthorization)
	}
	if objectDigest(manifestBytes) != state.Intent.ManifestDigest {
		return SlotState{}, ErrSlotHeadConflict
	}
	updatedHead, headErr := ledger.decodeHead(scope, headWithResultBytes, true)
	if headErr != nil {
		return SlotState{}, headErr
	}
	expectedHead := state.Head
	expectedHead.ResultDigest = objectDigest(resultBytes)
	if !sameHead(updatedHead, expectedHead) {
		return SlotState{}, ErrSlotHeadConflict
	}

	verifiedManifest, manifestEnvelope, manifestErr := ledger.verifyCurrentIntentManifest(scope, state.Intent, manifestBytes)
	manifestCurrent := manifestErr == nil
	var historicalManifest HistoricalManifest
	if manifestErr != nil {
		if !manifestExists {
			return SlotState{}, manifestErr
		}
		historicalManifest, manifestEnvelope, err = ledger.verifyHistoricalIntentManifest(scope, state.Intent, manifestBytes)
		if err != nil {
			return SlotState{}, err
		}
	}
	receiptEnvelope, err := trust.DecodeEnvelope(receiptBytes)
	if err != nil {
		return SlotState{}, fmt.Errorf("%w: decode canonical seed receipt envelope: %v", ErrInvalidRecord, err)
	}
	var receipt Receipt
	receiptCurrent := false
	var receiptCurrentErr error
	if manifestCurrent {
		verifiedReceipt, verifyErr := VerifySeedReceipt(receiptEnvelope, verifiedManifest, ledger.config.TrustRoots, facts, ledger.now(), ledger.config.TrustPolicy)
		if verifyErr == nil {
			receipt = verifiedReceipt.Receipt()
			receiptCurrent = true
		} else {
			receiptCurrentErr = verifyErr
			if !receiptExists {
				return SlotState{}, verifyErr
			}
		}
	}
	if !resultExists && (!manifestCurrent || !receiptCurrent) {
		if manifestErr != nil {
			return SlotState{}, manifestErr
		}
		if receiptCurrentErr != nil {
			return SlotState{}, receiptCurrentErr
		}
		return SlotState{}, ErrRecordAuthorization
	}
	if !receiptCurrent {
		if !manifestExists || !receiptExists {
			if manifestErr != nil {
				return SlotState{}, manifestErr
			}
			return SlotState{}, ErrRecordAuthorization
		}
		historicalManifest, _, err = ledger.verifyHistoricalIntentManifest(scope, state.Intent, manifestBytes)
		if err != nil {
			return SlotState{}, err
		}
		historicalReceipt, verifyErr := VerifyHistoricalSeedReceipt(receiptEnvelope, historicalManifest, ledger.config.TrustRoots, facts, ledger.config.TrustPolicy)
		if verifyErr != nil {
			return SlotState{}, verifyErr
		}
		receipt = historicalReceipt.Receipt()
	}
	if err := validateSeedReceiptForIntent(receipt, state.Intent, state.IntentRecord.SHA256); err != nil {
		return SlotState{}, err
	}
	if err := validateSeedReceiptForResult(receipt, result); err != nil {
		return SlotState{}, err
	}
	if _, err := ledger.decodeResult(scope, resultBytes, true); err != nil && !resultExists {
		return SlotState{}, err
	}
	if !manifestExists {
		manifestRecord, err = ledger.createOrRead(ctx, scope, state.Head.Attempt, ledgerManifest, manifestBytes)
		if err != nil {
			return SlotState{}, err
		}
	}
	if err := validateStoredInterval(manifestRecord, manifestEnvelope); err != nil {
		return SlotState{}, err
	}
	if err := ledger.validateStoredBeforeAnchorExpiry(manifestRecord); err != nil {
		return SlotState{}, err
	}
	if !receiptExists {
		receiptRecord, err = ledger.createOrRead(ctx, scope, state.Head.Attempt, ledgerSeedReceipt, receiptBytes)
		if err != nil {
			return SlotState{}, err
		}
	}
	if err := validateStoredInterval(receiptRecord, receiptEnvelope); err != nil {
		return SlotState{}, err
	}
	if err := ledger.validateStoredBeforeAnchorExpiry(receiptRecord); err != nil {
		return SlotState{}, err
	}
	if !resultExists {
		currentManifest, _, verifyErr := ledger.verifyCurrentIntentManifest(scope, state.Intent, manifestBytes)
		if verifyErr != nil {
			return SlotState{}, verifyErr
		}
		currentReceipt, verifyErr := VerifySeedReceipt(
			receiptEnvelope, currentManifest, ledger.config.TrustRoots, facts, ledger.now(), ledger.config.TrustPolicy,
		)
		if verifyErr != nil {
			return SlotState{}, fmt.Errorf("%w: root-signed seed receipt expired before the result write: %v", ErrRecordAuthorization, verifyErr)
		}
		receipt = currentReceipt.Receipt()
		if err := validateSeedReceiptForIntent(receipt, state.Intent, state.IntentRecord.SHA256); err != nil {
			return SlotState{}, err
		}
		if err := validateSeedReceiptForResult(receipt, result); err != nil {
			return SlotState{}, err
		}
		resultRecord, err = ledger.createOrRead(ctx, scope, result.Attempt, ledgerResult, resultBytes)
		if err != nil {
			return SlotState{}, err
		}
	}
	if err := validateResultClock(result, resultRecord, ledger.config.TrustPolicy.ClockSkew); err != nil {
		return SlotState{}, err
	}
	resultEnvelope, err := trust.DecodeEnvelope(resultBytes)
	if err != nil {
		return SlotState{}, fmt.Errorf("%w: decode result envelope: %v", ErrInvalidRecord, err)
	}
	if err := validateStoredInterval(resultRecord, resultEnvelope); err != nil {
		return SlotState{}, err
	}
	if err := validateResultStoredWithinProofs(manifestRecord, receiptRecord, resultRecord, ledger.config.AnchorExpiresAt); err != nil {
		return SlotState{}, err
	}
	if err := validateCompletionWriteOrder(manifestRecord, receiptRecord, resultRecord); err != nil {
		return SlotState{}, err
	}
	if _, _, err := ledger.writeHead(ctx, scope, state.HeadRecord.ETag, updatedHead, headWithResultBytes, true); err != nil {
		return SlotState{}, err
	}
	return ledger.ReadSlot(ctx, scope)
}

// ExternalSeedProgress reads the immutable proof keys for one unfinished
// external seed. It reports only exact bytes; a different existing object is
// a conflict. A caller may use ResultStored to reconcile an old observation,
// but this read grants no authority to create a new result or advance HEAD.
func (ledger *Ledger) ExternalSeedProgress(ctx context.Context, scope BootstrapScope,
	manifestBytes, receiptBytes, resultBytes []byte,
) (manifestStored, receiptStored, resultStored bool, err error) {
	state, err := ledger.ReadSlot(ctx, scope)
	if err != nil {
		return false, false, false, err
	}
	if state.Intent.Mode != IntentModeExternalSeed || state.Head.ResultDigest != "" {
		return false, false, false, ErrExternalSeedMode
	}
	_, manifestStored, err = ledger.readExistingExact(ctx, scope, state.Head.Attempt, ledgerManifest, manifestBytes)
	if err != nil {
		return false, false, false, err
	}
	_, receiptStored, err = ledger.readExistingExact(ctx, scope, state.Head.Attempt, ledgerSeedReceipt, receiptBytes)
	if err != nil {
		return false, false, false, err
	}
	_, resultStored, err = ledger.readExistingExact(ctx, scope, state.Head.Attempt, ledgerResult, resultBytes)
	if err != nil {
		return false, false, false, err
	}
	if resultStored && (!manifestStored || !receiptStored) {
		return false, false, false, ErrRecordAuthorization
	}
	return manifestStored, receiptStored, resultStored, nil
}

// RecordManagedPeer stores the root-authorized manifest and its delegated peer
// receipt before the exact positive result, then advances HEAD with one ETag
// CAS. Caller-supplied facts must come from authenticated OCI observations.
func (ledger *Ledger) RecordManagedPeer(
	ctx context.Context,
	scope BootstrapScope,
	manifestBytes []byte,
	peerReceiptBytes []byte,
	facts InstanceFacts,
	resultBytes []byte,
	headWithResultBytes []byte,
	signProgress ManagedPeerProgressSigner,
	refresh ManagedPeerRecoveryRefresh,
) (SlotState, error) {
	manifestBytes = bytes.Clone(manifestBytes)
	peerReceiptBytes = bytes.Clone(peerReceiptBytes)
	resultBytes = bytes.Clone(resultBytes)
	headWithResultBytes = bytes.Clone(headWithResultBytes)
	facts.Profile = cloneProfile(facts.Profile)
	state, err := ledger.readSlotForManagedPeerRecovery(ctx, scope)
	if err != nil {
		return SlotState{}, err
	}
	var lastRecoveryReadID uint64
	refreshCurrent := func() (VerifiedFounderPeer, error) {
		peer, refreshErr := ledger.refreshManagedPeer(ctx, scope, state, refresh)
		if refreshErr != nil {
			return VerifiedFounderPeer{}, refreshErr
		}
		if peer.recovery.readID == 0 || peer.recovery.readID <= lastRecoveryReadID {
			return VerifiedFounderPeer{}, fmt.Errorf("%w: managed-peer transition reused a recovery authorization", ErrRecordAuthorization)
		}
		lastRecoveryReadID = peer.recovery.readID
		return peer, nil
	}
	if state.Intent.Mode != IntentModeManaged {
		return SlotState{}, ErrExternalSeedMode
	}
	if state.Intent.SchemaVersion != 2 {
		return SlotState{}, ErrFounderPlanRequired
	}
	if state.Candidate == nil || state.CandidateRecord == nil ||
		state.Candidate.InstanceOCID != facts.InstanceOCID ||
		validateManagedPeerCandidateForIntent(*state.Candidate, state.Intent, state.IntentRecord.SHA256,
			state.Intent.FounderPlanSHA256, state.Intent.PeerRowDigest, state.Intent.ManifestDigest) != nil {
		return SlotState{}, fmt.Errorf("%w: managed-peer completion requires the exact pinned candidate", ErrRecordAuthorization)
	}
	result, err := ledger.decodeResult(scope, resultBytes, false)
	if err != nil {
		return SlotState{}, err
	}
	if result.Mode != IntentModeManaged || result.PeerReceiptDigest != objectDigest(peerReceiptBytes) || result.SeedReceiptDigest != "" {
		return SlotState{}, ErrSlotHeadConflict
	}
	if state.Head.ResultDigest != "" && !state.quarantined {
		if state.Head.ResultDigest == objectDigest(resultBytes) && state.ResultRecord != nil &&
			bytes.Equal(state.ResultRecord.Bytes, resultBytes) && state.ManifestRecord != nil &&
			state.ManifestRecord.SHA256 == objectDigest(manifestBytes) && bytes.Equal(state.ManifestRecord.Bytes, manifestBytes) &&
			state.PeerReceiptRecord != nil && state.PeerReceiptRecord.SHA256 == objectDigest(peerReceiptBytes) &&
			bytes.Equal(state.PeerReceiptRecord.Bytes, peerReceiptBytes) {
			return cloneSlotState(state), nil
		}
		return SlotState{}, ErrSlotHeadConflict
	} else if state.Head.ResultDigest != "" && state.Head.ResultDigest == objectDigest(resultBytes) &&
		state.ResultRecord != nil && bytes.Equal(state.ResultRecord.Bytes, resultBytes) &&
		state.ManifestRecord != nil && bytes.Equal(state.ManifestRecord.Bytes, manifestBytes) &&
		state.PeerReceiptRecord != nil && bytes.Equal(state.PeerReceiptRecord.Bytes, peerReceiptBytes) {
		// A quarantined completed HEAD can be repaired only with fresh signed
		// proof bytes. Replaying the same late completion would preserve the
		// quarantine and must not perform another write.
		return SlotState{}, ErrManagedPeerProofQuarantined
	}
	if state.Head.Attempt != result.Attempt || state.Head.Generation != result.Generation ||
		state.Head.IntentDigest != result.IntentDigest || result.IntentDigest != state.IntentRecord.SHA256 {
		return SlotState{}, ErrSlotHeadConflict
	}
	if err := validateResultForIntent(result, state.Intent, state.IntentRecord.SHA256); err != nil {
		return SlotState{}, err
	}
	if err := validateManagedFacts(ledger, facts, state.Intent, state.IntentRecord.SHA256, result); err != nil {
		return SlotState{}, err
	}
	manifestRecord, manifestExists, err := ledger.readExistingExact(ctx, scope, state.Head.Attempt, ledgerManifest, manifestBytes)
	if err != nil {
		return SlotState{}, err
	}
	receiptRecord, receiptExists, err := ledger.readContentExact(ctx, scope, state.Head.Attempt, ledgerPeerReceipt, peerReceiptBytes)
	if err != nil {
		return SlotState{}, err
	}
	resultRecord, resultExists, err := ledger.readContentExact(ctx, scope, result.Attempt, ledgerResult, resultBytes)
	if err != nil {
		return SlotState{}, err
	}
	if resultExists && (!manifestExists || !receiptExists) {
		return SlotState{}, fmt.Errorf("%w: an existing result cannot authorize creating a missing manifest or peer receipt", ErrRecordAuthorization)
	}
	if result.PeerReceiptDigest != objectDigest(peerReceiptBytes) || objectDigest(manifestBytes) != state.Intent.ManifestDigest {
		return SlotState{}, ErrSlotHeadConflict
	}
	updatedHead, headErr := ledger.decodeHead(scope, headWithResultBytes, true)
	if headErr != nil {
		return SlotState{}, headErr
	}
	headEnvelope, err := trust.DecodeEnvelope(headWithResultBytes)
	if err != nil {
		return SlotState{}, fmt.Errorf("%w: decode completed HEAD envelope: %v", ErrInvalidRecord, err)
	}
	resultEnvelope, err := trust.DecodeEnvelope(resultBytes)
	if err != nil {
		return SlotState{}, fmt.Errorf("%w: decode result envelope: %v", ErrInvalidRecord, err)
	}
	expectedHead := state.Head
	expectedHead.ResultDigest = objectDigest(resultBytes)
	expectedHead.CandidateDigest = state.CandidateRecord.SHA256
	if !sameHead(updatedHead, expectedHead) {
		return SlotState{}, ErrSlotHeadConflict
	}

	verifiedManifest, manifestEnvelope, manifestErr := ledger.verifyCurrentIntentManifest(scope, state.Intent, manifestBytes)
	manifestCurrent := manifestErr == nil
	var historicalManifest HistoricalManifest
	if manifestErr != nil {
		if !manifestExists {
			return SlotState{}, manifestErr
		}
		historicalManifest, manifestEnvelope, err = ledger.verifyHistoricalIntentManifest(scope, state.Intent, manifestBytes)
		if err != nil {
			return SlotState{}, err
		}
	}
	receiptEnvelope, err := trust.DecodeEnvelope(peerReceiptBytes)
	if err != nil {
		return SlotState{}, fmt.Errorf("%w: decode canonical peer receipt envelope: %v", ErrInvalidRecord, err)
	}
	var receipt Receipt
	receiptCurrent := false
	var receiptCurrentErr error
	if manifestCurrent {
		verifiedReceipt, verifyErr := VerifyPeerReceipt(receiptEnvelope, verifiedManifest, facts, ledger.now(), ledger.config.TrustPolicy)
		if verifyErr == nil {
			receipt = verifiedReceipt.Receipt()
			receiptCurrent = true
		} else {
			receiptCurrentErr = verifyErr
			if !receiptExists {
				return SlotState{}, verifyErr
			}
		}
	}
	if !resultExists && (!manifestCurrent || !receiptCurrent) {
		if manifestErr != nil && !manifestExists {
			return SlotState{}, manifestErr
		}
		if receiptCurrentErr != nil && !receiptExists {
			return SlotState{}, receiptCurrentErr
		}
		if !receiptExists {
			return SlotState{}, ErrRecordAuthorization
		}
	}
	if !receiptCurrent {
		if !manifestExists || !receiptExists {
			if manifestErr != nil {
				return SlotState{}, manifestErr
			}
			return SlotState{}, ErrRecordAuthorization
		}
		historicalManifest, _, err = ledger.verifyHistoricalIntentManifest(scope, state.Intent, manifestBytes)
		if err != nil {
			return SlotState{}, err
		}
		historicalReceipt, verifyErr := VerifyHistoricalPeerReceipt(receiptEnvelope, historicalManifest, facts, ledger.config.TrustPolicy)
		if verifyErr != nil {
			return SlotState{}, verifyErr
		}
		receipt = historicalReceipt.Receipt()
	}
	if err := validatePeerReceiptForIntent(receipt, state.Intent, state.IntentRecord.SHA256); err != nil {
		return SlotState{}, err
	}
	if err := validatePeerReceiptForResult(receipt, result); err != nil {
		return SlotState{}, err
	}
	if _, err := ledger.decodeResult(scope, resultBytes, true); err != nil && !resultExists {
		return SlotState{}, err
	}

	if !manifestExists {
		peer, refreshErr := refreshCurrent()
		if refreshErr != nil {
			return SlotState{}, refreshErr
		}
		current := peer.recovery.state
		if current.ManifestRecord != nil {
			if !bytes.Equal(current.ManifestRecord.Bytes, manifestBytes) {
				return SlotState{}, ErrImmutableConflict
			}
			manifestRecord, manifestExists = *current.ManifestRecord, true
		} else {
			if peer.recovery.phase != ManagedPeerRecoveryClean &&
				peer.recovery.phase != ManagedPeerRecoveryCandidateOnly &&
				peer.recovery.phase != ManagedPeerRecoveryQuarantined {
				return SlotState{}, ErrRecordAuthorization
			}
			effectCtx, cancel, effectErr := managedPeerEffectContext(ctx, peer, time.Time{}, manifestEnvelope.ExpiresAt)
			if effectErr != nil {
				return SlotState{}, effectErr
			}
			if err := effectCtx.Err(); err != nil {
				cancel()
				return SlotState{}, err
			}
			manifestRecord, err = ledger.createOrRead(effectCtx, scope, state.Head.Attempt, ledgerManifest, manifestBytes)
			cancel()
			if err != nil {
				return SlotState{}, err
			}
			manifestExists = true
		}
	}
	if err := validateStoredInterval(manifestRecord, manifestEnvelope); err != nil {
		return SlotState{}, err
	}
	if err := ledger.validateStoredBeforeAnchorExpiry(manifestRecord); err != nil {
		return SlotState{}, err
	}
	if !receiptExists {
		if err := ledger.stageManagedPeerProof(ctx, scope, state.Head.Attempt, state.CandidateRecord.SHA256,
			ManagedPeerProgressReceipt, "receipt", peerReceiptBytes, signProgress, refreshCurrent); err != nil {
			return SlotState{}, err
		}
		peer, refreshErr := refreshCurrent()
		if refreshErr != nil {
			return SlotState{}, refreshErr
		}
		current := peer.recovery.state
		if current.ManifestRecord == nil || !bytes.Equal(current.ManifestRecord.Bytes, manifestBytes) ||
			current.CandidateRecord == nil || current.CandidateRecord.SHA256 != state.CandidateRecord.SHA256 {
			return SlotState{}, ErrRecordAuthorization
		}
		if current.PeerReceiptRecord != nil {
			if !bytes.Equal(current.PeerReceiptRecord.Bytes, peerReceiptBytes) {
				return SlotState{}, ErrImmutableConflict
			}
			receiptRecord, receiptExists = *current.PeerReceiptRecord, true
		} else if current.Progress == nil || current.ProgressRecord == nil ||
			current.Progress.Phase != ManagedPeerProgressReceipt || current.Progress.PendingProofDigest != objectDigest(peerReceiptBytes) ||
			!bytes.Equal(current.Progress.PendingProofWire, peerReceiptBytes) {
			return SlotState{}, ErrRecordAuthorization
		} else {
			progressEnvelope, decodeErr := trust.DecodeEnvelope(current.ProgressRecord.Bytes)
			if decodeErr != nil {
				return SlotState{}, ErrRecordAuthorization
			}
			effectCtx, cancel, effectErr := managedPeerEffectContext(ctx, peer, time.Time{},
				receiptEnvelope.ExpiresAt, progressEnvelope.ExpiresAt)
			if effectErr != nil {
				return SlotState{}, effectErr
			}
			if err := effectCtx.Err(); err != nil {
				cancel()
				return SlotState{}, err
			}
			receiptRecord, err = ledger.createOrReadContent(effectCtx, scope, state.Head.Attempt,
				ledgerPeerReceipt, peerReceiptBytes)
			cancel()
			if err != nil {
				return SlotState{}, err
			}
			receiptExists = true
		}
	}
	if err := validateStoredInterval(receiptRecord, receiptEnvelope); err != nil {
		return SlotState{}, err
	}
	if err := ledger.validateStoredBeforeAnchorExpiry(receiptRecord); err != nil {
		return SlotState{}, err
	}
	if !resultExists {
		peer, refreshErr := refreshCurrent()
		if refreshErr != nil {
			return SlotState{}, refreshErr
		}
		current := peer.recovery.state
		if current.ResultRecord != nil && current.ResultRecord.SHA256 == objectDigest(resultBytes) {
			if !bytes.Equal(current.ResultRecord.Bytes, resultBytes) {
				return SlotState{}, ErrImmutableConflict
			}
			resultRecord, resultExists = *current.ResultRecord, true
		} else if current.ResultRecord != nil && !current.quarantined {
			return SlotState{}, ErrImmutableConflict
		}
		if !resultExists {
			stagedExactResult := peer.recovery.phase == ManagedPeerRecoveryProofStaged && current.Progress != nil &&
				current.Progress.Phase == ManagedPeerProgressResult &&
				current.Progress.PendingProofDigest == objectDigest(resultBytes) &&
				bytes.Equal(current.Progress.PendingProofWire, resultBytes)
			if current.ManifestRecord == nil || !bytes.Equal(current.ManifestRecord.Bytes, manifestBytes) ||
				current.CandidateRecord == nil || current.CandidateRecord.SHA256 != state.CandidateRecord.SHA256 ||
				current.PeerReceiptRecord == nil || !bytes.Equal(current.PeerReceiptRecord.Bytes, peerReceiptBytes) ||
				current.PeerReceipt == nil || current.PeerReceipt.InstanceOCID != facts.InstanceOCID ||
				peer.recovery.phase != ManagedPeerRecoveryReceiptOnly &&
					peer.recovery.phase != ManagedPeerRecoveryQuarantined && !stagedExactResult {
				return SlotState{}, ErrRecordAuthorization
			}
			if err := validateManagedPeerObservationFreshness(result, peer.recovery.AuthorizationTime()); err != nil {
				return SlotState{}, err
			}
			if err := ledger.stageManagedPeerProof(ctx, scope, state.Head.Attempt, state.CandidateRecord.SHA256,
				ManagedPeerProgressResult, "result", resultBytes, signProgress, refreshCurrent); err != nil {
				return SlotState{}, err
			}
			peer, refreshErr = refreshCurrent()
			if refreshErr != nil {
				return SlotState{}, refreshErr
			}
			current = peer.recovery.state
			if current.ManifestRecord == nil || !bytes.Equal(current.ManifestRecord.Bytes, manifestBytes) ||
				current.CandidateRecord == nil || current.CandidateRecord.SHA256 != state.CandidateRecord.SHA256 ||
				current.PeerReceiptRecord == nil || !bytes.Equal(current.PeerReceiptRecord.Bytes, peerReceiptBytes) ||
				current.Progress == nil || current.ProgressRecord == nil ||
				current.Progress.Phase != ManagedPeerProgressResult ||
				current.Progress.PendingProofDigest != objectDigest(resultBytes) ||
				!bytes.Equal(current.Progress.PendingProofWire, resultBytes) {
				return SlotState{}, ErrRecordAuthorization
			}
			if err := validatePeerReceiptForIntent(receipt, state.Intent, state.IntentRecord.SHA256); err != nil {
				return SlotState{}, err
			}
			if err := validatePeerReceiptForResult(receipt, result); err != nil {
				return SlotState{}, err
			}
			freshnessDeadline := result.ObservedAt.Add(ManagedPeerObservationMaxAge)
			effectCtx, cancel, effectErr := managedPeerEffectContext(ctx, peer, freshnessDeadline,
				receiptEnvelope.ExpiresAt, resultEnvelope.ExpiresAt,
			)
			if effectErr != nil {
				return SlotState{}, effectErr
			}
			if err := effectCtx.Err(); err != nil {
				cancel()
				return SlotState{}, err
			}
			progressEnvelope, decodeErr := trust.DecodeEnvelope(current.ProgressRecord.Bytes)
			if decodeErr != nil {
				cancel()
				return SlotState{}, ErrRecordAuthorization
			}
			if !progressEnvelope.ExpiresAt.After(peer.recovery.AuthorizationTime()) {
				cancel()
				return SlotState{}, ErrRecordAuthorization
			}
			resultRecord, err = ledger.createOrReadContent(effectCtx, scope, result.Attempt, ledgerResult, resultBytes)
			cancel()
			if err != nil {
				return SlotState{}, err
			}
		}
	}
	if err := validateResultClock(result, resultRecord, ledger.config.TrustPolicy.ClockSkew); err != nil {
		return SlotState{}, err
	}
	if err := validateStoredInterval(resultRecord, resultEnvelope); err != nil {
		return SlotState{}, err
	}
	if err := validateResultStoredWithinProofs(manifestRecord, receiptRecord, resultRecord, ledger.config.AnchorExpiresAt); err != nil {
		return SlotState{}, err
	}
	if err := validateCompletionWriteOrder(manifestRecord, receiptRecord, resultRecord); err != nil {
		return SlotState{}, err
	}

	peer, refreshErr := refreshCurrent()
	if refreshErr != nil {
		return SlotState{}, refreshErr
	}
	current := peer.recovery.state
	if current.Head.ResultDigest != "" {
		if current.Head.ResultDigest == objectDigest(resultBytes) && current.ResultRecord != nil &&
			bytes.Equal(current.ResultRecord.Bytes, resultBytes) && current.ManifestRecord != nil &&
			bytes.Equal(current.ManifestRecord.Bytes, manifestBytes) && current.PeerReceiptRecord != nil &&
			bytes.Equal(current.PeerReceiptRecord.Bytes, peerReceiptBytes) && !current.quarantined {
			return cloneSlotState(current), nil
		}
		if !current.quarantined {
			return SlotState{}, ErrSlotHeadConflict
		}
	}
	if current.ResultRecord == nil ||
		!bytes.Equal(current.ResultRecord.Bytes, resultBytes) || current.ManifestRecord == nil ||
		!bytes.Equal(current.ManifestRecord.Bytes, manifestBytes) || current.PeerReceiptRecord == nil ||
		!bytes.Equal(current.PeerReceiptRecord.Bytes, peerReceiptBytes) || !sameHead(current.Head, state.Head) {
		return SlotState{}, ErrRecordAuthorization
	}
	if peer.recovery.phase != ManagedPeerRecoveryResultReady &&
		!(peer.recovery.phase == ManagedPeerRecoveryQuarantined && current.quarantined) {
		return SlotState{}, ErrRecordAuthorization
	}
	effectCtx, cancel, effectErr := managedPeerEffectContext(ctx, peer, time.Time{}, headEnvelope.ExpiresAt)
	if effectErr != nil {
		return SlotState{}, effectErr
	}
	if err := effectCtx.Err(); err != nil {
		cancel()
		return SlotState{}, err
	}
	_, _, err = ledger.writeHead(effectCtx, scope, current.HeadRecord.ETag, updatedHead, headWithResultBytes, true)
	cancel()
	if err != nil {
		return SlotState{}, err
	}
	return ledger.ReadSlot(ctx, scope)
}

func (ledger *Ledger) refreshManagedPeer(
	ctx context.Context,
	scope BootstrapScope,
	baseline SlotState,
	refresh ManagedPeerRecoveryRefresh,
) (VerifiedFounderPeer, error) {
	if refresh == nil {
		return VerifiedFounderPeer{}, fmt.Errorf("%w: a fresh selected-plan and ledger recovery callback is required", ErrRecordAuthorization)
	}
	peer, err := refresh(ctx)
	if err != nil {
		return VerifiedFounderPeer{}, err
	}
	if !peer.IsVerified() || peer.recovery == nil || !peer.recovery.verified ||
		peer.recovery.scope != scope || peer.recovery.serverDate.IsZero() ||
		peer.planDigest != baseline.Intent.FounderPlanSHA256 || peer.rowDigest != baseline.Intent.PeerRowDigest ||
		peer.row.Slot != scope.Slot || peer.row.ManifestSHA256 != baseline.Intent.ManifestDigest ||
		peer.manifest.Digest() != baseline.Intent.ManifestDigest {
		return VerifiedFounderPeer{}, fmt.Errorf("%w: fresh recovery callback is not bound to the active founder intent", ErrRecordAuthorization)
	}
	current := peer.recovery.state
	if !sameIntent(current.Intent, baseline.Intent) || current.IntentRecord.SHA256 != baseline.IntentRecord.SHA256 ||
		!bytes.Equal(current.IntentRecord.Bytes, baseline.IntentRecord.Bytes) {
		return VerifiedFounderPeer{}, ErrSlotHeadConflict
	}
	currentHead := current.Head
	currentHead.ResultDigest = baseline.Head.ResultDigest
	if !sameHead(currentHead, baseline.Head) {
		return VerifiedFounderPeer{}, ErrSlotHeadConflict
	}
	if !peer.recovery.AuthorizationTime().Before(peer.EffectDeadline()) {
		return VerifiedFounderPeer{}, ErrFounderPlanExpired
	}
	if peer.recovery.phase == ManagedPeerRecoveryClean || peer.recovery.phase == ManagedPeerRecoveryManifestOnly {
		if err := CheckRetryWindow(StoredRecord{
			LastModified: current.IntentRecord.LastModified,
			ServerDate:   peer.recovery.AuthorizationTime(),
		}); err != nil {
			return VerifiedFounderPeer{}, fmt.Errorf("%w: original intent retry window is not current: %v", ErrFounderPlanExpired, err)
		}
	}
	return peer, nil
}

func managedPeerEffectContext(
	ctx context.Context,
	peer VerifiedFounderPeer,
	freshnessDeadline time.Time,
	additionalDeadlines ...time.Time,
) (context.Context, context.CancelFunc, error) {
	if !peer.IsVerified() || peer.recovery == nil || !peer.recovery.verified {
		return nil, nil, ErrRecordAuthorization
	}
	now := peer.recovery.AuthorizationTime()
	deadline := peer.EffectDeadline().Add(-time.Second)
	for _, expiry := range additionalDeadlines {
		if !expiry.IsZero() {
			writeDeadline := expiry.Add(-time.Second)
			if writeDeadline.Before(deadline) {
				deadline = writeDeadline
			}
		}
	}
	if !freshnessDeadline.IsZero() {
		freshnessWriteDeadline := freshnessDeadline.Add(-time.Second)
		if !now.Before(freshnessWriteDeadline) {
			return nil, nil, ErrManagedPeerObservationStale
		}
		if freshnessWriteDeadline.Before(deadline) {
			deadline = freshnessWriteDeadline
		}
	}
	remaining := deadline.Sub(now)
	if remaining <= 0 {
		return nil, nil, ErrFounderPlanExpired
	}
	effectCtx, cancel := context.WithTimeout(ctx, remaining)
	if err := effectCtx.Err(); err != nil {
		cancel()
		return nil, nil, err
	}
	return effectCtx, cancel, nil
}

func validateManagedPeerObservationFreshness(result Result, authorizationTime time.Time) error {
	if result.ObservedAt.IsZero() || result.ObservedAt.Location() != time.UTC ||
		authorizationTime.IsZero() || authorizationTime.Location() != time.UTC {
		return fmt.Errorf("%w: trusted observation and recovery times are required", ErrManagedPeerObservationStale)
	}
	age := authorizationTime.Sub(result.ObservedAt)
	if age < -time.Second || age > ManagedPeerObservationMaxAge {
		return fmt.Errorf("%w: observedAt differs from conservative recovery time by %s", ErrManagedPeerObservationStale, age)
	}
	return nil
}

// AdvanceSlot admits exactly the next attempt only after the current attempt
// has an immutable positive result and a current signed, resource-specific
// retirement or seed-handoff proof. The stale HEAD ETag cannot be overwritten.
// It returns durable state; managed callers must request launch authorization
// separately, and external-seed attempts never receive one.
func (ledger *Ledger) AdvanceSlot(
	ctx context.Context,
	scope BootstrapScope,
	expectedHeadETag string,
	retirementBytes []byte,
	nextIntentBytes []byte,
	nextHeadBytes []byte,
) (SlotState, error) {
	state, err := ledger.readSlot(ctx, scope, false)
	if err != nil {
		return SlotState{}, err
	}
	if expectedHeadETag == "" || state.HeadRecord.ETag != expectedHeadETag {
		return SlotState{}, ErrSlotHeadConflict
	}
	if state.Result == nil || state.Head.ResultDigest == "" || state.ResultRecord.SHA256 != state.Head.ResultDigest {
		return SlotState{}, ErrSlotNotReserved
	}
	if state.Head.Attempt == ^uint64(0) || state.Head.Generation == ^uint64(0) {
		return SlotState{}, fmt.Errorf("%w: slot attempt sequence is exhausted", ErrInvalidRecord)
	}
	historicalIntent, _, err := ledger.decodeIntent(scope, nextIntentBytes, false)
	if err != nil {
		return SlotState{}, err
	}
	if historicalIntent.Mode == IntentModeManaged && historicalIntent.SchemaVersion != 2 {
		return SlotState{}, ErrFounderPlanRequired
	}
	previousCandidateDigest := ""
	previousManagedV2 := state.Intent.Mode == IntentModeManaged && state.Intent.SchemaVersion == 2
	if previousManagedV2 {
		if state.Head.SchemaVersion != 2 || state.CandidateRecord == nil ||
			state.Head.CandidateDigest != state.CandidateRecord.SHA256 || !validDigest(state.Head.CandidateDigest) {
			return SlotState{}, ErrSlotNotReserved
		}
		previousCandidateDigest = state.Head.CandidateDigest
	}
	if historicalIntent.Attempt != state.Head.Attempt+1 || historicalIntent.Generation != state.Head.Generation+1 {
		return SlotState{}, fmt.Errorf("%w: next attempt and generation must each advance once", ErrInvalidRecord)
	}
	evidence, evidenceEnvelope, err := ledger.decodeRetirement(scope, retirementBytes, true)
	if err != nil {
		return SlotState{}, err
	}
	nextIntent, nextIntentEnvelope, intentErr := ledger.decodeIntent(scope, nextIntentBytes, true)
	if intentErr != nil {
		return SlotState{}, intentErr
	}
	if evidence.PreviousAttempt != state.Head.Attempt || evidence.PreviousGeneration != state.Head.Generation ||
		evidence.PreviousResultDigest != state.Head.ResultDigest || evidence.PriorInstanceOCID != state.Result.InstanceOCID ||
		evidence.PriorCreateKey != state.Intent.CreateKey || evidenceEnvelope.Scope.Domain != domainSlotRetirement && evidenceEnvelope.Scope.Domain != domainSeedHandoff ||
		nextIntent.RetirementDigest != objectDigest(retirementBytes) {
		return SlotState{}, ErrRetirementInvalid
	}
	if nextIntent.Attempt != state.Head.Attempt+1 || nextIntent.Generation != state.Head.Generation+1 ||
		nextIntent.CreateKey == state.Intent.CreateKey ||
		nextIntent.Mode == IntentModeManaged && state.Intent.Mode == IntentModeManaged && nextIntent.RetryToken == state.Intent.RetryToken {
		return SlotState{}, fmt.Errorf("%w: next attempt must advance once and use fresh provider idempotency identity", ErrInvalidRecord)
	}
	if err := ledger.ensureFreshIdempotencyIdentity(ctx, scope, state.Head.Attempt, nextIntent); err != nil {
		return SlotState{}, err
	}
	nextHead, headErr := ledger.decodeHead(scope, nextHeadBytes, true)
	if headErr != nil {
		return SlotState{}, headErr
	}
	if nextHead.Attempt != nextIntent.Attempt || nextHead.Generation != nextIntent.Generation ||
		nextHead.IntentDigest != objectDigest(nextIntentBytes) || nextHead.ResultDigest != "" ||
		nextHead.PreviousAttempt != state.Head.Attempt || nextHead.PreviousGeneration != state.Head.Generation ||
		nextHead.PreviousIntentDigest != state.Head.IntentDigest || nextHead.PreviousResultDigest != state.Head.ResultDigest ||
		nextHead.PreviousCandidateDigest != previousCandidateDigest ||
		nextHead.RetirementDigest != objectDigest(retirementBytes) ||
		(nextIntent.Mode == IntentModeManaged && nextIntent.SchemaVersion == 2 || previousManagedV2) && nextHead.SchemaVersion != 2 {
		return SlotState{}, ErrRetirementInvalid
	}
	// Persist the exact, proof-bound successor intent first. Historical proof
	// verification can repair HEAD only when both it and the matching evidence
	// were already durable during the evidence's signed validity interval.
	nextIntentRecord, err := ledger.createOrRead(ctx, scope, historicalIntent.Attempt, ledgerIntent, nextIntentBytes)
	if err != nil {
		return SlotState{}, err
	}
	retirementRecord, err := ledger.createOrRead(ctx, scope, historicalIntent.Attempt, ledgerRetirement, retirementBytes)
	if err != nil {
		return SlotState{}, err
	}
	if err := validateStoredInterval(nextIntentRecord, nextIntentEnvelope); err != nil {
		return SlotState{}, err
	}
	if err := validateStoredInterval(retirementRecord, evidenceEnvelope); err != nil {
		return SlotState{}, err
	}
	if err := validateStoredBeforeExpiry(nextIntentRecord, evidenceEnvelope.ExpiresAt); err != nil {
		return SlotState{}, fmt.Errorf("%w: successor intent was not durably stored while the retirement proof was current", ErrRetirementInvalid)
	}
	if err := validateStoredBeforeExpiry(retirementRecord, evidenceEnvelope.ExpiresAt); err != nil {
		return SlotState{}, fmt.Errorf("%w: successor intent and retirement evidence were not durably stored while the proof was current", ErrRetirementInvalid)
	}
	if err := ledger.validateStoredBeforeAnchorExpiry(nextIntentRecord); err != nil {
		return SlotState{}, err
	}
	if err := ledger.validateStoredBeforeAnchorExpiry(retirementRecord); err != nil {
		return SlotState{}, err
	}
	clockErr := validIntentClock(nextIntent, nextIntentRecord, ledger.config.TrustPolicy.ClockSkew)
	if clockErr != nil {
		return SlotState{}, clockErr
	}
	// Reverify the evidence and successor intent after the immutable writes and
	// immediately before HEAD admission. Their original validity can expire
	// while those Object Storage calls are in flight.
	currentIntent, currentIntentRecord, err := ledger.refreshCurrentIntent(ctx, scope, nextIntent, nextIntentBytes)
	if err != nil {
		return SlotState{}, err
	}
	if !sameIntent(currentIntent, nextIntent) || currentIntentRecord.SHA256 != nextIntentRecord.SHA256 {
		return SlotState{}, ErrRecordAuthorization
	}
	nextIntentRecord = currentIntentRecord
	currentEvidence, currentEvidenceEnvelope, err := ledger.decodeRetirement(scope, retirementBytes, true)
	if err != nil {
		return SlotState{}, err
	}
	if currentEvidence != evidence || !currentEvidenceEnvelope.ExpiresAt.Equal(evidenceEnvelope.ExpiresAt) {
		return SlotState{}, ErrRetirementInvalid
	}
	if err := ledger.validateCurrentAuthority(); err != nil {
		return SlotState{}, err
	}
	_, headRecord, err := ledger.writeHead(ctx, scope, state.HeadRecord.ETag, nextHead, nextHeadBytes, true)
	if err != nil {
		return SlotState{}, err
	}
	if err := validateStoredBeforeExpiry(headRecord, nextIntentEnvelope.ExpiresAt); err != nil {
		return SlotState{}, err
	}
	if err := validateStoredBeforeExpiry(headRecord, evidenceEnvelope.ExpiresAt); err != nil {
		return SlotState{}, err
	}
	if err := validateHeadWithinRetryWindow(headRecord, nextIntentRecord); err != nil {
		return SlotState{}, err
	}
	return ledger.ReadSlot(ctx, scope)
}

func (ledger *Ledger) ensureFreshIdempotencyIdentity(ctx context.Context, scope BootstrapScope, lastAttempt uint64, next Intent) error {
	for attempt := uint64(1); ; attempt++ {
		record, err := ledger.read(ctx, scope, attempt, ledgerIntent)
		if err != nil {
			return fmt.Errorf("read prior bootstrap intent %d before attempt advance: %w", attempt, err)
		}
		prior, _, err := ledger.decodeIntent(scope, record.Bytes, false)
		if err != nil || prior.Attempt != attempt {
			return fmt.Errorf("%w: prior immutable intent %d is invalid", ErrSlotNotReserved, attempt)
		}
		if next.CreateKey == prior.CreateKey ||
			next.Mode == IntentModeManaged && prior.Mode == IntentModeManaged && next.RetryToken == prior.RetryToken {
			return fmt.Errorf("%w: next attempt reuses provider idempotency identity from attempt %d", ErrInvalidRecord, attempt)
		}
		if attempt == lastAttempt {
			return nil
		}
	}
}

func (ledger *Ledger) readSlot(ctx context.Context, scope BootstrapScope, requireCurrentIntent bool) (SlotState, error) {
	return ledger.readSlotWithRecovery(ctx, scope, requireCurrentIntent, false)
}

func (ledger *Ledger) readSlotForManagedPeerRecovery(ctx context.Context, scope BootstrapScope) (SlotState, error) {
	return ledger.readSlotWithRecovery(ctx, scope, false, true)
}

func (ledger *Ledger) readSlotWithRecovery(
	ctx context.Context,
	scope BootstrapScope,
	requireCurrentIntent bool,
	allowExpiredUnfinishedRecovery bool,
) (SlotState, error) {
	if err := validateLedgerScope(scope); err != nil {
		return SlotState{}, err
	}
	if err := ledger.validateAnchorScope(scope); err != nil {
		return SlotState{}, err
	}
	headRecord, err := ledger.readObject(ctx, ledger.config.HeadBucket, ledger.headObjectName(scope))
	if err != nil {
		return SlotState{}, err
	}
	headEnvelope, err := trust.DecodeEnvelope(headRecord.Bytes)
	if err != nil {
		return SlotState{}, fmt.Errorf("%w: decode persisted HEAD envelope: %v", ErrInvalidRecord, err)
	}
	quarantined := false
	if err := validateStoredInterval(headRecord, headEnvelope); err != nil {
		if !allowExpiredUnfinishedRecovery {
			return SlotState{}, err
		}
		quarantined = true
	}
	if err := ledger.validateStoredBeforeAnchorExpiry(headRecord); err != nil {
		if !allowExpiredUnfinishedRecovery {
			return SlotState{}, err
		}
		quarantined = true
	}
	head, err := ledger.decodeHead(scope, headRecord.Bytes, false)
	if err != nil {
		return SlotState{}, err
	}
	intentRecord, err := ledger.read(ctx, scope, head.Attempt, ledgerIntent)
	if err != nil {
		return SlotState{}, fmt.Errorf("read HEAD-referenced intent: %w", err)
	}
	intent, intentEnvelope, err := ledger.decodeIntent(scope, intentRecord.Bytes, requireCurrentIntent)
	if err != nil {
		return SlotState{}, err
	}
	if err := validateStoredInterval(intentRecord, intentEnvelope); err != nil {
		if !allowExpiredUnfinishedRecovery {
			return SlotState{}, err
		}
		quarantined = true
	}
	if err := ledger.validateStoredBeforeAnchorExpiry(intentRecord); err != nil {
		if !allowExpiredUnfinishedRecovery {
			return SlotState{}, err
		}
		quarantined = true
	}
	if err := validateStoredBeforeExpiry(headRecord, intentEnvelope.ExpiresAt); err != nil {
		if !allowExpiredUnfinishedRecovery {
			return SlotState{}, err
		}
		quarantined = true
	}
	if head.ResultDigest == "" && !allowExpiredUnfinishedRecovery {
		if err := validateHeadWithinRetryWindow(headRecord, intentRecord); err != nil {
			return SlotState{}, err
		}
	}
	if intent.Attempt != head.Attempt || intent.Generation != head.Generation || intentRecord.SHA256 != head.IntentDigest {
		return SlotState{}, ErrSlotNotReserved
	}
	if intent.Mode == IntentModeManaged && intent.SchemaVersion == 2 {
		if head.SchemaVersion != 2 || head.ResultDigest != "" && !validDigest(head.CandidateDigest) {
			return SlotState{}, ErrSlotNotReserved
		}
	} else if head.CandidateDigest != "" {
		return SlotState{}, ErrSlotNotReserved
	}
	if head.Attempt > 1 {
		if intent.RetirementDigest != head.RetirementDigest {
			return SlotState{}, ErrSlotNotReserved
		}
		previousIntentRecord, err := ledger.read(ctx, scope, head.PreviousAttempt, ledgerIntent)
		if err != nil || previousIntentRecord.SHA256 != head.PreviousIntentDigest {
			return SlotState{}, ErrSlotNotReserved
		}
		previousIntent, previousIntentEnvelope, err := ledger.decodeIntent(scope, previousIntentRecord.Bytes, false)
		if err != nil || previousIntent.Attempt != head.PreviousAttempt || previousIntent.Generation != head.PreviousGeneration {
			return SlotState{}, ErrSlotNotReserved
		}
		if err := validateStoredInterval(previousIntentRecord, previousIntentEnvelope); err != nil {
			return SlotState{}, ErrSlotNotReserved
		}
		if err := ledger.validateStoredBeforeAnchorExpiry(previousIntentRecord); err != nil {
			return SlotState{}, ErrSlotNotReserved
		}
		previousManagedV2 := previousIntent.Mode == IntentModeManaged && previousIntent.SchemaVersion == 2
		if previousManagedV2 {
			if head.SchemaVersion != 2 || !validDigest(head.PreviousCandidateDigest) {
				return SlotState{}, ErrSlotNotReserved
			}
		} else if head.PreviousCandidateDigest != "" {
			return SlotState{}, ErrSlotNotReserved
		}
		var previousResultRecord StoredRecord
		if previousManagedV2 {
			previousResultRecord, err = ledger.readContent(ctx, scope, head.PreviousAttempt, ledgerResult, head.PreviousResultDigest)
		} else {
			previousResultRecord, err = ledger.read(ctx, scope, head.PreviousAttempt, ledgerResult)
		}
		if err != nil || previousResultRecord.SHA256 != head.PreviousResultDigest {
			return SlotState{}, ErrSlotNotReserved
		}
		previousResult, err := ledger.decodeResult(scope, previousResultRecord.Bytes, false)
		if err != nil || validateResultForIntent(previousResult, previousIntent, previousIntentRecord.SHA256) != nil {
			return SlotState{}, ErrSlotNotReserved
		}
		if err := ledger.validateStoredResult(previousResult, previousResultRecord); err != nil {
			return SlotState{}, ErrSlotNotReserved
		}
		if previousIntent.Mode == IntentModeExternalSeed {
			if err := ledger.ensurePeerReceiptAbsent(ctx, scope, head.PreviousAttempt); err != nil {
				return SlotState{}, ErrSlotNotReserved
			}
			_, _, _, previousReceiptRecord, err := ledger.loadSeedProof(
				ctx, scope, previousIntent, previousIntentRecord.SHA256, &previousResult,
			)
			if err != nil || previousReceiptRecord == nil || previousReceiptRecord.SHA256 != previousResult.SeedReceiptDigest {
				return SlotState{}, ErrSlotNotReserved
			}
			previousManifestRecord, readErr := ledger.read(ctx, scope, head.PreviousAttempt, ledgerManifest)
			if readErr != nil || validateCompletionWriteOrder(previousManifestRecord, *previousReceiptRecord, previousResultRecord) != nil {
				return SlotState{}, ErrSlotNotReserved
			}
			if err := validateResultStoredWithinProofs(previousManifestRecord, *previousReceiptRecord, previousResultRecord, ledger.config.AnchorExpiresAt); err != nil {
				return SlotState{}, ErrSlotNotReserved
			}
		} else if previousIntent.Mode == IntentModeManaged {
			if previousResult.SeedReceiptDigest != "" {
				return SlotState{}, ErrSlotNotReserved
			}
			if _, err := ledger.read(ctx, scope, head.PreviousAttempt, ledgerSeedReceipt); err == nil || !errors.Is(err, ErrRecordMissing) {
				return SlotState{}, ErrSlotNotReserved
			}
			if previousManagedV2 {
				if err := ledger.validateCompletedManagedPeerV2Predecessor(ctx, scope, previousIntent,
					previousIntentRecord, previousResult, previousResultRecord, head.PreviousCandidateDigest); err != nil {
					return SlotState{}, ErrSlotNotReserved
				}
			} else {
				_, _, _, previousPeerReceiptRecord, err := ledger.loadManagedPeerProof(
					ctx, scope, previousIntent, previousIntentRecord.SHA256, &previousResult,
				)
				if err != nil || previousPeerReceiptRecord == nil || previousPeerReceiptRecord.SHA256 != previousResult.PeerReceiptDigest {
					return SlotState{}, ErrSlotNotReserved
				}
				previousManifestRecord, readErr := ledger.read(ctx, scope, head.PreviousAttempt, ledgerManifest)
				if readErr != nil || validateCompletionWriteOrder(previousManifestRecord, *previousPeerReceiptRecord, previousResultRecord) != nil {
					return SlotState{}, ErrSlotNotReserved
				}
				if err := validateResultStoredWithinProofs(previousManifestRecord, *previousPeerReceiptRecord, previousResultRecord, ledger.config.AnchorExpiresAt); err != nil {
					return SlotState{}, ErrSlotNotReserved
				}
			}
		} else {
			return SlotState{}, ErrSlotNotReserved
		}
		retirementRecord, err := ledger.read(ctx, scope, head.Attempt, ledgerRetirement)
		if err != nil || retirementRecord.SHA256 != head.RetirementDigest {
			return SlotState{}, ErrSlotNotReserved
		}
		retirement, retirementEnvelope, err := ledger.decodeRetirement(scope, retirementRecord.Bytes, false)
		if err != nil || retirement.PreviousAttempt != previousIntent.Attempt ||
			retirement.PreviousGeneration != previousIntent.Generation || retirement.PreviousResultDigest != head.PreviousResultDigest ||
			retirement.PriorInstanceOCID != previousResult.InstanceOCID || retirement.PriorCreateKey != previousIntent.CreateKey {
			return SlotState{}, ErrSlotNotReserved
		}
		if err := validateStoredInterval(retirementRecord, retirementEnvelope); err != nil {
			return SlotState{}, ErrSlotNotReserved
		}
		if err := ledger.validateStoredBeforeAnchorExpiry(retirementRecord); err != nil {
			return SlotState{}, ErrSlotNotReserved
		}
		if err := validateStoredBeforeExpiry(intentRecord, retirementEnvelope.ExpiresAt); err != nil {
			return SlotState{}, ErrSlotNotReserved
		}
		if err := validateStoredBeforeExpiry(retirementRecord, retirementEnvelope.ExpiresAt); err != nil {
			return SlotState{}, ErrSlotNotReserved
		}
		if err := validateStoredBeforeExpiry(headRecord, retirementEnvelope.ExpiresAt); err != nil {
			return SlotState{}, ErrSlotNotReserved
		}
	}
	state := SlotState{Head: head, HeadRecord: headRecord, Intent: intent, IntentRecord: intentRecord,
		quarantined: quarantined}
	if intent.Mode == IntentModeManaged && intent.SchemaVersion == 2 && head.SchemaVersion == 2 {
		return ledger.readManagedPeerV2State(ctx, scope, state, allowExpiredUnfinishedRecovery)
	}
	if intent.Mode == IntentModeExternalSeed {
		if err := ledger.ensurePeerReceiptAbsent(ctx, scope, head.Attempt); err != nil {
			return SlotState{}, ErrSlotNotReserved
		}
		manifest, manifestRecord, receipt, receiptRecord, err := ledger.loadSeedProof(ctx, scope, intent, intentRecord.SHA256, nil)
		if err != nil {
			return SlotState{}, err
		}
		state.Manifest, state.ManifestRecord = manifest, manifestRecord
		state.SeedReceipt, state.SeedReceiptRecord = receipt, receiptRecord
	} else if intent.Mode == IntentModeManaged {
		if _, err := ledger.read(ctx, scope, head.Attempt, ledgerSeedReceipt); err == nil {
			return SlotState{}, ErrSlotNotReserved
		} else if !errors.Is(err, ErrRecordMissing) {
			return SlotState{}, err
		}
		manifest, manifestRecord, receipt, receiptRecord, err := ledger.loadManagedPeerProof(ctx, scope, intent, intentRecord.SHA256, nil)
		if err != nil {
			return SlotState{}, err
		}
		state.Manifest, state.ManifestRecord = manifest, manifestRecord
		state.PeerReceipt, state.PeerReceiptRecord = receipt, receiptRecord
	} else {
		return SlotState{}, ErrSlotNotReserved
	}
	if head.ResultDigest != "" {
		resultRecord, err := ledger.read(ctx, scope, head.Attempt, ledgerResult)
		if err != nil {
			return SlotState{}, fmt.Errorf("read HEAD-referenced positive result: %w", err)
		}
		if resultRecord.SHA256 != head.ResultDigest {
			return SlotState{}, ErrSlotNotReserved
		}
		result, err := ledger.decodeResult(scope, resultRecord.Bytes, false)
		if err != nil || validateResultForIntent(result, intent, intentRecord.SHA256) != nil {
			return SlotState{}, ErrSlotNotReserved
		}
		if err := ledger.validateStoredResult(result, resultRecord); err != nil {
			return SlotState{}, err
		}
		if intent.Mode == IntentModeExternalSeed {
			if state.Manifest == nil || state.ManifestRecord == nil || state.SeedReceipt == nil || state.SeedReceiptRecord == nil ||
				result.SeedReceiptDigest != state.SeedReceiptRecord.SHA256 ||
				validateSeedReceiptForResult(*state.SeedReceipt, result) != nil {
				return SlotState{}, ErrSlotNotReserved
			}
			if err := validateCompletionWriteOrder(*state.ManifestRecord, *state.SeedReceiptRecord, resultRecord); err != nil {
				return SlotState{}, ErrSlotNotReserved
			}
			if err := validateResultStoredWithinProofs(*state.ManifestRecord, *state.SeedReceiptRecord, resultRecord, ledger.config.AnchorExpiresAt); err != nil {
				return SlotState{}, err
			}
		} else if state.Manifest == nil || state.ManifestRecord == nil || state.PeerReceipt == nil ||
			state.PeerReceiptRecord == nil || result.PeerReceiptDigest != state.PeerReceiptRecord.SHA256 ||
			validatePeerReceiptForIntent(*state.PeerReceipt, intent, intentRecord.SHA256) != nil ||
			validatePeerReceiptForResult(*state.PeerReceipt, result) != nil {
			return SlotState{}, ErrSlotNotReserved
		}
		if intent.Mode == IntentModeManaged {
			if err := validateCompletionWriteOrder(*state.ManifestRecord, *state.PeerReceiptRecord, resultRecord); err != nil {
				return SlotState{}, ErrSlotNotReserved
			}
			if err := validateResultStoredWithinProofs(*state.ManifestRecord, *state.PeerReceiptRecord, resultRecord, ledger.config.AnchorExpiresAt); err != nil {
				return SlotState{}, err
			}
		}
		state.Result = &result
		state.ResultRecord = &resultRecord
	}
	return state, nil
}

func (ledger *Ledger) ensurePeerReceiptAbsent(ctx context.Context, scope BootstrapScope, attempt uint64) error {
	if _, err := ledger.read(ctx, scope, attempt, ledgerPeerReceipt); err == nil {
		return ErrSlotNotReserved
	} else if !errors.Is(err, ErrRecordMissing) {
		return err
	}
	return nil
}

// validateCompletedManagedPeerV2Predecessor verifies the immutable proof chain
// named by a schema-v2 successor HEAD. Progress is mutable and is deliberately
// not used to reconstruct a predecessor's completed state after advancement.
func (ledger *Ledger) validateCompletedManagedPeerV2Predecessor(
	ctx context.Context,
	scope BootstrapScope,
	intent Intent,
	intentRecord StoredRecord,
	result Result,
	resultRecord StoredRecord,
	candidateDigest string,
) error {
	if intent.Mode != IntentModeManaged || intent.SchemaVersion != 2 ||
		result.Mode != IntentModeManaged || result.PeerReceiptDigest == "" || result.SeedReceiptDigest != "" ||
		!validDigest(candidateDigest) || resultRecord.SHA256 != objectDigest(resultRecord.Bytes) {
		return ErrRecordAuthorization
	}
	if _, err := ledger.read(ctx, scope, intent.Attempt, ledgerResult); err == nil || !errors.Is(err, ErrRecordMissing) {
		return ErrRecordAuthorization
	}
	if err := ledger.ensurePeerReceiptAbsent(ctx, scope, intent.Attempt); err != nil {
		return ErrRecordAuthorization
	}

	candidateRecord, err := ledger.read(ctx, scope, intent.Attempt, ledgerCandidate)
	if err != nil || candidateRecord.SHA256 != candidateDigest {
		return ErrRecordAuthorization
	}
	candidate, candidateEnvelope, err := ledger.decodeManagedPeerCandidate(scope, candidateRecord.Bytes, false)
	if err != nil || validateManagedPeerCandidateForIntent(candidate, intent, intentRecord.SHA256,
		intent.FounderPlanSHA256, intent.PeerRowDigest, intent.ManifestDigest) != nil ||
		candidate.InstanceOCID != result.InstanceOCID {
		return ErrRecordAuthorization
	}
	if err := validateStoredInterval(candidateRecord, candidateEnvelope); err != nil {
		return err
	}
	if err := ledger.validateStoredBeforeAnchorExpiry(candidateRecord); err != nil {
		return err
	}

	manifestRecord, err := ledger.read(ctx, scope, intent.Attempt, ledgerManifest)
	if err != nil || manifestRecord.SHA256 != intent.ManifestDigest {
		return ErrRecordAuthorization
	}
	historicalManifest, manifestEnvelope, err := ledger.verifyHistoricalIntentManifest(scope, intent, manifestRecord.Bytes)
	if err != nil {
		return err
	}
	if err := validateStoredInterval(manifestRecord, manifestEnvelope); err != nil {
		return err
	}
	if err := ledger.validateStoredBeforeAnchorExpiry(manifestRecord); err != nil {
		return err
	}

	receiptRecord, err := ledger.readContent(ctx, scope, intent.Attempt, ledgerPeerReceipt, result.PeerReceiptDigest)
	if err != nil || receiptRecord.SHA256 != result.PeerReceiptDigest {
		return ErrRecordAuthorization
	}
	receiptEnvelope, err := trust.DecodeEnvelope(receiptRecord.Bytes)
	if err != nil {
		return ErrRecordAuthorization
	}
	receipt, err := ReceiptPayload(receiptEnvelope.Payload)
	if err != nil || validatePeerReceiptForIntent(receipt, intent, intentRecord.SHA256) != nil {
		return ErrRecordAuthorization
	}
	facts, err := instanceFactsFromReceipt(receipt, historicalManifest.Manifest())
	if err != nil || facts.InstanceOCID != candidate.InstanceOCID {
		return ErrRecordAuthorization
	}
	historicalReceipt, err := VerifyHistoricalPeerReceipt(receiptEnvelope, historicalManifest, facts, ledger.config.TrustPolicy)
	if err != nil {
		return err
	}
	receipt = historicalReceipt.Receipt()
	if err := validatePeerReceiptForResult(receipt, result); err != nil {
		return err
	}
	if err := validateStoredInterval(receiptRecord, receiptEnvelope); err != nil {
		return err
	}
	if err := ledger.validateStoredBeforeAnchorExpiry(receiptRecord); err != nil {
		return err
	}
	if candidateRecord.LastModified.After(receiptRecord.LastModified) ||
		validateCompletionWriteOrder(manifestRecord, receiptRecord, resultRecord) != nil {
		return ErrRecordAuthorization
	}
	return validateResultStoredWithinProofs(manifestRecord, receiptRecord, resultRecord, ledger.config.AnchorExpiresAt)
}

func (ledger *Ledger) loadManagedPeerProof(
	ctx context.Context,
	scope BootstrapScope,
	intent Intent,
	intentDigest string,
	result *Result,
) (*Manifest, *StoredRecord, *Receipt, *StoredRecord, error) {
	manifestRecord, manifestErr := ledger.read(ctx, scope, intent.Attempt, ledgerManifest)
	manifestExists := manifestErr == nil
	if manifestErr != nil && !errors.Is(manifestErr, ErrRecordMissing) {
		return nil, nil, nil, nil, manifestErr
	}
	receiptRecord, receiptErr := ledger.read(ctx, scope, intent.Attempt, ledgerPeerReceipt)
	receiptExists := receiptErr == nil
	if receiptErr != nil && !errors.Is(receiptErr, ErrRecordMissing) {
		return nil, nil, nil, nil, receiptErr
	}
	if !manifestExists {
		if receiptExists || result != nil {
			return nil, nil, nil, nil, ErrSlotNotReserved
		}
		return nil, nil, nil, nil, nil
	}
	if intent.Mode != IntentModeManaged || manifestRecord.SHA256 != intent.ManifestDigest {
		return nil, nil, nil, nil, ErrSlotNotReserved
	}
	historicalManifest, manifestEnvelope, err := ledger.verifyHistoricalIntentManifest(scope, intent, manifestRecord.Bytes)
	if err != nil || validateStoredInterval(manifestRecord, manifestEnvelope) != nil ||
		ledger.validateStoredBeforeAnchorExpiry(manifestRecord) != nil {
		return nil, nil, nil, nil, ErrSlotNotReserved
	}
	manifest := historicalManifest.Manifest()
	manifestCopy := cloneManifest(manifest)
	manifestRecordCopy := manifestRecord
	if !receiptExists {
		if result != nil {
			return nil, nil, nil, nil, ErrSlotNotReserved
		}
		return &manifestCopy, &manifestRecordCopy, nil, nil, nil
	}
	receiptEnvelope, err := trust.DecodeEnvelope(receiptRecord.Bytes)
	if err != nil {
		return nil, nil, nil, nil, ErrSlotNotReserved
	}
	receipt, err := ReceiptPayload([]byte(receiptEnvelope.Payload))
	if err != nil || validatePeerReceiptForIntent(receipt, intent, intentDigest) != nil {
		return nil, nil, nil, nil, ErrSlotNotReserved
	}
	facts, err := instanceFactsFromReceipt(receipt, manifest)
	if err != nil {
		return nil, nil, nil, nil, ErrSlotNotReserved
	}
	historicalReceipt, err := VerifyHistoricalPeerReceipt(receiptEnvelope, historicalManifest, facts, ledger.config.TrustPolicy)
	if err != nil {
		return nil, nil, nil, nil, ErrSlotNotReserved
	}
	receipt = historicalReceipt.Receipt()
	if result != nil && (result.Mode != IntentModeManaged || result.PeerReceiptDigest != receiptRecord.SHA256 ||
		validatePeerReceiptForResult(receipt, *result) != nil) {
		return nil, nil, nil, nil, ErrSlotNotReserved
	}
	if validateStoredInterval(receiptRecord, receiptEnvelope) != nil || ledger.validateStoredBeforeAnchorExpiry(receiptRecord) != nil {
		return nil, nil, nil, nil, ErrSlotNotReserved
	}
	receiptCopy := receipt
	receiptRecordCopy := receiptRecord
	return &manifestCopy, &manifestRecordCopy, &receiptCopy, &receiptRecordCopy, nil
}

func (ledger *Ledger) loadSeedProof(
	ctx context.Context,
	scope BootstrapScope,
	intent Intent,
	intentDigest string,
	result *Result,
) (*Manifest, *StoredRecord, *Receipt, *StoredRecord, error) {
	manifestRecord, manifestErr := ledger.read(ctx, scope, intent.Attempt, ledgerManifest)
	manifestExists := manifestErr == nil
	if manifestErr != nil && !errors.Is(manifestErr, ErrRecordMissing) {
		return nil, nil, nil, nil, manifestErr
	}
	receiptRecord, receiptErr := ledger.read(ctx, scope, intent.Attempt, ledgerSeedReceipt)
	receiptExists := receiptErr == nil
	if receiptErr != nil && !errors.Is(receiptErr, ErrRecordMissing) {
		return nil, nil, nil, nil, receiptErr
	}
	if !manifestExists {
		if receiptExists || result != nil {
			return nil, nil, nil, nil, ErrSlotNotReserved
		}
		return nil, nil, nil, nil, nil
	}
	if intent.Mode != IntentModeExternalSeed || manifestRecord.SHA256 != intent.ManifestDigest {
		return nil, nil, nil, nil, ErrSlotNotReserved
	}
	historicalManifest, manifestEnvelope, err := ledger.verifyHistoricalIntentManifest(scope, intent, manifestRecord.Bytes)
	if err != nil || validateStoredInterval(manifestRecord, manifestEnvelope) != nil ||
		ledger.validateStoredBeforeAnchorExpiry(manifestRecord) != nil {
		return nil, nil, nil, nil, ErrSlotNotReserved
	}
	manifest := historicalManifest.Manifest()
	manifestCopy := cloneManifest(manifest)
	manifestRecordCopy := manifestRecord
	if !receiptExists {
		if result != nil {
			return nil, nil, nil, nil, ErrSlotNotReserved
		}
		return &manifestCopy, &manifestRecordCopy, nil, nil, nil
	}
	receiptEnvelope, err := trust.DecodeEnvelope(receiptRecord.Bytes)
	if err != nil {
		return nil, nil, nil, nil, ErrSlotNotReserved
	}
	receipt, err := ReceiptPayload([]byte(receiptEnvelope.Payload))
	if err != nil || validateSeedReceiptForIntent(receipt, intent, intentDigest) != nil {
		return nil, nil, nil, nil, ErrSlotNotReserved
	}
	facts, err := instanceFactsFromReceipt(receipt, manifest)
	if err != nil {
		return nil, nil, nil, nil, ErrSlotNotReserved
	}
	historicalReceipt, err := VerifyHistoricalSeedReceipt(receiptEnvelope, historicalManifest, ledger.config.TrustRoots, facts, ledger.config.TrustPolicy)
	if err != nil {
		return nil, nil, nil, nil, ErrSlotNotReserved
	}
	receipt = historicalReceipt.Receipt()
	if result != nil && (result.Mode != IntentModeExternalSeed || result.SeedReceiptDigest != receiptRecord.SHA256 ||
		validateSeedReceiptForResult(receipt, *result) != nil) {
		return nil, nil, nil, nil, ErrSlotNotReserved
	}
	if validateStoredInterval(receiptRecord, receiptEnvelope) != nil || ledger.validateStoredBeforeAnchorExpiry(receiptRecord) != nil {
		return nil, nil, nil, nil, ErrSlotNotReserved
	}
	receiptCopy := receipt
	receiptRecordCopy := receiptRecord
	return &manifestCopy, &manifestRecordCopy, &receiptCopy, &receiptRecordCopy, nil
}

func (ledger *Ledger) decodeSeedReceipt(scope BootstrapScope, body []byte, current bool) (Receipt, trust.Envelope, error) {
	envelope, err := trust.DecodeEnvelope(body)
	if err != nil {
		return Receipt{}, trust.Envelope{}, fmt.Errorf("%w: decode seed receipt envelope: %v", ErrInvalidRecord, err)
	}
	expected := trust.Scope{
		Domain: seedReceiptDomain, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
		Environment: ledger.config.Environment, Role: roleController, Slot: scope.Slot,
	}
	if envelope.Scope != expected {
		return Receipt{}, trust.Envelope{}, fmt.Errorf("%w: seed receipt signed scope mismatch", ErrRecordAuthorization)
	}
	now := ledger.now()
	var payload []byte
	if current {
		payload, err = trust.VerifyCurrent(envelope, expected, ledger.config.TrustRoots, now, ledger.config.TrustPolicy)
	} else {
		payload, err = trust.VerifyHistorical(envelope, expected, ledger.config.TrustRoots, ledger.config.TrustPolicy)
	}
	if err != nil {
		return Receipt{}, trust.Envelope{}, fmt.Errorf("%w: verify root-signed seed receipt: %v", ErrRecordAuthorization, err)
	}
	var receipt Receipt
	if err := decodeCanonicalPayload(payload, &receipt); err != nil || receipt.validate() != nil {
		return Receipt{}, trust.Envelope{}, fmt.Errorf("%w: seed receipt payload is invalid", ErrInvalidRecord)
	}
	return receipt, envelope, nil
}

func validateSeedReceiptForIntent(receipt Receipt, intent Intent, intentDigest string) error {
	if intent.Mode != IntentModeExternalSeed || receipt.DeploymentID != intent.DeploymentID ||
		receipt.Environment != intent.Environment || string(receipt.Cell) != intent.Cell ||
		receipt.OCIRegion != intent.OCIRegion || receipt.Role != intent.Role || receipt.Slot != intent.Slot ||
		receipt.InstanceOCID == "" || receipt.CompartmentOCID != intent.CompartmentOCID ||
		receipt.ImageOCID != intent.ImageOCID || receipt.CreateKey != intent.CreateKey ||
		receipt.IntentSHA256 != intentDigest || receipt.ManifestDigest != intent.ManifestDigest ||
		receipt.ManifestIntentSHA256 != intent.RegionIntentDigest ||
		receipt.IntentGeneration != intent.RegionIntentGeneration || receipt.ProfileSHA256 != intent.LaunchRequestDigest {
		return fmt.Errorf("%w: root-signed seed receipt does not match the stored intent", ErrInvalidRecord)
	}
	return nil
}

func validateSeedReceiptForResult(receipt Receipt, result Result) error {
	if receipt.InstanceOCID != result.InstanceOCID || receipt.CompartmentOCID != result.CompartmentOCID ||
		receipt.ImageOCID != result.ImageOCID || receipt.CreateKey != result.CreateKey ||
		receipt.OCIRegion != result.OCIRegion || receipt.ProfileSHA256 != result.ObservedProfileDigest {
		return fmt.Errorf("%w: result does not match root-signed seed receipt facts", ErrInvalidRecord)
	}
	return nil
}

func (ledger *Ledger) writeInitialHead(ctx context.Context, scope BootstrapScope, expected SlotHead, body []byte, requireCurrent bool) (SlotHead, StoredRecord, error) {
	return ledger.writeHead(ctx, scope, "", expected, body, requireCurrent)
}

func (ledger *Ledger) writeHead(ctx context.Context, scope BootstrapScope, ifMatch string, expected SlotHead, body []byte, requireCurrent bool) (SlotHead, StoredRecord, error) {
	if !requireCurrent {
		return SlotHead{}, StoredRecord{}, fmt.Errorf("%w: a current anchor-verified ledger grant is required to write slot HEAD", ErrRecordAuthorization)
	}
	actualHead, err := ledger.decodeHead(scope, body, requireCurrent)
	if err != nil || !sameHead(actualHead, expected) {
		return SlotHead{}, StoredRecord{}, ErrSlotHeadConflict
	}
	headEnvelope, err := trust.DecodeEnvelope(body)
	if err != nil {
		return SlotHead{}, StoredRecord{}, fmt.Errorf("%w: decode HEAD envelope before write: %v", ErrInvalidRecord, err)
	}
	if len(body) == 0 || len(body) > ledger.maxRecord {
		return SlotHead{}, StoredRecord{}, errors.New("bootstrap HEAD exceeds its size bound")
	}
	if err := ledger.validateCurrentAuthority(); err != nil {
		return SlotHead{}, StoredRecord{}, err
	}
	objectName := ledger.headObjectName(scope)
	ifNoneMatch := "*"
	length := int64(len(body))
	digest := sha256.Sum256(body)
	digestHeader := base64.StdEncoding.EncodeToString(digest[:])
	request := objectstorage.PutObjectRequest{
		NamespaceName:        new(ledger.config.Namespace),
		BucketName:           new(ledger.config.HeadBucket),
		ObjectName:           new(objectName),
		PutObjectBody:        io.NopCloser(bytes.NewReader(body)),
		ContentLength:        &length,
		ContentType:          new("application/json"),
		OpcSseKmsKeyId:       new(ledger.config.HeadKMSKeyID),
		OpcChecksumAlgorithm: objectstorage.PutObjectOpcChecksumAlgorithmSha256,
		OpcContentSha256:     &digestHeader,
	}
	if ifMatch == "" {
		request.IfNoneMatch = &ifNoneMatch
	} else {
		request.IfMatch = &ifMatch
	}
	if err := ctx.Err(); err != nil {
		return SlotHead{}, StoredRecord{}, err
	}
	response, putErr, putAttempted := ledger.putObjectAfterTimestampBoundary(ctx, request, headEnvelope)
	if putErr != nil && (!putAttempted || !shouldReadAfterPutError(putErr)) {
		return SlotHead{}, StoredRecord{}, fmt.Errorf("update bootstrap slot HEAD: %w", putErr)
	}
	stored, readErr := ledger.readObject(ctx, ledger.config.HeadBucket, objectName)
	if readErr != nil {
		return SlotHead{}, StoredRecord{}, fmt.Errorf("%w: write bootstrap slot HEAD: %v; exact-key read: %w", ErrOutcomeUnknown, putErr, readErr)
	}
	confirmed, err := ledger.decodeHead(scope, stored.Bytes, false)
	if err != nil {
		return SlotHead{}, StoredRecord{}, err
	}
	if !sameHead(confirmed, expected) || !bytes.Equal(stored.Bytes, body) {
		return SlotHead{}, StoredRecord{}, ErrSlotHeadConflict
	}
	if putErr == nil && response.ETag != nil && *response.ETag != "" && stored.ETag != *response.ETag {
		return SlotHead{}, StoredRecord{}, ErrSlotHeadConflict
	}
	if err := validateStoredInterval(stored, headEnvelope); err != nil {
		return SlotHead{}, StoredRecord{}, err
	}
	if err := ledger.validateStoredBeforeAnchorExpiry(stored); err != nil {
		return SlotHead{}, StoredRecord{}, err
	}
	stored.Created = ifMatch == "" && putErr == nil
	return confirmed, stored, nil
}

func (ledger *Ledger) headObjectName(scope BootstrapScope) string {
	identity := sha256.Sum256([]byte(scope.Cell + "\x00controller\x00" + scope.Slot))
	name := "bootstrap/v1/" + scope.DeploymentID + "/" + hex.EncodeToString(identity[:]) + "/head.json"
	if ledger.config.Prefix != "" {
		return ledger.config.Prefix + "/" + name
	}
	return name
}

func validateResultForIntent(result Result, intent Intent, intentDigest string) error {
	if result.Mode != intent.Mode || result.Attempt != intent.Attempt || result.Generation != intent.Generation ||
		result.RegionIntentGeneration != intent.RegionIntentGeneration || result.IntentDigest != intentDigest ||
		result.OCIRegion != intent.OCIRegion || result.CompartmentOCID != intent.CompartmentOCID ||
		result.ImageOCID != intent.ImageOCID || result.Shape != intent.Shape || result.Slot != intent.Slot ||
		result.CreateKey != intent.CreateKey || result.ObservedProfileDigest != intent.LaunchRequestDigest {
		return fmt.Errorf("%w: positive result does not match the exact immutable launch intent", ErrInvalidRecord)
	}
	return nil
}

// ExternalSeedObservationMaxAge allows time to carry the exact observed seed
// identity through offline signing while bounding its first durable result.
const ExternalSeedObservationMaxAge = 15 * time.Minute

func validateResultClock(result Result, stored StoredRecord, tolerance time.Duration) error {
	if err := CheckRetryWindow(stored); err != nil && !errors.Is(err, ErrRetryWindowExpired) {
		return err
	}
	delta := stored.LastModified.Sub(result.ObservedAt)
	if result.Mode == IntentModeManaged {
		// The observation and persisted Last-Modified values are OCI Date
		// headers with whole-second precision. Keep the signed 10-second
		// freshness bound across historical replay; current age is checked only
		// before the first immutable result write.
		if delta < -time.Second || delta > ManagedPeerObservationMaxAge+time.Second {
			return ErrInvalidRetryClock
		}
		return nil
	}
	if delta < 0 {
		delta = -delta
	}
	if delta > ExternalSeedObservationMaxAge+tolerance+time.Second {
		return ErrInvalidRetryClock
	}
	return nil
}
