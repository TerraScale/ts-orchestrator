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
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// LaunchAuthorization is an unforgeable in-process token returned only after
// the signed intent and signed stable-slot HEAD have been read back. Provider
// callers should use Intent and IntentDigest from this value for one OCI call.
type LaunchAuthorization struct {
	scope        BootstrapScope
	intent       Intent
	intentRecord StoredRecord
	head         SlotHead
	headRecord   StoredRecord
}

func (authorization LaunchAuthorization) Intent() Intent {
	intent := authorization.intent
	intent.NetworkSecurityGroupIDs = append([]string(nil), intent.NetworkSecurityGroupIDs...)
	return intent
}

func (authorization LaunchAuthorization) IntentDigest() string {
	return authorization.intentRecord.SHA256
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
	Result            *Result
	ResultRecord      *StoredRecord
	SeedReceipt       *Receipt
	SeedReceiptRecord *StoredRecord
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
	_, existingIntent, err := ledger.readExistingExact(ctx, scope, 1, ledgerIntent, intentBytes)
	if err != nil {
		return SlotState{}, err
	}
	intent, _, intentErr := ledger.decodeIntent(scope, intentBytes, true)
	intentAuthorizedNow := intentErr == nil
	if intentErr != nil {
		if !existingIntent {
			return SlotState{}, intentErr
		}
		intent, _, err = ledger.decodeIntent(scope, intentBytes, false)
		if err != nil {
			return SlotState{}, err
		}
	}
	if intent.Attempt != 1 || intent.Generation != 1 {
		return SlotState{}, fmt.Errorf("%w: an initial reservation must begin at attempt and generation one", ErrInvalidRecord)
	}
	head, headErr := ledger.decodeHead(scope, initialHeadBytes, true)
	headAuthorizedNow := headErr == nil
	if headErr != nil {
		if !existingIntent {
			return SlotState{}, headErr
		}
		head, err = ledger.decodeHead(scope, initialHeadBytes, false)
		if err != nil {
			return SlotState{}, err
		}
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
	if clockErr != nil && !errors.Is(clockErr, ErrRetryWindowExpired) {
		return SlotState{}, clockErr
	}
	_, _, err = ledger.writeInitialHead(ctx, scope, head, initialHeadBytes, intentAuthorizedNow && headAuthorizedNow)
	if err != nil {
		return SlotState{}, err
	}
	return ledger.ReadSlot(ctx, scope)
}

// ReadSlot returns a historically verified record view. It does not authorize
// a cloud mutation; use ReadForLaunch for a current signed, unexpired intent.
func (ledger *Ledger) ReadSlot(ctx context.Context, scope BootstrapScope) (SlotState, error) {
	return ledger.readSlot(ctx, scope, false)
}

// ReadForLaunch returns a launch token only when the current signed intent is
// the exact attempt referenced by HEAD, has no committed positive result, and
// remains inside the original OCI retry window.
func (ledger *Ledger) ReadForLaunch(ctx context.Context, scope BootstrapScope) (LaunchAuthorization, error) {
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
	if state.Head.Attempt == ^uint64(0) {
		return LaunchAuthorization{}, fmt.Errorf("%w: slot attempt sequence is exhausted", ErrInvalidRecord)
	}
	if _, err := ledger.read(ctx, scope, state.Head.Attempt+1, ledgerIntent); err == nil {
		return LaunchAuthorization{}, ErrSlotAdvancePendingHead
	} else if !errors.Is(err, ErrRecordMissing) {
		return LaunchAuthorization{}, err
	}
	if _, err := ledger.read(ctx, scope, state.Head.Attempt, ledgerResult); err == nil {
		return LaunchAuthorization{}, ErrSlotResultPendingHead
	} else if !errors.Is(err, ErrRecordMissing) {
		return LaunchAuthorization{}, err
	}
	if err := CheckRetryWindow(state.IntentRecord); err != nil {
		return LaunchAuthorization{}, err
	}
	return LaunchAuthorization{
		scope: scope, intent: state.Intent, intentRecord: state.IntentRecord,
		head: state.Head, headRecord: state.HeadRecord,
	}, nil
}

// RecordResult writes a signed positive OCI observation for the current HEAD
// attempt, then CAS-updates HEAD to include its immutable result digest.
func (ledger *Ledger) RecordResult(ctx context.Context, scope BootstrapScope, resultBytes, headWithResultBytes []byte) (SlotState, error) {
	result, err := ledger.decodeResult(scope, resultBytes, false)
	if err != nil {
		return SlotState{}, err
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

// RecordExternalSeed commits a root-signed seed receipt and its matching
// positive observation before advancing the slot HEAD. Exact persisted receipt
// bytes may repair a partial transition after their signature expires; a new
// receipt must be current when first stored.
func (ledger *Ledger) RecordExternalSeed(
	ctx context.Context,
	scope BootstrapScope,
	receiptBytes []byte,
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
		if state.Head.ResultDigest == objectDigest(resultBytes) && state.ResultRecord != nil &&
			state.ResultRecord.SHA256 == objectDigest(resultBytes) && state.SeedReceiptRecord != nil &&
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
		result.IntentDigest != state.IntentRecord.SHA256 || result.SeedReceiptDigest != objectDigest(receiptBytes) {
		return SlotState{}, ErrSlotHeadConflict
	}
	if err := validateResultForIntent(result, state.Intent, state.IntentRecord.SHA256); err != nil {
		return SlotState{}, err
	}
	_, receiptExists, err := ledger.readExistingExact(ctx, scope, state.Head.Attempt, ledgerSeedReceipt, receiptBytes)
	if err != nil {
		return SlotState{}, err
	}
	receipt, envelope, receiptErr := ledger.decodeSeedReceipt(scope, receiptBytes, true)
	if receiptErr != nil {
		if !receiptExists {
			return SlotState{}, receiptErr
		}
		receipt, envelope, err = ledger.decodeSeedReceipt(scope, receiptBytes, false)
		if err != nil {
			return SlotState{}, err
		}
	}
	if err := validateSeedReceiptForIntent(receipt, state.Intent, state.IntentRecord.SHA256); err != nil {
		return SlotState{}, err
	}
	if err := validateSeedReceiptForResult(receipt, result); err != nil {
		return SlotState{}, err
	}
	_, resultExists, err := ledger.readExistingExact(ctx, scope, result.Attempt, ledgerResult, resultBytes)
	if err != nil {
		return SlotState{}, err
	}
	if _, err := ledger.decodeResult(scope, resultBytes, true); err != nil && !resultExists {
		return SlotState{}, err
	}
	storedReceipt, err := ledger.createOrRead(ctx, scope, state.Head.Attempt, ledgerSeedReceipt, receiptBytes)
	if err != nil {
		return SlotState{}, err
	}
	if storedReceipt.LastModified.Before(envelope.IssuedAt.Add(-ledger.config.TrustPolicy.ClockSkew)) ||
		storedReceipt.LastModified.After(envelope.ExpiresAt) {
		return SlotState{}, fmt.Errorf("%w: seed receipt was not durably stored while its root signature was current", ErrRecordAuthorization)
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
		if !resultExists {
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
	if _, _, err := ledger.writeHead(ctx, scope, state.HeadRecord.ETag, updatedHead, headWithResultBytes, headAuthorizedNow); err != nil {
		return SlotState{}, err
	}
	return ledger.ReadSlot(ctx, scope)
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
	if historicalIntent.Attempt != state.Head.Attempt+1 || historicalIntent.Generation != state.Head.Generation+1 {
		return SlotState{}, fmt.Errorf("%w: next attempt and generation must each advance once", ErrInvalidRecord)
	}
	_, retirementExists, err := ledger.readExistingExact(ctx, scope, historicalIntent.Attempt, ledgerRetirement, retirementBytes)
	if err != nil {
		return SlotState{}, err
	}
	_, nextIntentExists, err := ledger.readExistingExact(ctx, scope, historicalIntent.Attempt, ledgerIntent, nextIntentBytes)
	if err != nil {
		return SlotState{}, err
	}
	evidence, evidenceEnvelope, evidenceErr := ledger.decodeRetirement(scope, retirementBytes, true)
	if evidenceErr != nil {
		if !retirementExists || !nextIntentExists {
			return SlotState{}, evidenceErr
		}
		evidence, evidenceEnvelope, err = ledger.decodeRetirement(scope, retirementBytes, false)
		if err != nil {
			return SlotState{}, err
		}
	}
	nextIntent, _, intentErr := ledger.decodeIntent(scope, nextIntentBytes, true)
	if intentErr != nil {
		if !retirementExists || !nextIntentExists {
			return SlotState{}, intentErr
		}
		nextIntent = historicalIntent
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
	headAuthorizedNow := headErr == nil
	if headErr != nil {
		if !retirementExists || !nextIntentExists {
			return SlotState{}, headErr
		}
		nextHead, err = ledger.decodeHead(scope, nextHeadBytes, false)
		if err != nil {
			return SlotState{}, err
		}
	}
	if nextHead.Attempt != nextIntent.Attempt || nextHead.Generation != nextIntent.Generation ||
		nextHead.IntentDigest != objectDigest(nextIntentBytes) || nextHead.ResultDigest != "" ||
		nextHead.PreviousAttempt != state.Head.Attempt || nextHead.PreviousGeneration != state.Head.Generation ||
		nextHead.PreviousIntentDigest != state.Head.IntentDigest || nextHead.PreviousResultDigest != state.Head.ResultDigest ||
		nextHead.RetirementDigest != objectDigest(retirementBytes) {
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
	if nextIntentRecord.LastModified.Before(evidenceEnvelope.IssuedAt.Add(-ledger.config.TrustPolicy.ClockSkew)) ||
		nextIntentRecord.LastModified.After(evidenceEnvelope.ExpiresAt) ||
		retirementRecord.LastModified.Before(evidenceEnvelope.IssuedAt.Add(-ledger.config.TrustPolicy.ClockSkew)) ||
		retirementRecord.LastModified.After(evidenceEnvelope.ExpiresAt) {
		return SlotState{}, fmt.Errorf("%w: successor intent and retirement evidence were not durably stored while the proof was current", ErrRetirementInvalid)
	}
	clockErr := validIntentClock(nextIntent, nextIntentRecord, ledger.config.TrustPolicy.ClockSkew)
	if clockErr != nil && !errors.Is(clockErr, ErrRetryWindowExpired) {
		return SlotState{}, clockErr
	}
	_, _, err = ledger.writeHead(ctx, scope, state.HeadRecord.ETag, nextHead, nextHeadBytes, headAuthorizedNow)
	if err != nil {
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
	if err := validateLedgerScope(scope); err != nil {
		return SlotState{}, err
	}
	headRecord, err := ledger.readObject(ctx, ledger.config.HeadBucket, ledger.headObjectName(scope))
	if err != nil {
		return SlotState{}, err
	}
	head, err := ledger.decodeHead(scope, headRecord.Bytes, false)
	if err != nil {
		return SlotState{}, err
	}
	intentRecord, err := ledger.read(ctx, scope, head.Attempt, ledgerIntent)
	if err != nil {
		return SlotState{}, fmt.Errorf("read HEAD-referenced intent: %w", err)
	}
	intent, _, err := ledger.decodeIntent(scope, intentRecord.Bytes, requireCurrentIntent)
	if err != nil {
		return SlotState{}, err
	}
	if intent.Attempt != head.Attempt || intent.Generation != head.Generation || intentRecord.SHA256 != head.IntentDigest {
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
		previousIntent, _, err := ledger.decodeIntent(scope, previousIntentRecord.Bytes, false)
		if err != nil || previousIntent.Attempt != head.PreviousAttempt || previousIntent.Generation != head.PreviousGeneration {
			return SlotState{}, ErrSlotNotReserved
		}
		previousResultRecord, err := ledger.read(ctx, scope, head.PreviousAttempt, ledgerResult)
		if err != nil || previousResultRecord.SHA256 != head.PreviousResultDigest {
			return SlotState{}, ErrSlotNotReserved
		}
		previousResult, err := ledger.decodeResult(scope, previousResultRecord.Bytes, false)
		if err != nil || validateResultForIntent(previousResult, previousIntent, previousIntentRecord.SHA256) != nil {
			return SlotState{}, ErrSlotNotReserved
		}
		if previousIntent.Mode == IntentModeExternalSeed {
			previousReceiptRecord, err := ledger.read(ctx, scope, head.PreviousAttempt, ledgerSeedReceipt)
			if err != nil || previousReceiptRecord.SHA256 != previousResult.SeedReceiptDigest {
				return SlotState{}, ErrSlotNotReserved
			}
			previousReceipt, receiptEnvelope, err := ledger.decodeSeedReceipt(scope, previousReceiptRecord.Bytes, false)
			if err != nil || validateSeedReceiptForIntent(previousReceipt, previousIntent, previousIntentRecord.SHA256) != nil ||
				validateSeedReceiptForResult(previousReceipt, previousResult) != nil ||
				previousReceiptRecord.LastModified.Before(receiptEnvelope.IssuedAt.Add(-ledger.config.TrustPolicy.ClockSkew)) ||
				previousReceiptRecord.LastModified.After(receiptEnvelope.ExpiresAt) {
				return SlotState{}, ErrSlotNotReserved
			}
		} else if previousResult.SeedReceiptDigest != "" {
			return SlotState{}, ErrSlotNotReserved
		} else if _, err := ledger.read(ctx, scope, head.PreviousAttempt, ledgerSeedReceipt); err == nil || !errors.Is(err, ErrRecordMissing) {
			return SlotState{}, ErrSlotNotReserved
		}
		retirementRecord, err := ledger.read(ctx, scope, head.Attempt, ledgerRetirement)
		if err != nil || retirementRecord.SHA256 != head.RetirementDigest {
			return SlotState{}, ErrSlotNotReserved
		}
		retirement, _, err := ledger.decodeRetirement(scope, retirementRecord.Bytes, false)
		if err != nil || retirement.PreviousAttempt != previousIntent.Attempt ||
			retirement.PreviousGeneration != previousIntent.Generation || retirement.PreviousResultDigest != head.PreviousResultDigest ||
			retirement.PriorInstanceOCID != previousResult.InstanceOCID || retirement.PriorCreateKey != previousIntent.CreateKey {
			return SlotState{}, ErrSlotNotReserved
		}
	}
	state := SlotState{Head: head, HeadRecord: headRecord, Intent: intent, IntentRecord: intentRecord}
	if intent.Mode == IntentModeExternalSeed {
		receiptRecord, err := ledger.read(ctx, scope, head.Attempt, ledgerSeedReceipt)
		if err == nil {
			receipt, envelope, err := ledger.decodeSeedReceipt(scope, receiptRecord.Bytes, false)
			if err != nil || validateSeedReceiptForIntent(receipt, intent, intentRecord.SHA256) != nil ||
				receiptRecord.LastModified.Before(envelope.IssuedAt.Add(-ledger.config.TrustPolicy.ClockSkew)) ||
				receiptRecord.LastModified.After(envelope.ExpiresAt) {
				return SlotState{}, ErrSlotNotReserved
			}
			state.SeedReceipt = &receipt
			state.SeedReceiptRecord = &receiptRecord
		} else if !errors.Is(err, ErrRecordMissing) {
			return SlotState{}, err
		}
	} else {
		if _, err := ledger.read(ctx, scope, head.Attempt, ledgerSeedReceipt); err == nil {
			return SlotState{}, ErrSlotNotReserved
		} else if !errors.Is(err, ErrRecordMissing) {
			return SlotState{}, err
		}
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
		if intent.Mode == IntentModeExternalSeed {
			if state.SeedReceipt == nil || state.SeedReceiptRecord == nil || result.SeedReceiptDigest != state.SeedReceiptRecord.SHA256 ||
				validateSeedReceiptForResult(*state.SeedReceipt, result) != nil {
				return SlotState{}, ErrSlotNotReserved
			}
		}
		state.Result = &result
		state.ResultRecord = &resultRecord
	}
	return state, nil
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
	actualHead, err := ledger.decodeHead(scope, body, requireCurrent)
	if err != nil || !sameHead(actualHead, expected) {
		return SlotHead{}, StoredRecord{}, ErrSlotHeadConflict
	}
	if len(body) == 0 || len(body) > ledger.maxRecord {
		return SlotHead{}, StoredRecord{}, errors.New("bootstrap HEAD exceeds its size bound")
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
	response, putErr := ledger.client.PutObject(ctx, request)
	if putErr != nil && !shouldReadAfterPutError(putErr) {
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

func validateResultClock(result Result, stored StoredRecord, tolerance time.Duration) error {
	if err := CheckRetryWindow(stored); err != nil && !errors.Is(err, ErrRetryWindowExpired) {
		return err
	}
	delta := stored.LastModified.Sub(result.ObservedAt)
	if delta < 0 {
		delta = -delta
	}
	if delta > tolerance+time.Second {
		return ErrInvalidRetryClock
	}
	return nil
}
