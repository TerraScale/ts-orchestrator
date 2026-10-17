package bootstrap

import (
	"bytes"
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// ControllerRetirement is read from the actual verified ledger. It authorizes
// no Swarm action and proves no provider lifecycle state by itself.
type ControllerRetirement struct {
	Evidence         RetirementEvidence
	PriorIntent      Intent
	Current          SlotState
	RetirementSHA256 string
}

// ReadControllerRetirement verifies a root-signed retired managed attempt
// against the current slot. With no wire it reads the exact protected retirement
// selected by the current HEAD; it never searches by instance name or tags.
func (ledger *Ledger) ReadControllerRetirement(ctx context.Context, scope BootstrapScope, wire []byte) (ControllerRetirement, error) {
	fail := func() (ControllerRetirement, error) { return ControllerRetirement{}, ErrRetirementInvalid }
	if ledger == nil || ctx == nil || len(wire) > maxLedgerRecordBytes {
		return fail()
	}
	state, err := ledger.ReadSlot(ctx, scope)
	if err != nil {
		return ControllerRetirement{}, err
	}
	protected := len(wire) == 0
	if protected {
		if state.Head.Attempt <= 1 || state.Head.RetirementDigest == "" {
			return fail()
		}
		record, err := ledger.read(ctx, scope, state.Head.Attempt, ledgerRetirement)
		if err != nil || record.SHA256 != state.Head.RetirementDigest {
			return fail()
		}
		wire = record.Bytes
	}
	evidence, envelope, err := ledger.decodeRetirement(scope, wire, false)
	if err != nil || ValidateSlotRetirementCandidate(evidence) != nil || envelope.Scope.Domain != domainSlotRetirement {
		return fail()
	}
	// A delegated ledger writer never gains the offline root's retirement domain.
	if _, err := trust.VerifyHistorical(envelope, envelope.Scope, ledger.config.TrustRoots, ledger.config.TrustPolicy); err != nil {
		return fail()
	}
	var prior Intent
	switch {
	case state.Head.Attempt == evidence.PreviousAttempt:
		if protected || state.Result == nil || state.ResultRecord == nil || state.Intent.Mode != IntentModeManaged ||
			evidence.PreviousGeneration != state.Head.Generation || evidence.PreviousResultDigest != state.Head.ResultDigest ||
			evidence.PriorInstanceOCID != state.Result.InstanceOCID || evidence.PriorCreateKey != state.Intent.CreateKey {
			return fail()
		}
		if _, err := trust.VerifyCurrent(envelope, envelope.Scope, ledger.config.TrustRoots, ledger.now(), ledger.config.TrustPolicy); err != nil {
			return fail()
		}
		prior = state.Intent
	case state.Head.Attempt == evidence.PreviousAttempt+1:
		if state.Head.PreviousAttempt != evidence.PreviousAttempt || state.Head.PreviousGeneration != evidence.PreviousGeneration ||
			state.Head.PreviousResultDigest != evidence.PreviousResultDigest || state.Head.RetirementDigest != objectDigest(wire) {
			return fail()
		}
		record, err := ledger.read(ctx, scope, state.Head.Attempt, ledgerRetirement)
		if err != nil || record.SHA256 != state.Head.RetirementDigest || !bytes.Equal(record.Bytes, wire) {
			return fail()
		}
		previous, err := ledger.read(ctx, scope, evidence.PreviousAttempt, ledgerIntent)
		if err != nil || previous.SHA256 != state.Head.PreviousIntentDigest {
			return fail()
		}
		prior, _, err = ledger.decodeIntent(scope, previous.Bytes, false)
		if err != nil || prior.Mode != IntentModeManaged || prior.CreateKey != evidence.PriorCreateKey {
			return fail()
		}
		// ReadSlot already verified this predecessor's exact result/candidate/
		// receipt and the immutable retirement's signed storage interval.
	default:
		return fail()
	}
	if prior.Attempt != evidence.PreviousAttempt || prior.Generation != evidence.PreviousGeneration {
		return fail()
	}
	confirmed, err := ledger.ReadSlot(ctx, scope)
	if err != nil {
		return ControllerRetirement{}, err
	}
	if confirmed.HeadRecord.SHA256 != state.HeadRecord.SHA256 || confirmed.HeadRecord.ETag != state.HeadRecord.ETag || !bytes.Equal(confirmed.HeadRecord.Bytes, state.HeadRecord.Bytes) {
		return ControllerRetirement{}, errors.New("controller retirement HEAD changed while reading its predecessor")
	}
	if err := ctx.Err(); err != nil {
		return ControllerRetirement{}, err
	}
	return ControllerRetirement{Evidence: evidence, PriorIntent: prior, Current: state, RetirementSHA256: objectDigest(wire)}, nil
}
