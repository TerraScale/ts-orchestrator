package authority

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

// IdentityResetGlobalLease pins the home region's opaque global predecessor.
// Its root-signed replacement uses the same transaction and deployment.
type IdentityResetGlobalLease struct {
	PreviousSequence uint64 `json:"previous_sequence"`
	PreviousSHA256   string `json:"previous_sha256"`
	EpochFloor       uint64 `json:"epoch_floor"`
	Epoch            uint64 `json:"epoch"`
}

func (pin IdentityResetGlobalLease) validate(reset IdentityReset) error {
	if reset.Scope == protocol.GlobalScope || reset.LastSequence > ^uint64(0)-2 || pin.PreviousSequence > reset.LastSequence ||
		pin.PreviousSequence == 0 && (pin.PreviousSHA256 != "" || pin.EpochFloor != 0) ||
		pin.PreviousSequence != 0 && (!validTerminalDigest(pin.PreviousSHA256) || pin.EpochFloor == 0) ||
		pin.Epoch <= pin.EpochFloor || pin.Epoch == ^uint64(0) {
		return errors.New("identity reset global lease has invalid opaque predecessor or epoch")
	}
	return nil
}

func globalResetLease(reset IdentityReset, pinID string) ([]byte, error) {
	reset.Scope, reset.Epoch = protocol.GlobalScope, reset.GlobalLease.Epoch
	return identityResetLease(reset, pinID)
}

func verifyIdentityResetGlobalPredecessor(ctx context.Context, stream jetstream.Stream, reset IdentityReset) error {
	if reset.GlobalLease == nil {
		return nil
	}
	msg, err := stream.GetLastMsgForSubject(ctx, controlSubjectRoot+"."+protocol.GlobalScope+".lease")
	if errors.Is(err, jetstream.ErrMsgNotFound) && reset.GlobalLease.PreviousSequence == 0 {
		return nil
	}
	if err != nil {
		return err
	}
	if msg.Sequence != reset.GlobalLease.PreviousSequence || resetDigest(msg.Data) != reset.GlobalLease.PreviousSHA256 {
		return ErrConflict
	}
	return nil
}

// globalResetOutcome uses immutable subject history, so a later acquisition
// cannot hide either the exact hold or its completion.
func globalResetOutcome(ctx context.Context, stream jetstream.Stream, reset IdentityReset, pinID string) (uint64, uint64, error) {
	subject := controlSubjectRoot + "." + protocol.GlobalScope + ".lease"
	held, err := stream.GetMsg(ctx, reset.GlobalLease.PreviousSequence+1, jetstream.WithGetMsgSubject(subject))
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	want, err := globalResetLease(reset, pinID)
	if err != nil || held.Subject != subject || !bytes.Equal(held.Data, want) {
		return 0, 0, ErrConflict
	}
	complete, err := stream.GetMsg(ctx, held.Sequence+1, jetstream.WithGetMsgSubject(subject))
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return held.Sequence, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	want, err = globalResetLease(reset, "")
	if err != nil || complete.Subject != subject || !bytes.Equal(complete.Data, want) {
		return 0, 0, ErrConflict
	}
	return held.Sequence, complete.Sequence, nil
}

func holdIdentityResetGlobalLease(ctx context.Context, js jetstream.JetStream, reset IdentityReset, pinID string, replicas int) error {
	if reset.GlobalLease == nil {
		return nil
	}
	if err := verifyResetBarrier(ctx, js, reset, pinID, replicas); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
	defer cancel()
	stream, err := js.Stream(bounded, ControlStreamName)
	if err != nil {
		return err
	}
	held, _, err := globalResetOutcome(bounded, stream, reset, pinID)
	if err != nil || held != reset.LastSequence+2 {
		return errors.Join(ErrFenced, err)
	}
	return nil
}

// Both scopes enter the hold in one native atomic append. An election, renewal
// or lost reply can never leave only one root-pinned scope committed.
func publishIdentityResetBatch(ctx context.Context, js jetstream.JetStream, stream jetstream.Stream, reset IdentityReset,
	envelope trust.Envelope, roots trust.Keyring, target IdentityResetTarget,
) (uint64, error) {
	bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
	defer cancel()
	info, err := stream.Info(bounded)
	if err != nil {
		return 0, err
	}
	if err := verifyControlStreamConfig(info.Config, target.Replicas); err != nil {
		return 0, err
	}
	info.Config.AllowAtomicPublish = true
	if _, err := js.UpdateStream(bounded, info.Config); err != nil {
		return 0, err
	}
	pinID := resetDigest(envelope.Payload)
	regional, err := identityResetLease(reset, pinID)
	if err != nil {
		return 0, err
	}
	global, err := globalResetLease(reset, pinID)
	if err != nil {
		return 0, err
	}
	batchID := entityid.New()
	first := controlMessage(controlSubjectRoot+"."+reset.Scope+".lease", "lease", reset.OperationID, regional)
	first.Header.Set("Nats-Batch-Id", batchID)
	first.Header.Set("Nats-Batch-Sequence", "1")
	first.Header.Set(nats.ExpectedLastSeqHdr, strconv.FormatUint(reset.LastSequence, 10))
	first.Header.Set(nats.ExpectedLastSubjSeqHdr, strconv.FormatUint(reset.PreviousSequence, 10))
	second := controlMessage(controlSubjectRoot+"."+protocol.GlobalScope+".lease", "lease", reset.OperationID+":global", global)
	second.Header.Set("Nats-Batch-Id", batchID)
	second.Header.Set("Nats-Batch-Sequence", "2")
	second.Header.Set("Nats-Batch-Commit", "1")
	second.Header.Set(nats.ExpectedLastSubjSeqHdr, strconv.FormatUint(reset.GlobalLease.PreviousSequence, 10))
	publishErr := js.Conn().PublishMsg(first)
	if publishErr == nil {
		_, publishErr = js.PublishMsg(bounded, second)
	}
	probe, probeCancel := context.WithTimeout(context.WithoutCancel(ctx), authorityAPITimeout)
	defer probeCancel()
	if _, err := verifyCommittedIdentityReset(probe, js, envelope, roots, target); err == nil {
		return reset.LastSequence + 1, nil
	} else if isSequenceConflict(publishErr) || errors.Is(err, ErrConflict) {
		return 0, ErrConflict
	} else {
		return 0, fmt.Errorf("%w: atomic identity reset: %w", ErrOutcomeUnknown, errors.Join(publishErr, err))
	}
}

func completeIdentityResetBatch(ctx context.Context, js jetstream.JetStream, stream jetstream.Stream,
	reset IdentityReset, pinID string, lastSequence uint64, replicas int,
) (uint64, error) {
	bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
	defer cancel()
	held, complete, err := globalResetOutcome(bounded, stream, reset, pinID)
	if err != nil || complete != 0 || held != reset.LastSequence+2 {
		return 0, errors.Join(ErrFenced, err)
	}
	global, err := globalResetLease(reset, "")
	if err != nil {
		return 0, err
	}
	regional, err := identityResetLease(reset, "")
	if err != nil {
		return 0, err
	}
	batchID := entityid.New()
	first := controlMessage(controlSubjectRoot+"."+protocol.GlobalScope+".lease", "lease", reset.OperationID+":global:complete", global)
	first.Header.Set("Nats-Batch-Id", batchID)
	first.Header.Set("Nats-Batch-Sequence", "1")
	first.Header.Set(nats.ExpectedLastSeqHdr, strconv.FormatUint(lastSequence, 10))
	first.Header.Set(nats.ExpectedLastSubjSeqHdr, strconv.FormatUint(held, 10))
	second := controlMessage(controlSubjectRoot+"."+reset.Scope+".lease", "lease", reset.OperationID+":complete", regional)
	second.Header.Set("Nats-Batch-Id", batchID)
	second.Header.Set("Nats-Batch-Sequence", "2")
	second.Header.Set("Nats-Batch-Commit", "1")
	second.Header.Set(nats.ExpectedLastSubjSeqHdr, strconv.FormatUint(reset.LastSequence+1, 10))
	publishErr := js.Conn().PublishMsg(first)
	if publishErr == nil {
		_, publishErr = js.PublishMsg(bounded, second)
	}
	probe, probeCancel := context.WithTimeout(context.WithoutCancel(ctx), authorityAPITimeout)
	defer probeCancel()
	sequence, readErr := identityResetCompletion(probe, js, reset, pinID, replicas)
	if readErr == nil && sequence != 0 {
		return sequence, nil
	}
	if isSequenceConflict(publishErr) {
		return 0, ErrConflict
	}
	return 0, fmt.Errorf("%w: atomic reset completion: %w", ErrOutcomeUnknown, errors.Join(publishErr, readErr))
}
