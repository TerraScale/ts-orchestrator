package authority

import (
	"bytes"
	"context"
	"errors"

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
