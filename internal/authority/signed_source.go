package authority

import (
	"bytes"
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	maxPlacementSourceWire = 20 << 10
	maxTerminalSourceWire  = 36 << 10
)

// CommitSignedPlacementIntent atomically retains exact ingress with its admitted payload.
// The archive is evidence, never a substitute for independent root authentication.
func (r *Runtime) CommitSignedPlacementIntent(ctx context.Context, epoch uint64, databaseID, partitionID, operationID string,
	expectedSequence uint64, payload, originalWire []byte,
) (uint64, error) {
	if len(originalWire) == 0 {
		return 0, errors.New("placement admission requires its original signed ingress")
	}
	payload = bytes.Clone(payload)
	originalWire = bytes.Clone(originalWire)
	subjectKey, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil {
		return 0, err
	}
	release, err := r.beginWorkloadGate(ctx, WorkloadScope{DatabaseID: databaseID, PartitionID: partitionID})
	if err != nil {
		return 0, err
	}
	defer release()
	if err := r.requireNoTerminalIntent(ctx, databaseID, partitionID); err != nil {
		return 0, err
	}
	return r.commitMutationSourceVerified(ctx, epoch, MutationPlacementIntent, subjectKey, operationID, expectedSequence,
		payload, originalWire, func(check context.Context) error {
			return r.requireNoActiveBackup(check, databaseID, partitionID)
		})
}

// Readers expose retained evidence without acquiring a mutation capability.
func (r *Reader) CommitSignedPlacementIntent(context.Context, uint64, string, string, string, uint64, []byte, []byte) (uint64, error) {
	return 0, ErrNotLeader
}

// CommitSignedTerminalIntent preserves ingress under the existing exclusive terminal gate.
func (r *Runtime) CommitSignedTerminalIntent(ctx context.Context, epoch uint64, scope WorkloadScope,
	operationID string, payload, originalWire []byte, verifySettled func(context.Context) error,
) (uint64, error) {
	if len(originalWire) == 0 {
		return 0, errors.New("terminal admission requires its original signed ingress")
	}
	return r.commitTerminalIntent(ctx, epoch, scope, operationID, payload, originalWire, verifySettled)
}

func validateSignedSource(kind HostMutationKind, scope, operationID string, epoch uint64, payload, wire []byte) error {
	if len(wire) == 0 {
		return nil
	}
	var expectedKind string
	var limit int
	switch kind {
	case MutationPlacementIntent:
		expectedKind, limit = "placement.intent", maxPlacementSourceWire
	case MutationTerminalIntent:
		expectedKind, limit = "placement.terminal.apply", maxTerminalSourceWire
	default:
		return errors.New("original ingress is outside the bounded signed source")
	}
	if len(wire) > limit {
		return errors.New("original signed ingress exceeds its source limit")
	}
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, limit); err != nil {
		return err
	}
	if envelope.SchemaVersion != protocol.EnvelopeSchemaVersion || envelope.Kind != expectedKind || envelope.Region != scope ||
		envelope.OperationID != operationID || envelope.Epoch != epoch || envelope.Generation == 0 || envelope.Actor == "" ||
		envelope.KeyID == "" || envelope.Signature == "" || !envelope.ExpiresAt.After(envelope.IssuedAt) || !bytes.Equal(envelope.Payload, payload) {
		return errors.New("original signed ingress differs from its committed payload or scope")
	}
	return nil
}
