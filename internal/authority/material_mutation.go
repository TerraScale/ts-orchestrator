package authority

import (
	"bytes"
	"context"
	"errors"
)

// CommitMaterialReceiptVerified checks local sources at entry, the final CAS
// boundary and exact committed readback. The callback grants no root authority.
// It must accept an identical committed retry as well as a fresh candidate.
func (r *Runtime) CommitMaterialReceiptVerified(ctx context.Context, epoch uint64,
	databaseID, partitionID, operationID string, expectedSequence uint64, payload []byte,
	verify func(context.Context) error,
) (uint64, error) {
	return r.commitMaterialMutationVerified(ctx, epoch, MutationMaterialReceipt,
		databaseID, partitionID, operationID, expectedSequence, payload, verify)
}

// CommitClientCredentialsVerified retains the terminal workload gate while
// applying the same local checks as CommitMaterialReceiptVerified.
func (r *Runtime) CommitClientCredentialsVerified(ctx context.Context, epoch uint64,
	databaseID, partitionID, operationID string, expectedSequence uint64, payload []byte,
	verify func(context.Context) error,
) (uint64, error) {
	return r.commitMaterialMutationVerified(ctx, epoch, MutationClientCredentials,
		databaseID, partitionID, operationID, expectedSequence, payload, verify)
}

func (r *Runtime) commitMaterialMutationVerified(ctx context.Context, epoch uint64, kind HostMutationKind,
	databaseID, partitionID, operationID string, expectedSequence uint64, payload []byte,
	verify func(context.Context) error,
) (uint64, error) {
	if r == nil {
		return 0, ErrNotLeader
	}
	if ctx == nil || verify == nil {
		return 0, errors.New("verified material mutation requires its original context and local verifier")
	}
	subjectKey, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil {
		return 0, err
	}
	payload = bytes.Clone(payload)
	if err := validateMutation(kind, subjectKey, operationID, payload); err != nil {
		return 0, err
	}
	check := func(current context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := current.Err(); err != nil {
			return err
		}
		if err := verify(current); err != nil {
			return err
		}
		return errors.Join(ctx.Err(), current.Err())
	}
	if err := check(ctx); err != nil {
		return 0, err
	}
	if kind == MutationClientCredentials {
		release, err := r.beginWorkloadGate(ctx, WorkloadScope{DatabaseID: databaseID, PartitionID: partitionID})
		if err != nil {
			return 0, err
		}
		defer release()
		if err := r.requireNoTerminalIntent(ctx, databaseID, partitionID); err != nil {
			return 0, err
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	sequence, commitErr := r.commitMutationVerified(ctx, epoch, kind, subjectKey,
		operationID, expectedSequence, payload, check)
	if err := ctx.Err(); err != nil {
		return sequence, errors.Join(commitErr, err)
	}
	if commitErr != nil {
		return sequence, commitErr
	}
	// Preserve a known sequence on refusal; an error never means not applied.
	entry, err := r.ReadHostMutation(ctx, kind, subjectKey)
	if err != nil {
		return sequence, err
	}
	if entry.Sequence != sequence || entry.Epoch != epoch || entry.Kind != kind ||
		entry.SubjectKey != subjectKey || entry.OperationID != operationID || !bytes.Equal(entry.Payload, payload) {
		return sequence, ErrOperationConflict
	}
	if err := check(ctx); err != nil {
		return sequence, err
	}
	return sequence, nil
}
