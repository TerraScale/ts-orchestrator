package control

import (
	"context"
	"errors"
)

// NatsRuntimeLifecycleJournal is the controller-side lifecycle journal. It
// deliberately has no KV store dependency: all protected journal access
// crosses the typed private journal-writer boundary.
type NatsRuntimeLifecycleJournal struct {
	cell      RuntimeLifecycleCellId
	mutations *NatsOperationJournalMutationClient
}

func NewNatsRuntimeLifecycleJournal(cell RuntimeLifecycleCellId,
	mutations *NatsOperationJournalMutationClient) (*NatsRuntimeLifecycleJournal, error) {
	if mutations == nil {
		return nil, argumentNil("mutations")
	}
	return &NatsRuntimeLifecycleJournal{cell: cell, mutations: mutations}, nil
}

func isContextCancellation(ctx context.Context, err error) bool {
	return errors.Is(err, context.Canceled) && ctx != nil && ctx.Err() != nil
}

func (j *NatsRuntimeLifecycleJournal) ReadAsync(ctx context.Context,
	operationKey RuntimeLifecycleOperationKey) (RuntimeLifecycleJournalRead, error) {
	if j == nil || j.mutations == nil {
		return RuntimeLifecycleJournalRead{}, argumentNil("mutations")
	}
	if ctx == nil {
		return RuntimeLifecycleJournalRead{}, argumentNil("ctx")
	}
	reply, err := j.mutations.ReadRuntimeLifecycleAsync(ctx, j.cell.Value,
		RuntimeLifecycleNatsProtocol.Key(operationKey))
	if err != nil {
		if isContextCancellation(ctx, err) {
			return RuntimeLifecycleJournalRead{}, err
		}
		return RuntimeLifecycleJournalRead{Status: RuntimeLifecycleJournalReadStatusUnavailable}, nil
	}
	if reply.SchemaVersion != RuntimeLifecycleNatsProtocolSchemaVersion ||
		!runtimeLifecycleJournalReadStatusIsDefined(RuntimeLifecycleJournalReadStatus(reply.Status)) {
		return RuntimeLifecycleJournalRead{Status: RuntimeLifecycleJournalReadStatusAmbiguous}, nil
	}
	status := RuntimeLifecycleJournalReadStatus(reply.Status)
	if status != RuntimeLifecycleJournalReadStatusFound {
		return RuntimeLifecycleJournalRead{Status: status}, nil
	}
	checkpoint, ok := RuntimeLifecycleNatsProtocol.TryDeserialize(derefString(reply.Checkpoint))
	if !ok || !j.matches(checkpoint, operationKey, reply.Revision) {
		return RuntimeLifecycleJournalRead{Status: RuntimeLifecycleJournalReadStatusAmbiguous}, nil
	}
	return RuntimeLifecycleJournalRead{Status: RuntimeLifecycleJournalReadStatusFound, Checkpoint: &checkpoint}, nil
}

func (j *NatsRuntimeLifecycleJournal) CompareExchangeAsync(ctx context.Context,
	operationKey RuntimeLifecycleOperationKey, expectedRevision *uint64,
	checkpoint RuntimeLifecycleCheckpoint) (RuntimeLifecycleJournalWrite, error) {
	if j == nil || j.mutations == nil {
		return RuntimeLifecycleJournalWrite{}, argumentNil("mutations")
	}
	if ctx == nil {
		return RuntimeLifecycleJournalWrite{}, argumentNil("ctx")
	}
	if ctx.Err() != nil {
		return RuntimeLifecycleJournalWrite{}, ctx.Err()
	}
	expected := uint64(0)
	if expectedRevision != nil {
		expected = *expectedRevision
	}
	normalized := checkpoint
	if expectedRevision == nil {
		normalized = j.normalizeCreate(checkpoint)
	}
	if expected == ^uint64(0) {
		return RuntimeLifecycleJournalWrite{}, argumentOutOfRange("expectedRevision")
	}
	if !j.matches(normalized, operationKey, expected+1) {
		return RuntimeLifecycleJournalWrite{Status: RuntimeLifecycleJournalWriteStatusAmbiguous}, nil
	}
	serialized, err := RuntimeLifecycleNatsProtocol.Serialize(normalized)
	if err != nil {
		if isContextCancellation(ctx, err) {
			return RuntimeLifecycleJournalWrite{}, err
		}
		return RuntimeLifecycleJournalWrite{Status: RuntimeLifecycleJournalWriteStatusUnavailable}, nil
	}
	reply, err := j.mutations.WriteRuntimeLifecycleAsync(ctx, j.cell.Value,
		RuntimeLifecycleNatsProtocol.Key(operationKey), expected, serialized)
	if err != nil {
		if isContextCancellation(ctx, err) {
			return RuntimeLifecycleJournalWrite{}, err
		}
		return RuntimeLifecycleJournalWrite{Status: RuntimeLifecycleJournalWriteStatusUnavailable}, nil
	}
	if reply.SchemaVersion != RuntimeLifecycleNatsProtocolSchemaVersion ||
		!runtimeLifecycleJournalWriteStatusIsDefined(RuntimeLifecycleJournalWriteStatus(reply.Status)) {
		return RuntimeLifecycleJournalWrite{Status: RuntimeLifecycleJournalWriteStatusAmbiguous}, nil
	}
	status := RuntimeLifecycleJournalWriteStatus(reply.Status)
	if status != RuntimeLifecycleJournalWriteStatusApplied {
		return RuntimeLifecycleJournalWrite{Status: status}, nil
	}
	persisted, ok := RuntimeLifecycleNatsProtocol.TryDeserialize(derefString(reply.Checkpoint))
	if !ok || !j.matches(persisted, operationKey, reply.Revision) {
		return RuntimeLifecycleJournalWrite{Status: RuntimeLifecycleJournalWriteStatusAmbiguous}, nil
	}
	return RuntimeLifecycleJournalWrite{Status: RuntimeLifecycleJournalWriteStatusApplied, Checkpoint: &persisted}, nil
}

func (j *NatsRuntimeLifecycleJournal) normalizeCreate(checkpoint RuntimeLifecycleCheckpoint) RuntimeLifecycleCheckpoint {
	normalized := checkpoint
	normalized.JournalRevision = 1
	eventDigest, err := RuntimeLifecycleFingerprint.Event(normalized)
	if err != nil {
		return normalized
	}
	normalized.EventDigest = eventDigest
	return normalized
}

func (j *NatsRuntimeLifecycleJournal) matches(checkpoint RuntimeLifecycleCheckpoint,
	operationKey RuntimeLifecycleOperationKey, revision uint64) bool {
	return RuntimeLifecycleNatsProtocol.IsCheckpoint(&checkpoint, j.cell.Value,
		RuntimeLifecycleNatsProtocol.Key(operationKey), revision)
}
