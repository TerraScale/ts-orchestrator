using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Runtime;

/// <summary>
/// Controller-side lifecycle journal. It deliberately has no KV store dependency: all protected journal access
/// crosses the typed private journal-writer boundary.
/// </summary>
internal sealed class NatsRuntimeLifecycleJournal(
    RuntimeLifecycleCellId cell,
    NatsOperationJournalMutationClient mutations) : IRuntimeLifecycleJournal
{
    private readonly RuntimeLifecycleCellId cell = cell ?? throw new ArgumentNullException(nameof(cell));
    private readonly NatsOperationJournalMutationClient mutations = mutations ?? throw new ArgumentNullException(nameof(mutations));

    public async ValueTask<RuntimeLifecycleJournalRead> ReadAsync(
        RuntimeLifecycleOperationKey operationKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operationKey);
        try
        {
            var reply = await mutations.ReadRuntimeLifecycleAsync(cell.Value, RuntimeLifecycleNatsProtocol.Key(operationKey), cancellationToken)
                .ConfigureAwait(false);
            if (reply.SchemaVersion != RuntimeLifecycleNatsProtocol.SchemaVersion ||
                !Enum.IsDefined((RuntimeLifecycleJournalReadStatus)reply.Status))
                return new(RuntimeLifecycleJournalReadStatus.Ambiguous, null);
            var status = (RuntimeLifecycleJournalReadStatus)reply.Status;
            if (status != RuntimeLifecycleJournalReadStatus.Found)
                return new(status, null);
            if (!RuntimeLifecycleNatsProtocol.TryDeserialize(reply.Checkpoint, out var checkpoint) ||
                !Matches(checkpoint, operationKey, reply.Revision))
                return new(RuntimeLifecycleJournalReadStatus.Ambiguous, null);
            return new(RuntimeLifecycleJournalReadStatus.Found, checkpoint);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new(RuntimeLifecycleJournalReadStatus.Unavailable, null);
        }
    }

    public async ValueTask<RuntimeLifecycleJournalWrite> CompareExchangeAsync(
        RuntimeLifecycleOperationKey operationKey,
        ulong? expectedRevision,
        RuntimeLifecycleCheckpoint checkpoint,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operationKey);
        ArgumentNullException.ThrowIfNull(checkpoint);
        cancellationToken.ThrowIfCancellationRequested();
        var expected = expectedRevision ?? 0;
        var normalized = expectedRevision is null ? NormalizeCreate(checkpoint) : checkpoint;
        if (!Matches(normalized, operationKey, checked(expected + 1)))
            return new(RuntimeLifecycleJournalWriteStatus.Ambiguous, null);
        try
        {
            var reply = await mutations.WriteRuntimeLifecycleAsync(cell.Value, RuntimeLifecycleNatsProtocol.Key(operationKey),
                    expected, RuntimeLifecycleNatsProtocol.Serialize(normalized), cancellationToken)
                .ConfigureAwait(false);
            if (reply.SchemaVersion != RuntimeLifecycleNatsProtocol.SchemaVersion ||
                !Enum.IsDefined((RuntimeLifecycleJournalWriteStatus)reply.Status))
                return new(RuntimeLifecycleJournalWriteStatus.Ambiguous, null);
            var status = (RuntimeLifecycleJournalWriteStatus)reply.Status;
            if (status != RuntimeLifecycleJournalWriteStatus.Applied)
                return new(status, null);
            if (!RuntimeLifecycleNatsProtocol.TryDeserialize(reply.Checkpoint, out var persisted) ||
                !Matches(persisted, operationKey, reply.Revision))
                return new(RuntimeLifecycleJournalWriteStatus.Ambiguous, null);
            return new(RuntimeLifecycleJournalWriteStatus.Applied, persisted);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new(RuntimeLifecycleJournalWriteStatus.Unavailable, null);
        }
    }

    private RuntimeLifecycleCheckpoint NormalizeCreate(RuntimeLifecycleCheckpoint checkpoint)
    {
        var normalized = checkpoint with { JournalRevision = 1 };
        return normalized with { EventDigest = RuntimeLifecycleFingerprint.Event(normalized) };
    }

    private bool Matches(RuntimeLifecycleCheckpoint checkpoint, RuntimeLifecycleOperationKey operationKey, ulong revision) =>
        RuntimeLifecycleNatsProtocol.IsCheckpoint(checkpoint, cell.Value, RuntimeLifecycleNatsProtocol.Key(operationKey), revision);
}
