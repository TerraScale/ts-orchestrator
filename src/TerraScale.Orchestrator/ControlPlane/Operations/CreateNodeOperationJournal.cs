using System.Collections.Frozen;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Operations;

public enum CreateNodeJournalStage { Prepared = 1, ProviderCallStarted = 2, Completed = 3, RequiresManualRecovery = 4 }
public enum CreateNodeJournalDurability { NonCrashDurable = 1, AuthoritativeCrashDurable = 2 }
public sealed record CreateNodeOperationJournalEntry(long Version, string OperationFingerprint, CreateNodeReceiptBinding Binding,
    CreateNodeHandoffReceipt Receipt, CreateNodeRecoveryLookupAuthority RecoveryAuthority, CreateNodeJournalStage Stage, DateTimeOffset? ProviderCallStartedAt,
    int ProviderAttempts, CreateNodeProviderResponse? Response, string? InvocationLeaseOwner = null, string? InvocationLeaseToken = null,
    string? InvocationCapabilityNonce = null, DateTimeOffset? InvocationLeaseExpiresAt = null, DateTimeOffset? InvocationConsumedAt = null);
public interface ICreateNodeOperationJournal
{
    CreateNodeJournalDurability Durability => CreateNodeJournalDurability.NonCrashDurable;
    ValueTask<CreateNodeOperationJournalEntry?> ReadAsync(string operationId, CancellationToken cancellationToken);
    ValueTask<bool> CompareExchangeAsync(CreateNodeOperationJournalEntry? expected, CreateNodeOperationJournalEntry replacement, CancellationToken cancellationToken);
    ValueTask<CreateNodeAuthoritativeInvocationCapability> MintInvocationCapabilityAsync(CreateNodeOperationJournalEntry persistedCheckpoint, DateTimeOffset now, CancellationToken cancellationToken)
        => throw new InvalidOperationException("Only an authoritative crash-durable CreateNode journal can mint an invocation capability.");
    ValueTask<bool> TryConsumeInvocationCapabilityAsync(CreateNodeAuthoritativeInvocationCapability capability, CreateNodeReceiptBinding binding, DateTimeOffset now, CancellationToken cancellationToken)
        => throw new InvalidOperationException("Only an authoritative crash-durable CreateNode journal can consume an invocation capability.");
}
public sealed class InMemoryCreateNodeOperationJournal : ICreateNodeOperationJournal
{
    public CreateNodeJournalDurability Durability => CreateNodeJournalDurability.NonCrashDurable;
    private readonly object gate = new(); private readonly Dictionary<string, CreateNodeOperationJournalEntry> entries = new(StringComparer.Ordinal);
    public ValueTask<CreateNodeOperationJournalEntry?> ReadAsync(string operationId, CancellationToken cancellationToken)
    { cancellationToken.ThrowIfCancellationRequested(); lock (gate) return ValueTask.FromResult(entries.GetValueOrDefault(operationId)); }
    public ValueTask<bool> CompareExchangeAsync(CreateNodeOperationJournalEntry? expected, CreateNodeOperationJournalEntry replacement, CancellationToken cancellationToken)
    { cancellationToken.ThrowIfCancellationRequested(); Validate(replacement); lock (gate) { var current = entries.GetValueOrDefault(replacement.Binding.OperationId); if (current != expected) return ValueTask.FromResult(false); entries[replacement.Binding.OperationId] = replacement with { Version = checked((current?.Version ?? 0) + 1) }; return ValueTask.FromResult(true); } }
    internal static void Validate(CreateNodeOperationJournalEntry entry)
    {
        if (entry.Version < 0 || string.IsNullOrWhiteSpace(entry.OperationFingerprint) || entry.RecoveryAuthority is null || !Enum.IsDefined(entry.Stage) || entry.ProviderAttempts < 0 ||
            (entry.Stage == CreateNodeJournalStage.Completed) != (entry.Response is not null) ||
            (entry.Stage != CreateNodeJournalStage.Prepared) != (entry.ProviderCallStartedAt is not null) ||
            (entry.Stage == CreateNodeJournalStage.ProviderCallStarted && (string.IsNullOrWhiteSpace(entry.InvocationLeaseOwner) || string.IsNullOrWhiteSpace(entry.InvocationLeaseToken) || string.IsNullOrWhiteSpace(entry.InvocationCapabilityNonce) || entry.InvocationLeaseExpiresAt is null || entry.InvocationLeaseExpiresAt <= entry.ProviderCallStartedAt)))
            throw new InvalidDataException("CreateNode journal entry is structurally invalid.");
    }
}

public interface ICreateNodeJournalTagKeyResolver { bool TryResolve(string keyId, string algorithm, out byte[] key); }
public sealed class CreateNodeJournalTagKeyRing(IReadOnlyDictionary<string, byte[]> keys) : ICreateNodeJournalTagKeyResolver
{
    private readonly FrozenDictionary<string, byte[]> keys = keys.ToFrozenDictionary(static p => p.Key, static p => p.Value.ToArray(), StringComparer.Ordinal);
    public bool TryResolve(string keyId, string algorithm, out byte[] key)
    { if (algorithm != "HMAC-SHA256" || !keys.TryGetValue(keyId, out var value)) { key = []; return false; } key = value.ToArray(); return true; }
}


