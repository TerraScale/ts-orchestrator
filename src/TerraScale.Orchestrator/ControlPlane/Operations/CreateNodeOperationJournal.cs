using System.Collections.Concurrent;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Operations;

public enum CreateNodeJournalStage { Prepared = 1, ProviderCallStarted = 2, Completed = 3 }

public sealed record CreateNodeOperationJournalEntry(
    long Version,
    string OperationFingerprint,
    string OperationId,
    string TenantId,
    string NodeRequestId,
    string CreateKey,
    CreateNodeHandoffReceipt Receipt,
    CreateNodeJournalStage Stage,
    DateTimeOffset? ProviderCallStartedAt,
    int ProviderAttempts,
    CreateNodeProviderResponse? Response);

/// <summary>Authoritative compare-and-swap store for the provider side-effect checkpoint.</summary>
public interface ICreateNodeOperationJournal
{
    ValueTask<CreateNodeOperationJournalEntry?> ReadAsync(string operationId, CancellationToken cancellationToken);
    ValueTask<bool> CompareExchangeAsync(CreateNodeOperationJournalEntry? expected, CreateNodeOperationJournalEntry replacement,
        CancellationToken cancellationToken);
}

public sealed class InMemoryCreateNodeOperationJournal : ICreateNodeOperationJournal
{
    private readonly object gate = new();
    private readonly Dictionary<string, CreateNodeOperationJournalEntry> entries = new(StringComparer.Ordinal);

    public ValueTask<CreateNodeOperationJournalEntry?> ReadAsync(string operationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate) return ValueTask.FromResult(entries.GetValueOrDefault(operationId));
    }

    public ValueTask<bool> CompareExchangeAsync(CreateNodeOperationJournalEntry? expected,
        CreateNodeOperationJournalEntry replacement, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            var current = entries.GetValueOrDefault(replacement.OperationId);
            if (!ReferenceEquals(current, expected) && current != expected) return ValueTask.FromResult(false);
            entries[replacement.OperationId] = replacement with { Version = checked((current?.Version ?? 0) + 1) };
            return ValueTask.FromResult(true);
        }
    }
}

/// <summary>Single-operation durable journal. Replacement is atomic and the receipt is stored in the same flushed write.</summary>
public sealed class FileCreateNodeOperationJournal(string directory) : ICreateNodeOperationJournal
{
    private static readonly ConcurrentDictionary<string, object> Gates = new(StringComparer.Ordinal);
    private readonly string directory = Path.GetFullPath(directory ?? throw new ArgumentNullException(nameof(directory)));

    public ValueTask<CreateNodeOperationJournalEntry?> ReadAsync(string operationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (Gate(operationId)) return ValueTask.FromResult(Read(operationId));
    }

    public ValueTask<bool> CompareExchangeAsync(CreateNodeOperationJournalEntry? expected,
        CreateNodeOperationJournalEntry replacement, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (Gate(replacement.OperationId))
        {
            try
            {
                Directory.CreateDirectory(directory);
                using var exclusive = new FileStream(LockPath(replacement.OperationId), FileMode.OpenOrCreate,
                    FileAccess.ReadWrite, FileShare.None, 1, FileOptions.WriteThrough);
                var current = Read(replacement.OperationId);
                if (current != expected) return ValueTask.FromResult(false);
                Write(replacement with { Version = checked((current?.Version ?? 0) + 1) });
                return ValueTask.FromResult(true);
            }
            catch (IOException) { return ValueTask.FromResult(false); }
        }
    }

    private object Gate(string operationId) => Gates.GetOrAdd(Path.Combine(directory, FileName(operationId)), static _ => new object());
    private string LockPath(string operationId) => Path.Combine(directory, string.Concat(FileName(operationId), ".lock"));
    private CreateNodeOperationJournalEntry? Read(string operationId)
    {
        var path = Path.Combine(directory, FileName(operationId));
        if (!File.Exists(path)) return null;
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
        return JsonSerializer.Deserialize<CreateNodeOperationJournalEntry>(stream)
            ?? throw new InvalidDataException("CreateNode operation journal contains no entry.");
    }

    private void Write(CreateNodeOperationJournalEntry entry)
    {
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, FileName(entry.OperationId));
        var temporary = string.Concat(path, ".", Guid.NewGuid().ToString("N"), ".tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(stream, entry);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private static string FileName(string operationId) => string.Concat(
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(operationId))).ToLowerInvariant(), ".json");
}
