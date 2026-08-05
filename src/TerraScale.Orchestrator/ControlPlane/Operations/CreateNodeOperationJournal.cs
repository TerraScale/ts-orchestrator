using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Operations;

public enum CreateNodeJournalStage { Prepared = 1, ProviderCallStarted = 2, Completed = 3, RequiresManualRecovery = 4 }
public sealed record CreateNodeOperationJournalEntry(long Version, string OperationFingerprint, CreateNodeReceiptBinding Binding,
    CreateNodeHandoffReceipt Receipt, CreateNodeJournalStage Stage, DateTimeOffset? ProviderCallStartedAt,
    int ProviderAttempts, CreateNodeProviderResponse? Response);
public interface ICreateNodeOperationJournal
{
    ValueTask<CreateNodeOperationJournalEntry?> ReadAsync(string operationId, CancellationToken cancellationToken);
    ValueTask<bool> CompareExchangeAsync(CreateNodeOperationJournalEntry? expected, CreateNodeOperationJournalEntry replacement, CancellationToken cancellationToken);
}
public sealed class InMemoryCreateNodeOperationJournal : ICreateNodeOperationJournal
{
    private readonly object gate = new(); private readonly Dictionary<string, CreateNodeOperationJournalEntry> entries = new(StringComparer.Ordinal);
    public ValueTask<CreateNodeOperationJournalEntry?> ReadAsync(string operationId, CancellationToken cancellationToken)
    { cancellationToken.ThrowIfCancellationRequested(); lock (gate) return ValueTask.FromResult(entries.GetValueOrDefault(operationId)); }
    public ValueTask<bool> CompareExchangeAsync(CreateNodeOperationJournalEntry? expected, CreateNodeOperationJournalEntry replacement, CancellationToken cancellationToken)
    { cancellationToken.ThrowIfCancellationRequested(); Validate(replacement); lock (gate) { var current = entries.GetValueOrDefault(replacement.Binding.OperationId); if (current != expected) return ValueTask.FromResult(false); entries[replacement.Binding.OperationId] = replacement with { Version = checked((current?.Version ?? 0) + 1) }; return ValueTask.FromResult(true); } }
    internal static void Validate(CreateNodeOperationJournalEntry entry)
    {
        if (entry.Version < 0 || string.IsNullOrWhiteSpace(entry.OperationFingerprint) || !Enum.IsDefined(entry.Stage) || entry.ProviderAttempts < 0 ||
            (entry.Stage == CreateNodeJournalStage.Completed) != (entry.Response is not null) ||
            (entry.Stage != CreateNodeJournalStage.Prepared) != (entry.ProviderCallStartedAt is not null))
            throw new InvalidDataException("CreateNode journal entry is structurally invalid.");
    }
}

public interface ICreateNodeJournalTagKeyResolver { bool TryResolve(string keyId, string algorithm, out byte[] key); }
public sealed class CreateNodeJournalTagKeyRing(IReadOnlyDictionary<string, byte[]> keys) : ICreateNodeJournalTagKeyResolver
{
    private readonly IReadOnlyDictionary<string, byte[]> keys = keys.ToDictionary(static p => p.Key, static p => p.Value.ToArray(), StringComparer.Ordinal);
    public bool TryResolve(string keyId, string algorithm, out byte[] key)
    { if (algorithm != "HMAC-SHA256" || !keys.TryGetValue(keyId, out var value)) { key = []; return false; } key = value.ToArray(); return true; }
}

/// <summary>Development/test-only local journal. Production must inject a reviewed R3 CAS journal.</summary>
public sealed class DevelopmentFileCreateNodeOperationJournal(string environmentName, string directory, string activeKeyId, byte[] activeKey,
    ICreateNodeJournalTagKeyResolver verificationKeys) : ICreateNodeOperationJournal
{
    private readonly string directory = string.Equals(environmentName, "Development", StringComparison.Ordinal) ? Path.GetFullPath(directory ?? throw new ArgumentNullException(nameof(directory))) : throw new InvalidOperationException("Development file journal is rejected outside Development.");
    private readonly string activeKeyId = string.IsNullOrWhiteSpace(activeKeyId) ? throw new ArgumentException("Key ID required.", nameof(activeKeyId)) : activeKeyId;
    private readonly byte[] activeKey = activeKey?.ToArray() ?? throw new ArgumentNullException(nameof(activeKey));
    private readonly ICreateNodeJournalTagKeyResolver verificationKeys = verificationKeys ?? throw new ArgumentNullException(nameof(verificationKeys));
    private readonly object gate = new();
    public ValueTask<CreateNodeOperationJournalEntry?> ReadAsync(string operationId, CancellationToken cancellationToken)
    { cancellationToken.ThrowIfCancellationRequested(); lock (gate) return ValueTask.FromResult(Read(operationId)); }
    public ValueTask<bool> CompareExchangeAsync(CreateNodeOperationJournalEntry? expected, CreateNodeOperationJournalEntry replacement, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); InMemoryCreateNodeOperationJournal.Validate(replacement); lock (gate)
        { using var exclusive = AcquireLock(replacement.Binding.OperationId, cancellationToken); var current = Read(replacement.Binding.OperationId); if (current != expected) return ValueTask.FromResult(false); Write(replacement with { Version = checked((current?.Version ?? 0) + 1) }); return ValueTask.FromResult(true); }
    }
    private CreateNodeOperationJournalEntry? Read(string operationId)
    {
        var path = PathFor(operationId); if (!File.Exists(path)) return null;
        Envelope envelope;
        try { envelope = JsonSerializer.Deserialize<Envelope>(File.ReadAllBytes(path)) ?? throw new InvalidDataException("Missing journal envelope."); }
        catch (JsonException exception) { throw new InvalidDataException("Journal envelope is malformed.", exception); }
        if (!verificationKeys.TryResolve(envelope.KeyId, envelope.Algorithm, out var key)) throw new InvalidDataException("Unknown journal tag key.");
        var payload = Convert.FromBase64String(envelope.Payload); var tag = Convert.FromBase64String(envelope.Tag);
        using var hmac = new HMACSHA256(key); if (!CryptographicOperations.FixedTimeEquals(tag, hmac.ComputeHash(payload))) throw new InvalidDataException("Journal integrity tag is invalid.");
        var entry = JsonSerializer.Deserialize<CreateNodeOperationJournalEntry>(payload) ?? throw new InvalidDataException("Missing journal entry."); InMemoryCreateNodeOperationJournal.Validate(entry); return entry;
    }
    private void Write(CreateNodeOperationJournalEntry entry)
    {
        Directory.CreateDirectory(directory);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var payload = JsonSerializer.SerializeToUtf8Bytes(entry); using var hmac = new HMACSHA256(activeKey);
        var data = JsonSerializer.SerializeToUtf8Bytes(new Envelope("HMAC-SHA256", activeKeyId, Convert.ToBase64String(payload), Convert.ToBase64String(hmac.ComputeHash(payload))));
        var path = PathFor(entry.Binding.OperationId); var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        { if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite); stream.Write(data); stream.Flush(true); }
        File.Move(temporary, path, true);
    }
    private string PathFor(string operationId) => Path.Combine(directory, Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(operationId))) + ".json");
    private FileStream AcquireLock(string operationId, CancellationToken token)
    { Directory.CreateDirectory(directory); var path = PathFor(operationId) + ".lock"; for (var attempt = 0; ; attempt++) { token.ThrowIfCancellationRequested(); try { return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.WriteThrough); } catch (IOException) when (attempt < 40) { Thread.Sleep(5); } } }
    private sealed record Envelope(string Algorithm, string KeyId, string Payload, string Tag);
}
