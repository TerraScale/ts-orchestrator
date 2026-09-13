using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Operations;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

/// <summary>
/// Test-owned file-backed CreateNode journal: an HMAC-SHA256-tagged envelope per operation with
/// cross-process file-lock CAS, write-through appends, and a private directory. It ports the
/// former production development file journal into the test project so the crash-tamper and
/// two-process compare-and-swap lanes survive the production purity cut (GOAL REQ-ORCH-021).
/// </summary>
internal sealed class TestFileCreateNodeOperationJournal(
    string directory,
    string activeKeyId,
    byte[] activeKey,
    ICreateNodeJournalTagKeyResolver verificationKeys) : ICreateNodeOperationJournal
{
    public CreateNodeJournalDurability Durability => CreateNodeJournalDurability.NonCrashDurable;
    private readonly string directory = Path.GetFullPath(directory ?? throw new ArgumentNullException(nameof(directory)));
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
        if (!CryptographicOperations.FixedTimeEquals(tag, HMACSHA256.HashData(key, payload))) throw new InvalidDataException("Journal integrity tag is invalid.");
        var entry = JsonSerializer.Deserialize<CreateNodeOperationJournalEntry>(payload) ?? throw new InvalidDataException("Missing journal entry."); InMemoryCreateNodeOperationJournal.Validate(entry); return entry;
    }
    private void Write(CreateNodeOperationJournalEntry entry)
    {
        Directory.CreateDirectory(directory);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var payload = JsonSerializer.SerializeToUtf8Bytes(entry);
        var data = JsonSerializer.SerializeToUtf8Bytes(new Envelope("HMAC-SHA256", activeKeyId, Convert.ToBase64String(payload), Convert.ToBase64String(HMACSHA256.HashData(activeKey, payload))));
        var path = PathFor(entry.Binding.OperationId); var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        { if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite); stream.Write(data); stream.Flush(true); }
        File.Move(temporary, path, true);
    }
    private string PathFor(string operationId) => Path.Combine(directory, Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(operationId))) + ".json");
    private FileStream AcquireLock(string operationId, CancellationToken token)
    // A write-through journal update can fsync for far longer than a fixed
    // attempt budget under host IO load; wait on a wall-clock deadline so a
    // contending holder always gets a bounded but generous window.
    { Directory.CreateDirectory(directory); var path = PathFor(operationId) + ".lock"; var deadline = Environment.TickCount64 + 15_000; for (var attempt = 0; ; attempt++) { token.ThrowIfCancellationRequested(); try { return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.WriteThrough); } catch (IOException) when (Environment.TickCount64 < deadline) { Thread.Sleep(attempt < 8 ? 5 : 25); } } }
    private sealed record Envelope(string Algorithm, string KeyId, string Payload, string Tag);
}

