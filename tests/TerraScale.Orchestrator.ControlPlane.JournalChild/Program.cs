using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Operations;
using TerraScale.Orchestrator.ControlPlane.Providers;

if (args is ["host-recovery", ..]) return await HostRecoveryChild.RunAsync(args);

if (args.Length != 5) return 64;
var (directory, keyText, barrier, result, actor) = (args[0], args[1], args[2], args[3], args[4]);
var key = Convert.FromBase64String(keyText);
var keys = new CreateNodeJournalTagKeyRing(new Dictionary<string, byte[]> { ["test"] = key });
var journal = new ChildFileCreateNodeOperationJournal(directory, "test", key, keys);
var binding = new CreateNodeReceiptBinding("op-contention", "tenant", "node", "idempotency", "create", "cell", "compartment", 1, 1, "template", "placement", new string('a', 64), 1, "authorization", "context");
var receipt = new CreateNodeHandoffReceipt("test", "test", binding, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddDays(1), "test");
var recovery = new CreateNodeRecoveryLookupAuthority("test", "test", "create-node-provider-lookup", "test", DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddDays(1), "test");
var entry = new CreateNodeOperationJournalEntry(0, "fingerprint", binding, receipt, recovery, CreateNodeJournalStage.Prepared, null, 0, null);
await File.WriteAllTextAsync(result + ".ready", actor);
// The parent writes the barrier only after BOTH children are ready, so this
// wait must tolerate a heavily loaded sibling startup, not a fixed ten seconds.
var deadline = DateTime.UtcNow.AddSeconds(120);
while (!File.Exists(barrier) && DateTime.UtcNow < deadline) Thread.Sleep(5);
if (!File.Exists(barrier)) return 65;
var wrote = await journal.CompareExchangeAsync(null, entry, default);
var observed = await journal.ReadAsync(binding.OperationId, default);
await File.WriteAllTextAsync(result, $"{actor}|{wrote}|{observed?.Version}|{observed?.Binding.OperationId}");
return wrote ? 0 : 1;

/// <summary>
/// Test-child-owned file-backed CreateNode journal with cross-process file-lock CAS. It ports
/// the former production development file journal into this test fixture so the two-process
/// compare-and-swap lane survives the production purity cut (GOAL REQ-ORCH-021).
/// </summary>
internal sealed class ChildFileCreateNodeOperationJournal(
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
        cancellationToken.ThrowIfCancellationRequested(); Validate(replacement); lock (gate)
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
        var entry = JsonSerializer.Deserialize<CreateNodeOperationJournalEntry>(payload) ?? throw new InvalidDataException("Missing journal entry."); Validate(entry); return entry;
    }
    // Validate the test file journal's persisted entries before reading or writing them.
    private static void Validate(CreateNodeOperationJournalEntry entry)
    {
        if (entry.Version < 0 || string.IsNullOrWhiteSpace(entry.OperationFingerprint) || entry.RecoveryAuthority is null || !Enum.IsDefined(entry.Stage) || entry.ProviderAttempts < 0 ||
            (entry.Stage == CreateNodeJournalStage.Completed) != (entry.Response is not null) ||
            (entry.Stage != CreateNodeJournalStage.Prepared) != (entry.ProviderCallStartedAt is not null) ||
            (entry.Stage == CreateNodeJournalStage.ProviderCallStarted && (string.IsNullOrWhiteSpace(entry.InvocationLeaseOwner) || string.IsNullOrWhiteSpace(entry.InvocationLeaseToken) || string.IsNullOrWhiteSpace(entry.InvocationCapabilityNonce) || entry.InvocationLeaseExpiresAt is null || entry.InvocationLeaseExpiresAt <= entry.ProviderCallStartedAt)))
            throw new InvalidDataException("CreateNode journal entry is structurally invalid.");
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
    { Directory.CreateDirectory(directory); var path = PathFor(operationId) + ".lock"; var deadline = Environment.TickCount64 + 15_000; for (var attempt = 0; ; attempt++) { token.ThrowIfCancellationRequested(); try { return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.WriteThrough); } catch (IOException) when (Environment.TickCount64 < deadline) { Thread.Sleep(attempt < 8 ? 5 : 25); } } }
    private sealed record Envelope(string Algorithm, string KeyId, string Payload, string Tag);
}

