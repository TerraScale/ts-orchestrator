using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.ControlPlane.Providers;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Operations;

internal sealed record CreateNodeJournalEncryptionKey(string KeyId, byte[] Key);

/// <summary>Production composition supplies a rotation-aware key service backed by the regional key authority.</summary>
internal interface ICreateNodeJournalEncryptionKeyService
{
    bool IsHealthy { get; }
    bool TryGetActiveKey(out CreateNodeJournalEncryptionKey key);
    bool TryResolve(string keyId, string algorithm, out byte[] key);
}

internal sealed class CreateNodeJournalEncryptionKeyRing(
    string activeKeyId,
    IReadOnlyDictionary<string, byte[]> keys,
    Func<bool>? health = null) : ICreateNodeJournalEncryptionKeyService
{
    private readonly IReadOnlyDictionary<string, byte[]> keys = keys.ToDictionary(
        static pair => pair.Key,
        static pair => pair.Value.ToArray(),
        StringComparer.Ordinal);
    public bool IsHealthy => health?.Invoke() ?? true;

    public bool TryGetActiveKey(out CreateNodeJournalEncryptionKey key)
    {
        if (!IsHealthy || !TryResolve(activeKeyId, NatsCreateNodeOperationJournal.EncryptionAlgorithm, out var material))
        {
            key = null!;
            return false;
        }
        key = new(activeKeyId, material);
        return true;
    }

    public bool TryResolve(string keyId, string algorithm, out byte[] key)
    {
        if (algorithm != NatsCreateNodeOperationJournal.EncryptionAlgorithm ||
            !keys.TryGetValue(keyId, out var material) || material.Length != 32)
        {
            key = [];
            return false;
        }
        key = material.ToArray();
        return true;
    }
}

/// <summary>R3 JetStream KV-backed authoritative CreateNode journal. OCI remains intentionally unwired.</summary>
internal sealed class NatsCreateNodeOperationJournal : ICreateNodeOperationJournal
{
    internal const string EncryptionAlgorithm = "AES-256-GCM";
    private const string Domain = "terrascale-create-node-journal-v1";
    private const int MaximumEnvelopeBytes = 16 * 1024;
    private readonly INatsKVStore store;
    private readonly ICreateNodeJournalEncryptionKeyService keys;
    private readonly CreateNodeAuthoritativeInvocationCapabilitySigner capabilitySigner;

    public NatsCreateNodeOperationJournal(
        INatsKVStore store,
        ICreateNodeJournalEncryptionKeyService keys,
        CreateNodeAuthoritativeInvocationCapabilitySigner capabilitySigner)
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
        this.keys = keys ?? throw new ArgumentNullException(nameof(keys));
        this.capabilitySigner = capabilitySigner ?? throw new ArgumentNullException(nameof(capabilitySigner));
    }

    public CreateNodeJournalDurability Durability => CreateNodeJournalDurability.AuthoritativeCrashDurable;

    public async ValueTask<CreateNodeOperationJournalEntry?> ReadAsync(
        string operationId,
        CancellationToken cancellationToken) => await ReadAsync(OperationKey(operationId), operationId, cancellationToken);

    public async ValueTask<bool> CompareExchangeAsync(
        CreateNodeOperationJournalEntry? expected,
        CreateNodeOperationJournalEntry replacement,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        InMemoryCreateNodeOperationJournal.Validate(replacement);
        var key = OperationKey(replacement.Binding.OperationId);
        var current = await ReadAsync(key, replacement.Binding.OperationId, cancellationToken);
        if (current != expected)
            return false;
        await RequireMutationEnabledAsync(cancellationToken);

        var value = Encrypt(replacement with { Version = 0 }, key, expected?.Version ?? 0);
        try
        {
            if (expected is null)
                await store.CreateAsync(key, value, cancellationToken: cancellationToken);
            else
                await store.UpdateAsync(key, value, checked((ulong)expected.Version), cancellationToken: cancellationToken);
            return true;
        }
        catch (NatsKVCreateException)
        {
            return false;
        }
        catch (NatsKVWrongLastRevisionException)
        {
            return false;
        }
    }

    public async ValueTask<CreateNodeAuthoritativeInvocationCapability> MintInvocationCapabilityAsync(
        CreateNodeOperationJournalEntry persistedCheckpoint,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(persistedCheckpoint);
        await RequireMutationEnabledAsync(cancellationToken);
        var current = await ReadAsync(persistedCheckpoint.Binding.OperationId, cancellationToken)
            ?? throw new InvalidOperationException("The CreateNode checkpoint no longer exists.");
        if (current != persistedCheckpoint || !CanInvoke(current, now))
            throw new InvalidOperationException("The CreateNode checkpoint is not an unconsumed active provider invocation.");
        return capabilitySigner.Sign(current, now, current.InvocationLeaseExpiresAt!.Value);
    }

    public async ValueTask<bool> TryConsumeInvocationCapabilityAsync(
        CreateNodeAuthoritativeInvocationCapability capability,
        CreateNodeReceiptBinding binding,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(capability);
        ArgumentNullException.ThrowIfNull(binding);
        await RequireMutationEnabledAsync(cancellationToken);
        var current = await ReadAsync(binding.OperationId, cancellationToken);
        if (current is null || !CanInvoke(current, now) ||
            capability.Algorithm != CreateNodeHandoffReceiptSigner.Algorithm ||
            capability.Audience != "create-node-authoritative-invocation" ||
            current.Binding != binding || current.Version != capability.JournalVersion ||
            current.InvocationLeaseOwner != capability.LeaseOwner ||
            current.InvocationLeaseToken != capability.LeaseToken ||
            current.InvocationCapabilityNonce != capability.Nonce ||
            current.InvocationLeaseExpiresAt != capability.LeaseExpiresAt ||
            capability.OperationId != binding.OperationId || capability.BindingDigest != binding.Digest ||
            capability.LeaseExpiresAt <= capability.IssuedAt || capability.ExpiresAt < capability.LeaseExpiresAt ||
            capability.ExpiresAt - capability.IssuedAt > TimeSpan.FromMinutes(10) ||
            now >= capability.ExpiresAt || now < capability.IssuedAt)
            return false;
        return await CompareExchangeAsync(current, current with { InvocationConsumedAt = now }, cancellationToken);
    }

    private async ValueTask<CreateNodeOperationJournalEntry?> ReadAsync(
        string key,
        string operationId,
        CancellationToken cancellationToken)
    {
        try
        {
            var entry = await store.GetEntryAsync<string>(key, cancellationToken: cancellationToken);
            entry.EnsureSuccess();
            var envelope = JsonSerializer.Deserialize<Envelope>(
                entry.Value ?? throw new InvalidDataException("CreateNode journal envelope is empty."))
                ?? throw new InvalidDataException("CreateNode journal envelope is missing.");
            var document = Decrypt(envelope, key);
            var journal = JsonSerializer.Deserialize<CreateNodeOperationJournalEntry>(document)
                ?? throw new InvalidDataException("CreateNode journal entry is missing.");
            InMemoryCreateNodeOperationJournal.Validate(journal);
            if (journal.Binding.OperationId != operationId)
                throw new InvalidDataException("CreateNode journal key does not match its operation.");
            return journal with { Version = checked((long)entry.Revision) };
        }
        catch (NatsKVKeyNotFoundException)
        {
            return null;
        }
        catch (NatsKVKeyDeletedException)
        {
            return null;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("CreateNode journal envelope is malformed.", exception);
        }
    }

    private string Encrypt(CreateNodeOperationJournalEntry entry, string operationKey, long priorVersion)
    {
        byte[]? material = null;
        if (!keys.IsHealthy || !keys.TryGetActiveKey(out var active) ||
            string.IsNullOrWhiteSpace(active.KeyId) || active.Key.Length != 32)
            throw new InvalidOperationException("CreateNode journal encryption key is unavailable.");
        try
        {
            material = active.Key;
            var plaintext = JsonSerializer.SerializeToUtf8Bytes(entry);
            var nonce = RandomNumberGenerator.GetBytes(12);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];
            using (var cipher = new AesGcm(material, tag.Length))
                cipher.Encrypt(nonce, plaintext, ciphertext, tag, Aad(active.KeyId, operationKey, priorVersion));
            var value = JsonSerializer.Serialize(new Envelope(1, EncryptionAlgorithm, active.KeyId, priorVersion,
                Convert.ToBase64String(nonce), Convert.ToBase64String(ciphertext), Convert.ToBase64String(tag)));
            if (Encoding.UTF8.GetByteCount(value) > MaximumEnvelopeBytes)
                throw new InvalidDataException("CreateNode journal envelope exceeded its bound.");
            return value;
        }
        finally
        {
            if (material is not null) CryptographicOperations.ZeroMemory(material);
        }
    }

    private byte[] Decrypt(Envelope envelope, string operationKey)
    {
        if (envelope.SchemaVersion != 1 || envelope.Algorithm != EncryptionAlgorithm || envelope.PriorVersion < 0 ||
            string.IsNullOrWhiteSpace(envelope.KeyId) || !keys.TryResolve(envelope.KeyId, envelope.Algorithm, out var key) ||
            key.Length != 32)
            throw new InvalidDataException("CreateNode journal encryption key is unavailable or retired.");
        try
        {
            var nonce = Convert.FromBase64String(envelope.Nonce);
            var ciphertext = Convert.FromBase64String(envelope.Ciphertext);
            var tag = Convert.FromBase64String(envelope.Tag);
            if (nonce.Length != 12 || tag.Length != 16 || ciphertext.Length > MaximumEnvelopeBytes)
                throw new InvalidDataException("CreateNode journal envelope is invalid.");
            var plaintext = new byte[ciphertext.Length];
            using var cipher = new AesGcm(key, tag.Length);
            cipher.Decrypt(nonce, ciphertext, tag, plaintext, Aad(envelope.KeyId, operationKey, envelope.PriorVersion));
            return plaintext;
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException("CreateNode journal envelope authentication failed.", exception);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("CreateNode journal envelope is malformed.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private async ValueTask RequireMutationEnabledAsync(CancellationToken cancellationToken)
    {
        if (!keys.IsHealthy)
            throw new InvalidOperationException("CreateNode mutation is disabled while the journal key service is unhealthy.");
        // Peer status is only a sampled readiness observation. Any subsequent
        // Create/Update CAS acknowledgement, not this sample, is the durable
        // JetStream Raft-quorum commit boundary.
        await NatsOperationJournalStore.ValidateAsync(store, new NatsTopology("journal", 1).Operations, cancellationToken);
    }

    private static bool CanInvoke(CreateNodeOperationJournalEntry entry, DateTimeOffset now) =>
        entry.Stage == CreateNodeJournalStage.ProviderCallStarted &&
        entry.InvocationConsumedAt is null &&
        entry.InvocationLeaseExpiresAt > now &&
        !string.IsNullOrWhiteSpace(entry.InvocationLeaseOwner) &&
        !string.IsNullOrWhiteSpace(entry.InvocationLeaseToken) &&
        !string.IsNullOrWhiteSpace(entry.InvocationCapabilityNonce);

    private static string OperationKey(string operationId)
    {
        if (string.IsNullOrWhiteSpace(operationId))
            throw new ArgumentException("CreateNode operation ID is required.", nameof(operationId));
        return "operation." + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(operationId)));
    }

    private static byte[] Aad(string keyId, string operationKey, long priorVersion) => Encoding.UTF8.GetBytes(
        $"{Domain}|{keyId}|{operationKey}|{priorVersion.ToString(System.Globalization.CultureInfo.InvariantCulture)}");

    private sealed record Envelope(int SchemaVersion, string Algorithm, string KeyId, long PriorVersion,
        string Nonce, string Ciphertext, string Tag);
}
