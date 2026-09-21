using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.KeyValueStore;

namespace TerraScale.Orchestrator.Bootstrap;

/// <summary>
/// Signed first-boot material for one regional controller or workload host.
/// The envelope carries public identities and digests only; NATS seeds,
/// certificates, and Vault values are fetched by the admitted bootstrap agent.
/// </summary>
public sealed record RegionalNodeEnrollmentEnvelope
{
    public const string Version = "terrascale-regional-node-enrollment-v2";

    public RegionalNodeEnrollmentEnvelope(
        string region,
        string nodeId,
        ulong bootstrapGeneration,
        string natsAccountPublicKey,
        string natsUserPublicKey,
        string credentialBundleSha256,
        string clusterName,
        RegionalNodeEnrollmentScope scope,
        SignedBootstrapGrant grant,
        string signerKeyId,
        ulong signerKeyVersion,
        string signature)
    {
        if (region is not ("GRU" or "SFO" or "FRA"))
            throw new ArgumentException("A node enrollment region must be GRU, SFO, or FRA.", nameof(region));
        NodeId = ValidateToken(nodeId, nameof(nodeId));
        if (bootstrapGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(bootstrapGeneration));
        NatsAccountPublicKey = ValidateKey(natsAccountPublicKey, nameof(natsAccountPublicKey));
        NatsUserPublicKey = ValidateKey(natsUserPublicKey, nameof(natsUserPublicKey));
        CredentialBundleSha256 = BootstrapGrantCanonical.ValidateLowercaseHex(
            credentialBundleSha256, 64, nameof(credentialBundleSha256));
        ClusterName = ValidateToken(clusterName, nameof(clusterName));
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
        Grant = grant ?? throw new ArgumentNullException(nameof(grant));
        SignerKeyId = BootstrapGrantCanonical.ValidateToken(signerKeyId, nameof(signerKeyId));
        if (signerKeyVersion == 0)
            throw new ArgumentOutOfRangeException(nameof(signerKeyVersion));
        Signature = ValidateSignature(signature);
        Region = region;
        BootstrapGeneration = bootstrapGeneration;
        SignerKeyVersion = signerKeyVersion;
    }

    public string Region { get; }
    public string NodeId { get; }
    public ulong BootstrapGeneration { get; }
    public string NatsAccountPublicKey { get; }
    public string NatsUserPublicKey { get; }
    public string CredentialBundleSha256 { get; }
    public string ClusterName { get; }
    public RegionalNodeEnrollmentScope Scope { get; }
    public SignedBootstrapGrant Grant { get; }
    public string SignerKeyId { get; }
    public ulong SignerKeyVersion { get; }
    public string Signature { get; init; }

    internal string Digest => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
        BootstrapGrantCanonical.EncodeFields([CanonicalUnsigned(), Signature]))));

    internal string CanonicalUnsigned() => BootstrapGrantCanonical.EncodeFields([
        Version,
        Region,
        NodeId,
        BootstrapGeneration.ToString(System.Globalization.CultureInfo.InvariantCulture),
        NatsAccountPublicKey,
        NatsUserPublicKey,
        CredentialBundleSha256,
        ClusterName,
        Scope.Canonical(),
        Grant.PayloadText,
        Grant.Algorithm,
        Grant.Signature,
        SignerKeyId,
        SignerKeyVersion.ToString(System.Globalization.CultureInfo.InvariantCulture)]);

    internal static string ValidateToken(string value, string name) =>
        value is { Length: >= 1 and <= 128 } &&
        value.All(static character => character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '-' or '_')
            ? value
            : throw new ArgumentException("The enrollment identity is not a bounded token.", name);

    private static string ValidateKey(string value, string name) =>
        value is { Length: >= 2 and <= 256 } && value.All(static character => !char.IsWhiteSpace(character) && !char.IsControl(character))
            ? value
            : throw new ArgumentException("The enrollment public key is invalid.", name);

    private static string ValidateSignature(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 1024)
            throw new ArgumentException("The enrollment signature is invalid.", nameof(value));
        try
        {
            var bytes = Convert.FromBase64String(value);
            return bytes.Length > 0 && Convert.ToBase64String(bytes) == value
                ? value
                : throw new ArgumentException("The enrollment signature is invalid.", nameof(value));
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("The enrollment signature is invalid.", nameof(value), exception);
        }
    }
}

public sealed class RegionalNodeEnrollmentSigner : IDisposable
{
    private readonly ECDsa signingKey;

    public RegionalNodeEnrollmentSigner(string keyId, ulong keyVersion, ECDsa signingKey)
    {
        KeyId = BootstrapGrantCanonical.ValidateToken(keyId, nameof(keyId));
        if (keyVersion == 0)
            throw new ArgumentOutOfRangeException(nameof(keyVersion));
        this.signingKey = signingKey ?? throw new ArgumentNullException(nameof(signingKey));
        BootstrapTrustBundleKey.RequireP256(this.signingKey);
        KeyVersion = keyVersion;
    }

    public string KeyId { get; }
    public ulong KeyVersion { get; }

    public RegionalNodeEnrollmentEnvelope Sign(
        string region,
        string nodeId,
        ulong bootstrapGeneration,
        string natsAccountPublicKey,
        string natsUserPublicKey,
        string credentialBundleSha256,
        string clusterName,
        RegionalNodeEnrollmentScope scope,
        SignedBootstrapGrant grant)
    {
        var unsigned = new RegionalNodeEnrollmentEnvelope(
            region,
            nodeId,
            bootstrapGeneration,
            natsAccountPublicKey,
            natsUserPublicKey,
            credentialBundleSha256,
            clusterName,
            scope,
            grant,
            KeyId,
            KeyVersion,
            Convert.ToBase64String([1]));
        var signature = Convert.ToBase64String(signingKey.SignData(
            Encoding.UTF8.GetBytes(unsigned.CanonicalUnsigned()), HashAlgorithmName.SHA256));
        return unsigned with { Signature = signature };
    }

    public byte[] ExportSubjectPublicKeyInfo() => signingKey.ExportSubjectPublicKeyInfo();
    public void Dispose() => signingKey.Dispose();
}

public enum RegionalNodeEnrollmentDecision
{
    Authorized = 1,
    InvalidSignature = 2,
    UnknownSigner = 3,
    WrongRegion = 4,
    WrongNode = 5,
    StaleGeneration = 6,
    GrantDenied = 7,
    GrantAudienceMismatch = 8,
    AccountMismatch = 9,
    UserIdentityMismatch = 10,
    ReplayDetected = 11,
    ReplayJournalUnavailable = 12,
    ScopeMismatch = 13,
}

public sealed record RegionalNodeEnrollmentVerification(
    RegionalNodeEnrollmentDecision Decision,
    string? SignerKeyId,
    ulong? SignerKeyVersion)
{
    public bool Authorized => Decision == RegionalNodeEnrollmentDecision.Authorized;
}

public interface IRegionalNodeEnrollmentReplayStore
{
    bool TryAccept(string nodeId, ulong generation, string grantId, string nonce);
}

/// <summary>Durable replay fence used by first-boot admission in a live regional cell.</summary>
public interface IRegionalNodeEnrollmentDurableReplayStore
{
    ValueTask<bool> TryAcceptAsync(
        string nodeId,
        ulong generation,
        string grantId,
        string nonce,
        CancellationToken cancellationToken);
}

/// <summary>
/// In-memory replay/generation fence used by local qualification. Production
/// composition must replace it with a durable regional KV record before OCI.
/// </summary>
public sealed class InMemoryRegionalNodeEnrollmentReplayStore : IRegionalNodeEnrollmentReplayStore
{
    private readonly ConcurrentDictionary<string, (ulong Generation, string GrantId, string Nonce)> accepted = new(StringComparer.Ordinal);

    public bool TryAccept(string nodeId, ulong generation, string grantId, string nonce)
    {
        while (true)
        {
            if (accepted.TryGetValue(nodeId, out var current))
            {
                if (generation <= current.Generation || current.GrantId == grantId || current.Nonce == nonce)
                    return false;
                if (!accepted.TryUpdate(nodeId, (generation, grantId, nonce), current))
                    continue;
                return true;
            }
            if (accepted.TryAdd(nodeId, (generation, grantId, nonce)))
                return true;
        }
    }
}

/// <summary>
/// A compare-and-set replay/generation fence backed by the regional NATS KV store.
/// The value is deliberately small and contains no credential material. A node can
/// advance only its own generation, and a second consumer of the same grant is
/// rejected by the create/update race.
/// </summary>
public sealed class NatsRegionalNodeEnrollmentReplayStore : IRegionalNodeEnrollmentDurableReplayStore
{
    private const int MaximumAttempts = 8;
    private readonly INatsKVStore store;
    private readonly string keyPrefix;

    public NatsRegionalNodeEnrollmentReplayStore(INatsKVStore store, string keyPrefix = "node-enrollment")
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
        keyPrefix = RegionalNodeEnrollmentEnvelope.ValidateToken(keyPrefix, nameof(keyPrefix));
        this.keyPrefix = keyPrefix;
    }

    public async ValueTask<bool> TryAcceptAsync(
        string nodeId,
        ulong generation,
        string grantId,
        string nonce,
        CancellationToken cancellationToken)
    {
        nodeId = RegionalNodeEnrollmentEnvelope.ValidateToken(nodeId, nameof(nodeId));
        grantId = RegionalNodeEnrollmentEnvelope.ValidateToken(grantId, nameof(grantId));
        nonce = RegionalNodeEnrollmentEnvelope.ValidateToken(nonce, nameof(nonce));
        if (generation == 0) throw new ArgumentOutOfRangeException(nameof(generation));
        // Membership observations expire in ORCH_RUNTIME. An enrollment fence
        // must live in the dedicated non-expiring ORCH_NODE_ENROLLMENTS store,
        // or an old generation becomes admissible again after its observation TTL.
        var status = await store.GetStatusAsync(cancellationToken).ConfigureAwait(false);
        if (status.Info.Config.MaxAge != TimeSpan.Zero ||
            status.Info.Config.Storage != NATS.Client.JetStream.Models.StreamConfigStorage.File)
            throw new NatsKVException("Node enrollment requires non-expiring file-backed storage.");
        var key = $"{keyPrefix}.{Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(nodeId)))}";
        var candidate = JsonSerializer.Serialize(
            new RegionalNodeEnrollmentReplayRecord(generation, grantId, nonce),
            RegionalNodeEnrollmentJsonContext.Default.RegionalNodeEnrollmentReplayRecord);

        for (var attempt = 0; attempt < MaximumAttempts; attempt++)
        {
            try
            {
                var entry = await store.GetEntryAsync<string>(key, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                entry.EnsureSuccess();
                var current = JsonSerializer.Deserialize(
                    entry.Value ?? string.Empty,
                    RegionalNodeEnrollmentJsonContext.Default.RegionalNodeEnrollmentReplayRecord)
                    ?? throw new InvalidDataException("The node enrollment replay record is empty.");
                if (generation <= current.Generation || current.GrantId == grantId || current.Nonce == nonce)
                    return false;
                await store.UpdateAsync(key, candidate, entry.Revision, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                return true;
            }
            catch (NatsKVKeyNotFoundException)
            {
                try
                {
                    await store.CreateAsync(key, candidate, cancellationToken: cancellationToken)
                        .ConfigureAwait(false);
                    return true;
                }
                catch (NatsKVCreateException) when (attempt + 1 < MaximumAttempts)
                {
                    // Another admission won the create race; re-read and apply the generation fence.
                }
            }
            catch (NatsKVWrongLastRevisionException) when (attempt + 1 < MaximumAttempts)
            {
                // A concurrent generation update won; re-read it before deciding.
            }
        }

        throw new NatsKVException("The regional node enrollment replay fence could not be committed.");
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record RegionalNodeEnrollmentReplayRecord(ulong Generation, string GrantId, string Nonce);

[JsonSerializable(typeof(RegionalNodeEnrollmentReplayRecord))]
internal sealed partial class RegionalNodeEnrollmentJsonContext : JsonSerializerContext;

public static class RegionalNodeEnrollmentVerifier
{
    public static RegionalNodeEnrollmentVerification Verify(
        RegionalNodeEnrollmentEnvelope envelope,
        ECDsa signerPublicKey,
        string expectedRegion,
        string expectedNodeId,
        string expectedNatsAccountPublicKey,
        string expectedNatsUserPublicKey,
        string expectedSignerKeyId,
        ulong expectedSignerKeyVersion,
        RegionalNodeEnrollmentScope expectedScope,
        SignedBootstrapGrantVerification grantVerification,
        IRegionalNodeEnrollmentReplayStore replayStore)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(signerPublicKey);
        ArgumentNullException.ThrowIfNull(grantVerification);
        ArgumentNullException.ThrowIfNull(replayStore);
        BootstrapTrustBundleKey.RequireP256(signerPublicKey);
        var preliminary = VerifyBeforeReplay(
            envelope,
            signerPublicKey,
            expectedRegion,
            expectedNodeId,
            expectedNatsAccountPublicKey,
            expectedNatsUserPublicKey,
            expectedSignerKeyId,
            expectedSignerKeyVersion,
            expectedScope,
            grantVerification);
        if (preliminary.Decision is not null)
            return preliminary.Decision;
        return replayStore.TryAccept(envelope.NodeId, envelope.BootstrapGeneration,
                preliminary.Payload!.GrantId.Value, preliminary.Payload.Nonce)
            ? new(RegionalNodeEnrollmentDecision.Authorized, envelope.SignerKeyId, envelope.SignerKeyVersion)
            : new(RegionalNodeEnrollmentDecision.ReplayDetected, envelope.SignerKeyId, envelope.SignerKeyVersion);
    }

    /// <summary>Verifies an enrollment against the durable regional replay fence.</summary>
    public static async ValueTask<RegionalNodeEnrollmentVerification> VerifyAsync(
        RegionalNodeEnrollmentEnvelope envelope,
        ECDsa signerPublicKey,
        string expectedRegion,
        string expectedNodeId,
        string expectedNatsAccountPublicKey,
        string expectedNatsUserPublicKey,
        string expectedSignerKeyId,
        ulong expectedSignerKeyVersion,
        RegionalNodeEnrollmentScope expectedScope,
        SignedBootstrapGrantVerification grantVerification,
        IRegionalNodeEnrollmentDurableReplayStore replayStore,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(signerPublicKey);
        ArgumentNullException.ThrowIfNull(grantVerification);
        ArgumentNullException.ThrowIfNull(replayStore);
        BootstrapTrustBundleKey.RequireP256(signerPublicKey);
        var preliminary = VerifyBeforeReplay(
            envelope,
            signerPublicKey,
            expectedRegion,
            expectedNodeId,
            expectedNatsAccountPublicKey,
            expectedNatsUserPublicKey,
            expectedSignerKeyId,
            expectedSignerKeyVersion,
            expectedScope,
            grantVerification);
        if (preliminary.Decision is not null)
            return preliminary.Decision;
        try
        {
            var accepted = await replayStore.TryAcceptAsync(
                    envelope.NodeId,
                    envelope.BootstrapGeneration,
                    preliminary.Payload!.GrantId.Value,
                    preliminary.Payload.Nonce,
                    cancellationToken)
                .ConfigureAwait(false);
            return accepted
                ? new(RegionalNodeEnrollmentDecision.Authorized, envelope.SignerKeyId, envelope.SignerKeyVersion)
                : new(RegionalNodeEnrollmentDecision.ReplayDetected, envelope.SignerKeyId, envelope.SignerKeyVersion);
        }
        catch (Exception exception) when (exception is NATS.Client.Core.NatsException or IOException or TimeoutException or JsonException)
        {
            return new(RegionalNodeEnrollmentDecision.ReplayJournalUnavailable, envelope.SignerKeyId, envelope.SignerKeyVersion);
        }
    }

    private static (RegionalNodeEnrollmentVerification? Decision, BootstrapGrantPayload? Payload) VerifyBeforeReplay(
        RegionalNodeEnrollmentEnvelope envelope,
        ECDsa signerPublicKey,
        string expectedRegion,
        string expectedNodeId,
        string expectedNatsAccountPublicKey,
        string expectedNatsUserPublicKey,
        string expectedSignerKeyId,
        ulong expectedSignerKeyVersion,
        RegionalNodeEnrollmentScope expectedScope,
        SignedBootstrapGrantVerification grantVerification)
    {
        if (expectedRegion is not ("GRU" or "SFO" or "FRA") || envelope.Region != expectedRegion)
            return (new(RegionalNodeEnrollmentDecision.WrongRegion, envelope.SignerKeyId, envelope.SignerKeyVersion), null);
        if (!string.Equals(envelope.NodeId, expectedNodeId, StringComparison.Ordinal))
            return (new(RegionalNodeEnrollmentDecision.WrongNode, envelope.SignerKeyId, envelope.SignerKeyVersion), null);
        if (!string.Equals(envelope.NatsAccountPublicKey, expectedNatsAccountPublicKey, StringComparison.Ordinal))
            return (new(RegionalNodeEnrollmentDecision.AccountMismatch, envelope.SignerKeyId, envelope.SignerKeyVersion), null);
        if (!string.Equals(envelope.NatsUserPublicKey, expectedNatsUserPublicKey, StringComparison.Ordinal))
            return (new(RegionalNodeEnrollmentDecision.UserIdentityMismatch, envelope.SignerKeyId, envelope.SignerKeyVersion), null);
        if (!string.Equals(envelope.SignerKeyId, expectedSignerKeyId, StringComparison.Ordinal) ||
            envelope.SignerKeyVersion != expectedSignerKeyVersion)
            return (new(RegionalNodeEnrollmentDecision.UnknownSigner, envelope.SignerKeyId, envelope.SignerKeyVersion), null);
        ArgumentNullException.ThrowIfNull(expectedScope);
        if (!envelope.Scope.Matches(expectedScope))
            return (new(RegionalNodeEnrollmentDecision.ScopeMismatch, envelope.SignerKeyId, envelope.SignerKeyVersion), null);
        if (!grantVerification.Authorized)
            return (new(RegionalNodeEnrollmentDecision.GrantDenied, envelope.SignerKeyId, envelope.SignerKeyVersion), null);
        BootstrapGrantPayload payload;
        try
        {
            payload = envelope.Grant.ParsePayload();
        }
        catch (FormatException)
        {
            return (new(RegionalNodeEnrollmentDecision.GrantDenied, envelope.SignerKeyId, envelope.SignerKeyVersion), null);
        }
        if (!string.Equals(payload.Audience, envelope.NodeId, StringComparison.Ordinal))
            return (new(RegionalNodeEnrollmentDecision.GrantAudienceMismatch, envelope.SignerKeyId, envelope.SignerKeyVersion), null);
        try
        {
            if (!signerPublicKey.VerifyData(
                    Encoding.UTF8.GetBytes(envelope.CanonicalUnsigned()),
                    Convert.FromBase64String(envelope.Signature),
                    HashAlgorithmName.SHA256))
                return (new(RegionalNodeEnrollmentDecision.InvalidSignature, envelope.SignerKeyId, envelope.SignerKeyVersion), null);
        }
        catch (Exception exception) when (exception is CryptographicException or FormatException)
        {
            return (new(RegionalNodeEnrollmentDecision.InvalidSignature, envelope.SignerKeyId, envelope.SignerKeyVersion), null);
        }
        return (null, payload);
    }
}
