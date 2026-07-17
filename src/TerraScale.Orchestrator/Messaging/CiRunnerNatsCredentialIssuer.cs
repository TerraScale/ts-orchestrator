using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NATS.Client.Core;

namespace TerraScale.Orchestrator.Messaging;

internal interface INatsAccountJwtSigner
{
    string IssuerPublicKey { get; }
    string AccountPublicKey { get; }

    ValueTask<byte[]> SignAsync(
        ReadOnlyMemory<byte> material,
        CancellationToken cancellationToken = default);
}

/// <summary>Account or account-signing NKey retained from a private systemd credential.</summary>
internal sealed class NatsAccountJwtSigner : INatsAccountJwtSigner, IDisposable
{
    private const UnixFileMode ForbiddenMode =
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    private readonly object gate = new();
    private byte[]? seed;

    private NatsAccountJwtSigner(string seed, string issuerPublicKey, string accountPublicKey)
    {
        this.seed = Encoding.ASCII.GetBytes(seed);
        IssuerPublicKey = issuerPublicKey;
        AccountPublicKey = accountPublicKey;
    }

    public string IssuerPublicKey { get; }
    public string AccountPublicKey { get; }

    internal static NatsAccountJwtSigner Open(string path, string? accountPublicKey = null)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("The NATS account signing credential path is required.", nameof(path));
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("NATS account signing credentials require Linux file permissions.");
        var fullPath = Path.GetFullPath(path);
        var file = new FileInfo(fullPath);
        if (!file.Exists || file.Length is < 1 or > 4096)
            throw new ArgumentException("The NATS account signing credential must be a bounded existing file.", nameof(path));
        if ((File.GetUnixFileMode(fullPath) & ForbiddenMode) != 0)
            throw new ArgumentException("The NATS account signing credential must be private to the current user.", nameof(path));

        var seed = File.ReadLines(fullPath)
            .FirstOrDefault(static line => !string.IsNullOrWhiteSpace(line))?
            .Trim() ?? throw new ArgumentException("The NATS account signing credential is empty.", nameof(path));
        try
        {
            var issuer = NKeys.PublicKeyFromSeed(seed);
            RequireAccountPublicKey(issuer, "The NATS signing seed must be an account NKey.");
            var account = string.IsNullOrWhiteSpace(accountPublicKey) ? issuer : accountPublicKey;
            RequireAccountPublicKey(account, "The NATS issuer account must be an account public NKey.");
            var signer = new NatsAccountJwtSigner(seed, issuer, account);
            NKeys.Wipe(seed);
            return signer;
        }
        catch (Exception exception) when (exception is NatsException or FormatException or ArgumentException)
        {
            NKeys.Wipe(seed);
            throw new ArgumentException("The NATS account signing credential is invalid.", nameof(path), exception);
        }
    }

    public ValueTask<byte[]> SignAsync(
        ReadOnlyMemory<byte> material,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(seed is null, this);
            var encodedSeed = Encoding.ASCII.GetString(seed);
            try
            {
                using var pair = NKeys.FromSeed(encodedSeed);
                return ValueTask.FromResult(pair.Sign(material.ToArray()));
            }
            finally
            {
                NKeys.Wipe(encodedSeed);
            }
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (seed is null) return;
            CryptographicOperations.ZeroMemory(seed);
            seed = null;
        }
    }

    private static void RequireAccountPublicKey(string value, string message)
    {
        byte[]? decoded = null;
        try
        {
            decoded = NKeys.Decode(value);
            if (decoded.Length != 33 || decoded[0] != 0) throw new ArgumentException(message);
        }
        finally
        {
            if (decoded is not null) CryptographicOperations.ZeroMemory(decoded);
        }
    }
}

/// <summary>A disposable user JWT and nonce-signing seed. Its string form never contains either.</summary>
internal sealed class CiRunnerNatsCredentialLease : IDisposable
{
    private byte[]? seed;

    internal CiRunnerNatsCredentialLease(
        string publicKey,
        string jwt,
        string seed,
        string leaseId,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt)
    {
        PublicKey = publicKey;
        Jwt = jwt;
        this.seed = Encoding.ASCII.GetBytes(seed);
        LeaseId = leaseId;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
    }

    internal string PublicKey { get; }
    internal string Jwt { get; }
    internal string LeaseId { get; }
    internal DateTimeOffset IssuedAt { get; }
    internal DateTimeOffset ExpiresAt { get; }

    internal NatsAuthCred CreateAuthCredential()
    {
        ObjectDisposedException.ThrowIf(seed is null, this);
        return NatsAuthCred.FromJwt(Jwt, Encoding.ASCII.GetString(seed));
    }

    public void Dispose()
    {
        if (seed is null) return;
        CryptographicOperations.ZeroMemory(seed);
        seed = null;
    }

    public override string ToString() =>
        $"CI runner NATS credential {LeaseId} for {PublicKey}, expires {ExpiresAt:O}";
}

/// <summary>Issues a short-lived NATS user only after its exact consumer was reconciled.</summary>
internal sealed class CiRunnerNatsCredentialIssuer
{
    internal static readonly TimeSpan MaximumLifetime = TimeSpan.FromMinutes(15);
    internal static readonly TimeSpan MinimumLifetime = TimeSpan.FromMinutes(1);
    internal const int MaximumPayloadBytes = 128 * 1024;
    internal const int MaximumSubscriptions = 32;

    private readonly GlobalNatsTopology topology;
    private readonly INatsAccountJwtSigner signer;

    internal CiRunnerNatsCredentialIssuer(GlobalNatsTopology topology, INatsAccountJwtSigner signer)
    {
        this.topology = topology ?? throw new ArgumentNullException(nameof(topology));
        this.signer = signer ?? throw new ArgumentNullException(nameof(signer));
    }

    internal async Task<CiRunnerNatsCredentialLease> IssueAsync(
        CiRunnerConsumerRegistration registration,
        string runner,
        DateTimeOffset now,
        TimeSpan lifetime,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(registration);
        if (lifetime < MinimumLifetime || lifetime > MaximumLifetime ||
            lifetime.Ticks % TimeSpan.TicksPerSecond != 0)
            throw new ArgumentOutOfRangeException(nameof(lifetime));
        var expected = topology.CiJobConsumer(registration.Zone, runner);
        if (registration.Consumer != expected.Name || registration.Subject != expected.FilterSubject)
            throw new InvalidOperationException("A matching reconciled CI runner consumer is required before identity issuance.");

        var issuedSeconds = now.ToUnixTimeSeconds();
        if (issuedSeconds <= 0) throw new ArgumentOutOfRangeException(nameof(now));
        var expiresSeconds = checked(issuedSeconds + (long)lifetime.TotalSeconds);
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(issuedSeconds);
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(expiresSeconds);
        var seed = NKeys.CreateUserSeed();
        try
        {
            var publicKey = NKeys.PublicKeyFromSeed(seed);
            var plan = CiRunnerNatsPermissions.Create(topology, registration.Zone, runner);
            var name = expected.Name!;
            var token = await NatsUserJwtCodec.EncodeAsync(
                signer,
                publicKey,
                name,
                plan,
                issuedSeconds,
                expiresSeconds,
                cancellationToken);
            var credential = new CiRunnerNatsCredentialLease(
                publicKey,
                token.Jwt,
                seed,
                token.Id,
                issuedAt,
                expiresAt);
            NKeys.Wipe(seed);
            return credential;
        }
        catch
        {
            NKeys.Wipe(seed);
            throw;
        }
    }
}

internal static class NatsUserJwtCodec
{
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    internal static async Task<(string Jwt, string Id)> EncodeAsync(
        INatsAccountJwtSigner signer,
        string userPublicKey,
        string name,
        CiRunnerNatsPermissionPlan permissions,
        long issuedAt,
        long expiresAt,
        CancellationToken cancellationToken)
    {
        var claims = WriteJson(writer => WriteClaims(writer, signer, userPublicKey, name, issuedAt, expiresAt));
        var idHash = SHA256.HashData(claims);
        var id = Base32(idHash);
        CryptographicOperations.ZeroMemory(idHash);

        var header = WriteJson(static writer =>
        {
            writer.WriteStartObject();
            writer.WriteString("typ", "JWT");
            writer.WriteString("alg", "ed25519-nkey");
            writer.WriteEndObject();
        });
        var payload = WriteJson(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("exp", expiresAt);
            writer.WriteString("jti", id);
            writer.WriteNumber("iat", issuedAt);
            writer.WriteString("iss", signer.IssuerPublicKey);
            writer.WriteString("name", name);
            writer.WriteString("sub", userPublicKey);
            writer.WritePropertyName("nats");
            writer.WriteStartObject();
            WritePermission(writer, "pub", permissions.Publish);
            WritePermission(writer, "sub", permissions.Subscribe);
            writer.WriteNumber("subs", CiRunnerNatsCredentialIssuer.MaximumSubscriptions);
            writer.WriteNumber("data", -1);
            writer.WriteNumber("payload", CiRunnerNatsCredentialIssuer.MaximumPayloadBytes);
            writer.WritePropertyName("allowed_connection_types");
            writer.WriteStartArray();
            writer.WriteStringValue("STANDARD");
            writer.WriteEndArray();
            if (signer.IssuerPublicKey != signer.AccountPublicKey)
                writer.WriteString("issuer_account", signer.AccountPublicKey);
            writer.WriteString("type", "user");
            writer.WriteNumber("version", 2);
            writer.WriteEndObject();
            writer.WriteEndObject();
        });
        var signingInput = $"{Base64Url.EncodeToString(header)}.{Base64Url.EncodeToString(payload)}";
        var signature = await signer.SignAsync(Encoding.ASCII.GetBytes(signingInput), cancellationToken);
        if (signature.Length != 64)
            throw new CryptographicException("A NATS account NKey signature must contain 64 bytes.");
        return ($"{signingInput}.{Base64Url.EncodeToString(signature)}", id);
    }

    private static void WriteClaims(
        Utf8JsonWriter writer,
        INatsAccountJwtSigner signer,
        string userPublicKey,
        string name,
        long issuedAt,
        long expiresAt)
    {
        writer.WriteStartObject();
        writer.WriteNumber("exp", expiresAt);
        writer.WriteNumber("iat", issuedAt);
        writer.WriteString("iss", signer.IssuerPublicKey);
        writer.WriteString("name", name);
        writer.WriteString("sub", userPublicKey);
        writer.WriteEndObject();
    }

    private static void WritePermission(
        Utf8JsonWriter writer,
        string name,
        IEnumerable<string> allowed)
    {
        writer.WritePropertyName(name);
        writer.WriteStartObject();
        writer.WritePropertyName("allow");
        writer.WriteStartArray();
        foreach (var subject in allowed) writer.WriteStringValue(subject);
        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static byte[] WriteJson(Action<Utf8JsonWriter> write)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream)) write(writer);
        return stream.ToArray();
    }

    private static string Base32(ReadOnlySpan<byte> value)
    {
        Span<char> encoded = stackalloc char[(value.Length * 8 + 4) / 5];
        var buffer = 0;
        var bits = 0;
        var output = 0;
        foreach (var current in value)
        {
            buffer = (buffer << 8) | current;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                encoded[output++] = Base32Alphabet[(buffer >> bits) & 31];
            }
        }
        if (bits > 0) encoded[output++] = Base32Alphabet[(buffer << (5 - bits)) & 31];
        return new(encoded[..output]);
    }
}
