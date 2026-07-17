using System.Buffers.Binary;
using System.Security.Cryptography;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

/// <summary>Bounded credential references opened before any command-capable runtime connects.</summary>
public sealed class CommandIdentityConfiguration
{
    private CommandIdentityConfiguration(string? signingKeyFile, string[] trustKeyFiles)
    {
        SigningKeyFile = signingKeyFile;
        TrustKeyFiles = Array.AsReadOnly(trustKeyFiles);
    }

    public string? SigningKeyFile { get; }
    public IReadOnlyList<string> TrustKeyFiles { get; }

    internal static CommandIdentityConfiguration? Resolve(
        string? signingKeyFile,
        string? trustKeyFiles)
    {
        var signing = string.IsNullOrWhiteSpace(signingKeyFile)
            ? null
            : Path.GetFullPath(signingKeyFile.Trim());
        var trust = Paths(trustKeyFiles);
        return signing is null && trust.Length == 0 ? null : new(signing, trust);
    }

    internal CommandIdentityRuntime Open() => CommandIdentityRuntime.Open(this);

    private static string[] Paths(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return [];
        var values = value.Split(Path.PathSeparator, StringSplitOptions.TrimEntries);
        if (values.Length is < 1 or > 4 || values.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException(
                "TS_ORCH_COMMAND_TRUST_KEY_FILES must contain one to four complete paths.",
                nameof(value));
        var paths = values.Select(Path.GetFullPath).ToArray();
        if (paths.Distinct(StringComparer.Ordinal).Count() != paths.Length)
            throw new ArgumentException(
                "TS_ORCH_COMMAND_TRUST_KEY_FILES must not contain duplicate paths.",
                nameof(value));
        return paths;
    }
}

/// <summary>Owns the loaded command signer and verifier for one process lifetime.</summary>
internal sealed class CommandIdentityRuntime : IDisposable
{
    private CommandIdentityRuntime(
        EcdsaCommandSigner? signer,
        EcdsaCommandSignatureVerifier? verifier)
    {
        Signer = signer;
        Verifier = verifier;
    }

    internal EcdsaCommandSigner? Signer { get; }
    internal EcdsaCommandSignatureVerifier? Verifier { get; }

    internal static CommandIdentityRuntime Open(CommandIdentityConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        EcdsaCommandSigner? signer = null;
        try
        {
            signer = configuration.SigningKeyFile is null
                ? null
                : EcdsaCommandSigner.LoadPrivatePem(configuration.SigningKeyFile);
            var verifier = configuration.TrustKeyFiles.Count == 0
                ? null
                : EcdsaCommandSignatureVerifier.LoadPublicPem(configuration.TrustKeyFiles);
            return new(signer, verifier);
        }
        catch
        {
            signer?.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        Verifier?.Dispose();
        Signer?.Dispose();
    }
}

/// <summary>
/// Signs canonical command digests with one P-256 intermediate supplied as a private systemd
/// credential. Production root protection and intermediate issuance remain at the OCI KMS boundary.
/// </summary>
internal sealed class EcdsaCommandSigner :
    IRepositoryCiJobSigner,
    INativeGitOpsCellSpecSigner,
    IRepositoryCiArtifactAttestationSigner,
    IDisposable
{
    private readonly ECDsa key;
    private readonly byte[] keyId;
    private readonly object sync = new();

    private EcdsaCommandSigner(ECDsa key)
    {
        this.key = key;
        keyId = SHA256.HashData(key.ExportSubjectPublicKeyInfo());
        Identity = EcdsaCommandSignatureEnvelope.Identity(keyId);
    }

    public string Identity { get; }

    internal static EcdsaCommandSigner LoadPrivatePem(string path)
    {
        var pem = ReadPrivateCredential(path);
        var key = ECDsa.Create();
        try
        {
            key.ImportFromPem(pem);
            ValidateKey(key, requirePrivate: true);
            return new(key);
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        {
            key.Dispose();
            throw new ArgumentException("The command signing credential is not a P-256 private key.", nameof(path), exception);
        }
    }

    public OpaqueSignature Sign(CommandSignedMaterial material)
    {
        var digest = CommandSignedMaterialCodec.Hash(material);
        return SignDigest(digest);
    }

    public OpaqueSignature Sign(ReadOnlyMemory<byte> canonicalMaterial) =>
        SignDigest(SHA256.HashData(canonicalMaterial.Span));

    private OpaqueSignature SignDigest(ReadOnlySpan<byte> digest)
    {
        byte[] signature;
        lock (sync)
            signature = key.SignHash(digest, DSASignatureFormat.Rfc3279DerSequence);
        var encoded = EcdsaCommandSignatureEnvelope.Encode(keyId, signature);
        OpaqueSignature.TryCopyFrom(encoded, out var result);
        return result!;
    }

    public void Dispose() => key.Dispose();

    private static string ReadPrivateCredential(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("The command signing credential path is required.", nameof(value));
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Command signing credentials require Linux file permissions.");
        var path = Path.GetFullPath(value);
        var file = new FileInfo(path);
        if (!file.Exists || file.Length is < 1 or > 32 * 1024)
            throw new ArgumentException("The command signing credential must be a bounded existing PEM file.", nameof(value));
        var mode = File.GetUnixFileMode(path);
        if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                     UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
            throw new ArgumentException("The command signing credential must be private to the current user.", nameof(value));
        return File.ReadAllText(path);
    }

    internal static void ValidateKey(ECDsa key, bool requirePrivate)
    {
        if (key.KeySize != 256 || key.ExportParameters(false).Curve.Oid.Value !=
            ECCurve.NamedCurves.nistP256.Oid.Value)
            throw new CryptographicException("The command signing key must use NIST P-256.");
        if (!requirePrivate) return;
        var parameters = key.ExportParameters(true);
        try
        {
            if (parameters.D is not { Length: > 0 })
                throw new CryptographicException("The command signing key has no private component.");
        }
        finally
        {
            if (parameters.D is not null) CryptographicOperations.ZeroMemory(parameters.D);
        }
    }
}

/// <summary>Verifies versioned command signatures against a bounded rotating P-256 trust set.</summary>
internal sealed class EcdsaCommandSignatureVerifier :
    ICommandSignatureVerifier,
    IRepositoryCiArtifactSignatureVerifier,
    IDisposable
{
    private const int MaximumTrustedKeys = 4;
    private readonly Dictionary<string, TrustedKey> keys;

    private EcdsaCommandSignatureVerifier(Dictionary<string, TrustedKey> keys) => this.keys = keys;

    internal static EcdsaCommandSignatureVerifier LoadPublicPem(IEnumerable<string> paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        var captured = paths.Take(MaximumTrustedKeys + 1).ToArray();
        if (captured.Length is < 1 or > MaximumTrustedKeys)
            throw new ArgumentException("The command trust set must contain one to four public keys.", nameof(paths));
        var keys = new Dictionary<string, TrustedKey>(StringComparer.Ordinal);
        try
        {
            foreach (var path in captured)
            {
                var file = new FileInfo(Path.GetFullPath(path));
                if (!file.Exists || file.Length is < 1 or > 32 * 1024)
                    throw new ArgumentException("A command trust key must be a bounded existing PEM file.", nameof(paths));
                var pem = File.ReadAllText(file.FullName);
                if (pem.Contains("PRIVATE KEY", StringComparison.Ordinal))
                    throw new ArgumentException("A command trust key must not contain private key material.", nameof(paths));
                var key = ECDsa.Create();
                try
                {
                    key.ImportFromPem(pem);
                    EcdsaCommandSigner.ValidateKey(key, requirePrivate: false);
                    var keyId = Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
                    if (!keys.TryAdd(keyId, new(key)))
                        throw new ArgumentException("The command trust set contains a duplicate key.", nameof(paths));
                    key = null!;
                }
                finally
                {
                    key?.Dispose();
                }
            }
            return new(keys);
        }
        catch (ArgumentException)
        {
            foreach (var key in keys.Values) key.Dispose();
            throw;
        }
        catch (CryptographicException exception)
        {
            foreach (var key in keys.Values) key.Dispose();
            throw new ArgumentException("A command trust key is not a P-256 public key.", nameof(paths), exception);
        }
    }

    public VerificationOutcome Verify(CommandSignedMaterial signedMaterial, OpaqueSignature signature)
        => VerifyDigest(CommandSignedMaterialCodec.Hash(signedMaterial), signature);

    public VerificationOutcome Verify(
        string signingIdentity,
        ReadOnlyMemory<byte> canonicalMaterial,
        OpaqueSignature signature) =>
        VerifyDigest(SHA256.HashData(canonicalMaterial.Span), signature, signingIdentity);

    private VerificationOutcome VerifyDigest(
        ReadOnlySpan<byte> digest,
        OpaqueSignature signature,
        string? signingIdentity = null)
    {
        if (!EcdsaCommandSignatureEnvelope.TryDecode(signature.Bytes, out var keyId, out var value) ||
            signingIdentity is not null && signingIdentity != EcdsaCommandSignatureEnvelope.Identity(keyId) ||
            !keys.TryGetValue(Convert.ToHexStringLower(keyId), out var key))
            return VerificationOutcome.Invalid;
        try
        {
            return key.Verify(digest, value)
                ? VerificationOutcome.Valid
                : VerificationOutcome.Invalid;
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException or InvalidDataException)
        {
            return VerificationOutcome.Invalid;
        }
    }

    public void Dispose()
    {
        foreach (var key in keys.Values) key.Dispose();
    }

    private sealed class TrustedKey(ECDsa key) : IDisposable
    {
        private readonly object sync = new();

        internal bool Verify(ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
        {
            lock (sync)
                return key.VerifyHash(digest, signature, DSASignatureFormat.Rfc3279DerSequence);
        }

        public void Dispose() => key.Dispose();
    }
}

internal static class EcdsaCommandSignatureEnvelope
{
    private const byte Version = 1;
    private const byte EcdsaP256Sha256 = 1;
    private const int KeyIdBytes = 32;
    private const int HeaderBytes = 4 + 1 + 1 + KeyIdBytes + 2;
    private const int MaximumSignatureBytes = 128;
    private static ReadOnlySpan<byte> Magic => "TSCS"u8;

    internal static string Identity(ReadOnlySpan<byte> keyId) =>
        $"ecdsa-p256-sha256-{Convert.ToHexStringLower(keyId)}";

    internal static byte[] Encode(ReadOnlySpan<byte> keyId, ReadOnlySpan<byte> signature)
    {
        if (keyId.Length != KeyIdBytes || signature.Length is < 1 or > MaximumSignatureBytes)
            throw new InvalidDataException("The command signature envelope is invalid.");
        var result = new byte[HeaderBytes + signature.Length];
        Magic.CopyTo(result);
        result[4] = Version;
        result[5] = EcdsaP256Sha256;
        keyId.CopyTo(result.AsSpan(6, KeyIdBytes));
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(38, 2), checked((ushort)signature.Length));
        signature.CopyTo(result.AsSpan(HeaderBytes));
        return result;
    }

    internal static bool TryDecode(
        ReadOnlySpan<byte> envelope,
        out ReadOnlySpan<byte> keyId,
        out ReadOnlySpan<byte> signature)
    {
        keyId = default;
        signature = default;
        if (envelope.Length < HeaderBytes || !envelope[..4].SequenceEqual(Magic) ||
            envelope[4] != Version || envelope[5] != EcdsaP256Sha256)
            return false;
        var length = BinaryPrimitives.ReadUInt16BigEndian(envelope.Slice(38, 2));
        if (length is < 1 or > MaximumSignatureBytes || envelope.Length != HeaderBytes + length)
            return false;
        keyId = envelope.Slice(6, KeyIdBytes);
        signature = envelope[HeaderBytes..];
        return true;
    }
}
