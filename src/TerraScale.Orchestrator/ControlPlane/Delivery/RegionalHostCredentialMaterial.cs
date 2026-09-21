using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>
/// Validates one immutable delivered generation. This is material evidence, not admission:
/// only the regional session authority consumes enrollment and grants execution leases.
/// No host access to the controller's private replay store is required.
/// </summary>
internal sealed class RegionalHostCredentialMaterial
{
    private const int MaximumMaterialBytes = 256 * 1024;
    private const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";
    private readonly RegionalHostAdmissionConfiguration configuration;
    private readonly NatsAuthenticationFiles authentication;
    private readonly NatsTlsFiles tls;
    private readonly TimeProvider clock;
    private readonly Dictionary<string, string> pins;
    private readonly HostExecutionMaterial evidence;

    private RegionalHostCredentialMaterial(RegionalHostAdmissionConfiguration configuration,
        NatsAuthenticationFiles authentication, NatsTlsFiles tls, TimeProvider clock,
        RegionalNodeEnrollmentEnvelope enrollment, Dictionary<string, string> pins, HostExecutionMaterial evidence)
    {
        this.configuration = configuration;
        this.authentication = authentication;
        this.tls = tls;
        this.clock = clock;
        Enrollment = enrollment;
        this.pins = pins;
        this.evidence = evidence;
    }

    internal RegionalNodeEnrollmentEnvelope Enrollment { get; }

    internal static RegionalHostCredentialMaterial Load(RegionalHostAdmissionConfiguration configuration,
        NatsAuthenticationFiles authentication, NatsTlsFiles tls, TimeProvider? clock = null)
    {
        var time = clock ?? TimeProvider.System;
        var pins = new Dictionary<string, string>(StringComparer.Ordinal);
        var enrollment = ReadJson<RegionalNodeEnrollmentEnvelope>(configuration.EnrollmentFile, pins);
        var trust = ReadTrustBundle(configuration.BootstrapTrustBundleFile, pins);
        using var signer = ECDsa.Create();
        var signerBytes = ReadPinned(configuration.EnrollmentSignerPublicKeyFile, pins);
        var signerText = Encoding.UTF8.GetString(signerBytes);
        if (signerText.Contains("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal)) signer.ImportFromPem(signerText);
        else
        {
            signer.ImportSubjectPublicKeyInfo(signerBytes, out var consumed);
            if (consumed != signerBytes.Length) throw new InvalidDataException("The enrollment signer contains trailing data.");
        }
        var policy = new RegionalHostEnrollmentPolicy(configuration.Region.ToLowerInvariant(), configuration.NatsAccountPublicKey,
            configuration.ClusterName, configuration.Scope, configuration.EnrollmentSignerKeyId, configuration.EnrollmentSignerKeyVersion,
            signer, trust, configuration.ExpectedSystemProject, configuration.RequestedOperation, configuration.MaximumGrantLifetime);
        var now = time.GetUtcNow();
        // Validate the signed document without replaying bootstrap. The authority decides
        // whether a fresh or already committed enrollment may acquire a process session.
        if (enrollment.NodeId != configuration.NodeId || enrollment.NatsUserPublicKey != authentication.PublicKey ||
            !enrollment.Scope.Matches(configuration.Scope) ||
            !policy.AllowsContinuingEnrollment(enrollment, now, now + RegionalHostSessionAuthority.LeaseLifetime))
            throw new InvalidDataException("The signed host enrollment does not match its pinned identity, scope or trust.");

        var expiresAt = ValidateBundle(configuration.BundleFile, enrollment, authentication, tls, now);
        var payload = enrollment.Grant.ParsePayload();
        if (trust.Find(payload.KeyId, payload.KeyVersion)?.AcceptedUntil is { } trustExpires && trustExpires < expiresAt)
            expiresAt = trustExpires;
        if (expiresAt - now <= RegionalHostSessionLease.ExecutionReserve)
            throw new InvalidDataException("The pinned host credentials have no safe execution window.");
        return new(configuration, authentication, tls, time, enrollment, pins, new(expiresAt));
    }

    internal ValueTask<HostExecutionMaterial?> ObserveAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            foreach (var (path, digest) in pins)
                if (Digest(ReadMaterial(path, ownerOnly: false)) != digest) return ValueTask.FromResult<HostExecutionMaterial?>(null);
            var now = clock.GetUtcNow();
            var expiresAt = ValidateBundle(configuration.BundleFile, Enrollment, authentication, tls, now);
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<HostExecutionMaterial?>(now < evidence.ExpiresAt && expiresAt >= evidence.ExpiresAt ? evidence : null);
        }
        catch (Exception exception) when (exception is InvalidDataException or IOException or UnauthorizedAccessException or JsonException or
                                           CryptographicException or ArgumentException or InvalidOperationException)
        {
            return ValueTask.FromResult<HostExecutionMaterial?>(null);
        }
    }

    private static DateTimeOffset ValidateBundle(string bundleFile, RegionalNodeEnrollmentEnvelope enrollment,
        NatsAuthenticationFiles authentication, NatsTlsFiles tls, DateTimeOffset now)
    {
        var manifestBytes = ReadMaterial(bundleFile, ownerOnly: true);
        if (Digest(manifestBytes) != enrollment.CredentialBundleSha256)
            throw new InvalidDataException("The credential manifest does not match its enrollment digest.");
        var manifest = JsonSerializer.Deserialize<CredentialManifest>(manifestBytes, JsonOptions);
        var expected = new HashSet<string>(StringComparer.Ordinal)
            { authentication.CredentialsFile ?? authentication.NKeyFile!, tls.CaFile, tls.CertificateFile, tls.KeyFile };
        if (expected.Count != 4 || manifest is not { SchemaVersion: 1, Files.Count: 4 })
            throw new InvalidDataException("The host bundle must name the four distinct transport credential files.");
        var contents = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        try
        {
            foreach (var entry in manifest.Files)
            {
                if (entry is null || !Path.IsPathFullyQualified(entry.Path) || Path.GetFullPath(entry.Path) != entry.Path ||
                    !expected.Remove(entry.Path)) throw new InvalidDataException("The host manifest contains an unexpected or duplicate path.");
                var bytes = ReadMaterial(entry.Path, ownerOnly: true);
                contents.Add(entry.Path, bytes);
                if (Digest(bytes) != entry.Sha256) throw new InvalidDataException("A host credential does not match its manifest digest.");
            }
            using var certificate = X509Certificate2.CreateFromPem(Encoding.UTF8.GetString(contents[tls.CertificateFile]),
                Encoding.UTF8.GetString(contents[tls.KeyFile]));
            if (!certificate.HasPrivateKey || certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault()?.CertificateAuthority != false ||
                certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault() is not { } usage ||
                !usage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature) ||
                certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault() is not { } enhanced ||
                !enhanced.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == ClientAuthenticationOid) ||
                BootstrapWorkloadIdentity.CertificateFingerprint(certificate.PublicKey.ExportSubjectPublicKeyInfo()) != enrollment.Grant.ParsePayload().CertificateFingerprint)
                throw new InvalidDataException("The host client certificate does not match its enrollment or required usage.");

            var authorities = new X509Certificate2Collection();
            try
            {
                authorities.ImportFromPem(Encoding.UTF8.GetString(contents[tls.CaFile]));
                if (authorities.Count is < 1 or > 16 || authorities.Any(ca =>
                        ca.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault()?.CertificateAuthority != true))
                    throw new InvalidDataException("The pinned host CA bundle is invalid.");
                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.AddRange(authorities);
                chain.ChainPolicy.ExtraStore.AddRange(authorities);
                chain.ChainPolicy.ApplicationPolicy.Add(new(ClientAuthenticationOid));
                chain.ChainPolicy.VerificationTime = now.UtcDateTime;
                chain.ChainPolicy.DisableCertificateDownloads = true;
                // Revocation is enforced by the regional authority; this offline probe
                // never depends on network CRL/AIA retrieval to enforce local expiry.
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                if (!chain.Build(certificate)) throw new InvalidDataException("The host client certificate has no valid pinned trust chain.");
                var expiresAt = chain.ChainElements.Min(element => new DateTimeOffset(element.Certificate.NotAfter.ToUniversalTime()));
                var jwtExpiry = authentication.ExecutionExpiresAt(now);
                // The auth resolver consumes paths too. Recheck the manifest snapshot
                // after that read; generations must remain immutable for the transport.
                foreach (var (path, bytes) in contents)
                {
                    var current = ReadMaterial(path, ownerOnly: true);
                    try
                    {
                        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes), SHA256.HashData(current)))
                            throw new InvalidDataException("The host credentials changed during validation.");
                    }
                    finally { CryptographicOperations.ZeroMemory(current); }
                }
                return expiresAt < jwtExpiry ? expiresAt : jwtExpiry;
            }
            finally { foreach (var authority in authorities) authority.Dispose(); }
        }
        finally { foreach (var bytes in contents.Values) CryptographicOperations.ZeroMemory(bytes); }
    }

    private static string Digest(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static T ReadJson<T>(string path, Dictionary<string, string> pins) =>
        JsonSerializer.Deserialize<T>(ReadPinned(path, pins), JsonOptions) ?? throw new InvalidDataException("Host material is empty.");

    private static byte[] ReadPinned(string path, Dictionary<string, string> pins)
    {
        var bytes = ReadMaterial(path, ownerOnly: false);
        if (!pins.TryAdd(path, Digest(bytes))) throw new InvalidDataException("Host material paths must be distinct.");
        return bytes;
    }

    private static byte[] ReadMaterial(string path, bool ownerOnly)
    {
        _ = NatsFileResolver.Resolve(path, "host credential material", MaximumMaterialBytes, ownerOnly);
        using var stream = File.OpenRead(path);
        var buffer = new byte[MaximumMaterialBytes + 1];
        try
        {
            var length = stream.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
            if (length is < 1 or > MaximumMaterialBytes) throw new InvalidDataException("Host material exceeds its bounds.");
            return buffer[..length];
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    private static RotatedBootstrapTrustBundle ReadTrustBundle(string path, Dictionary<string, string> pins)
    {
        var document = ReadJson<TrustBundleDocument>(path, pins);
        if (document.SchemaVersion != 1 || document.Keys is not { Count: >= 1 and <= 32 })
            throw new InvalidDataException("The bootstrap trust bundle schema or key count is invalid.");
        return new(document.BundleVersion, document.Keys.Select(key => new BootstrapTrustBundleKey(key.KeyId, key.KeyVersion,
            key.Purpose, Convert.FromBase64String(key.SubjectPublicKeyInfo), key.AcceptedUntil)).ToArray(),
            document.CurrentGrantSigningKeyId, document.CurrentGrantSigningKeyVersion);
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties = false,
        PropertyNameCaseInsensitive = false,
        MaxDepth = 16
    };

    private sealed record CredentialManifest(int SchemaVersion, IReadOnlyList<CredentialFile> Files);
    private sealed record CredentialFile(string Path, string Sha256);
    private sealed record TrustBundleDocument(int SchemaVersion, ulong BundleVersion, string CurrentGrantSigningKeyId,
        ulong CurrentGrantSigningKeyVersion, IReadOnlyList<TrustKeyDocument> Keys);
    private sealed record TrustKeyDocument(string KeyId, ulong KeyVersion, BootstrapTrustKeyPurpose Purpose,
        string SubjectPublicKeyInfo, DateTimeOffset? AcceptedUntil);
}
