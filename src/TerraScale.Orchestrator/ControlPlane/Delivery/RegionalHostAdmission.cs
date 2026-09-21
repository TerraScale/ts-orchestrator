using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>
/// Protected first-boot material required before a production host can
/// install or serve an admitted workload. The material contains public
/// enrollment/trust data and a digest-addressed manifest of credential files.
/// The configuration itself contains no NATS seed or TLS private key.
/// </summary>
public sealed record RegionalHostAdmissionConfiguration(
    string EnrollmentFile,
    string EnrollmentSignerPublicKeyFile,
    string BootstrapTrustBundleFile,
    string BundleFile,
    string NodeId,
    string Region,
    string NatsAccountPublicKey,
    string ClusterName,
    string EnrollmentSignerKeyId,
    ulong EnrollmentSignerKeyVersion,
    BootstrapSystemProjectUlds ExpectedSystemProject,
    string RequestedOperation,
    TimeSpan MaximumGrantLifetime)
{
    private const string DefaultOperation = BootstrapGrantOperation.EnsureSystemProjectConfiguration;
    private static readonly TimeSpan DefaultMaximumGrantLifetime = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Loads the production admission shape from environment-backed runtime
    /// configuration. Missing values are an error once production host roles
    /// are enabled, so a host cannot silently run without the gate.
    /// </summary>
    public static RegionalHostAdmissionConfiguration Load(
        Func<string, string?> environment,
        string logicalCell)
    {
        ArgumentNullException.ThrowIfNull(environment);
        var region = logicalCell.ToUpperInvariant() switch
        {
            "GRU" => "GRU",
            "SFO" => "SFO",
            "FRA" => "FRA",
            _ => throw new InvalidOperationException(
                $"Production host admission requires a supported logical region; cell '{logicalCell}' is invalid.")
        };

        var enrollment = Required(environment, "TS_ORCH_HOST_ENROLLMENT_FILE");
        var signer = Required(environment, "TS_ORCH_HOST_ENROLLMENT_SIGNER_PUBLIC_KEY_FILE");
        var trust = Required(environment, "TS_ORCH_HOST_BOOTSTRAP_TRUST_BUNDLE_FILE");
        var credential = Required(environment, "TS_ORCH_HOST_CREDENTIAL_BUNDLE_FILE");
        var nodeId = RegionalNodeEnrollmentEnvelope.ValidateToken(
            Required(environment, "TS_ORCH_HOST_NODE_ID"), "TS_ORCH_HOST_NODE_ID");
        var account = Required(environment, "TS_ORCH_NATS_ACCOUNT_PUBLIC_KEY");
        var cluster = RegionalNodeEnrollmentEnvelope.ValidateToken(
            Required(environment, "TS_ORCH_HOST_CLUSTER_NAME"), "TS_ORCH_HOST_CLUSTER_NAME");
        var signerKeyId = BootstrapGrantCanonicalToken(
            Required(environment, "TS_ORCH_HOST_ENROLLMENT_SIGNER_KEY_ID"),
            "TS_ORCH_HOST_ENROLLMENT_SIGNER_KEY_ID");
        var signerVersion = ParsePositiveUInt64(
            Required(environment, "TS_ORCH_HOST_ENROLLMENT_SIGNER_KEY_VERSION"),
            "TS_ORCH_HOST_ENROLLMENT_SIGNER_KEY_VERSION");

        var organization = new BootstrapUlid(
            Required(environment, "TS_ORCH_BOOTSTRAP_SYSTEM_ORGANIZATION_ULID"));
        var project = new BootstrapUlid(
            Required(environment, "TS_ORCH_BOOTSTRAP_SYSTEM_PROJECT_ULID"));
        var database = new BootstrapUlid(
            Required(environment, "TS_ORCH_BOOTSTRAP_SYSTEM_DATABASE_ULID"));
        var operation = environment("TS_ORCH_HOST_BOOTSTRAP_OPERATION") is { Length: > 0 } configuredOperation
            ? BootstrapGrantCanonicalToken(configuredOperation, "TS_ORCH_HOST_BOOTSTRAP_OPERATION")
            : DefaultOperation;
        if (!BootstrapGrantOperation.IsIdempotentBootstrapOperation(operation))
            throw new ArgumentException(
                "TS_ORCH_HOST_BOOTSTRAP_OPERATION must be an idempotent bootstrap operation.");

        var lifetime = ParseMaximumLifetime(environment("TS_ORCH_HOST_BOOTSTRAP_MAX_LIFETIME_SECONDS"));
        return new(
            Path.GetFullPath(enrollment),
            Path.GetFullPath(signer),
            Path.GetFullPath(trust),
            Path.GetFullPath(credential),
            nodeId,
            region,
            ValidatePublicIdentity(account, "TS_ORCH_NATS_ACCOUNT_PUBLIC_KEY"),
            cluster,
            signerKeyId,
            signerVersion,
            new BootstrapSystemProjectUlds(organization, project, database),
            operation,
            lifetime);
    }

    internal RegionalHostAdmissionGate Create(
        INatsKVStore enrollmentStore,
        NatsAuthenticationFiles authentication,
        NatsTlsFiles tls)
    {
        ArgumentNullException.ThrowIfNull(enrollmentStore);
        ArgumentNullException.ThrowIfNull(authentication);
        ArgumentNullException.ThrowIfNull(tls);
        return RegionalHostAdmissionGate.Load(this, enrollmentStore, authentication, tls);
    }

    private static string Required(Func<string, string?> environment, string name) =>
        !string.IsNullOrWhiteSpace(environment(name))
            ? environment(name)!
            : throw new ArgumentException($"{name} is required for production host admission.");

    private static string ValidatePublicIdentity(string value, string name) =>
        value is { Length: >= 2 and <= 256 } && value.All(static character => !char.IsWhiteSpace(character) && !char.IsControl(character))
            ? value
            : throw new ArgumentException($"{name} is not a bounded public identity.");

    private static string BootstrapGrantCanonicalToken(string value, string name) =>
        value is { Length: >= 1 and <= 128 } && value.All(static character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-')
            ? value
            : throw new ArgumentException($"{name} is not a bounded bootstrap token.");

    private static ulong ParsePositiveUInt64(string value, string name) =>
        ulong.TryParse(value, System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture, out var parsed) && parsed > 0
            ? parsed
            : throw new ArgumentException($"{name} must be a positive decimal integer.");

    private static TimeSpan ParseMaximumLifetime(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return DefaultMaximumGrantLifetime;
        if (!int.TryParse(value, System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var seconds) ||
            seconds is < 1 or > 86_400)
            throw new ArgumentException(
                "TS_ORCH_HOST_BOOTSTRAP_MAX_LIFETIME_SECONDS must be between 1 and 86400.");
        return TimeSpan.FromSeconds(seconds);
    }
}

/// <summary>
/// Production host admission gate. Static material is loaded once; a
/// successful admission is cached for the process lifetime while credential
/// readiness and durable enrollment replay remain fail-closed.
/// </summary>
internal sealed class RegionalHostAdmissionGate : IHostAdmissionGate, IDisposable
{
    private const long MaximumMaterialBytes = 256 * 1024;
    private readonly RegionalHostAdmissionConfiguration configuration;
    private readonly IRegionalNodeEnrollmentDurableReplayStore replayStore;
    private readonly string natsUserPublicKey;
    private readonly ECDsa enrollmentSignerKey;
    private readonly RotatedBootstrapTrustBundle trustBundle;
    private readonly RegionalNodeEnrollmentEnvelope enrollment;
    private readonly string certificateFingerprint;
    private readonly NatsAuthenticationFiles authentication;
    private readonly NatsTlsFiles tls;
    private readonly SemaphoreSlim admissionLock = new(1, 1);
    private HostAdmissionSnapshot? admitted;

    private RegionalHostAdmissionGate(
        RegionalHostAdmissionConfiguration configuration,
        IRegionalNodeEnrollmentDurableReplayStore replayStore,
        string natsUserPublicKey,
        ECDsa enrollmentSignerKey,
        RotatedBootstrapTrustBundle trustBundle,
        RegionalNodeEnrollmentEnvelope enrollment,
        string certificateFingerprint,
        NatsAuthenticationFiles authentication,
        NatsTlsFiles tls)
    {
        this.configuration = configuration;
        this.replayStore = replayStore;
        this.natsUserPublicKey = natsUserPublicKey;
        this.enrollmentSignerKey = enrollmentSignerKey;
        this.trustBundle = trustBundle;
        this.enrollment = enrollment;
        this.certificateFingerprint = certificateFingerprint;
        this.authentication = authentication;
        this.tls = tls;
    }

    public static RegionalHostAdmissionGate Load(
        RegionalHostAdmissionConfiguration configuration,
        INatsKVStore enrollmentStore,
        NatsAuthenticationFiles authentication,
        NatsTlsFiles tls)
    {
        ArgumentNullException.ThrowIfNull(enrollmentStore);
        return LoadCore(configuration, new NatsRegionalNodeEnrollmentReplayStore(enrollmentStore), authentication, tls);
    }

    internal static RegionalHostAdmissionGate LoadForTests(
        RegionalHostAdmissionConfiguration configuration,
        IRegionalNodeEnrollmentDurableReplayStore replayStore,
        NatsAuthenticationFiles authentication,
        NatsTlsFiles tls) => LoadCore(configuration, replayStore, authentication, tls);

    private static RegionalHostAdmissionGate LoadCore(
        RegionalHostAdmissionConfiguration configuration,
        IRegionalNodeEnrollmentDurableReplayStore replayStore,
        NatsAuthenticationFiles authentication,
        NatsTlsFiles tls)
    {
        ArgumentNullException.ThrowIfNull(replayStore);
        var enrollment = ReadJson<RegionalNodeEnrollmentEnvelope>(configuration.EnrollmentFile,
            "regional node enrollment");
        var trustBundle = ReadTrustBundle(configuration.BootstrapTrustBundleFile);
        var resolvedAuthentication = NatsAuthenticationFiles.Resolve(
            authentication.NKeyFile, authentication.CredentialsFile, "host admission NATS")
            ?? throw new InvalidDataException("Host admission requires private NATS authentication.");
        var resolvedTls = NatsTlsFiles.Resolve(tls.CaFile, tls.CertificateFile, tls.KeyFile, "host admission mTLS")!;
        using var certificate = X509CertificateLoader.LoadCertificateFromFile(resolvedTls.CertificateFile);
        var fingerprint = BootstrapWorkloadIdentity.CertificateFingerprint(
            certificate.PublicKey.ExportSubjectPublicKeyInfo()).Value;

        if (enrollment.Region != configuration.Region || enrollment.NodeId != configuration.NodeId ||
            enrollment.ClusterName != configuration.ClusterName)
            throw new InvalidOperationException("The enrollment envelope does not match the host admission identity.");

        var enrollmentSignerKey = LoadPublicKey(configuration.EnrollmentSignerPublicKeyFile, "enrollment signer");
        return new(configuration, replayStore, resolvedAuthentication.PublicKey, enrollmentSignerKey,
            trustBundle, enrollment, fingerprint, resolvedAuthentication, resolvedTls);
    }

    public async ValueTask<HostAdmissionSnapshot> ObserveAsync(CancellationToken cancellationToken)
    {
        await admissionLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Recheck delivered files even after initial admission. A process
            // cache must never mask missing or changed credentials.
            if (!CredentialBundleMatches())
                return new(false, false, "credential-bundle-not-ready");
            using var certificate = X509CertificateLoader.LoadCertificateFromFile(tls.CertificateFile);
            if (DateTimeOffset.UtcNow < certificate.NotBefore.ToUniversalTime() ||
                DateTimeOffset.UtcNow >= certificate.NotAfter.ToUniversalTime())
                return new(false, false, "credential-certificate-expired");
            if (admitted is { } afterWait) return afterWait;

            var crypto = SignedBootstrapGrantVerifier.VerifyCryptographic(
                enrollment.Grant, trustBundle, DateTimeOffset.UtcNow);
            if (!crypto.Crypto.Authorized || crypto.Payload is null)
                return new(false, false, $"bootstrap-grant-{crypto.Crypto.Decision}");

            var payload = crypto.Payload;
            if (payload.ExpiresAt - payload.IssuedAt > configuration.MaximumGrantLifetime)
                return new(false, false, "bootstrap-grant-lifetime-exceeded");
            if (!string.Equals(payload.Audience, configuration.NodeId, StringComparison.Ordinal))
                return new(false, false, "bootstrap-grant-audience-mismatch");
            if (!CryptographicOperations.FixedTimeEquals(
                    System.Text.Encoding.UTF8.GetBytes(payload.CertificateFingerprint.Value),
                    System.Text.Encoding.UTF8.GetBytes(certificateFingerprint)))
                return new(false, false, "bootstrap-grant-certificate-mismatch");
            if (payload.SystemProject != configuration.ExpectedSystemProject)
                return new(false, false, "bootstrap-grant-system-project-mismatch");
            if (!payload.AllowedOperations.Contains(configuration.RequestedOperation, StringComparer.Ordinal) ||
                payload.AllowedOperations.Any(operation => !BootstrapGrantOperation.IsIdempotentBootstrapOperation(operation)))
                return new(false, false, "bootstrap-grant-operation-denied");

            var verification = await RegionalNodeEnrollmentVerifier.VerifyAsync(
                    enrollment,
                    enrollmentSignerKey,
                    configuration.Region,
                    configuration.NodeId,
                    configuration.NatsAccountPublicKey,
                    natsUserPublicKey,
                    configuration.EnrollmentSignerKeyId,
                    configuration.EnrollmentSignerKeyVersion,
                    crypto.Crypto,
                    replayStore,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!verification.Authorized)
                return new(false, false, $"regional-enrollment-{verification.Decision}");

            var success = new HostAdmissionSnapshot(true, true, "authorized");
            admitted = success;
            return success;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException or CryptographicException or ArgumentException)
        {
            return new(false, false, $"admission-material-{exception.GetType().Name}");
        }
        finally
        {
            admissionLock.Release();
        }
    }

    public void Dispose()
    {
        enrollmentSignerKey.Dispose();
        admissionLock.Dispose();
    }

    private bool CredentialBundleMatches()
    {
        try
        {
            return CredentialBundleMatchesCore();
        }
        catch (Exception exception) when (exception is InvalidDataException or IOException or UnauthorizedAccessException or JsonException or CryptographicException)
        {
            return false;
        }
    }

    private bool CredentialBundleMatchesCore()
    {
        var bytes = ReadMaterial(configuration.BundleFile, "credential bundle", ownerOnly: true);
        if (Convert.ToHexStringLower(SHA256.HashData(bytes)) != enrollment.CredentialBundleSha256)
            return false;
        var manifest = JsonSerializer.Deserialize<HostCredentialManifest>(bytes, JsonOptions);
        if (manifest is not { SchemaVersion: 1, Files.Count: >= 4 and <= 32 })
            return false;
        var paths = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in manifest.Files)
        {
            if (entry is null || !Path.IsPathFullyQualified(entry.Path) || !paths.Add(entry.Path))
                return false;
            var material = ReadMaterial(entry.Path, "credential file", ownerOnly: true);
            try
            {
                if (Convert.ToHexStringLower(SHA256.HashData(material)) != entry.Sha256)
                    return false;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(material);
            }
        }
        return paths.Contains(authentication.CredentialsFile ?? authentication.NKeyFile!) && paths.Contains(tls.CaFile) &&
            paths.Contains(tls.CertificateFile) && paths.Contains(tls.KeyFile) &&
            NatsAuthenticationFiles.Resolve(authentication.NKeyFile, authentication.CredentialsFile, "host admission NATS")?.PublicKey == natsUserPublicKey;
    }

    private static T ReadJson<T>(string path, string description) =>
        JsonSerializer.Deserialize<T>(ReadMaterial(path, description, ownerOnly: false), JsonOptions)
            ?? throw new InvalidDataException($"The {description} file is empty.");

    private static byte[] ReadMaterial(string path, string description, bool ownerOnly)
    {
        EnsureMaterialFile(path, description, ownerOnly);
        using var stream = File.OpenRead(path);
        // Bound the read itself as well as the initial filesystem observation.
        var bytes = new byte[MaximumMaterialBytes + 1];
        var length = checked((int)stream.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false));
        if (length is < 1 or > (int)MaximumMaterialBytes)
            throw new InvalidDataException($"The {description} file exceeds its bounds.");
        return bytes[..length];
    }

    internal sealed record HostCredentialManifest(int SchemaVersion, IReadOnlyList<HostCredentialFile> Files);
    internal sealed record HostCredentialFile(string Path, string Sha256);

    private static RotatedBootstrapTrustBundle ReadTrustBundle(string path)
    {
        var document = ReadJson<BootstrapTrustBundleDocument>(path, "bootstrap trust bundle");
        if (document.SchemaVersion != 1)
            throw new InvalidDataException("The bootstrap trust bundle schema is unsupported.");
        var keys = document.Keys?.Select(key => new BootstrapTrustBundleKey(
                key.KeyId,
                key.KeyVersion,
                key.Purpose,
                Convert.FromBase64String(key.SubjectPublicKeyInfo),
                key.AcceptedUntil))
            .ToArray() ?? throw new InvalidDataException("The bootstrap trust bundle has no keys.");
        return new RotatedBootstrapTrustBundle(
            document.BundleVersion,
            keys,
            document.CurrentGrantSigningKeyId,
            document.CurrentGrantSigningKeyVersion);
    }

    private static ECDsa LoadPublicKey(string path, string description)
    {
        var bytes = ReadMaterial(path, description, ownerOnly: false);
        var key = ECDsa.Create();
        try
        {
            var text = System.Text.Encoding.UTF8.GetString(bytes);
            if (text.Contains("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal))
                key.ImportFromPem(text);
            else
            {
                key.ImportSubjectPublicKeyInfo(bytes, out var consumed);
                if (consumed != bytes.Length)
                    throw new InvalidDataException("The enrollment public key contains trailing data.");
            }
            BootstrapTrustBundleKey.RequireP256(key);
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    private static void EnsureMaterialFile(string path, string description, bool ownerOnly)
    {
        try
        {
            _ = NatsFileResolver.Resolve(
                path,
                description,
                MaximumMaterialBytes,
                ownerOnly);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException(
                $"The {description} file is missing or has unsafe permissions.", exception);
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        PropertyNameCaseInsensitive = true,
        AllowDuplicateProperties = false,
        MaxDepth = 16
    };

    private sealed record BootstrapTrustBundleDocument(
        int SchemaVersion,
        ulong BundleVersion,
        string CurrentGrantSigningKeyId,
        ulong CurrentGrantSigningKeyVersion,
        IReadOnlyList<BootstrapTrustBundleKeyDocument>? Keys);

    private sealed record BootstrapTrustBundleKeyDocument(
        string KeyId,
        ulong KeyVersion,
        BootstrapTrustKeyPurpose Purpose,
        string SubjectPublicKeyInfo,
        DateTimeOffset? AcceptedUntil);
}
