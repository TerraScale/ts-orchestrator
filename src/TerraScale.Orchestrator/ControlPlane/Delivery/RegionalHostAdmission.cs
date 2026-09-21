using TerraScale.Orchestrator.Bootstrap;

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
    TimeSpan MaximumGrantLifetime,
    RegionalNodeEnrollmentScope Scope)
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
            lifetime,
            new RegionalNodeEnrollmentScope(environment("TS_ORCH_HOST_ENVIRONMENT") is { Length: > 0 } hostEnvironment
                    ? hostEnvironment : "production",
                Required(environment, "TS_ORCH_HOST_ROLES").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                    .Select(TerraScale.Orchestrator.Runtime.HostRuntimeCli.ParseRole).ToArray()));
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
