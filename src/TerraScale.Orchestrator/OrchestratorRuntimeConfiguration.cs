using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator;

internal sealed record OrchestratorRuntimeConfiguration(
    int SchemaVersion,
    string Cell,
    string NatsUrl,
    int Replicas,
    string Instance,
    string? GlobalNatsUrl = null,
    string? GlobalNatsNKeyFile = null,
    string? GlobalNatsTlsCaFile = null,
    string? GlobalNatsTlsCertificateFile = null,
    string? GlobalNatsTlsKeyFile = null,
    string? CommandSigningKeyFile = null,
    string[]? CommandTrustKeyFiles = null,
    string? CiRunnerNatsAccountSigningKeyFile = null,
    string? CiRunnerNatsAccountPublicKey = null,
    string? InfisicalUrl = null,
    string? InfisicalProjectId = null,
    string? InfisicalEnvironment = null,
    string? InfisicalSecretPath = null,
    string? InfisicalClientIdFile = null,
    string? InfisicalClientSecretFile = null,
    string? InfisicalOrganizationSlug = null,
    string? CiRunnerId = null,
    string? CiRunnerZone = null,
    long? CiRunnerSequence = null,
    string? CiRunnerCapabilities = null,
    string? CiRunnerWorkspaceRoot = null,
    string? CiRunnerOutputRoot = null,
    int? CiRunnerCpuMilliCores = null,
    long? CiRunnerMemoryBytes = null,
    long? CiRunnerEphemeralDiskBytes = null,
    int? CiRunnerPids = null,
    long? CiRunnerMaximumLogBytes = null,
    int? CiRunnerIdleSeconds = null)
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public static OrchestratorRuntimeConfiguration? Load(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }
        var fullPath = Path.GetFullPath(path);
        using var stream = File.OpenRead(fullPath);
        var configuration = JsonSerializer.Deserialize<OrchestratorRuntimeConfiguration>(stream, SerializerOptions)
            ?? throw new InvalidOperationException("Orchestrator runtime configuration is empty.");
        if (configuration.SchemaVersion != 1)
        {
            throw new InvalidOperationException(
                $"Unsupported Orchestrator runtime configuration schema {configuration.SchemaVersion}.");
        }
        return configuration;
    }

    public string? GetEnvironmentValue(string key) => key switch
    {
        "TS_ORCH_CELL" => Cell,
        "TS_ORCH_NATS_URL" => NatsUrl,
        "TS_ORCH_REPLICAS" => Replicas.ToString(System.Globalization.CultureInfo.InvariantCulture),
        "TS_ORCH_INSTANCE" => Instance,
        "TS_ORCH_GLOBAL_NATS_URL" => GlobalNatsUrl,
        "TS_ORCH_GLOBAL_NATS_NKEY_FILE" => GlobalNatsNKeyFile,
        "TS_ORCH_GLOBAL_NATS_TLS_CA_FILE" => GlobalNatsTlsCaFile,
        "TS_ORCH_GLOBAL_NATS_TLS_CERT_FILE" => GlobalNatsTlsCertificateFile,
        "TS_ORCH_GLOBAL_NATS_TLS_KEY_FILE" => GlobalNatsTlsKeyFile,
        "TS_ORCH_COMMAND_SIGNING_KEY_FILE" => CommandSigningKeyFile,
        "TS_ORCH_COMMAND_TRUST_KEY_FILES" => CommandTrustKeyFiles is { Length: > 0 }
            ? string.Join(Path.PathSeparator, CommandTrustKeyFiles)
            : null,
        "TS_ORCH_CI_RUNNER_NATS_ACCOUNT_SIGNING_KEY_FILE" => CiRunnerNatsAccountSigningKeyFile,
        "TS_ORCH_CI_RUNNER_NATS_ACCOUNT_PUBLIC_KEY" => CiRunnerNatsAccountPublicKey,
        "TS_ORCH_INFISICAL_URL" => InfisicalUrl,
        "TS_ORCH_INFISICAL_PROJECT_ID" => InfisicalProjectId,
        "TS_ORCH_INFISICAL_ENVIRONMENT" => InfisicalEnvironment,
        "TS_ORCH_INFISICAL_SECRET_PATH" => InfisicalSecretPath,
        "TS_ORCH_INFISICAL_CLIENT_ID_FILE" => InfisicalClientIdFile,
        "TS_ORCH_INFISICAL_CLIENT_SECRET_FILE" => InfisicalClientSecretFile,
        "TS_ORCH_INFISICAL_ORGANIZATION_SLUG" => InfisicalOrganizationSlug,
        "TS_ORCH_CI_RUNNER_ID" => CiRunnerId,
        "TS_ORCH_CI_RUNNER_ZONE" => CiRunnerZone,
        "TS_ORCH_CI_RUNNER_SEQUENCE" => Invariant(CiRunnerSequence),
        "TS_ORCH_CI_RUNNER_CAPABILITIES" => CiRunnerCapabilities,
        "TS_ORCH_CI_RUNNER_WORKSPACE_ROOT" => CiRunnerWorkspaceRoot,
        "TS_ORCH_CI_RUNNER_OUTPUT_ROOT" => CiRunnerOutputRoot,
        "TS_ORCH_CI_RUNNER_CPU_MILLICORES" => Invariant(CiRunnerCpuMilliCores),
        "TS_ORCH_CI_RUNNER_MEMORY_BYTES" => Invariant(CiRunnerMemoryBytes),
        "TS_ORCH_CI_RUNNER_EPHEMERAL_DISK_BYTES" => Invariant(CiRunnerEphemeralDiskBytes),
        "TS_ORCH_CI_RUNNER_PIDS" => Invariant(CiRunnerPids),
        "TS_ORCH_CI_RUNNER_MAXIMUM_LOG_BYTES" => Invariant(CiRunnerMaximumLogBytes),
        "TS_ORCH_CI_RUNNER_IDLE_SECONDS" => Invariant(CiRunnerIdleSeconds),
        _ => null
    };

    private static string? Invariant(long? value) => value?.ToString(
        System.Globalization.CultureInfo.InvariantCulture);
}
