using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator;

internal sealed record OrchestratorRuntimeConfiguration(
    int SchemaVersion,
    string Cell,
    string NatsUrl,
    int Replicas,
    string Instance,
    string? NatsNKeyFile = null,
    string? NatsTlsCaFile = null,
    string? NatsTlsCertificateFile = null,
    string? NatsTlsKeyFile = null,
    string? GlobalNatsUrl = null,
    string? GlobalNatsNKeyFile = null,
    string? GlobalNatsCredentialsFile = null,
    string? GlobalNatsTlsCaFile = null,
    string? GlobalNatsTlsCertificateFile = null,
    string? GlobalNatsTlsKeyFile = null,
    string? GlobalDirectoryNatsUrl = null,
    string? GlobalDirectoryNatsNKeyFile = null,
    string? GlobalDirectoryNatsCredentialsFile = null,
    string? GlobalDirectoryNatsTlsCaFile = null,
    string? GlobalDirectoryNatsTlsCertificateFile = null,
    string? GlobalDirectoryNatsTlsKeyFile = null,
    string? GlobalDirectoryServiceNatsUrl = null,
    string? GlobalDirectoryServiceNatsNKeyFile = null,
    string? GlobalDirectoryServiceNatsCredentialsFile = null,
    string? GlobalDirectoryServiceNatsTlsCaFile = null,
    string? GlobalDirectoryServiceNatsTlsCertificateFile = null,
    string? GlobalDirectoryServiceNatsTlsKeyFile = null,
    string? GlobalDirectoryEndpoints = null,
    string? InfrastructureNatsNKeyFile = null,
    string? InfrastructureNatsTlsCaFile = null,
    string? InfrastructureNatsTlsCertificateFile = null,
    string? InfrastructureNatsTlsKeyFile = null,
    string? JournalNatsNKeyFile = null,
    string? JournalNatsTlsCaFile = null,
    string? JournalNatsTlsCertificateFile = null,
    string? JournalNatsTlsKeyFile = null,
    string? JournalAuthorityPublicKeyFile = null,
    string? JournalReplySigningKeyFile = null,
    string? JournalControllerNKeys = null,
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
    int? CiRunnerIdleSeconds = null,
    string? CiRunnerNatsUrl = null,
    string? CiRunnerNatsCredentialsFile = null,
    string? CiRunnerNatsTlsCaFile = null,
    string? CiRunnerNatsTlsCertificateFile = null,
    string? CiRunnerNatsTlsKeyFile = null,
    string? OciCiRunnerPoolConfigurationFile = null,
    string? ForgejoListenPrefix = null,
    string? ForgejoRepository = null,
    string? ForgejoSecretFile = null,
    string? ForgejoApiUrl = null,
    string? ForgejoApiTokenFile = null,
    string? ForgejoCiSourceGraphFile = null)
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
        "TS_ORCH_NATS_NKEY_FILE" => NatsNKeyFile,
        "TS_ORCH_NATS_TLS_CA_FILE" => NatsTlsCaFile,
        "TS_ORCH_NATS_TLS_CERT_FILE" => NatsTlsCertificateFile,
        "TS_ORCH_NATS_TLS_KEY_FILE" => NatsTlsKeyFile,
        "TS_ORCH_GLOBAL_NATS_URL" => GlobalNatsUrl,
        "TS_ORCH_GLOBAL_NATS_NKEY_FILE" => GlobalNatsNKeyFile,
        "TS_ORCH_GLOBAL_NATS_CREDENTIALS_FILE" => GlobalNatsCredentialsFile,
        "TS_ORCH_GLOBAL_NATS_TLS_CA_FILE" => GlobalNatsTlsCaFile,
        "TS_ORCH_GLOBAL_NATS_TLS_CERT_FILE" => GlobalNatsTlsCertificateFile,
        "TS_ORCH_GLOBAL_NATS_TLS_KEY_FILE" => GlobalNatsTlsKeyFile,
        "TS_ORCH_GLOBAL_DIRECTORY_NATS_URL" => GlobalDirectoryNatsUrl,
        "TS_ORCH_GLOBAL_DIRECTORY_NATS_NKEY_FILE" => GlobalDirectoryNatsNKeyFile,
        "TS_ORCH_GLOBAL_DIRECTORY_NATS_CREDENTIALS_FILE" => GlobalDirectoryNatsCredentialsFile,
        "TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_CA_FILE" => GlobalDirectoryNatsTlsCaFile,
        "TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_CERT_FILE" => GlobalDirectoryNatsTlsCertificateFile,
        "TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_KEY_FILE" => GlobalDirectoryNatsTlsKeyFile,
        "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_URL" => GlobalDirectoryServiceNatsUrl,
        "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_NKEY_FILE" => GlobalDirectoryServiceNatsNKeyFile,
        "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_CREDENTIALS_FILE" => GlobalDirectoryServiceNatsCredentialsFile,
        "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_CA_FILE" => GlobalDirectoryServiceNatsTlsCaFile,
        "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_CERT_FILE" => GlobalDirectoryServiceNatsTlsCertificateFile,
        "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_KEY_FILE" => GlobalDirectoryServiceNatsTlsKeyFile,
        "TS_ORCH_GLOBAL_DIRECTORY_ENDPOINTS" => GlobalDirectoryEndpoints,
        "TS_ORCH_INFRA_NATS_NKEY_FILE" => InfrastructureNatsNKeyFile,
        "TS_ORCH_INFRA_NATS_TLS_CA_FILE" => InfrastructureNatsTlsCaFile,
        "TS_ORCH_INFRA_NATS_TLS_CERT_FILE" => InfrastructureNatsTlsCertificateFile,
        "TS_ORCH_INFRA_NATS_TLS_KEY_FILE" => InfrastructureNatsTlsKeyFile,
        "TS_ORCH_JOURNAL_NATS_NKEY_FILE" => JournalNatsNKeyFile,
        "TS_ORCH_JOURNAL_NATS_TLS_CA_FILE" => JournalNatsTlsCaFile,
        "TS_ORCH_JOURNAL_NATS_TLS_CERT_FILE" => JournalNatsTlsCertificateFile,
        "TS_ORCH_JOURNAL_NATS_TLS_KEY_FILE" => JournalNatsTlsKeyFile,
        "TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE" => JournalAuthorityPublicKeyFile,
        "TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE" => JournalReplySigningKeyFile,
        "TS_ORCH_JOURNAL_CONTROLLER_NKEYS" => JournalControllerNKeys,
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
        "TS_ORCH_CI_RUNNER_NATS_URL" => CiRunnerNatsUrl,
        "TS_ORCH_CI_RUNNER_NATS_CREDENTIALS_FILE" => CiRunnerNatsCredentialsFile,
        "TS_ORCH_CI_RUNNER_NATS_TLS_CA_FILE" => CiRunnerNatsTlsCaFile,
        "TS_ORCH_CI_RUNNER_NATS_TLS_CERT_FILE" => CiRunnerNatsTlsCertificateFile,
        "TS_ORCH_CI_RUNNER_NATS_TLS_KEY_FILE" => CiRunnerNatsTlsKeyFile,
        "TS_ORCH_CI_OCI_CONFIG" => OciCiRunnerPoolConfigurationFile,
        "TS_ORCH_FORGEJO_LISTEN_PREFIX" => ForgejoListenPrefix,
        "TS_ORCH_FORGEJO_REPOSITORY" => ForgejoRepository,
        "TS_ORCH_FORGEJO_SECRET_FILE" => ForgejoSecretFile,
        "TS_ORCH_FORGEJO_API_URL" => ForgejoApiUrl,
        "TS_ORCH_FORGEJO_API_TOKEN_FILE" => ForgejoApiTokenFile,
        "TS_ORCH_FORGEJO_CI_SOURCE_GRAPH_FILE" => ForgejoCiSourceGraphFile,
        _ => null
    };

    private static string? Invariant(long? value) => value?.ToString(
        System.Globalization.CultureInfo.InvariantCulture);
}
