using System.Text.Json;

namespace TerraScale.Orchestrator.Tests;

public sealed class OrchestratorRuntimeConfigurationTests
{
    [Test]
    public async Task TypedConfigurationFeedsTheExistingValidatedOptionBoundary()
    {
        var path = Path.Combine(Path.GetTempPath(), $"orchestrator-config-{Guid.NewGuid():N}.json");
        try
        {
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                cell = "fra",
                natsUrl = "tls://control-nats.fra.internal:4222",
                replicas = 3,
                instance = "2",
                commandSigningKeyFile = "/run/credentials/orchestrator/command-signing.pem",
                commandTrustKeyFiles = new[]
                {
                    "/etc/terrascale/command-current.pem",
                    "/etc/terrascale/command-previous.pem"
                }
            }));

            var configuration = OrchestratorRuntimeConfiguration.Load(path)!;
            var options = OrchestratorOptions.Parse(
                ["check"],
                configuration.GetEnvironmentValue);

            await Assert.That(options.Cell).IsEqualTo("fra");
            await Assert.That(options.NatsUrl).IsEqualTo("tls://control-nats.fra.internal:4222/");
            await Assert.That(options.Replicas).IsEqualTo(3);
            await Assert.That(options.Instance).IsEqualTo("2");
            await Assert.That(options.CommandIdentity!.SigningKeyFile)
                .IsEqualTo("/run/credentials/orchestrator/command-signing.pem");
            await Assert.That(options.CommandIdentity.TrustKeyFiles).IsEquivalentTo([
                "/etc/terrascale/command-current.pem",
                "/etc/terrascale/command-previous.pem",
            ]);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task TypedConfigurationFeedsRunWithRegionalCredentials(bool jwtCredentials)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var directory = Path.Combine(Path.GetTempPath(), $"orchestrator-config-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            using var tlsKey = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            var tls = await WriteCertificateAsync(directory, "regional", tlsKey);
            var nkey = Path.Combine(directory, "regional.nk");
            var seed = NATS.Client.Core.NKeys.CreateUserSeed();
            await File.WriteAllTextAsync(nkey, jwtCredentials ? NatsAuthenticationFilesTests.Credentials(seed) : seed);
            File.SetUnixFileMode(nkey, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            var path = Path.Combine(directory, "config.json");
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                cell = "fra",
                natsUrl = "tls://control-nats.fra.internal:4222",
                replicas = 3,
                instance = "2",
                natsNKeyFile = jwtCredentials ? null : nkey,
                natsCredentialsFile = jwtCredentials ? nkey : null,
                natsTlsCaFile = tls.Certificate,
                natsTlsCertificateFile = tls.Certificate,
                natsTlsKeyFile = tls.PrivateKey
            }));

            var configuration = OrchestratorRuntimeConfiguration.Load(path)!;
            var options = OrchestratorOptions.Parse(["run"], configuration.GetEnvironmentValue);

            await Assert.That(options.NatsNKeyFile).IsEqualTo(jwtCredentials ? null : nkey);
            await Assert.That(options.NatsCredentialsFile).IsEqualTo(jwtCredentials ? nkey : null);
            await Assert.That(options.NatsTls).IsNotNull();
            await Assert.That(options.NatsTls!.CaFile).IsEqualTo(tls.Certificate);
            await Assert.That(options.NatsTls.CertificateFile).IsEqualTo(tls.Certificate);
            await Assert.That(options.NatsTls.KeyFile).IsEqualTo(tls.PrivateKey);
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Test]
    public async Task TypedConfigurationCarriesAllRoleCredentialReferences()
    {
        var path = Path.Combine(Path.GetTempPath(), $"orchestrator-config-{Guid.NewGuid():N}.json");
        try
        {
            var values = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["TS_ORCH_NATS_NKEY_FILE"] = "/run/credentials/regional.nk",
                ["TS_ORCH_NATS_TLS_CA_FILE"] = "/run/credentials/regional-ca.pem",
                ["TS_ORCH_NATS_TLS_CERT_FILE"] = "/run/credentials/regional.pem",
                ["TS_ORCH_NATS_TLS_KEY_FILE"] = "/run/credentials/regional-key.pem",
                ["TS_ORCH_INFRA_NATS_NKEY_FILE"] = "/run/credentials/infrastructure.nk",
                ["TS_ORCH_INFRA_NATS_TLS_CA_FILE"] = "/run/credentials/infrastructure-ca.pem",
                ["TS_ORCH_INFRA_NATS_TLS_CERT_FILE"] = "/run/credentials/infrastructure.pem",
                ["TS_ORCH_INFRA_NATS_TLS_KEY_FILE"] = "/run/credentials/infrastructure-key.pem",
                ["TS_ORCH_JOURNAL_NATS_NKEY_FILE"] = "/run/credentials/journal.nk",
                ["TS_ORCH_JOURNAL_NATS_TLS_CA_FILE"] = "/run/credentials/journal-ca.pem",
                ["TS_ORCH_JOURNAL_NATS_TLS_CERT_FILE"] = "/run/credentials/journal.pem",
                ["TS_ORCH_JOURNAL_NATS_TLS_KEY_FILE"] = "/run/credentials/journal-key.pem",
                ["TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE"] = "/run/credentials/journal-authority.pem",
                ["TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE"] = "/run/credentials/journal-reply.pem",
                ["TS_ORCH_JOURNAL_CONTROLLER_NKEYS"] = "UABCDEFGHIJKLMNOPQRSTUV",
                ["TS_ORCH_FORGEJO_LISTEN_PREFIX"] = "http://127.0.0.1:8080/hooks/forgejo/",
                ["TS_ORCH_FORGEJO_REPOSITORY"] = "TerraScale/TerraScale.Orchestrator",
                ["TS_ORCH_FORGEJO_SECRET_FILE"] = "/run/credentials/forgejo-webhook.secret",
                ["TS_ORCH_FORGEJO_API_URL"] = "https://git.terrascale.tech/api/v1",
                ["TS_ORCH_FORGEJO_API_TOKEN_FILE"] = "/run/credentials/forgejo-api.token"
            };

            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                cell = "fra",
                natsUrl = "tls://control-nats.fra.internal:4222",
                replicas = 3,
                instance = "2",
                natsNKeyFile = values["TS_ORCH_NATS_NKEY_FILE"],
                natsTlsCaFile = values["TS_ORCH_NATS_TLS_CA_FILE"],
                natsTlsCertificateFile = values["TS_ORCH_NATS_TLS_CERT_FILE"],
                natsTlsKeyFile = values["TS_ORCH_NATS_TLS_KEY_FILE"],
                infrastructureNatsNKeyFile = values["TS_ORCH_INFRA_NATS_NKEY_FILE"],
                infrastructureNatsTlsCaFile = values["TS_ORCH_INFRA_NATS_TLS_CA_FILE"],
                infrastructureNatsTlsCertificateFile = values["TS_ORCH_INFRA_NATS_TLS_CERT_FILE"],
                infrastructureNatsTlsKeyFile = values["TS_ORCH_INFRA_NATS_TLS_KEY_FILE"],
                journalNatsNKeyFile = values["TS_ORCH_JOURNAL_NATS_NKEY_FILE"],
                journalNatsTlsCaFile = values["TS_ORCH_JOURNAL_NATS_TLS_CA_FILE"],
                journalNatsTlsCertificateFile = values["TS_ORCH_JOURNAL_NATS_TLS_CERT_FILE"],
                journalNatsTlsKeyFile = values["TS_ORCH_JOURNAL_NATS_TLS_KEY_FILE"],
                journalAuthorityPublicKeyFile = values["TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE"],
                journalReplySigningKeyFile = values["TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE"],
                journalControllerNKeys = values["TS_ORCH_JOURNAL_CONTROLLER_NKEYS"],
                forgejoListenPrefix = values["TS_ORCH_FORGEJO_LISTEN_PREFIX"],
                forgejoRepository = values["TS_ORCH_FORGEJO_REPOSITORY"],
                forgejoSecretFile = values["TS_ORCH_FORGEJO_SECRET_FILE"],
                forgejoApiUrl = values["TS_ORCH_FORGEJO_API_URL"],
                forgejoApiTokenFile = values["TS_ORCH_FORGEJO_API_TOKEN_FILE"]
            }));

            var configuration = OrchestratorRuntimeConfiguration.Load(path)!;
            foreach (var (key, expected) in values)
            {
                await Assert.That(configuration.GetEnvironmentValue(key)).IsEqualTo(expected);
            }
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Test]
    public async Task UnknownConfigurationFieldsFailClosed()
    {
        var path = Path.Combine(Path.GetTempPath(), $"orchestrator-config-{Guid.NewGuid():N}.json");
        try
        {
            await File.WriteAllTextAsync(path,
                "{\"schemaVersion\":1,\"cell\":\"gru\",\"natsUrl\":\"nats://127.0.0.1:4222\",\"replicas\":3,\"instance\":\"1\",\"arbitraryCommand\":\"/bin/sh\"}");

            await Assert.That(() => OrchestratorRuntimeConfiguration.Load(path)).Throws<JsonException>();
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static async Task<(string Certificate, string PrivateKey)> WriteCertificateAsync(
        string directory,
        string name,
        System.Security.Cryptography.ECDsa key)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException();
        }

        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            $"CN={name}", key, System.Security.Cryptography.HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(
            new System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(
                true, false, 0, true));
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var certificatePath = Path.Combine(directory, $"{name}.pem");
        var keyPath = Path.Combine(directory, $"{name}-key.pem");
        await File.WriteAllTextAsync(certificatePath, certificate.ExportCertificatePem());
        await File.WriteAllTextAsync(keyPath, key.ExportPkcs8PrivateKeyPem());
        File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return (certificatePath, keyPath);
    }

    [Test]
    public async Task TypedConfigurationCarriesCiRunnerAccountSignerReferences()
    {
        var path = Path.Combine(Path.GetTempPath(), $"orchestrator-config-{Guid.NewGuid():N}.json");
        try
        {
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                cell = "gru",
                natsUrl = "nats://127.0.0.1:4222",
                replicas = 3,
                instance = "1",
                ciRunnerNatsAccountSigningKeyFile = "/run/credentials/orchestrator/runner-account.nk",
                ciRunnerNatsAccountPublicKey = "AEXAMPLE",
                infisicalUrl = "https://eu.infisical.com",
                infisicalProjectId = "project-1",
                infisicalEnvironment = "prod",
                infisicalSecretPath = "/orchestrator/fra",
                infisicalClientIdFile = "/run/credentials/infisical-client-id",
                infisicalClientSecretFile = "/run/credentials/infisical-client-secret",
                infisicalOrganizationSlug = "terrascale",
                ciRunnerNatsUrl = "tls://global-control.internal:4222",
                ciRunnerNatsCredentialsFile = "/run/credentials/ci-runner.creds",
                ciRunnerNatsTlsCaFile = "/run/credentials/global-ca.pem",
                ciRunnerNatsTlsCertificateFile = "/run/credentials/ci-runner.pem",
                ciRunnerNatsTlsKeyFile = "/run/credentials/ci-runner-key.pem",
                ociCiRunnerPoolConfigurationFile = "/etc/terrascale/oci-ci-pool.json",
                ociWorkloadFleetConfigurationFile = "/etc/terrascale/oci-workload-fleet.json",
                forgejoCiSourceGraphFile = "/etc/terrascale/forgejo-ci-source-graph.json"
            }));

            var configuration = OrchestratorRuntimeConfiguration.Load(path)!;

            await Assert.That(configuration.GetEnvironmentValue(
                    "TS_ORCH_CI_RUNNER_NATS_ACCOUNT_SIGNING_KEY_FILE"))
                .IsEqualTo("/run/credentials/orchestrator/runner-account.nk");
            await Assert.That(configuration.GetEnvironmentValue(
                    "TS_ORCH_CI_RUNNER_NATS_ACCOUNT_PUBLIC_KEY"))
                .IsEqualTo("AEXAMPLE");
            await Assert.That(configuration.GetEnvironmentValue("TS_ORCH_INFISICAL_URL"))
                .IsEqualTo("https://eu.infisical.com");
            await Assert.That(configuration.GetEnvironmentValue("TS_ORCH_INFISICAL_PROJECT_ID"))
                .IsEqualTo("project-1");
            await Assert.That(configuration.GetEnvironmentValue("TS_ORCH_INFISICAL_ENVIRONMENT"))
                .IsEqualTo("prod");
            await Assert.That(configuration.GetEnvironmentValue("TS_ORCH_INFISICAL_SECRET_PATH"))
                .IsEqualTo("/orchestrator/fra");
            await Assert.That(configuration.GetEnvironmentValue("TS_ORCH_INFISICAL_CLIENT_ID_FILE"))
                .IsEqualTo("/run/credentials/infisical-client-id");
            await Assert.That(configuration.GetEnvironmentValue("TS_ORCH_INFISICAL_CLIENT_SECRET_FILE"))
                .IsEqualTo("/run/credentials/infisical-client-secret");
            await Assert.That(configuration.GetEnvironmentValue("TS_ORCH_INFISICAL_ORGANIZATION_SLUG"))
                .IsEqualTo("terrascale");
            await Assert.That(configuration.GetEnvironmentValue("TS_ORCH_CI_RUNNER_NATS_URL"))
                .IsEqualTo("tls://global-control.internal:4222");
            await Assert.That(configuration.GetEnvironmentValue(
                    "TS_ORCH_CI_RUNNER_NATS_CREDENTIALS_FILE"))
                .IsEqualTo("/run/credentials/ci-runner.creds");
            await Assert.That(configuration.GetEnvironmentValue("TS_ORCH_CI_RUNNER_NATS_TLS_CA_FILE"))
                .IsEqualTo("/run/credentials/global-ca.pem");
            await Assert.That(configuration.GetEnvironmentValue("TS_ORCH_CI_OCI_CONFIG"))
                .IsEqualTo("/etc/terrascale/oci-ci-pool.json");
            await Assert.That(configuration.GetEnvironmentValue("TS_ORCH_WORKLOAD_FLEET_FILE"))
                .IsEqualTo("/etc/terrascale/oci-workload-fleet.json");
            await Assert.That(configuration.GetEnvironmentValue("TS_ORCH_FORGEJO_CI_SOURCE_GRAPH_FILE"))
                .IsEqualTo("/etc/terrascale/forgejo-ci-source-graph.json");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Test]
    public async Task TypedConfigurationCarriesSeparateDirectoryAndServiceIdentities()
    {
        var path = Path.Combine(Path.GetTempPath(), $"orchestrator-config-{Guid.NewGuid():N}.json");
        try
        {
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                cell = "gru",
                natsUrl = "tls://regional-control.internal:4222",
                replicas = 3,
                instance = "1",
                globalDirectoryNatsUrl = "tls://control-nats-gru.internal:4222",
                globalDirectoryNatsNKeyFile = "/run/credentials/global-directory.nk",
                globalDirectoryNatsTlsCaFile = "/run/credentials/global-ca.pem",
                globalDirectoryNatsTlsCertificateFile = "/run/credentials/global-directory.pem",
                globalDirectoryNatsTlsKeyFile = "/run/credentials/global-directory-key.pem",
                globalDirectoryServiceNatsUrl = "tls://control-nats-gru.internal:4222",
                globalDirectoryServiceNatsNKeyFile = "/run/credentials/global-directory-service.nk",
                globalDirectoryServiceNatsTlsCaFile = "/run/credentials/global-ca.pem",
                globalDirectoryServiceNatsTlsCertificateFile = "/run/credentials/global-directory-service.pem",
                globalDirectoryServiceNatsTlsKeyFile = "/run/credentials/global-directory-service-key.pem",
                globalDirectoryEndpoints = "tls://control-gru-a.internal:4222,tls://control-gru-b.internal:4222"
            }));

            var configuration = OrchestratorRuntimeConfiguration.Load(path)!;

            await Assert.That(configuration.GetEnvironmentValue("TS_ORCH_GLOBAL_DIRECTORY_NATS_URL"))
                .IsEqualTo("tls://control-nats-gru.internal:4222");
            await Assert.That(configuration.GetEnvironmentValue("TS_ORCH_GLOBAL_DIRECTORY_NATS_NKEY_FILE"))
                .IsEqualTo("/run/credentials/global-directory.nk");
            await Assert.That(configuration.GetEnvironmentValue("TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_URL"))
                .IsEqualTo("tls://control-nats-gru.internal:4222");
            await Assert.That(configuration.GetEnvironmentValue("TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_NKEY_FILE"))
                .IsEqualTo("/run/credentials/global-directory-service.nk");
            await Assert.That(configuration.GetEnvironmentValue("TS_ORCH_GLOBAL_DIRECTORY_ENDPOINTS"))
                .IsEqualTo("tls://control-gru-a.internal:4222,tls://control-gru-b.internal:4222");
        }
        finally
        {
            File.Delete(path);
        }
    }
}
