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
                ciRunnerNatsTlsKeyFile = "/run/credentials/ci-runner-key.pem"
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
        }
        finally
        {
            File.Delete(path);
        }
    }
}
