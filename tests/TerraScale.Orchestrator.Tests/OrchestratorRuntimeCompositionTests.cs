using TerraScale.Orchestrator;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Fail-closed startup composition: a Forgejo-ingesting global runtime without a CI executor can
/// only journal-and-drop work, so composition must refuse it before anything starts.
/// </summary>
public sealed class OrchestratorRuntimeCompositionTests
{
    [Test]
    public async Task ForgejoIngestionRequiresACiExecutor()
    {
        await Assert.That(() => OrchestratorRuntimeComposition.Describe(
                "gru",
                hasDirectory: false,
                hasDirectoryService: false,
                hasAuthority: true,
                hasForgejo: true,
                hasCi: false,
                hasNativeGitOps: false))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task ForgejoIngestionRequiresTheRunnerPoolNotJustAnIdentity()
    {
        // A runner-NATS identity alone can issue credentials but cannot execute pipelines: with
        // Forgejo configured and no TS_ORCH_CI_OCI_CONFIG, option parsing fails closed.
        var identityPath = Path.Combine(Path.GetTempPath(), $"ts-comp-identity-{Guid.NewGuid():N}.nk");
        File.WriteAllText(identityPath, "SUACSLQNGDDTRE5TK7WBJKQHVLKXUKM2VGBRWL4CGPZLYAVLYKJDV7SD");
        try
        {
            var values = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["TS_ORCH_CELL"] = "gru",
                ["TS_ORCH_NATS_URL"] = "tls://regional-control.internal:4222",
                ["TS_ORCH_GLOBAL_NATS_URL"] = "tls://global-control.internal:4222",
                ["TS_ORCH_CI_RUNNER_NATS_ACCOUNT_SIGNING_KEY_FILE"] = identityPath,
            };

            await Assert.That(() => OrchestratorOptions.Parse(["check"], name => values.GetValueOrDefault(name)))
                .Throws<ArgumentException>();
        }
        finally
        {
            File.Delete(identityPath);
        }
    }

    [Test]
    public async Task CheckModeNeverConsumesCiEventsNorServesMutations()
    {
        var run = PlanFor(OrchestratorCommand.Run);
        var check = PlanFor(OrchestratorCommand.Check);

        await Assert.That(run.StartsCiConsumption).IsTrue();
        await Assert.That(run.RegistersDirectDeliveryEndpoint).IsTrue();
        await Assert.That(check.StartsCiConsumption).IsFalse();
        await Assert.That(check.RegistersDirectDeliveryEndpoint).IsFalse();
    }

    private static OrchestratorStartupPlan PlanFor(OrchestratorCommand command) =>
        OrchestratorRuntimeComposition.Plan(new OrchestratorOptions(
            command,
            "gru",
            "tls://regional-control.internal:4222",
            1));

    [Test]
    public async Task MissingGlobalDirectDeliveryAdaptersFailClosedWhileUnavailabilityDegrades()
    {
        // A started global runtime without durable direct-delivery adapters is a fatal
        // composition bug: the guard must throw, mirroring the regional twin invariant.
        await Assert.That(() => OrchestratorRuntimeComposition.EnsureGlobalDirectDeliveryComposed(
                startsDirectDelivery: true,
                globalRuntimeStarted: true,
                composedDirectDelivery: false))
            .Throws<InvalidOperationException>();

        // A runtime that never started (global control unavailable) legitimately degrades
        // to regional control and must never be reported as a mis-composition.
        await Assert.That(() => OrchestratorRuntimeComposition.EnsureGlobalDirectDeliveryComposed(
                startsDirectDelivery: true,
                globalRuntimeStarted: false,
                composedDirectDelivery: false))
            .ThrowsNothing();

        // A correctly composed runtime, and compositions that do not serve direct
        // delivery (for example the Lab command), stay valid.
        await Assert.That(() => OrchestratorRuntimeComposition.EnsureGlobalDirectDeliveryComposed(
                startsDirectDelivery: true,
                globalRuntimeStarted: true,
                composedDirectDelivery: true))
            .ThrowsNothing();
        await Assert.That(() => OrchestratorRuntimeComposition.EnsureGlobalDirectDeliveryComposed(
                startsDirectDelivery: false,
                globalRuntimeStarted: true,
                composedDirectDelivery: false))
            .ThrowsNothing();
    }

    [Test]
    public async Task ForgejoWithACiExecutorStillComposes()
    {
        var plan = OrchestratorRuntimeComposition.Describe(
            "gru",
            hasDirectory: false,
            hasDirectoryService: false,
            hasAuthority: true,
            hasForgejo: true,
            hasCi: true,
            hasNativeGitOps: false);

        await Assert.That(plan.StartsGlobalDelivery).IsTrue();
        await Assert.That(plan.StartsDirectDelivery).IsTrue();
    }
}
