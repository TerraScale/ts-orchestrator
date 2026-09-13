using System.Reflection;
using NATS.Client.JetStream;
using NATS.Client.ObjectStore;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class GlobalNatsCompositionTests
{
    [Test]
    public async Task GlobalCellDirectoryRuntimeDeclaresNoStreamOrObjectStoreCreationSurface()
    {
        // The directory runtime is a read-only projection: it must never accept a JetStream
        // context, an object-store context, or a bound stream handle (NATS.Net 2.7.2 has no
        // separate stream-manager interface — NatsJSStream itself carries update/delete/purge),
        // because each could create or mutate global state.
        var forbidden = new[] { typeof(INatsJSContext), typeof(INatsObjContext), typeof(NatsJSStream) };
        var surface = typeof(GlobalCellDirectoryRuntime)
            .GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
            .Cast<MethodBase>()
            .Concat(typeof(GlobalCellDirectoryRuntime).GetMethods(
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance |
                BindingFlags.DeclaredOnly));
        await Assert.That(surface
                .SelectMany(method => method.GetParameters())
                .Any(parameter => forbidden.Any(type => type.IsAssignableFrom(parameter.ParameterType))))
            .IsFalse();
    }

    [Test]
    public async Task AbsentOptionalGlobalConfigurationKeepsRegionalAutonomy()
    {
        var options = OrchestratorOptions.Parse(
            ["check"],
            name => name switch
            {
                "TS_ORCH_CELL" => "sfo",
                "TS_ORCH_NATS_URL" => "tls://regional.internal:4222",
                _ => null
            });

        var plan = OrchestratorRuntimeComposition.Plan(options);

        await Assert.That(plan.StartsRegionalControl).IsTrue();
        await Assert.That(plan.StartsDirectory).IsFalse();
        await Assert.That(plan.StartsDirectoryService).IsFalse();
        await Assert.That(plan.StartsGlobalAuthority).IsFalse();
        await Assert.That(plan.StartsGlobalDelivery).IsFalse();
        await Assert.That(plan.StartsDirectDelivery).IsTrue();
    }

    [Test]
    public async Task DirectoryOnlyRegionalCompositionHasNoGlobalMutationRoles()
    {
        var plan = OrchestratorRuntimeComposition.Describe(
            cell: "sfo",
            hasDirectory: true,
            hasDirectoryService: false,
            hasAuthority: false,
            hasForgejo: false,
            hasCi: false,
            hasNativeGitOps: false);

        await Assert.That(plan.StartsRegionalControl).IsTrue();
        await Assert.That(plan.StartsDirectory).IsTrue();
        await Assert.That(plan.StartsDirectoryService).IsFalse();
        await Assert.That(plan.StartsGlobalAuthority).IsFalse();
        await Assert.That(plan.StartsGlobalDelivery).IsFalse();
        await Assert.That(plan.AllowsGlobalMutation).IsFalse();
        await Assert.That(plan.StartsDirectDelivery).IsTrue();
    }

    [Test]
    public async Task GruCompositionStartsDirectoryServiceAuthorityAndDelivery()
    {
        var plan = OrchestratorRuntimeComposition.Describe(
            cell: "gru",
            hasDirectory: true,
            hasDirectoryService: true,
            hasAuthority: true,
            hasForgejo: true,
            hasCi: true,
            hasNativeGitOps: true);

        await Assert.That(plan.StartsDirectory).IsTrue();
        await Assert.That(plan.StartsDirectoryService).IsTrue();
        await Assert.That(plan.StartsGlobalAuthority).IsTrue();
        await Assert.That(plan.StartsGlobalDelivery).IsTrue();
        await Assert.That(plan.AllowsGlobalMutation).IsTrue();
        await Assert.That(plan.StartsDirectDelivery).IsTrue();
    }

    [Test]
    public async Task DirectoryServiceIsGruOnlyAndAuthorityIsNeverRegional()
    {
        await Assert.That(() => OrchestratorRuntimeComposition.Describe(
                "sfo", true, true, false, false, false, false))
            .Throws<ArgumentException>();
        await Assert.That(() => OrchestratorRuntimeComposition.Describe(
                "fra", false, false, true, false, false, false))
            .Throws<ArgumentException>();
    }
}

