using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class ContainerdHostRuntimeAdapterTests
{
    private const string Digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Test]
    public async Task AbsentAllocationIsPulledByDigestCreatedWithSecurityAndStarted()
    {
        var client = new RecordingContainerdClient { PulledDigest = Digest };
        var plan = OciPlan();

        await new ContainerdHostRuntimeAdapter(client).ConvergeAsync(plan, CancellationToken.None);

        await Assert.That(client.Operations).IsEquivalentTo(["observe", "pull", "create", "start"]);
        await Assert.That(client.Created!.Namespace).IsEqualTo("terrascale");
        await Assert.That(client.Created.ImageReference).Contains("@sha256:");
        await Assert.That(client.Created.Security.RunAsUser).IsEqualTo(65532U);
        await Assert.That(client.Created.Security.NoNewPrivileges).IsTrue();
        await Assert.That(client.Created.Security.ReadOnlyRootFileSystem).IsTrue();
        await Assert.That(client.Created.Security.DroppedCapabilities).IsEquivalentTo(["ALL"]);
        await Assert.That(client.Created.Resources).IsEqualTo(plan.Resources);
        await Assert.That(client.Created.Resources.MemorySwapMaxBytes).IsEqualTo(0);
        await Assert.That(client.Created.PlanFingerprint).Length().IsEqualTo(64);
    }

    [Test]
    public async Task ExistingForeignAllocationIsFencedInsteadOfReplaced()
    {
        var plan = OciPlan();
        var client = new RecordingContainerdClient
        {
            Observation = new(
                plan.Oci!.ContainerId,
                ContainerdAllocationState.Running,
                plan.Oci.ImageReference,
                plan.Oci.Platform,
                "foreign",
                123,
                "running")
        };

        await Assert.That(() => new ContainerdHostRuntimeAdapter(client)
                .ConvergeAsync(plan, CancellationToken.None))
            .Throws<InvalidOperationException>();
        await Assert.That(client.Operations).IsEquivalentTo(["observe"]);
    }

    [Test]
    public async Task PulledManifestMustMatchTheRequestedImmutableDigest()
    {
        var client = new RecordingContainerdClient
        {
            PulledDigest = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        };

        await Assert.That(() => new ContainerdHostRuntimeAdapter(client)
                .ConvergeAsync(OciPlan(), CancellationToken.None))
            .Throws<InvalidOperationException>();
        await Assert.That(client.Operations).IsEquivalentTo(["observe", "pull"]);
    }

    [Test]
    public async Task CanonicalFingerprintChangesWhenSecurityIsTampered()
    {
        var original = OciPlan();
        var tampered = original with
        {
            Oci = original.Oci! with
            {
                Security = original.Oci.Security with { NoNewPrivileges = false }
            }
        };

        await Assert.That(CanonicalPlanFingerprint.Compute(tampered))
            .IsNotEqualTo(CanonicalPlanFingerprint.Compute(original));
        await Assert.That(() => new ContainerdHostRuntimeAdapter(new RecordingContainerdClient())
                .ConvergeAsync(tampered, CancellationToken.None))
            .Throws<InvalidOperationException>();
    }

    private static HostRuntimePlan OciPlan() => HostRuntimePlan.Create(
        AdmittedRole.Api,
        RuntimeDriver.OciContainer,
        new RuntimeAllocationId("gru-api-1"),
        new ArtifactDigest(Digest),
        HostArchitecture.Arm64);

    private sealed class RecordingContainerdClient : IContainerdClient
    {
        public List<string> Operations { get; } = [];
        public string PulledDigest { get; init; } = Digest;
        public ContainerdCreateRequest? Created { get; private set; }
        public ContainerdAllocationObservation Observation { get; init; } =
            new("terrascale-gru-api-1", ContainerdAllocationState.Absent, null, null, null, null, "absent");

        public Task<ContainerdAllocationObservation> ObserveAsync(
            string @namespace,
            string containerId,
            CancellationToken cancellationToken)
        {
            Operations.Add("observe");
            return Task.FromResult(Observation);
        }

        public Task<string> PullAsync(
            string @namespace,
            string imageReference,
            string platform,
            CancellationToken cancellationToken)
        {
            Operations.Add("pull");
            return Task.FromResult(PulledDigest);
        }

        public Task CreateAsync(ContainerdCreateRequest request, CancellationToken cancellationToken)
        {
            Operations.Add("create");
            Created = request;
            return Task.CompletedTask;
        }

        public Task StartAsync(string @namespace, string containerId, CancellationToken cancellationToken)
        {
            Operations.Add("start");
            return Task.CompletedTask;
        }

        public Task StopAsync(string @namespace, string containerId, CancellationToken cancellationToken)
        {
            Operations.Add("stop");
            return Task.CompletedTask;
        }

        public Task DeleteAsync(string @namespace, string containerId, CancellationToken cancellationToken)
        {
            Operations.Add("delete");
            return Task.CompletedTask;
        }
    }
}
