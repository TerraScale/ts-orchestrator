using System.Security.Cryptography;
using System.Text;
using Oci.CoreService.Models;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class OciCiRunnerCapacityTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 18, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task MissingDemandLaunchesOneStandalonePreemptibleA1Runner()
    {
        var demand = Demand("runner-build-1", 41);
        var action = OciCiRunnerCapacityEngine.Decide(Request([demand], [])).Single();
        var launch = OciCiRunnerRequestCompiler.Launch((LaunchOciCiRunnerAction)action);
        var details = launch.LaunchInstanceDetails;
        var preemption = (TerminatePreemptionAction)details.PreemptibleInstanceConfig.PreemptionAction;
        var source = (InstanceSourceViaImageDetails)details.SourceDetails;

        await Assert.That(details.Shape).IsEqualTo("VM.Standard.A1.Flex");
        await Assert.That(details.ShapeConfig.Ocpus).IsEqualTo(4f);
        await Assert.That(details.ShapeConfig.MemoryInGBs).IsEqualTo(24f);
        await Assert.That(preemption.PreserveBootVolume).IsFalse();
        await Assert.That(details.InstanceConfigurationId).IsNull();
        await Assert.That(details.CapacityReservationId).IsNull();
        await Assert.That(details.CreateVnicDetails.AssignPublicIp).IsFalse();
        await Assert.That(details.CreateVnicDetails.NsgIds).Count().IsEqualTo(1);
        await Assert.That(source.ImageId).IsEqualTo("ocid1.image.oc1.sa-saopaulo-1.runner");
        await Assert.That(details.Metadata["user_data"]).IsEqualTo(demand.BootstrapCloudInitBase64);
        await Assert.That(details.FreeformTags["terrascale-owner"]).IsEqualTo("orchestrator");
        await Assert.That(launch.OpcRetryToken).IsEqualTo(demand.IdempotencyToken);
    }

    [Test]
    public async Task OnlyExactOwnedInactiveExpiredNodeIsDeletedWithItsBootVolume()
    {
        var demand = Demand("runner-idle", 42);
        var idle = Node(demand, "idle", active: false, Now.AddSeconds(-61));
        var active = Node(Demand("runner-active", 43), "active", active: true, Now.AddMinutes(-5));
        var unownedDemand = Demand("runner-unowned", 44);
        var unownedTags = new Dictionary<string, string>(
            OciCiRunnerCapacityEngine.Tags(unownedDemand, 7),
            StringComparer.Ordinal)
        {
            ["terrascale-owner"] = "somebody-else",
        };
        var unowned = Node(unownedDemand, "unowned", active: false, Now.AddMinutes(-5), unownedTags);

        var action = OciCiRunnerCapacityEngine.Decide(Request([], [idle, active, unowned])).Single();
        var terminate = OciCiRunnerRequestCompiler.Terminate((TerminateOciCiRunnerAction)action);

        await Assert.That(terminate.InstanceId).IsEqualTo(idle.InstanceId);
        await Assert.That(terminate.IfMatch).IsEqualTo(idle.ETag);
        await Assert.That(terminate.PreserveBootVolume).IsFalse();
        await Assert.That(terminate.PreserveDataVolumesCreatedAtLaunch).IsFalse();
    }

    [Test]
    public async Task CapacityAndOwnershipAmbiguityFailClosed()
    {
        var obsolete = Demand("runner-obsolete", 45);
        var wanted = Demand("runner-wanted", 46);
        var full = Request(
            [wanted],
            [Node(obsolete, "obsolete", active: false, Now.AddMinutes(-5))],
            maximumNodes: 1);
        var actions = OciCiRunnerCapacityEngine.Decide(full);
        var collision = Node(
            wanted,
            "collision",
            active: false,
            Now,
            new Dictionary<string, string>(StringComparer.Ordinal));
        var durable = Node(wanted, "durable", active: false, Now) with { Preemptible = false };

        await Assert.That(actions).Count().IsEqualTo(1);
        await Assert.That(actions.Single()).IsTypeOf<TerminateOciCiRunnerAction>();
        await Assert.That(() => OciCiRunnerCapacityEngine.Decide(Request([wanted], [collision])))
            .Throws<InvalidDataException>();
        await Assert.That(() => OciCiRunnerCapacityEngine.Decide(Request([wanted], [durable])))
            .Throws<InvalidDataException>();
    }

    private static OciCiRunnerCapacityRequest Request(
        IEnumerable<OciCiRunnerDemand> desired,
        IEnumerable<OciCiRunnerNodeObservation> observed,
        int maximumNodes = 8) => new(
        Now,
        TimeSpan.FromSeconds(60),
        maximumNodes,
        new(
            "ocid1.compartment.oc1..ci",
            "sa-saopaulo-1-ad-1",
            "FAULT-DOMAIN-1",
            "ocid1.subnet.oc1.sa-saopaulo-1.ci",
            ["ocid1.networksecuritygroup.oc1.sa-saopaulo-1.ci"],
            "ocid1.image.oc1.sa-saopaulo-1.runner",
            7),
        desired,
        observed);

    private static OciCiRunnerDemand Demand(string runner, long sequence)
    {
        var content = Encoding.UTF8.GetBytes($"#cloud-config\nwrite_files: []\n# {runner}:{sequence}\n");
        return new(
            runner,
            TrustZone.UntrustedProduct,
            sequence,
            Convert.ToBase64String(content),
            Convert.ToHexStringLower(SHA256.HashData(content)));
    }

    private static OciCiRunnerNodeObservation Node(
        OciCiRunnerDemand demand,
        string suffix,
        bool active,
        DateTimeOffset lastActivity,
        IReadOnlyDictionary<string, string>? tags = null) => new(
        $"ocid1.instance.oc1.sa-saopaulo-1.{suffix}",
        $"etag-{suffix}",
        demand.Runner,
        demand.Sequence,
        OciCiRunnerNodeState.Running,
        active,
        lastActivity,
        Preemptible: true,
        PreserveBootVolume: false,
        tags ?? OciCiRunnerCapacityEngine.Tags(demand, 7));
}
