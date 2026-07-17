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
        var activeDemand = Demand("runner-active", 43);
        var active = Node(activeDemand, "active", active: true, Now.AddMinutes(-5));
        var unownedDemand = Demand("runner-unowned", 44);
        var unownedTags = new Dictionary<string, string>(
            OciCiRunnerCapacityEngine.Tags(unownedDemand, 7),
            StringComparer.Ordinal)
        {
            ["terrascale-owner"] = "somebody-else",
        };
        var unowned = Node(unownedDemand, "unowned", active: false, Now.AddMinutes(-5), unownedTags);

        var action = OciCiRunnerCapacityEngine.Decide(
            Request([], [idle, active, unowned], permitted: [demand, activeDemand])).Single();
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
            maximumNodes: 2,
            permitted: [obsolete, wanted]);
        var actions = OciCiRunnerCapacityEngine.Decide(full);
        var collision = Node(
            wanted,
            "collision",
            active: false,
            Now,
            new Dictionary<string, string>(StringComparer.Ordinal));
        var durable = Node(wanted, "durable", active: false, Now) with { Preemptible = false };

        await Assert.That(actions).Count().IsEqualTo(2);
        await Assert.That(actions[0]).IsTypeOf<TerminateOciCiRunnerAction>();
        await Assert.That(actions[1]).IsTypeOf<LaunchOciCiRunnerAction>();
        await Assert.That(() => OciCiRunnerCapacityEngine.Decide(Request([wanted], [collision])))
            .Throws<InvalidDataException>();
        await Assert.That(() => OciCiRunnerCapacityEngine.Decide(Request([wanted], [durable])))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task StoppedRunnerIsNeverReportedAvailableAndIsTerminatedForReplacement()
    {
        var demand = Demand("runner-stopped", 47);
        var stopped = Node(demand, "stopped", active: true, Now) with
        {
            State = OciCiRunnerNodeState.Stopped,
        };

        var action = OciCiRunnerCapacityEngine.Decide(Request([demand], [stopped])).Single();

        await Assert.That(OciCiRunnerComputeAdapter.State(Instance.LifecycleStateEnum.Stopped))
            .IsEqualTo(OciCiRunnerNodeState.Stopped);
        await Assert.That(action).IsTypeOf<TerminateOciCiRunnerAction>();
        await Assert.That(((TerminateOciCiRunnerAction)action).InstanceId).IsEqualTo(stopped.InstanceId);
    }

    [Test]
    public async Task TagsAloneNeverAuthorizeIdleRunnerDeletion()
    {
        var tagged = Demand("runner-tag-only", 48);
        var configured = Demand("runner-configured", 49);

        var actions = OciCiRunnerCapacityEngine.Decide(Request(
            [],
            [Node(tagged, "tag-only", active: false, Now.AddMinutes(-5))],
            permitted: [configured]));

        await Assert.That(actions).IsEmpty();
    }

    [Test]
    public async Task ProviderReadbackMustMatchTheExactPrivateLaunchTemplate()
    {
        var template = Template();
        var demand = Demand("runner-exact", 50);
        var instance = new Instance
        {
            Id = "ocid1.instance.oc1.sa-saopaulo-1.exact",
            CompartmentId = template.CompartmentId,
            AvailabilityDomain = template.AvailabilityDomain,
            FaultDomain = template.FaultDomain,
            Shape = OciCiRunnerRequestCompiler.Shape,
            ShapeConfig = new()
            {
                Ocpus = OciCiRunnerRequestCompiler.Ocpus,
                MemoryInGBs = OciCiRunnerRequestCompiler.MemoryInGbs,
            },
            ImageId = template.ImageId,
            SourceDetails = new InstanceSourceViaImageDetails
            {
                ImageId = template.ImageId,
                BootVolumeSizeInGBs = 50,
                BootVolumeVpusPerGB = 10,
            },
            LaunchOptions = new() { IsPvEncryptionInTransitEnabled = true },
            Metadata = new(StringComparer.Ordinal)
            {
                ["user_data"] = demand.BootstrapCloudInitBase64,
            },
            FreeformTags = new(OciCiRunnerCapacityEngine.Tags(demand, template.Generation),
                StringComparer.Ordinal),
        };
        var attachment = new VnicAttachment
        {
            InstanceId = instance.Id,
            VnicId = "ocid1.vnic.oc1.sa-saopaulo-1.exact",
            CompartmentId = template.CompartmentId,
            AvailabilityDomain = template.AvailabilityDomain,
            SubnetId = template.SubnetId,
            NicIndex = 0,
            LifecycleState = VnicAttachment.LifecycleStateEnum.Attached,
        };
        var vnic = new Vnic
        {
            Id = attachment.VnicId,
            CompartmentId = template.CompartmentId,
            AvailabilityDomain = template.AvailabilityDomain,
            SubnetId = template.SubnetId,
            IsPrimary = true,
            LifecycleState = Vnic.LifecycleStateEnum.Available,
            NsgIds = template.NetworkSecurityGroupIds.ToList(),
            Ipv6Addresses = [],
        };

        OciCiRunnerComputeAdapter.RequireLaunchTemplate(instance, attachment, vnic, template);
        vnic.PublicIp = "203.0.113.10";

        await Assert.That(() =>
                OciCiRunnerComputeAdapter.RequireLaunchTemplate(instance, attachment, vnic, template))
            .Throws<InvalidDataException>();
        vnic.PublicIp = null;
        instance.Metadata["user_data"] = Convert.ToBase64String("changed bootstrap"u8);

        await Assert.That(() =>
                OciCiRunnerComputeAdapter.RequireLaunchTemplate(instance, attachment, vnic, template))
            .Throws<InvalidDataException>();
    }

    private static OciCiRunnerCapacityRequest Request(
        IEnumerable<OciCiRunnerDemand> desired,
        IEnumerable<OciCiRunnerNodeObservation> observed,
        int maximumNodes = 8,
        IEnumerable<OciCiRunnerDemand>? permitted = null)
    {
        var wanted = desired.ToArray();
        return new(
            Now,
            TimeSpan.FromSeconds(60),
            maximumNodes,
            Template(),
            permitted ?? wanted,
            wanted,
            observed);
    }

    private static OciCiRunnerLaunchTemplate Template() => new(
        "ocid1.compartment.oc1..ci",
        "sa-saopaulo-1-ad-1",
        "FAULT-DOMAIN-1",
        "ocid1.subnet.oc1.sa-saopaulo-1.ci",
        ["ocid1.networksecuritygroup.oc1.sa-saopaulo-1.ci"],
        "ocid1.image.oc1.sa-saopaulo-1.runner",
        7);

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
