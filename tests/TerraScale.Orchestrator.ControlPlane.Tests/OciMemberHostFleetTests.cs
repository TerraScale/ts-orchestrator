using System.Net;
using System.Security.Cryptography;
using System.Text;
using Oci.Common.Model;
using Oci.CoreService.Models;
using Oci.CoreService.Requests;
using TerraScale.Orchestrator.ControlPlane.Providers;
using TerraScale.Orchestrator.ControlPlane.Storage;
using TerraScale.Orchestrator.Nodes;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class OciMemberHostFleetTests
{
    private const string Compartment = "ocid1.compartment.oc1..member";
    private const string InstanceId = "ocid1.instance.oc1.sa-saopaulo-1.member-1";

    [Test]
    public async Task Launch_compiles_the_exact_non_preemptible_member_request()
    {
        var plan = Plan();
        var createKey = "create-key-1";

        var launch = OciMemberHostRequestCompiler.Launch(plan, createKey);
        var details = launch.LaunchInstanceDetails;
        var source = (InstanceSourceViaImageDetails)details.SourceDetails;
        var tags = OciMemberHostRequestCompiler.Tags(plan, createKey);

        await Assert.That(launch.OpcRetryToken).IsEqualTo(createKey);
        await Assert.That(details.PreemptibleInstanceConfig).IsNull();
        await Assert.That(source.BootVolumeSizeInGBs).IsEqualTo(50);
        await Assert.That(source.BootVolumeVpusPerGB).IsEqualTo(10);
        await Assert.That(source.ImageId).IsEqualTo(plan.Template.ImageId);
        await Assert.That(details.CreateVnicDetails.AssignPublicIp).IsFalse();
        await Assert.That(details.CreateVnicDetails.NsgIds).Count().IsEqualTo(1);
        await Assert.That(details.IsPvEncryptionInTransitEnabled).IsTrue();
        await Assert.That(details.Metadata["user_data"]).IsEqualTo(plan.BootstrapCloudInitBase64);
        await Assert.That(tags["terrascale-owner"]).IsEqualTo("orchestrator");
        await Assert.That(tags["terrascale-role"]).IsEqualTo("terrabase-member");
        await Assert.That(tags["terrascale-database"]).IsEqualTo("db-main");
        await Assert.That(tags["terrascale-member"]).IsEqualTo("member-gru-1");
        await Assert.That(tags["terrascale-region"]).IsEqualTo("GRU");
        await Assert.That(tags["terrascale-bootstrap-sha256"]).IsEqualTo(plan.BootstrapSha256);
        await Assert.That(tags["terrascale-create-key"]).IsEqualTo(createKey);
        await Assert.That(OciMemberHostInstances.Owned(
            new Dictionary<string, string>(tags, StringComparer.Ordinal))).IsTrue();

        await Assert.That(() => new OciMemberHostLaunchPlan(
                Template(), "db-main", "member-gru-1", "XYZ", plan.BootstrapCloudInitBase64, plan.BootstrapSha256))
            .Throws<ArgumentException>();
        await Assert.That(() => new OciMemberHostLaunchPlan(
                Template(), "db-main", "member-gru-1", "GRU", plan.BootstrapCloudInitBase64,
                new string('0', 64)))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task Terminate_compiles_the_exact_instance_fenced_retirement()
    {
        var terminate = OciMemberHostRequestCompiler.Terminate(InstanceId, "etag-9");

        await Assert.That(terminate.InstanceId).IsEqualTo(InstanceId);
        await Assert.That(terminate.IfMatch).IsEqualTo("etag-9");
        await Assert.That(terminate.PreserveBootVolume).IsFalse();
        await Assert.That(terminate.PreserveDataVolumesCreatedAtLaunch).IsFalse();
        await Assert.That(() => OciMemberHostRequestCompiler.Terminate(InstanceId, " "))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task Observation_is_ownership_tag_scoped()
    {
        var transport = new FakeMemberHostTransport();
        transport.AddSeededMember(memberCordoned: false);
        transport.AddForeignInstance(owner: "somebody-else");
        transport.AddForeignInstance(owner: "orchestrator", role: "ci-runner");
        var observations = new FakeObservations { Health = new(true, 0, "Follower", 2, 3) };
        using var fleet = Fleet(transport, observations);

        var observed = await fleet.ObserveAsync(CancellationToken.None);

        await Assert.That(observed).Count().IsEqualTo(1);
        var host = observed.Single();
        await Assert.That(host.ResourceId.InstanceId).IsEqualTo(InstanceId);
        await Assert.That(host.ETag).IsEqualTo("etag-seed");
        await Assert.That(host.MemberId).IsEqualTo("member-gru-1");
        await Assert.That(host.Region).IsEqualTo("GRU");
        await Assert.That(host.State).IsEqualTo(MemberHostState.Running);
        await Assert.That(host.Cordon).IsFalse();
        await Assert.That(host.MemberHealth.Up).IsTrue();
        await Assert.That(host.MemberHealth.Role).IsEqualTo("Follower");
        await Assert.That(host.VolumeId).IsEqualTo("ocid1.bootvolume.oc1.sa-saopaulo-1.member-1");
        await Assert.That(transport.Calls.Count(static call => call == "list")).IsEqualTo(1);
        await Assert.That(transport.Calls.First()).IsEqualTo("list");

        observations.Health = null;
        var withoutHealth = await fleet.ObserveAsync(CancellationToken.None);
        await Assert.That(withoutHealth.Single().MemberHealth.Up).IsFalse();
        await Assert.That(withoutHealth.Single().MemberHealth.Role).IsEqualTo("Unknown");
    }

    [Test]
    public async Task Provision_is_idempotent_per_create_key()
    {
        var transport = new FakeMemberHostTransport();
        using var fleet = Fleet(transport, new FakeObservations());
        var request = Request();

        var first = await fleet.ProvisionAsync(request, CancellationToken.None);
        var second = await fleet.ProvisionAsync(request, CancellationToken.None);

        await Assert.That(transport.Launches).Count().IsEqualTo(1);
        await Assert.That(transport.Launches.Single().OpcRetryToken).IsEqualTo("create-key-1");
        await Assert.That(second.InstanceId).IsEqualTo(first.InstanceId);
    }

    [Test]
    public async Task Stopped_provider_instance_never_inherits_a_healthy_member_report()
    {
        var transport = new FakeMemberHostTransport
        {
            LifecycleSequence = [Instance.LifecycleStateEnum.Stopped]
        };
        transport.AddSeededMember(memberCordoned: false);
        using var fleet = Fleet(transport, new FakeObservations { Health = new(true, 0, "Follower", 2, 3) });
        var observed = await fleet.ObserveAsync(CancellationToken.None);
        await Assert.That(observed.Single().State).IsEqualTo(MemberHostState.Stopped);
        await Assert.That(observed.Single().MemberHealth.Up).IsFalse();
    }

    [Test]
    [Arguments("owner")]
    [Arguments("member")]
    [Arguments("bootstrap")]
    [Arguments("image")]
    public async Task Provision_refuses_drift_before_accepting_an_enrollment_report(string drift)
    {
        var observations = new FakeObservations();
        var transport = new FakeMemberHostTransport
        {
            ReadMutation = instance =>
            {
                if (drift == "owner") instance.FreeformTags[OciMemberHostRequestCompiler.OwnerTag] = "foreign";
                if (drift == "member") instance.FreeformTags[OciMemberHostRequestCompiler.MemberTag] = "other-member";
                if (drift == "bootstrap") instance.Metadata["user_data"] = "other-bootstrap";
                if (drift == "image") instance.ImageId = "other-image";
            }
        };
        using var fleet = Fleet(transport, observations);
        await Assert.That(async () => await fleet.ProvisionAsync(Request(), CancellationToken.None))
            .Throws<InvalidDataException>();
        await Assert.That(observations.ReadyPolls).IsEqualTo(0);
    }

    [Test]
    public async Task Provision_waits_for_running_and_the_first_host_observation()
    {
        var transport = new FakeMemberHostTransport { LaunchedState = Instance.LifecycleStateEnum.Starting };
        var observations = new FakeObservations { ReadyAfterPolls = 3 };
        transport.LifecycleSequence =
        [
            Instance.LifecycleStateEnum.Starting,
            Instance.LifecycleStateEnum.Running,
            Instance.LifecycleStateEnum.Running,
        ];
        using var fleet = Fleet(transport, observations);

        var provisioned = await fleet.ProvisionAsync(Request(), CancellationToken.None);

        await Assert.That(transport.Calls.Count(static call => call == "get")).IsGreaterThanOrEqualTo(3);
        await Assert.That(observations.ReadyPolls).IsGreaterThanOrEqualTo(3);
        await Assert.That(provisioned.InstanceId).IsEqualTo(transport.LaunchedInstanceId);
    }

    [Test]
    public async Task Provision_failure_records_evidence()
    {
        var transport = new FakeMemberHostTransport
        {
            LaunchedState = Instance.LifecycleStateEnum.Starting,
            LifecycleSequence = [Instance.LifecycleStateEnum.Starting],
        };
        var observations = new FakeObservations { ReadyAfterPolls = int.MaxValue };
        using var fleet = Fleet(transport, observations, FastOptions());

        var failure = (await Assert.ThrowsAsync<InvalidOperationException>(
            () => fleet.ProvisionAsync(Request(), CancellationToken.None)))!;

        await Assert.That(failure.Message.Contains("lifecycle=Starting", StringComparison.Ordinal)).IsTrue();
        await Assert.That(failure.Message.Contains("hostReported=False", StringComparison.Ordinal)).IsTrue();
    }

    [Test]
    public async Task Retire_verifies_boot_volume_absence_before_returning()
    {
        var transport = new FakeMemberHostTransport();
        transport.AddSeededMember(memberCordoned: false);
        using var fleet = Fleet(transport, new FakeObservations());

        await fleet.RetireAsync(new(InstanceId), "etag-seed", CancellationToken.None);

        var terminate = transport.Terminates.Single();
        await Assert.That(terminate.InstanceId).IsEqualTo(InstanceId);
        await Assert.That(terminate.IfMatch).IsEqualTo("etag-seed");
        await Assert.That(terminate.PreserveBootVolume).IsFalse();
        await Assert.That(terminate.PreserveDataVolumesCreatedAtLaunch).IsFalse();
        // The absence verification is a provider read after the exact-instance terminate.
        await Assert.That(transport.BootVolumeListings).Count().IsGreaterThanOrEqualTo(1);
        await Assert.That(transport.Calls.IndexOf("terminate"))
            .IsLessThan(transport.Calls.IndexOf("bootvolumes"));

        // An instance that is already gone is an idempotent goal state.
        await fleet.RetireAsync(new("ocid1.instance.oc1.sa-saopaulo-1.gone"), "etag-x", CancellationToken.None);
        await Assert.That(transport.Terminates).Count().IsEqualTo(1);
    }

    [Test]
    public async Task Retire_refuses_when_the_boot_volume_never_becomes_absent()
    {
        var transport = new FakeMemberHostTransport { BootVolumeNeverAbsent = true };
        transport.AddSeededMember(memberCordoned: false);
        using var fleet = Fleet(transport, new FakeObservations(), FastOptions());

        await Assert.That(() => fleet.RetireAsync(new(InstanceId), "etag-seed", CancellationToken.None))
            .Throws<InvalidOperationException>();
        await Assert.That(transport.Terminates).Count().IsEqualTo(1);
    }

    [Test]
    public async Task Retire_and_cordon_refuse_instances_the_fleet_does_not_own()
    {
        var transport = new FakeMemberHostTransport();
        transport.AddForeignInstance(owner: "somebody-else");
        using var fleet = Fleet(transport, new FakeObservations(), FastOptions());

        await Assert.That(() => fleet.RetireAsync(new(transport.ForeignInstanceId), "etag-foreign", CancellationToken.None))
            .Throws<InvalidOperationException>();
        await Assert.That(() => fleet.CordonAsync(new(transport.ForeignInstanceId), CancellationToken.None))
            .Throws<InvalidOperationException>();
        await Assert.That(transport.Terminates).IsEmpty();
        await Assert.That(transport.Updates).IsEmpty();
    }

    [Test]
    public async Task Cordon_marks_the_owned_instance_idempotently()
    {
        var transport = new FakeMemberHostTransport();
        transport.AddSeededMember(memberCordoned: false);
        using var fleet = Fleet(transport, new FakeObservations());

        await fleet.CordonAsync(new(InstanceId), CancellationToken.None);
        await fleet.CordonAsync(new(InstanceId), CancellationToken.None);

        var update = transport.Updates.Single();
        await Assert.That(update.InstanceId).IsEqualTo(InstanceId);
        await Assert.That(update.IfMatch).IsEqualTo("etag-seed");
        await Assert.That(update.UpdateInstanceDetails.FreeformTags["terrascale-cordoned"]).IsEqualTo("true");
    }

    [Test]
    public async Task Drain_publishes_the_fenced_host_agent_command()
    {
        var transport = new FakeMemberHostTransport();
        var channel = new FakeCommandChannel();
        using var fleet = new OciMemberHostFleet(
            transport,
            Configuration(),
            static () => true,
            new FakeObservations(),
            channel,
            TimeProvider.System);

        await fleet.DrainAsync(new(InstanceId), CancellationToken.None);

        var subject = channel.Subjects.Single();
        await Assert.That(subject).IsEqualTo(NatsSubjectTaxonomy.HostAgentCommandSubject("gru-1", InstanceId, "drain"));
        await Assert.That(subject.EndsWith(".command.drain", StringComparison.Ordinal)).IsTrue();
        // The raw provider identity never becomes a subject token.
        await Assert.That(subject.Contains(InstanceId, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task Volume_mutations_execute_through_the_fleet_seam()
    {
        var transport = new FakeMemberHostTransport();
        transport.AddSeededMember(memberCordoned: false);
        transport.AddVolumeAttachment(
            "ocid1.volume.oc1.sa-saopaulo-1.member-1", InstanceId, VolumeAttachment.LifecycleStateEnum.Attached);
        using var fleet = Fleet(transport, new FakeObservations());

        var detached = await fleet.DetachVolumeAsync(
            "ocid1.volume.oc1.sa-saopaulo-1.member-1", new(InstanceId), CancellationToken.None);
        var attached = await fleet.AttachVolumeAsync(
            "ocid1.volume.oc1.sa-saopaulo-1.member-1", new(InstanceId), "attach-key-1", CancellationToken.None);

        await Assert.That(detached).IsEqualTo(MemberVolumeOutcome.Completed);
        await Assert.That(attached).IsEqualTo(MemberVolumeOutcome.Completed);
        await Assert.That(transport.Detaches.Single().VolumeAttachmentId).IsEqualTo("attachment-volume-1");
        await Assert.That(transport.Attaches.Single().OpcRetryToken).IsEqualTo("attach-key-1");
        await Assert.That(() => fleet.DetachVolumeAsync(" ", new(InstanceId), CancellationToken.None))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task Lost_authority_aborts_every_provider_mutation()
    {
        var transport = new FakeMemberHostTransport();
        transport.AddSeededMember(memberCordoned: false);
        var observations = new FakeObservations();
        using var fleet = Fleet(transport, observations, FastOptions(), authority: static () => false);
        var adapter = new OciMemberHostVolumeAdapter(transport, static () => false, TimeProvider.System, FastOptions());

        await Assert.ThrowsAsync<InvalidOperationException>(() => fleet.ProvisionAsync(Request(), CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(() => fleet.CordonAsync(new(InstanceId), CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(() => fleet.DrainAsync(new(InstanceId), CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(() => fleet.RetireAsync(new(InstanceId), "etag-seed", CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(() => fleet.DetachVolumeAsync(
            "ocid1.volume.oc1.sa-saopaulo-1.member-1", new(InstanceId), CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(() => fleet.AttachVolumeAsync(
            "ocid1.volume.oc1.sa-saopaulo-1.member-1", new(InstanceId), "attach-key-1", CancellationToken.None));
        await Assert.That(() => adapter.DetachAsync(Compartment, "ocid1.volume.oc1..v", InstanceId, CancellationToken.None).AsTask())
            .Throws<InvalidOperationException>();
        await Assert.That(() => adapter.AttachAsync(Compartment, "ocid1.volume.oc1..v", InstanceId, "reattach-1", CancellationToken.None).AsTask())
            .Throws<InvalidOperationException>();

        await Assert.That(transport.Launches).IsEmpty();
        await Assert.That(transport.Updates).IsEmpty();
        await Assert.That(transport.Terminates).IsEmpty();
        await Assert.That(transport.Attaches).IsEmpty();
        await Assert.That(transport.Detaches).IsEmpty();
        await Assert.That(observations.ReadyPolls).IsEqualTo(0);
    }

    [Test]
    public async Task Authority_lost_between_the_read_and_the_mutation_aborts_the_mutation()
    {
        var transport = new FakeMemberHostTransport();
        transport.AddSeededMember(memberCordoned: false);
        var authority = new MutableAuthority(true);
        using var fleet = Fleet(transport, new FakeObservations(), authority: authority.StillValid);

        authority.Valid = false;
        await Assert.That(() => fleet.CordonAsync(new(InstanceId), CancellationToken.None))
            .Throws<InvalidOperationException>();

        await Assert.That(transport.Calls.Any(static call => call == "get")).IsTrue();
        await Assert.That(transport.Updates).IsEmpty();
    }

    [Test]
    public async Task Volume_reattach_follows_the_attachment_planner_discipline()
    {
        // The planner emits Detach while the previous writer's provider detach is unproven.
        var writer = new StorageWriterObservation(
            StorageTestData.Node("old"), StorageTestData.Attachment(), StorageTestData.Epoch(7));
        var detachEvidence = new StorageReattachEvidence(
            StorageTestData.Scope(), [writer], StorageProof.Proven, StorageProof.Proven, StorageProof.Unknown,
            StorageProof.Unknown, StorageProof.Proven, StorageTestData.Epoch(8), 2);
        var detach = StorageAttachmentPlanner.Plan(
            StorageTestData.Volume(), StorageTestData.Context(), StorageTestData.Node("new"), detachEvidence);
        await Assert.That(detach.Action).IsEqualTo(StorageAction.Detach);
        await Assert.That(detach.Target).IsEqualTo(StorageIntentTarget.ProviderAttachment);

        // With a proven detach and a strictly greater writer epoch the planner emits Attach.
        var attachEvidence = new StorageReattachEvidence(
            StorageTestData.Scope(), [], StorageProof.Proven, StorageProof.Proven, StorageProof.Proven,
            StorageProof.Unknown, StorageProof.Proven, StorageTestData.Epoch(8), 2);
        var attach = StorageAttachmentPlanner.Plan(
            StorageTestData.Volume(), StorageTestData.Context(), StorageTestData.Node("new"), attachEvidence);
        await Assert.That(attach.Action).IsEqualTo(StorageAction.Attach);
        await Assert.That(StorageTestData.Require(attach.Trace).Epoch).IsEqualTo(StorageTestData.Epoch(8));

        // The adapter executes exactly those provider-attachment mutations, idempotently.
        var transport = new FakeMemberHostTransport();
        transport.AddVolumeAttachment("ocid1.volume.oc1..v", InstanceId, VolumeAttachment.LifecycleStateEnum.Attached);
        var adapter = new OciMemberHostVolumeAdapter(transport, static () => true, TimeProvider.System, FastOptions());

        await Assert.That(await adapter.DetachAsync(Compartment, "ocid1.volume.oc1..v", InstanceId, CancellationToken.None))
            .IsEqualTo(OciMemberHostVolumeOutcome.Completed);
        await Assert.That(transport.Detaches.Single().VolumeAttachmentId).IsEqualTo("attachment-volume-1");

        await Assert.That(await adapter.AttachAsync(Compartment, "ocid1.volume.oc1..v", InstanceId, "reattach-8", CancellationToken.None))
            .IsEqualTo(OciMemberHostVolumeOutcome.Completed);
        await Assert.That(transport.Attaches.Single().OpcRetryToken).IsEqualTo("reattach-8");
        await Assert.That(transport.Attaches.Single().AttachVolumeDetails.InstanceId).IsEqualTo(InstanceId);
        await Assert.That(transport.Attaches.Single().AttachVolumeDetails.VolumeId).IsEqualTo("ocid1.volume.oc1..v");

        // An attachment that already exists on the target is the goal state, not a new mutation.
        await Assert.That(await adapter.AttachAsync(Compartment, "ocid1.volume.oc1..v", InstanceId, "reattach-8", CancellationToken.None))
            .IsEqualTo(OciMemberHostVolumeOutcome.Completed);
        await Assert.That(transport.Attaches).Count().IsEqualTo(1);
    }

    [Test]
    public async Task A_lost_volume_response_is_never_retried()
    {
        var transport = new FakeMemberHostTransport();
        transport.AddVolumeAttachment("ocid1.volume.oc1..v", InstanceId, VolumeAttachment.LifecycleStateEnum.Attached);
        transport.DetachFailure = new TimeoutException("detach response lost");
        var adapter = new OciMemberHostVolumeAdapter(transport, static () => true, TimeProvider.System, FastOptions());

        var detach = await adapter.DetachAsync(Compartment, "ocid1.volume.oc1..v", InstanceId, CancellationToken.None);
        await Assert.That(detach).IsEqualTo(OciMemberHostVolumeOutcome.OutcomeUnknown);
        // Exactly one mutation attempt, then only reobservation — never a second detach.
        await Assert.That(transport.Calls.Count(static call => call == "detach")).IsEqualTo(1);
        await Assert.That(transport.Detaches).IsEmpty();
        await Assert.That(transport.Calls.Count(static call => call == "volumes")).IsGreaterThanOrEqualTo(2);

        var attachTransport = new FakeMemberHostTransport();
        attachTransport.AttachFailure = new TimeoutException("attach response lost");
        var attachAdapter = new OciMemberHostVolumeAdapter(attachTransport, static () => true, TimeProvider.System, FastOptions());
        var attach = await attachAdapter.AttachAsync(Compartment, "ocid1.volume.oc1..v", InstanceId, "reattach-8", CancellationToken.None);
        await Assert.That(attach).IsEqualTo(OciMemberHostVolumeOutcome.OutcomeUnknown);
        await Assert.That(attachTransport.Calls.Count(static call => call == "attach")).IsEqualTo(1);
        await Assert.That(attachTransport.Attaches).IsEmpty();
    }

    private static OciMemberHostLaunchPlan Plan()
    {
        var content = Encoding.UTF8.GetBytes("#cloud-config\nwrite_files: []\n# terrabase member\n");
        return new(
            Template(),
            "db-main",
            "member-gru-1",
            "GRU",
            Convert.ToBase64String(content),
            Convert.ToHexStringLower(SHA256.HashData(content)));
    }

    private static OciCiRunnerLaunchTemplate Template() => new(
        Compartment,
        "sa-saopaulo-1-ad-1",
        "FAULT-DOMAIN-2",
        "ocid1.subnet.oc1.sa-saopaulo-1.member",
        ["ocid1.networksecuritygroup.oc1.sa-saopaulo-1.member"],
        "ocid1.image.oc1.sa-saopaulo-1.terrabase",
        7);

    private static OciMemberHostFleetConfiguration Configuration()
    {
        var content = Encoding.UTF8.GetBytes("#cloud-config\nwrite_files: []\n# terrabase member\n");
        var bootstrap = new OciMemberHostBootstrap(
            Convert.ToBase64String(content), Convert.ToHexStringLower(SHA256.HashData(content)));
        return new(
            "gru-1",
            new Dictionary<string, OciCiRunnerLaunchTemplate>(StringComparer.Ordinal) { ["GRU"] = Template() },
            bootstrap);
    }

    private static MemberHostRequest Request() =>
        new("db-main", "member-gru-1", "GRU", "partition-1", Permanent: true, CreateKey: "create-key-1");

    private static OciMemberHostFleetOptions FastOptions() =>
        new(TimeSpan.FromMilliseconds(400), TimeSpan.FromMilliseconds(20));

    private static OciMemberHostFleet Fleet(
        FakeMemberHostTransport transport,
        IMemberHostObservationSource observations,
        OciMemberHostFleetOptions? options = null,
        Func<bool>? authority = null) => new(
        transport,
        Configuration(),
        authority ?? (static () => true),
        observations,
        new FakeCommandChannel(),
        TimeProvider.System,
        options ?? FastOptions());

    private sealed class MutableAuthority(bool valid)
    {
        public bool Valid = valid;
        public bool StillValid() => Valid;
    }

    private sealed class FakeObservations : IMemberHostObservationSource
    {
        public int ReadyAfterPolls { get; set; }
        public MemberHealth? Health { get; set; } = new(true, 0, "Follower", 2, 3);
        public int ReadyPolls { get; private set; }

        public ValueTask<bool> HasHostReportedAsync(string instance, CancellationToken cancellationToken) =>
            ValueTask.FromResult(++ReadyPolls > ReadyAfterPolls);

        public ValueTask<MemberHealth?> ObserveMemberHealthAsync(string instance, CancellationToken cancellationToken) =>
            ValueTask.FromResult(Health);
    }

    private sealed class FakeCommandChannel : IMemberHostCommandChannel
    {
        public List<string> Subjects { get; } = [];

        public ValueTask PublishAsync(string subject, CancellationToken cancellationToken)
        {
            Subjects.Add(subject);
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>A counting fake over the member-host transport seam: no real OCI is touched.</summary>
    private sealed class FakeMemberHostTransport : IOciMemberHostComputeTransport
    {
        private readonly List<Instance> instances = [];
        private readonly Dictionary<string, string> etags = new(StringComparer.Ordinal);
        private readonly Dictionary<string, Instance> launchedByToken = new(StringComparer.Ordinal);
        private readonly List<VolumeAttachment> volumeAttachments = [];
        private int launches;

        public List<string> Calls { get; } = [];
        public List<LaunchInstanceRequest> Launches { get; } = [];
        public List<TerminateInstanceRequest> Terminates { get; } = [];
        public List<UpdateInstanceRequest> Updates { get; } = [];
        public List<AttachVolumeRequest> Attaches { get; } = [];
        public List<DetachVolumeRequest> Detaches { get; } = [];
        public List<ListBootVolumeAttachmentsRequest> BootVolumeListings { get; } = [];
        public Instance.LifecycleStateEnum LaunchedState { get; set; } = Instance.LifecycleStateEnum.Running;
        public List<Instance.LifecycleStateEnum>? LifecycleSequence { get; set; }
        public bool BootVolumeNeverAbsent { get; set; }
        public bool BootVolumePresent { get; set; } = true;
        public string BootVolumeId { get; set; } = "ocid1.bootvolume.oc1.sa-saopaulo-1.member-1";
        public Exception? DetachFailure { get; set; }
        public Exception? AttachFailure { get; set; }
        public string ForeignInstanceId => "ocid1.instance.oc1.sa-saopaulo-1.foreign";
        public string LaunchedInstanceId { get; private set; } = "";
        public Action<Instance>? ReadMutation { get; init; }

        public void AddSeededMember(bool memberCordoned)
        {
            var content = Encoding.UTF8.GetBytes("#cloud-config\nwrite_files: []\n# terrabase member\n");
            var tags = new Dictionary<string, string>(OciMemberHostRequestCompiler.Tags(
                new OciMemberHostLaunchPlan(
                    Template(), "db-main", "member-gru-1", "GRU",
                    Convert.ToBase64String(content), Convert.ToHexStringLower(SHA256.HashData(content))),
                "create-key-seed"), StringComparer.Ordinal);
            if (memberCordoned)
                tags[OciMemberHostRequestCompiler.CordonTag] = "true";
            instances.Add(MemberInstance(
                InstanceId,
                tags,
                Instance.LifecycleStateEnum.Running));
            etags[InstanceId] = "etag-seed";
        }

        private static Dictionary<string, string> Tags(LaunchInstanceRequest request) =>
            new(request.LaunchInstanceDetails.FreeformTags, StringComparer.Ordinal);

        public void AddForeignInstance(string owner, string role = "terrabase-member")
        {
            var tags = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [OciMemberHostRequestCompiler.OwnerTag] = owner,
                [OciMemberHostRequestCompiler.RoleTag] = role,
            };
            instances.Add(MemberInstance(
                ForeignInstanceId,
                tags,
                Instance.LifecycleStateEnum.Running));
            etags[ForeignInstanceId] = "etag-foreign";
        }

        public void AddVolumeAttachment(
            string volumeId, string instanceId, VolumeAttachment.LifecycleStateEnum state) =>
            volumeAttachments.Add(new VolumeAttachment
            {
                Id = "attachment-volume-1",
                VolumeId = volumeId,
                InstanceId = instanceId,
                LifecycleState = state,
            });

        public Task<Oci.CoreService.Responses.ListInstancesResponse> ListInstancesAsync(
            ListInstancesRequest request, CancellationToken cancellationToken)
        {
            Calls.Add("list");
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new Oci.CoreService.Responses.ListInstancesResponse
            {
                Items = [.. instances.Where(instance => instance.CompartmentId == request.CompartmentId)],
            });
        }

        public Task<Oci.CoreService.Responses.GetInstanceResponse> GetInstanceAsync(
            GetInstanceRequest request, CancellationToken cancellationToken)
        {
            Calls.Add("get");
            cancellationToken.ThrowIfCancellationRequested();
            var instance = instances.FirstOrDefault(value => value.Id == request.InstanceId) ??
                throw new OciException(HttpStatusCode.NotFound, "not found", "request", "work");
            if (LifecycleSequence is { Count: > 0 })
            {
                instance.LifecycleState = LifecycleSequence[0];
                LifecycleSequence.RemoveAt(0);
            }
            ReadMutation?.Invoke(instance);
            return Task.FromResult(new Oci.CoreService.Responses.GetInstanceResponse
            {
                Instance = instance,
                Etag = etags[instance.Id],
            });
        }

        public Task<Oci.CoreService.Responses.LaunchInstanceResponse> LaunchInstanceAsync(
            LaunchInstanceRequest request, CancellationToken cancellationToken)
        {
            Calls.Add("launch");
            cancellationToken.ThrowIfCancellationRequested();
            // The provider honors the idempotency token: the same token returns the same instance.
            if (launchedByToken.TryGetValue(request.OpcRetryToken ?? string.Empty, out var existing))
                return Task.FromResult(new Oci.CoreService.Responses.LaunchInstanceResponse
                {
                    Instance = existing,
                    Etag = etags[existing.Id],
                    OpcWorkRequestId = "work-launched",
                    OpcRequestId = "request-launched",
                });
            Launches.Add(request);
            launches++;
            var id = $"ocid1.instance.oc1.sa-saopaulo-1.launched-{launches}";
            var instance = MemberInstance(id, Tags(request), LaunchedState);
            instances.Add(instance);
            etags[id] = $"etag-launched-{launches}";
            launchedByToken[request.OpcRetryToken ?? string.Empty] = instance;
            LaunchedInstanceId = id;
            return Task.FromResult(new Oci.CoreService.Responses.LaunchInstanceResponse
            {
                Instance = instance,
                Etag = etags[id],
                OpcWorkRequestId = "work-launched",
                OpcRequestId = "request-launched",
            });
        }

        public Task<Oci.CoreService.Responses.TerminateInstanceResponse> TerminateInstanceAsync(
            TerminateInstanceRequest request, CancellationToken cancellationToken)
        {
            Calls.Add("terminate");
            cancellationToken.ThrowIfCancellationRequested();
            Terminates.Add(request);
            var instance = instances.Single(value => value.Id == request.InstanceId);
            instance.LifecycleState = Instance.LifecycleStateEnum.Terminating;
            if (!BootVolumeNeverAbsent)
                BootVolumePresent = false;
            return Task.FromResult(new Oci.CoreService.Responses.TerminateInstanceResponse
            {
                OpcRequestId = "request-terminated",
                OpcWorkRequestId = "work-terminated",
            });
        }

        public Task<Oci.CoreService.Responses.UpdateInstanceResponse> UpdateInstanceAsync(
            UpdateInstanceRequest request, CancellationToken cancellationToken)
        {
            Calls.Add("update");
            cancellationToken.ThrowIfCancellationRequested();
            Updates.Add(request);
            var instance = instances.Single(value => value.Id == request.InstanceId);
            instance.FreeformTags = request.UpdateInstanceDetails.FreeformTags;
            etags[instance.Id] = $"etag-updated-{Updates.Count}";
            return Task.FromResult(new Oci.CoreService.Responses.UpdateInstanceResponse
            {
                Instance = instance,
                Etag = etags[instance.Id],
                OpcRequestId = "request-updated",
            });
        }

        public Task<Oci.CoreService.Responses.ListBootVolumeAttachmentsResponse> ListBootVolumeAttachmentsAsync(
            ListBootVolumeAttachmentsRequest request, CancellationToken cancellationToken)
        {
            Calls.Add("bootvolumes");
            BootVolumeListings.Add(request);
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new Oci.CoreService.Responses.ListBootVolumeAttachmentsResponse
            {
                Items = BootVolumePresent
                    ? [new BootVolumeAttachment
                    {
                        Id = "boot-attachment-1",
                        InstanceId = request.InstanceId,
                        BootVolumeId = BootVolumeId,
                    }]
                    : [],
            });
        }

        public Task<Oci.CoreService.Responses.ListVnicAttachmentsResponse> ListVnicAttachmentsAsync(
            ListVnicAttachmentsRequest request, CancellationToken cancellationToken)
        {
            Calls.Add("vnics");
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new Oci.CoreService.Responses.ListVnicAttachmentsResponse
            {
                Items =
                [
                    new VnicAttachment
                    {
                        InstanceId = request.InstanceId,
                        VnicId = "ocid1.vnic.oc1.sa-saopaulo-1.member",
                        CompartmentId = request.CompartmentId,
                        AvailabilityDomain = Template().AvailabilityDomain,
                        SubnetId = Template().SubnetId,
                        NicIndex = 0,
                        LifecycleState = VnicAttachment.LifecycleStateEnum.Attached,
                    },
                ],
            });
        }

        public Task<Oci.CoreService.Responses.GetVnicResponse> GetVnicAsync(
            GetVnicRequest request, CancellationToken cancellationToken)
        {
            Calls.Add("vnic");
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new Oci.CoreService.Responses.GetVnicResponse
            {
                Vnic = new Vnic
                {
                    Id = request.VnicId,
                    CompartmentId = Compartment,
                    AvailabilityDomain = Template().AvailabilityDomain,
                    SubnetId = Template().SubnetId,
                    IsPrimary = true,
                    LifecycleState = Vnic.LifecycleStateEnum.Available,
                    NsgIds = Template().NetworkSecurityGroupIds.ToList(),
                    Ipv6Addresses = [],
                },
            });
        }

        public Task<Oci.CoreService.Responses.ListVolumeAttachmentsResponse> ListVolumeAttachmentsAsync(
            ListVolumeAttachmentsRequest request, CancellationToken cancellationToken)
        {
            Calls.Add("volumes");
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new Oci.CoreService.Responses.ListVolumeAttachmentsResponse
            {
                Items = [.. volumeAttachments.Where(attachment =>
                    attachment.VolumeId == request.VolumeId &&
                    attachment.LifecycleState != VolumeAttachment.LifecycleStateEnum.Detached)],
            });
        }

        public Task<Oci.CoreService.Responses.AttachVolumeResponse> AttachVolumeAsync(
            AttachVolumeRequest request, CancellationToken cancellationToken)
        {
            Calls.Add("attach");
            cancellationToken.ThrowIfCancellationRequested();
            if (AttachFailure is { } failure)
            {
                AttachFailure = null;
                throw failure;
            }
            Attaches.Add(request);
            volumeAttachments.Add(new VolumeAttachment
            {
                Id = $"attachment-{Attaches.Count}",
                VolumeId = request.AttachVolumeDetails.VolumeId,
                InstanceId = request.AttachVolumeDetails.InstanceId,
                LifecycleState = VolumeAttachment.LifecycleStateEnum.Attached,
            });
            return Task.FromResult(new Oci.CoreService.Responses.AttachVolumeResponse
            {
                VolumeAttachment = volumeAttachments[^1],
                OpcRequestId = "request-attached",
            });
        }

        public Task<Oci.CoreService.Responses.DetachVolumeResponse> DetachVolumeAsync(
            DetachVolumeRequest request, CancellationToken cancellationToken)
        {
            Calls.Add("detach");
            cancellationToken.ThrowIfCancellationRequested();
            if (DetachFailure is { } failure)
            {
                DetachFailure = null;
                throw failure;
            }
            Detaches.Add(request);
            var attachment = volumeAttachments.Single(value => value.Id == request.VolumeAttachmentId);
            attachment.LifecycleState = VolumeAttachment.LifecycleStateEnum.Detached;
            return Task.FromResult(new Oci.CoreService.Responses.DetachVolumeResponse
            {
                OpcRequestId = "request-detached",
            });
        }

        public void Dispose()
        {
        }

        private static Instance MemberInstance(
            string id,
            Dictionary<string, string> tags,
            Instance.LifecycleStateEnum state)
        {
            var template = Template();
            var source = new InstanceSourceViaImageDetails
            {
                ImageId = template.ImageId,
                BootVolumeSizeInGBs = 50,
                BootVolumeVpusPerGB = 10,
            };
            return new Instance
            {
                Id = id,
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
                SourceDetails = source,
                LaunchOptions = new() { IsPvEncryptionInTransitEnabled = true },
                Metadata = new(StringComparer.Ordinal)
                {
                    ["user_data"] = Convert.ToBase64String(
                        Encoding.UTF8.GetBytes("#cloud-config\nwrite_files: []\n# terrabase member\n")),
                },
                FreeformTags = tags,
                LifecycleState = state,
                TimeCreated = DateTime.UnixEpoch,
            };
        }
    }
}
