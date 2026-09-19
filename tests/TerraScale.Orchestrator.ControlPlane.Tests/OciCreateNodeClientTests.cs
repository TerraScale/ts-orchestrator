using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Oci.Common.Model;
using Oci.CoreService.Models;
using Oci.CoreService.Requests;
using TerraScale.Orchestrator.ControlPlane.Operations;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class OciCreateNodeClientTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 19, 12, 0, 0, TimeSpan.Zero);
    private const string Compartment = "ocid1.compartment.oc1..member";

    [Test]
    public async Task Create_launches_with_the_durable_create_key_as_the_idempotency_token()
    {
        var transport = new FakeOciCreateNodeTransport();
        var keys = new AttestationKeys();
        using var client = new OciCreateNodeClient(transport, new TemplateSource(), keys.ProofSigner);

        var response = await client.CreateNodeAsync(Request("create-key-1"), CancellationToken.None);

        var launch = transport.Launches.Single();
        await Assert.That(launch.OpcRetryToken).IsEqualTo("create-key-1");
        await Assert.That(launch.LaunchInstanceDetails.FreeformTags["terrascale-create-key"])
            .IsEqualTo("create-key-1");
        await Assert.That(launch.LaunchInstanceDetails.CompartmentId).IsEqualTo(Compartment);
        await Assert.That(response.NodeId.Value).IsEqualTo(FakeOciCreateNodeTransport.LaunchedInstanceId);
        await Assert.That(response.WorkRequestId.Value).IsEqualTo("work-launched-1");
    }

    [Test]
    public async Task A_repeated_create_key_resolves_to_the_same_instance_without_a_second_launch()
    {
        var transport = new FakeOciCreateNodeTransport();
        var keys = new AttestationKeys();
        using var client = new OciCreateNodeClient(transport, new TemplateSource(), keys.ProofSigner);

        var first = await client.CreateNodeAsync(Request("create-key-1"), CancellationToken.None);
        var second = await client.CreateNodeAsync(Request("create-key-1"), CancellationToken.None);

        await Assert.That(transport.Launches).Count().IsEqualTo(1);
        await Assert.That(second.NodeId).IsEqualTo(first.NodeId);
    }

    [Test]
    public async Task A_conflicted_launch_resolves_by_create_key_never_by_launching_again()
    {
        var transport = new FakeOciCreateNodeTransport
        {
            LaunchFailure = new OciException(HttpStatusCode.Conflict, "conflict", "request", "work"),
            AddMemberOnListCall = 2,
        };
        var keys = new AttestationKeys();
        using var client = new OciCreateNodeClient(transport, new TemplateSource(), keys.ProofSigner);

        var response = await client.CreateNodeAsync(Request("create-key-1"), CancellationToken.None);

        // Exactly one launch attempt, then resolution by the durable create key.
        await Assert.That(transport.LaunchAttempts).IsEqualTo(1);
        await Assert.That(transport.Launches).IsEmpty();
        await Assert.That(response.NodeId.Value).IsEqualTo(FakeOciCreateNodeTransport.TaggedInstanceId);
        // The resolved path reports the durable create key as the stable provider operation identity.
        await Assert.That(response.WorkRequestId.Value).IsEqualTo("create-key:create-key-1");
    }

    [Test]
    public async Task Reconcile_finds_the_create_key_or_reports_not_found_with_a_verifiable_proof()
    {
        var transport = new FakeOciCreateNodeTransport();
        var keys = new AttestationKeys();
        using var client = new OciCreateNodeClient(transport, new TemplateSource(), keys.ProofSigner);
        var request = Request("create-key-1");

        var missing = await client.ReconcileCreateNodeAsync(request, CancellationToken.None);
        await Assert.That(missing.Status).IsEqualTo(CreateNodeReconciliationStatus.NotFound);

        _ = await client.CreateNodeAsync(request, CancellationToken.None);
        var found = await client.ReconcileCreateNodeAsync(request, CancellationToken.None);
        await Assert.That(found.Status).IsEqualTo(CreateNodeReconciliationStatus.Found);
        await Assert.That(found.Response!.NodeId.Value).IsEqualTo(FakeOciCreateNodeTransport.LaunchedInstanceId);
        await Assert.That(CreateNodeProviderProofVerifier.Verify(found.Proof!, keys.ProviderKeys, request.Binding))
            .IsTrue();
    }

    [Test]
    public async Task An_unknown_template_or_mismatched_bootstrap_fails_closed()
    {
        var transport = new FakeOciCreateNodeTransport();
        using var client = new OciCreateNodeClient(
            transport, new TemplateSource(), new AttestationKeys().ProofSigner);

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await client.CreateNodeAsync(Request("create-key-1", templateId: "template-other"), CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await client.CreateNodeAsync(Request("create-key-1", bootstrapSha: new string('b', 64)), CancellationToken.None));
        await Assert.That(transport.Launches).IsEmpty();
    }

    private static CreateNodeProviderRequest Request(
        string createKey,
        string templateId = "template-member-gru",
        string? bootstrapSha = null) =>
        // The OciCreateNodeProvider wrapper has verified the signed handoff before the client runs;
        // only the binding and parameters reach the OCI calls.
        new(
            null!,
            new CreateNodeProviderParameters(new(templateId), new("placement-a"),
                new ProviderBootstrapEnvelopeDigest(bootstrapSha ?? Plan().BootstrapSha256)),
            new CreateNodeReceiptBinding(
                "op-1", "tenant-a", "node-request-1", "idempotency-1", createKey,
                "cell-a", Compartment, 7, 12, templateId, "placement-a",
                bootstrapSha ?? Plan().BootstrapSha256, 1, "auth-digest-1", "fingerprint-1"),
            null!,
            null!);

    internal static OciMemberHostLaunchPlan Plan()
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

    private sealed class TemplateSource : IOciCreateNodeTemplateSource
    {
        public bool TryResolve(ProviderTemplateId templateId, [NotNullWhen(true)] out OciMemberHostLaunchPlan? plan)
        {
            plan = templateId.Value == "template-member-gru" ? Plan() : null;
            return plan is not null;
        }
    }

    private sealed class AttestationKeys : IDisposable
    {
        private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public CreateNodeProviderProofSigner ProofSigner { get; }

        public ICreateNodeProviderAttestationKeyResolver ProviderKeys { get; }

        public AttestationKeys()
        {
            var publicKey = key.ExportSubjectPublicKeyInfo();
            var keyId = Convert.ToHexStringLower(SHA256.HashData(publicKey));
            ProofSigner = new(keyId, key);
            ProviderKeys = new CreateNodeProviderAttestationKeyRing(
                new Dictionary<string, byte[]> { [keyId] = publicKey });
        }

        public void Dispose() => key.Dispose();
    }

    /// <summary>A counting fake over the member-host transport seam: no real OCI is touched.</summary>
    private sealed class FakeOciCreateNodeTransport : IOciMemberHostComputeTransport
    {
        internal const string LaunchedInstanceId = "ocid1.instance.oc1.sa-saopaulo-1.launched-1";
        internal const string TaggedInstanceId = "ocid1.instance.oc1.sa-saopaulo-1.tagged-1";

        private readonly List<Instance> instances = [];
        private int listCalls;
        private int launches;

        public List<LaunchInstanceRequest> Launches { get; } = [];
        public int LaunchAttempts { get; private set; }
        public Exception? LaunchFailure { get; set; }
        public int AddMemberOnListCall { get; set; }

        public Task<Oci.CoreService.Responses.ListInstancesResponse> ListInstancesAsync(
            ListInstancesRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            listCalls++;
            if (listCalls == AddMemberOnListCall)
                instances.Add(TaggedMember("create-key-1"));
            return Task.FromResult(new Oci.CoreService.Responses.ListInstancesResponse
            {
                Items = [.. instances],
            });
        }

        public Task<Oci.CoreService.Responses.GetInstanceResponse> GetInstanceAsync(
            GetInstanceRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<Oci.CoreService.Responses.LaunchInstanceResponse> LaunchInstanceAsync(
            LaunchInstanceRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LaunchAttempts++;
            if (LaunchFailure is { } failure)
            {
                LaunchFailure = null;
                throw failure;
            }
            Launches.Add(request);
            launches++;
            instances.Add(TaggedMember(request.OpcRetryToken ?? $"launch-{launches}", LaunchedInstanceId));
            return Task.FromResult(new Oci.CoreService.Responses.LaunchInstanceResponse
            {
                Instance = instances.Single(instance => instance.Id == LaunchedInstanceId),
                Etag = "etag-launched",
                OpcWorkRequestId = $"work-launched-{launches}",
                OpcRequestId = "request-launched",
            });
        }

        public Task<Oci.CoreService.Responses.TerminateInstanceResponse> TerminateInstanceAsync(
            TerminateInstanceRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<Oci.CoreService.Responses.UpdateInstanceResponse> UpdateInstanceAsync(
            UpdateInstanceRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<Oci.CoreService.Responses.ListBootVolumeAttachmentsResponse> ListBootVolumeAttachmentsAsync(
            ListBootVolumeAttachmentsRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<Oci.CoreService.Responses.ListVnicAttachmentsResponse> ListVnicAttachmentsAsync(
            ListVnicAttachmentsRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<Oci.CoreService.Responses.GetVnicResponse> GetVnicAsync(
            GetVnicRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<Oci.CoreService.Responses.ListVolumeAttachmentsResponse> ListVolumeAttachmentsAsync(
            ListVolumeAttachmentsRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<Oci.CoreService.Responses.AttachVolumeResponse> AttachVolumeAsync(
            AttachVolumeRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<Oci.CoreService.Responses.DetachVolumeResponse> DetachVolumeAsync(
            DetachVolumeRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public void Dispose()
        {
        }

        private static Instance TaggedMember(string createKey, string id = TaggedInstanceId) => new()
        {
            Id = id,
            CompartmentId = Compartment,
            AvailabilityDomain = "sa-saopaulo-1-ad-1",
            LifecycleState = Instance.LifecycleStateEnum.Running,
            FreeformTags = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["terrascale-owner"] = "orchestrator",
                ["terrascale-role"] = "terrabase-member",
                ["terrascale-create-key"] = createKey,
            },
        };
    }
}
