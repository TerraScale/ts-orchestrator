using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Oci.Common;
using Oci.Common.Auth;
using Oci.Common.Model;
using Oci.CoreService;
using Oci.CoreService.Models;
using Oci.CoreService.Requests;
using TerraScale.Orchestrator.ControlPlane.TerraBase;
using TerraScale.Orchestrator.Nodes;

namespace TerraScale.Orchestrator.ControlPlane.Providers;

/// <summary>
/// One member-host launch: the exact OCI launch template plus the member identity tags and
/// bootstrap envelope the instance carries for its whole lifetime. The bootstrap is validated
/// against its digest exactly like a CI runner demand, so an owned member host can always be
/// re-derived from its tags.
/// </summary>
internal sealed record OciMemberHostLaunchPlan
{
    private const int MaximumBootstrapBytes = 32 * 1024;

    internal OciMemberHostLaunchPlan(
        OciCiRunnerLaunchTemplate template,
        string database,
        string memberId,
        string region,
        string bootstrapCloudInitBase64,
        string bootstrapSha256)
    {
        Template = template ?? throw new ArgumentNullException(nameof(template));
        Database = Bounded(database, 128, nameof(database));
        MemberId = Bounded(memberId, 128, nameof(memberId));
        if (!TerraBaseRegionCode.TryCreate(region, out var code))
            throw new ArgumentException("The member host region is not a TerraBase region.", nameof(region));
        Region = code.Value;
        var decoded = new byte[MaximumBootstrapBytes + 1];
        if (!Convert.TryFromBase64String(bootstrapCloudInitBase64, decoded, out var bytes) ||
            bytes is < 1 or > MaximumBootstrapBytes ||
            Convert.ToHexStringLower(SHA256.HashData(decoded.AsSpan(0, bytes))) != bootstrapSha256)
            throw new ArgumentException("The member host bootstrap is invalid.", nameof(bootstrapCloudInitBase64));
        BootstrapCloudInitBase64 = bootstrapCloudInitBase64;
        BootstrapSha256 = bootstrapSha256;
    }

    internal OciCiRunnerLaunchTemplate Template { get; }
    internal string Database { get; }
    internal string MemberId { get; }
    internal string Region { get; }
    internal string BootstrapCloudInitBase64 { get; }
    internal string BootstrapSha256 { get; }

    /// <summary>The stable subject-safe identity of the member this host runs.</summary>
    internal string IdentityHash => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes($"{Database}:{MemberId}")));

    internal static string Bounded(string value, int maximum, string parameter) =>
        value is { Length: > 0 } && value.Length <= maximum &&
        value.All(static character => !char.IsWhiteSpace(character) && !char.IsControl(character))
            ? value
            : throw new ArgumentException("A member host identity value is invalid.", parameter);
}

/// <summary>Compiles the exact OCI requests for member hosts: idempotent creates, exact-instance terminate, tag-fenced cordon.</summary>
internal static class OciMemberHostRequestCompiler
{
    internal const string OwnerTag = "terrascale-owner";
    internal const string RoleTag = "terrascale-role";
    internal const string DatabaseTag = "terrascale-database";
    internal const string MemberTag = "terrascale-member";
    internal const string RegionTag = "terrascale-region";
    internal const string BootstrapTag = "terrascale-bootstrap-sha256";
    internal const string CreateKeyTag = "terrascale-create-key";
    internal const string CordonTag = "terrascale-cordoned";

    internal static IReadOnlyDictionary<string, string> Tags(OciMemberHostLaunchPlan plan, string createKey)
    {
        ArgumentNullException.ThrowIfNull(plan);
        OciMemberHostLaunchPlan.Bounded(createKey, 256, nameof(createKey));
        return new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [OwnerTag] = "orchestrator",
            [RoleTag] = "terrabase-member",
            [DatabaseTag] = plan.Database,
            [MemberTag] = plan.MemberId,
            [RegionTag] = plan.Region,
            [BootstrapTag] = plan.BootstrapSha256,
            [CreateKeyTag] = createKey,
        });
    }

    internal static LaunchInstanceRequest Launch(OciMemberHostLaunchPlan plan, string createKey)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var hash = plan.IdentityHash;
        return new LaunchInstanceRequest
        {
            // The create key is the provider idempotency token: a retried create resolves to the
            // same instance, never a second one.
            OpcRetryToken = OciMemberHostLaunchPlan.Bounded(createKey, 256, nameof(createKey)),
            LaunchInstanceDetails = new LaunchInstanceDetails
            {
                AvailabilityDomain = plan.Template.AvailabilityDomain,
                FaultDomain = plan.Template.FaultDomain,
                CompartmentId = plan.Template.CompartmentId,
                DisplayName = $"terrabase-member-{hash[..16]}",
                HostnameLabel = $"tb-{hash[..16]}",
                // ponytail: one pinned shape for every member host v1; a per-template shape field
                // when members actually need heterogeneous capacity.
                Shape = OciCiRunnerRequestCompiler.Shape,
                ShapeConfig = new LaunchInstanceShapeConfigDetails
                {
                    Ocpus = OciCiRunnerRequestCompiler.Ocpus,
                    MemoryInGBs = OciCiRunnerRequestCompiler.MemoryInGbs,
                },
                SourceDetails = new InstanceSourceViaImageDetails
                {
                    ImageId = plan.Template.ImageId,
                    BootVolumeSizeInGBs = 50,
                    BootVolumeVpusPerGB = 10,
                },
                CreateVnicDetails = new CreateVnicDetails
                {
                    SubnetId = plan.Template.SubnetId,
                    NsgIds = plan.Template.NetworkSecurityGroupIds.ToList(),
                    AssignPublicIp = false,
                    AssignIpv6Ip = false,
                    AssignPrivateDnsRecord = false,
                },
                // Members are deliberately never preemptible: a member losing its host to provider
                // preemption is an availability event, not a cost lever. There is no
                // PreemptibleInstanceConfig, and the boot volume is pinned in the source details;
                // it is destroyed only at retire, after every data volume has been detached.
                Metadata = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["user_data"] = plan.BootstrapCloudInitBase64,
                },
                FreeformTags = new Dictionary<string, string>(Tags(plan, createKey), StringComparer.Ordinal),
                IsPvEncryptionInTransitEnabled = true,
            },
        };
    }

    internal static TerminateInstanceRequest Terminate(string instanceId, string etag)
    {
        if (string.IsNullOrWhiteSpace(instanceId) || string.IsNullOrWhiteSpace(etag))
            throw new ArgumentException("Member host retirement requires the exact instance and ETag fence.");
        return new()
        {
            InstanceId = instanceId,
            // Exact-instance retirement: the ETag fence never resolves by name or tag alone.
            IfMatch = etag,
            PreserveBootVolume = false,
            PreserveDataVolumesCreatedAtLaunch = false,
        };
    }

    internal static UpdateInstanceRequest Cordon(
        string instanceId,
        string etag,
        IReadOnlyDictionary<string, string> freeformTags)
    {
        if (string.IsNullOrWhiteSpace(instanceId) || string.IsNullOrWhiteSpace(etag))
            throw new ArgumentException("Member host cordon requires the exact instance and ETag fence.");
        ArgumentNullException.ThrowIfNull(freeformTags);
        var tags = new Dictionary<string, string>(freeformTags, StringComparer.Ordinal)
        {
            [CordonTag] = "true",
        };
        return new UpdateInstanceRequest
        {
            InstanceId = instanceId,
            IfMatch = etag,
            UpdateInstanceDetails = new UpdateInstanceDetails { FreeformTags = tags },
        };
    }
}

/// <summary>The member-host state mapping; any provider state the fleet does not know is provisioning.</summary>
internal static class OciMemberHostStates
{
    internal static MemberHostState State(Instance.LifecycleStateEnum? state) => state switch
    {
        Instance.LifecycleStateEnum.Running => MemberHostState.Running,
        Instance.LifecycleStateEnum.Stopped => MemberHostState.Stopped,
        Instance.LifecycleStateEnum.Terminating => MemberHostState.Terminating,
        Instance.LifecycleStateEnum.Terminated => MemberHostState.Terminated,
        null => MemberHostState.Unknown,
        _ => MemberHostState.Provisioning,
    };
}

/// <summary>Ownership and create-key resolution shared by the fleet and the CreateNode client.</summary>
internal static class OciMemberHostInstances
{
    internal const string Owner = "orchestrator";
    internal const string Role = "terrabase-member";
    private const int MaximumMatches = 8;

    internal static bool Owned(IReadOnlyDictionary<string, string> tags) =>
        tags.TryGetValue(OciMemberHostRequestCompiler.OwnerTag, out var owner) && owner == Owner &&
        tags.TryGetValue(OciMemberHostRequestCompiler.RoleTag, out var role) && role == Role;

    /// <summary>
    /// Resolves the exact instance one create key produced. This is the recovery path for a lost
    /// launch response and the idempotency check before every create: the durable create key —
    /// never a name or display label — identifies the instance.
    /// </summary>
    internal static async Task<Instance?> FindByCreateKeyAsync(
        IOciMemberHostComputeTransport transport,
        string compartmentId,
        string createKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transport);
        if (string.IsNullOrWhiteSpace(compartmentId) || string.IsNullOrWhiteSpace(createKey))
            throw new ArgumentException("Member host create-key resolution requires a compartment and create key.");
        var matches = new List<Instance>();
        string? page = null;
        do
        {
            var response = await transport.ListInstancesAsync(
                new ListInstancesRequest
                {
                    CompartmentId = compartmentId,
                    Limit = 100,
                    Page = page,
                    SortBy = ListInstancesRequest.SortByEnum.Timecreated,
                    SortOrder = ListInstancesRequest.SortOrderEnum.Asc,
                },
                cancellationToken);
            foreach (var instance in response.Items ?? [])
            {
                var tags = instance.FreeformTags;
                if (tags is null || !Owned(tags) ||
                    !tags.TryGetValue(OciMemberHostRequestCompiler.CreateKeyTag, out var key) || key != createKey)
                    continue;
                matches.Add(instance);
                if (matches.Count > MaximumMatches)
                    throw new InvalidDataException("Member host create-key resolution exceeded its bound.");
            }
            page = response.OpcNextPage;
        }
        while (!string.IsNullOrEmpty(page));
        return matches.Count switch
        {
            0 => null,
            1 => matches[0],
            _ => throw new InvalidDataException("One member host create key resolves to more than one instance."),
        };
    }
}

/// <summary>The single-attempt OCI transport for member hosts: the CI runner compute seam plus the mutation and volume reads a fleet needs.</summary>
internal interface IOciMemberHostComputeTransport : IOciCiRunnerComputeTransport
{
    Task<Oci.CoreService.Responses.UpdateInstanceResponse> UpdateInstanceAsync(
        UpdateInstanceRequest request, CancellationToken cancellationToken);

    Task<Oci.CoreService.Responses.ListBootVolumeAttachmentsResponse> ListBootVolumeAttachmentsAsync(
        ListBootVolumeAttachmentsRequest request, CancellationToken cancellationToken);

    Task<Oci.CoreService.Responses.ListVolumeAttachmentsResponse> ListVolumeAttachmentsAsync(
        ListVolumeAttachmentsRequest request, CancellationToken cancellationToken);

    Task<Oci.CoreService.Responses.AttachVolumeResponse> AttachVolumeAsync(
        AttachVolumeRequest request, CancellationToken cancellationToken);

    Task<Oci.CoreService.Responses.DetachVolumeResponse> DetachVolumeAsync(
        DetachVolumeRequest request, CancellationToken cancellationToken);
}

/// <summary>Generated-OCI-client transport with instance-principal authentication for member hosts; composes the CI runner compute seam.</summary>
internal sealed class OciMemberHostSdkTransport(
    ComputeClient compute,
    IOciCiRunnerComputeTransport baseTransport) : IOciMemberHostComputeTransport
{
    private readonly ComputeClient compute = compute ?? throw new ArgumentNullException(nameof(compute));
    private readonly IOciCiRunnerComputeTransport baseTransport = baseTransport ?? throw new ArgumentNullException(nameof(baseTransport));

    internal OciMemberHostSdkTransport(ComputeClient compute, VirtualNetworkClient network)
        : this(compute, new OciCiRunnerSdkTransport(compute, network))
    {
    }

    internal static OciMemberHostSdkTransport CreateForInstancePrincipal(string endpoint)
    {
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(uri.UserInfo) || uri.AbsolutePath != "/" || !string.IsNullOrEmpty(uri.Query) ||
            !uri.Host.StartsWith("iaas.", StringComparison.Ordinal) || !uri.Host.EndsWith(".oraclecloud.com", StringComparison.Ordinal))
            throw new ArgumentException("The OCI Compute endpoint is invalid.", nameof(endpoint));
        var provider = new InstancePrincipalsAuthenticationDetailsProvider();
        var configuration = new ClientConfiguration { TimeoutMillis = 30_000 };
        var endpointUri = uri.ToString().TrimEnd('/');
        var compute = new ComputeClient(provider, configuration, endpointUri);
        try
        {
            return new(compute, new OciCiRunnerSdkTransport(compute, new(provider, configuration, endpointUri)));
        }
        catch
        {
            compute.Dispose();
            throw;
        }
    }

    public Task<Oci.CoreService.Responses.ListInstancesResponse> ListInstancesAsync(
        ListInstancesRequest request, CancellationToken cancellationToken) =>
        baseTransport.ListInstancesAsync(request, cancellationToken);

    public Task<Oci.CoreService.Responses.GetInstanceResponse> GetInstanceAsync(
        GetInstanceRequest request, CancellationToken cancellationToken) =>
        baseTransport.GetInstanceAsync(request, cancellationToken);

    public Task<Oci.CoreService.Responses.ListVnicAttachmentsResponse> ListVnicAttachmentsAsync(
        ListVnicAttachmentsRequest request, CancellationToken cancellationToken) =>
        baseTransport.ListVnicAttachmentsAsync(request, cancellationToken);

    public Task<Oci.CoreService.Responses.GetVnicResponse> GetVnicAsync(
        GetVnicRequest request, CancellationToken cancellationToken) =>
        baseTransport.GetVnicAsync(request, cancellationToken);

    public Task<Oci.CoreService.Responses.LaunchInstanceResponse> LaunchInstanceAsync(
        LaunchInstanceRequest request, CancellationToken cancellationToken) =>
        baseTransport.LaunchInstanceAsync(request, cancellationToken);

    public Task<Oci.CoreService.Responses.TerminateInstanceResponse> TerminateInstanceAsync(
        TerminateInstanceRequest request, CancellationToken cancellationToken) =>
        baseTransport.TerminateInstanceAsync(request, cancellationToken);

    public Task<Oci.CoreService.Responses.UpdateInstanceResponse> UpdateInstanceAsync(
        UpdateInstanceRequest request, CancellationToken cancellationToken) =>
        compute.UpdateInstance(request, null, cancellationToken, HttpCompletionOption.ResponseHeadersRead);

    public Task<Oci.CoreService.Responses.ListBootVolumeAttachmentsResponse> ListBootVolumeAttachmentsAsync(
        ListBootVolumeAttachmentsRequest request, CancellationToken cancellationToken) =>
        compute.ListBootVolumeAttachments(request, null, cancellationToken, HttpCompletionOption.ResponseHeadersRead);

    public Task<Oci.CoreService.Responses.ListVolumeAttachmentsResponse> ListVolumeAttachmentsAsync(
        ListVolumeAttachmentsRequest request, CancellationToken cancellationToken) =>
        compute.ListVolumeAttachments(request, null, cancellationToken, HttpCompletionOption.ResponseHeadersRead);

    public Task<Oci.CoreService.Responses.AttachVolumeResponse> AttachVolumeAsync(
        AttachVolumeRequest request, CancellationToken cancellationToken) =>
        compute.AttachVolume(request, null, cancellationToken, HttpCompletionOption.ResponseHeadersRead);

    public Task<Oci.CoreService.Responses.DetachVolumeResponse> DetachVolumeAsync(
        DetachVolumeRequest request, CancellationToken cancellationToken) =>
        compute.DetachVolume(request, null, cancellationToken, HttpCompletionOption.ResponseHeadersRead);

    public void Dispose()
    {
        baseTransport.Dispose();
        compute.Dispose();
    }
}

/// <summary>Resolves the configured launch plan behind one provider template identity.</summary>
internal interface IOciCreateNodeTemplateSource
{
    bool TryResolve(ProviderTemplateId templateId, [NotNullWhen(true)] out OciMemberHostLaunchPlan? plan);
}

/// <summary>
/// The production OCI CreateNode mutation client: the durable create key becomes both the launch
/// idempotency token and the ownership tag a lost response is reconciled by. The
/// <see cref="OciCreateNodeProvider"/> wrapper has already verified the exact signed handoff when
/// this client is reached.
/// </summary>
internal sealed class OciCreateNodeClient(
    IOciMemberHostComputeTransport transport,
    IOciCreateNodeTemplateSource templates,
    CreateNodeProviderProofSigner proofSigner) : IOciCreateNodeClient, IDisposable
{
    private readonly IOciMemberHostComputeTransport transport = transport ?? throw new ArgumentNullException(nameof(transport));
    private readonly IOciCreateNodeTemplateSource templates = templates ?? throw new ArgumentNullException(nameof(templates));
    private readonly CreateNodeProviderProofSigner proofSigner = proofSigner ?? throw new ArgumentNullException(nameof(proofSigner));

    public async ValueTask<CreateNodeProviderResponse> CreateNodeAsync(
        CreateNodeProviderRequest request, CancellationToken cancellationToken)
    {
        var plan = Plan(request);
        // The durable create key resolves to at most one instance: a repeated create never
        // launches a second host.
        var existing = await OciMemberHostInstances.FindByCreateKeyAsync(
            transport, plan.Template.CompartmentId, request.Binding.CreateKey, cancellationToken);
        if (existing is not null)
            return Resolved(request.Binding.CreateKey, existing.Id);
        Oci.CoreService.Responses.LaunchInstanceResponse response;
        try
        {
            response = await transport.LaunchInstanceAsync(
                OciMemberHostRequestCompiler.Launch(plan, request.Binding.CreateKey), cancellationToken);
        }
        catch (OciException failure) when ((int)failure.StatusCode is (int)HttpStatusCode.Conflict or (int)HttpStatusCode.TooManyRequests)
        {
            // The idempotency token already produced this instance, or the call was throttled
            // before it mutated: resolve by the durable create key, never by launching again.
            var resolved = await OciMemberHostInstances.FindByCreateKeyAsync(
                transport, plan.Template.CompartmentId, request.Binding.CreateKey, cancellationToken);
            if (resolved is not null)
                return Resolved(request.Binding.CreateKey, resolved.Id);
            throw;
        }
        var instance = response.Instance ??
            throw new InvalidDataException("OCI returned no launched member host instance.");
        return new(
            new(instance.Id),
            new ProviderWorkRequestId(response.OpcWorkRequestId ?? string.Empty));
    }

    public async ValueTask<CreateNodeReconciliation> ReconcileCreateNodeAsync(
        CreateNodeProviderRequest request, CancellationToken cancellationToken)
    {
        var plan = Plan(request);
        var instance = await OciMemberHostInstances.FindByCreateKeyAsync(
            transport, plan.Template.CompartmentId, request.Binding.CreateKey, cancellationToken);
        if (instance is null)
            return new(CreateNodeReconciliationStatus.NotFound, null, null);
        var response = Resolved(request.Binding.CreateKey, instance.Id);
        return CreateNodeReconciliation.Found(response, proofSigner.Sign(request.Binding, response));
    }

    private static CreateNodeProviderResponse Resolved(string createKey, string instanceId) =>
        // A create key resolved from tags has no live work request; the durable key is the stable
        // provider operation identity for the reconciled path.
        new(new(instanceId), new ProviderWorkRequestId($"create-key:{createKey}"));

    private OciMemberHostLaunchPlan Plan(CreateNodeProviderRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!templates.TryResolve(request.Parameters.TemplateId, out var plan))
            throw new InvalidOperationException(
                $"The OCI CreateNode template {request.Parameters.TemplateId.Value} is not configured for this composition.");
        if (request.Binding.BootstrapEnvelopeDigest != plan.BootstrapSha256)
            throw new InvalidOperationException(
                "The OCI CreateNode bootstrap envelope differs from the configured member bootstrap.");
        return plan;
    }

    public void Dispose() => transport.Dispose();
}
