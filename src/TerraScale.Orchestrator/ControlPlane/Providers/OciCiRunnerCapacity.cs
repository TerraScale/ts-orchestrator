using System.Collections.ObjectModel;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using Oci.Common;
using Oci.Common.Auth;
using Oci.Common.Model;
using Oci.CoreService;
using Oci.CoreService.Models;
using Oci.CoreService.Requests;
using Oci.WorkrequestsService;
using Oci.WorkrequestsService.Requests;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Providers;

internal enum OciCiRunnerNodeState
{
    Launching,
    Running,
    Stopped,
    Terminating,
    Terminated,
}

internal sealed record OciCiRunnerDemand
{
    // OCI retains user_data in instance metadata. This payload is bootstrap code or an
    // encrypted reference only; the runner obtains scoped credentials after mTLS admission.
    internal OciCiRunnerDemand(
        string runner,
        TrustZone zone,
        long sequence,
        string bootstrapCloudInitBase64,
        string bootstrapSha256)
    {
        _ = GlobalNatsTopology.CiRunnerIdentityHash(runner);
        if (zone is not (TrustZone.UntrustedProduct or TrustZone.TrustedBuild) || sequence <= 0)
            throw new ArgumentOutOfRangeException(nameof(zone));
        var decoded = new byte[32 * 1024 + 1];
        if (!Convert.TryFromBase64String(bootstrapCloudInitBase64, decoded, out var bytes) ||
            bytes is < 1 or > 32 * 1024 ||
            Convert.ToHexStringLower(SHA256.HashData(decoded.AsSpan(0, bytes))) != bootstrapSha256)
            throw new ArgumentException("The OCI CI runner bootstrap is invalid.", nameof(bootstrapCloudInitBase64));
        Runner = runner;
        Zone = zone;
        Sequence = sequence;
        BootstrapCloudInitBase64 = bootstrapCloudInitBase64;
        BootstrapSha256 = bootstrapSha256;
        IdempotencyToken = $"ci-{Hash($"{runner}:{sequence}:{bootstrapSha256}")}";
    }

    internal string Runner { get; }
    internal TrustZone Zone { get; }
    internal long Sequence { get; }
    internal string BootstrapCloudInitBase64 { get; }
    internal string BootstrapSha256 { get; }
    internal string IdempotencyToken { get; }

    private static string Hash(string value) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..48];
}

internal sealed record OciCiRunnerNodeObservation(
    string InstanceId,
    string ETag,
    string Runner,
    long Sequence,
    OciCiRunnerNodeState State,
    bool ActiveJob,
    DateTimeOffset LastActivity,
    bool Preemptible,
    bool PreserveBootVolume,
    IReadOnlyDictionary<string, string> FreeformTags);

internal sealed class OciCiRunnerLaunchTemplate
{
    internal OciCiRunnerLaunchTemplate(
        string compartmentId,
        string availabilityDomain,
        string? faultDomain,
        string subnetId,
        IEnumerable<string> networkSecurityGroupIds,
        string imageId,
        long generation)
    {
        CompartmentId = Ocid(compartmentId, "compartment");
        AvailabilityDomain = Bounded(availabilityDomain, 128, nameof(availabilityDomain));
        FaultDomain = string.IsNullOrWhiteSpace(faultDomain)
            ? null
            : Bounded(faultDomain, 64, nameof(faultDomain));
        SubnetId = Ocid(subnetId, "subnet");
        ImageId = Ocid(imageId, "image");
        if (generation <= 0) throw new ArgumentOutOfRangeException(nameof(generation));
        Generation = generation;
        var groups = networkSecurityGroupIds?.ToArray() ??
            throw new ArgumentNullException(nameof(networkSecurityGroupIds));
        if (groups.Length is < 1 or > 5 || groups.Distinct(StringComparer.Ordinal).Count() != groups.Length)
            throw new ArgumentException("OCI CI runners require one to five distinct NSGs.",
                nameof(networkSecurityGroupIds));
        NetworkSecurityGroupIds = Array.AsReadOnly(groups.Select(id => Ocid(id, "networksecuritygroup")).ToArray());
    }

    internal string CompartmentId { get; }
    internal string AvailabilityDomain { get; }
    internal string? FaultDomain { get; }
    internal string SubnetId { get; }
    internal ReadOnlyCollection<string> NetworkSecurityGroupIds { get; }
    internal string ImageId { get; }
    internal long Generation { get; }

    private static string Ocid(string value, string kind) =>
        value is { Length: >= 12 and <= 255 } && value.StartsWith($"ocid1.{kind}", StringComparison.Ordinal) &&
        value.All(static character => !char.IsWhiteSpace(character) && !char.IsControl(character))
            ? value
            : throw new ArgumentException($"The OCI {kind} OCID is invalid.");

    private static string Bounded(string value, int maximum, string parameter) =>
        value is { Length: > 0 } && value.Length <= maximum && value.All(static character => !char.IsControl(character))
            ? value
            : throw new ArgumentException("An OCI placement value is invalid.", parameter);
}

internal sealed class OciCiRunnerCapacityRequest
{
    /// <summary>
    /// OCI control-plane timestamps can sit marginally ahead of the controller clock (NTP skew).
    /// A future-dated observation inside this window is accepted; a zero-tolerance check would
    /// permanently terminate the CI event that observed it for a two-second clock difference.
    /// </summary>
    private static readonly TimeSpan AllowedClockSkew = TimeSpan.FromSeconds(2);

    internal OciCiRunnerCapacityRequest(
        DateTimeOffset now,
        TimeSpan idleTimeout,
        int maximumNodes,
        OciCiRunnerLaunchTemplate launchTemplate,
        IEnumerable<OciCiRunnerDemand> permitted,
        IEnumerable<OciCiRunnerDemand> desired,
        IEnumerable<OciCiRunnerNodeObservation> observed)
    {
        if (now.ToUnixTimeMilliseconds() <= 0) throw new ArgumentOutOfRangeException(nameof(now));
        if (idleTimeout < TimeSpan.FromSeconds(30) || idleTimeout > TimeSpan.FromMinutes(15))
            throw new ArgumentOutOfRangeException(nameof(idleTimeout));
        if (maximumNodes is < 1 or > 256) throw new ArgumentOutOfRangeException(nameof(maximumNodes));
        Now = now;
        IdleTimeout = idleTimeout;
        MaximumNodes = maximumNodes;
        LaunchTemplate = launchTemplate ?? throw new ArgumentNullException(nameof(launchTemplate));
        Permitted = Snapshot(permitted, maximumNodes, nameof(permitted));
        Desired = Snapshot(desired, maximumNodes, nameof(desired));
        Observed = Snapshot(observed, 512, nameof(observed));
        var permittedByIdentity = Permitted.ToDictionary(
            static item => $"{item.Runner}:{item.Sequence}",
            StringComparer.Ordinal);
        if (Permitted.Count == 0 || permittedByIdentity.Count != Permitted.Count ||
            Desired.Select(static item => $"{item.Runner}:{item.Sequence}").Distinct(StringComparer.Ordinal).Count() !=
                Desired.Count || Desired.Any(item => !permittedByIdentity.TryGetValue(
                    $"{item.Runner}:{item.Sequence}", out var configured) ||
                    configured.Zone != item.Zone || configured.BootstrapSha256 != item.BootstrapSha256) ||
            Observed.Select(static item => item.InstanceId).Distinct(StringComparer.Ordinal).Count() != Observed.Count)
            throw new ArgumentException("OCI CI runner capacity evidence contains a duplicate identity.");
        foreach (var node in Observed)
        {
            _ = new ProviderResourceId(node.InstanceId);
            _ = GlobalNatsTopology.CiRunnerIdentityHash(node.Runner);
            if (node.Sequence <= 0 || !Enum.IsDefined(node.State) ||
                node.LastActivity > now.Add(AllowedClockSkew) ||
                node.FreeformTags is null || node.FreeformTags.Count > 16)
                throw new ArgumentException("An OCI CI runner observation is invalid.", nameof(observed));
        }
    }

    internal DateTimeOffset Now { get; }
    internal TimeSpan IdleTimeout { get; }
    internal int MaximumNodes { get; }
    internal OciCiRunnerLaunchTemplate LaunchTemplate { get; }
    internal IReadOnlyList<OciCiRunnerDemand> Permitted { get; }
    internal IReadOnlyList<OciCiRunnerDemand> Desired { get; }
    internal IReadOnlyList<OciCiRunnerNodeObservation> Observed { get; }

    private static IReadOnlyList<T> Snapshot<T>(IEnumerable<T> values, int maximum, string parameter)
    {
        ArgumentNullException.ThrowIfNull(values, parameter);
        var captured = values.Take(maximum + 1).ToArray();
        if (captured.Length > maximum || captured.Any(static value => value is null))
            throw new ArgumentException("OCI CI runner capacity input exceeded its bound.", parameter);
        return Array.AsReadOnly(captured);
    }
}

internal abstract record OciCiRunnerCapacityAction;
internal sealed record LaunchOciCiRunnerAction(
    OciCiRunnerDemand Demand,
    OciCiRunnerLaunchTemplate Template) : OciCiRunnerCapacityAction;
internal sealed record TerminateOciCiRunnerAction(
    string InstanceId,
    string ETag) : OciCiRunnerCapacityAction;

/// <summary>Scales exact standalone preemptible runners and selects only owned idle nodes for deletion.</summary>
internal static class OciCiRunnerCapacityEngine
{
    private const string OwnerTag = "terrascale-owner";
    private const string RoleTag = "terrascale-role";
    private const string RunnerTag = "terrascale-runner";
    private const string SequenceTag = "terrascale-runner-sequence";

    internal static IReadOnlyList<OciCiRunnerCapacityAction> Decide(OciCiRunnerCapacityRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var desired = request.Desired.ToDictionary(
            static demand => $"{demand.Runner}:{demand.Sequence}",
            StringComparer.Ordinal);
        var live = request.Observed.Where(static node => node.State is not OciCiRunnerNodeState.Terminated).ToArray();
        var managed = live.Where(node => request.Permitted.Any(demand =>
            demand.Runner == node.Runner && demand.Sequence == node.Sequence &&
            Matches(node, demand, request.LaunchTemplate))).ToArray();
        foreach (var demand in request.Desired)
        {
            // An exact identity claimed by two live nodes, or worn by a node this pool does not
            // own, is genuinely ambiguous and fails closed. A single owned node with the same
            // identity but a stale generation/bootstrap is ordinary rotation, not ambiguity.
            var collisions = live.Where(node => node.Runner == demand.Runner && node.Sequence == demand.Sequence).ToArray();
            if (collisions.Length > 1 || collisions.Any(node => !Owned(node)))
                throw new InvalidDataException("An OCI CI runner identity has ambiguous provider ownership.");
        }

        var actions = new List<OciCiRunnerCapacityAction>();
        foreach (var node in live.Where(node => Owned(node) && !managed.Contains(node) &&
                     node.State is OciCiRunnerNodeState.Launching or OciCiRunnerNodeState.Running or
                         OciCiRunnerNodeState.Stopped)
                     .OrderBy(static node => node.InstanceId, StringComparer.Ordinal))
        {
            // Rotation reconciliation: an owned node that no longer matches the current pool
            // identity (generation, bootstrap, or sequence rotation) is retired deterministically.
            // The idle loop below only ever reaches matching nodes, so without this branch every
            // rotation would leak a billed instance and its boot volume forever.
            if (string.IsNullOrWhiteSpace(node.ETag))
                throw new InvalidDataException("A drifted OCI CI runner has no exact ETag fence.");
            actions.Add(new TerminateOciCiRunnerAction(node.InstanceId, node.ETag));
        }
        foreach (var node in managed.OrderBy(static node => node.InstanceId, StringComparer.Ordinal))
        {
            var stopped = node.State == OciCiRunnerNodeState.Stopped;
            if (!Owned(node) || node.State is not (OciCiRunnerNodeState.Running or OciCiRunnerNodeState.Stopped) ||
                !stopped && (node.ActiveJob || desired.ContainsKey($"{node.Runner}:{node.Sequence}") ||
                    request.Now - node.LastActivity < request.IdleTimeout))
                continue;
            if (string.IsNullOrWhiteSpace(node.ETag))
                throw new InvalidDataException("An idle OCI CI runner has no exact ETag fence.");
            actions.Add(new TerminateOciCiRunnerAction(node.InstanceId, node.ETag));
        }

        var available = Math.Max(0, request.MaximumNodes - managed.Length);
        foreach (var demand in request.Desired
                     .Where(demand => managed.All(node =>
                         node.Runner != demand.Runner || node.Sequence != demand.Sequence))
                     .OrderBy(static demand => demand.Runner, StringComparer.Ordinal)
                     .ThenBy(static demand => demand.Sequence)
                     .Take(available))
            actions.Add(new LaunchOciCiRunnerAction(demand, request.LaunchTemplate));
        return Array.AsReadOnly(actions.ToArray());
    }

    internal static IReadOnlyDictionary<string, string> Tags(OciCiRunnerDemand demand, long generation) =>
        new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [OwnerTag] = "orchestrator",
            [RoleTag] = "ci-runner",
            [RunnerTag] = demand.Runner,
            [SequenceTag] = demand.Sequence.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["terrascale-zone"] = demand.Zone == TrustZone.UntrustedProduct ? "untrusted-product" : "trusted-build",
            ["terrascale-generation"] = generation.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["terrascale-bootstrap-sha256"] = demand.BootstrapSha256,
        });

    private static bool Owned(OciCiRunnerNodeObservation node) =>
        node.Preemptible && !node.PreserveBootVolume &&
        node.FreeformTags.TryGetValue(OwnerTag, out var owner) && owner == "orchestrator" &&
        node.FreeformTags.TryGetValue(RoleTag, out var role) && role == "ci-runner" &&
        node.FreeformTags.TryGetValue(RunnerTag, out var runner) && runner == node.Runner &&
        node.FreeformTags.TryGetValue(SequenceTag, out var sequence) &&
        sequence == node.Sequence.ToString(System.Globalization.CultureInfo.InvariantCulture);

    internal static bool Matches(
        OciCiRunnerNodeObservation node,
        OciCiRunnerDemand demand,
        OciCiRunnerLaunchTemplate template) =>
        Owned(node) && node.FreeformTags.TryGetValue("terrascale-zone", out var zone) &&
        zone == (demand.Zone == TrustZone.UntrustedProduct ? "untrusted-product" : "trusted-build") &&
        node.FreeformTags.TryGetValue("terrascale-generation", out var generation) &&
        generation == template.Generation.ToString(System.Globalization.CultureInfo.InvariantCulture) &&
        node.FreeformTags.TryGetValue("terrascale-bootstrap-sha256", out var bootstrap) &&
        bootstrap == demand.BootstrapSha256;
}

internal static class OciCiRunnerRequestCompiler
{
    internal const string Shape = "VM.Standard.A1.Flex";
    internal const float Ocpus = 4;
    internal const float MemoryInGbs = 24;

    internal static LaunchInstanceRequest Launch(LaunchOciCiRunnerAction action)
    {
        ArgumentNullException.ThrowIfNull(action);
        var demand = action.Demand;
        var template = action.Template;
        var hash = GlobalNatsTopology.CiRunnerIdentityHash(demand.Runner);
        return new LaunchInstanceRequest
        {
            OpcRetryToken = demand.IdempotencyToken,
            LaunchInstanceDetails = new LaunchInstanceDetails
            {
                AvailabilityDomain = template.AvailabilityDomain,
                FaultDomain = template.FaultDomain,
                CompartmentId = template.CompartmentId,
                DisplayName = $"ci-runner-{hash[..16]}",
                HostnameLabel = $"ci-{hash[..16]}",
                Shape = Shape,
                ShapeConfig = new LaunchInstanceShapeConfigDetails
                {
                    Ocpus = Ocpus,
                    MemoryInGBs = MemoryInGbs,
                },
                SourceDetails = new InstanceSourceViaImageDetails
                {
                    ImageId = template.ImageId,
                    BootVolumeSizeInGBs = 50,
                    BootVolumeVpusPerGB = 10,
                },
                CreateVnicDetails = new CreateVnicDetails
                {
                    SubnetId = template.SubnetId,
                    NsgIds = template.NetworkSecurityGroupIds.ToList(),
                    AssignPublicIp = false,
                    AssignIpv6Ip = false,
                    AssignPrivateDnsRecord = false,
                },
                PreemptibleInstanceConfig = new PreemptibleInstanceConfigDetails
                {
                    PreemptionAction = new TerminatePreemptionAction { PreserveBootVolume = false },
                },
                Metadata = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["user_data"] = demand.BootstrapCloudInitBase64,
                },
                FreeformTags = new Dictionary<string, string>(
                    OciCiRunnerCapacityEngine.Tags(demand, template.Generation),
                    StringComparer.Ordinal),
                IsPvEncryptionInTransitEnabled = true,
            },
        };
    }

    internal static TerminateInstanceRequest Terminate(TerminateOciCiRunnerAction action)
    {
        ArgumentNullException.ThrowIfNull(action);
        return new()
        {
            InstanceId = action.InstanceId,
            IfMatch = action.ETag,
            PreserveBootVolume = false,
            PreserveDataVolumesCreatedAtLaunch = false,
        };
    }
}

internal sealed record OciCiRunnerMutationReceipt(
    string InstanceId,
    string ETag,
    string OpcRequestId,
    string OpcWorkRequestId);

internal interface IOciCiRunnerCapacityAdapter : IDisposable
{
    Task<IReadOnlyList<OciCiRunnerNodeObservation>> ObserveAsync(
        OciCiRunnerLaunchTemplate template,
        CancellationToken cancellationToken);

    Task<OciCiRunnerMutationReceipt> ExecuteAsync(
        OciCiRunnerCapacityAction action,
        CancellationToken cancellationToken);
}

/// <summary>One single-attempt transport over the generated OCI compute and network clients.</summary>
internal interface IOciCiRunnerComputeTransport : IDisposable
{
    Task<Oci.CoreService.Responses.ListInstancesResponse> ListInstancesAsync(
        ListInstancesRequest request, CancellationToken cancellationToken);

    Task<Oci.CoreService.Responses.GetInstanceResponse> GetInstanceAsync(
        GetInstanceRequest request, CancellationToken cancellationToken);

    Task<Oci.CoreService.Responses.ListVnicAttachmentsResponse> ListVnicAttachmentsAsync(
        ListVnicAttachmentsRequest request, CancellationToken cancellationToken);

    Task<Oci.CoreService.Responses.GetVnicResponse> GetVnicAsync(
        GetVnicRequest request, CancellationToken cancellationToken);

    Task<Oci.CoreService.Responses.LaunchInstanceResponse> LaunchInstanceAsync(
        LaunchInstanceRequest request, CancellationToken cancellationToken);

    Task<Oci.CoreService.Responses.TerminateInstanceResponse> TerminateInstanceAsync(
        TerminateInstanceRequest request, CancellationToken cancellationToken);
}

/// <summary>Optional work-request polling seam. Existing compute-only test transports remain valid.</summary>
internal interface IOciWorkRequestTransport
{
    Task<Oci.WorkrequestsService.Responses.GetWorkRequestResponse> GetWorkRequestAsync(
        string workRequestId,
        CancellationToken cancellationToken);
}

internal sealed class OciCiRunnerSdkTransport(
    ComputeClient compute,
    VirtualNetworkClient network,
    WorkRequestClient? workRequests = null) : IOciCiRunnerComputeTransport, IOciWorkRequestTransport
{
    private readonly WorkRequestClient? workRequests = workRequests;
    public Task<Oci.CoreService.Responses.ListInstancesResponse> ListInstancesAsync(
        ListInstancesRequest request, CancellationToken cancellationToken) =>
        compute.ListInstances(request, null, cancellationToken, HttpCompletionOption.ResponseHeadersRead);

    public Task<Oci.CoreService.Responses.GetInstanceResponse> GetInstanceAsync(
        GetInstanceRequest request, CancellationToken cancellationToken) =>
        compute.GetInstance(request, null, cancellationToken, HttpCompletionOption.ResponseHeadersRead);

    public Task<Oci.CoreService.Responses.ListVnicAttachmentsResponse> ListVnicAttachmentsAsync(
        ListVnicAttachmentsRequest request, CancellationToken cancellationToken) =>
        compute.ListVnicAttachments(request, null, cancellationToken, HttpCompletionOption.ResponseHeadersRead);

    public Task<Oci.CoreService.Responses.GetVnicResponse> GetVnicAsync(
        GetVnicRequest request, CancellationToken cancellationToken) =>
        network.GetVnic(request, null, cancellationToken, HttpCompletionOption.ResponseHeadersRead);

    public Task<Oci.CoreService.Responses.LaunchInstanceResponse> LaunchInstanceAsync(
        LaunchInstanceRequest request, CancellationToken cancellationToken) =>
        compute.LaunchInstance(request, null, cancellationToken, HttpCompletionOption.ResponseHeadersRead);

    public Task<Oci.CoreService.Responses.TerminateInstanceResponse> TerminateInstanceAsync(
        TerminateInstanceRequest request, CancellationToken cancellationToken) =>
        compute.TerminateInstance(request, null, cancellationToken, HttpCompletionOption.ResponseHeadersRead);

    public Task<Oci.WorkrequestsService.Responses.GetWorkRequestResponse> GetWorkRequestAsync(
        string workRequestId,
        CancellationToken cancellationToken) =>
        workRequests is null
            ? Task.FromException<Oci.WorkrequestsService.Responses.GetWorkRequestResponse>(
                new InvalidOperationException("OCI work-request polling is not configured for this transport."))
            : workRequests.GetWorkRequest(
                new GetWorkRequestRequest { WorkRequestId = workRequestId },
                null,
                cancellationToken,
                HttpCompletionOption.ResponseHeadersRead);

    public void Dispose()
    {
        network.Dispose();
        workRequests?.Dispose();
        compute.Dispose();
    }
}

/// <summary>Executes already-decided OCI CI capacity actions with instance-principal authentication.</summary>
internal sealed class OciCiRunnerComputeAdapter : IOciCiRunnerCapacityAdapter
{
    private const int MaximumBootstrapBytes = 32 * 1024;

    private readonly IOciCiRunnerComputeTransport transport;

    // An instance is immutable after launch except for its lifecycle state (and the ETag that
    // rotates with it), so the first verified read of each instance is cached and every later
    // poll tick derives the observation from the single list call. The cache is bounded by the
    // observation cap and evicts entries the list stops returning.
    private readonly Dictionary<string, CachedInstance> verified = new(StringComparer.Ordinal);

    private sealed record CachedInstance(string ETag, Instance.LifecycleStateEnum? LifecycleState);

    internal OciCiRunnerComputeAdapter(IOciCiRunnerComputeTransport transport)
    {
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));
    }

    internal static OciCiRunnerComputeAdapter CreateForInstancePrincipal(string endpoint)
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
            return new(new OciCiRunnerSdkTransport(
                compute,
                new(provider, configuration, endpointUri),
                new WorkRequestClient(provider, configuration, endpointUri)));
        }
        catch
        {
            compute.Dispose();
            throw;
        }
    }

    public async Task<IReadOnlyList<OciCiRunnerNodeObservation>> ObserveAsync(
        OciCiRunnerLaunchTemplate template,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(template);
        var instances = new List<Instance>();
        string? page = null;
        do
        {
            // One filtered list call per poll tick: compartment and availability domain are
            // narrowed server-side (the API offers no tag, prefix, or multi-state filters), and
            // per-instance details come from this listing plus the cache below.
            var response = await transport.ListInstancesAsync(
                new ListInstancesRequest
                {
                    CompartmentId = template.CompartmentId,
                    AvailabilityDomain = template.AvailabilityDomain,
                    Limit = 100,
                    Page = page,
                    SortBy = ListInstancesRequest.SortByEnum.Timecreated,
                    SortOrder = ListInstancesRequest.SortOrderEnum.Asc,
                },
                cancellationToken);
            foreach (var instance in response.Items ?? [])
            {
                var tags = instance.FreeformTags;
                if (tags is null || !tags.TryGetValue("terrascale-owner", out var owner) ||
                    owner != "orchestrator" || !tags.TryGetValue("terrascale-role", out var role) ||
                    role != "ci-runner")
                    continue;
                instances.Add(instance);
                if (instances.Count > 512)
                    throw new InvalidDataException("The OCI CI runner observation exceeded its bound.");
            }
            page = response.OpcNextPage;
        } while (!string.IsNullOrEmpty(page));

        var observed = new List<OciCiRunnerNodeObservation>(instances.Count);
        foreach (var listed in instances)
        {
            if (verified.TryGetValue(listed.Id, out var cached) &&
                cached.LifecycleState == listed.LifecycleState)
            {
                observed.Add(Observation(listed, cached.ETag));
                continue;
            }
            var response = await TryGetInstanceAsync(listed.Id, cancellationToken);
            if (response is null) continue;
            var instance = response.Instance ??
                throw new InvalidDataException("OCI returned an empty CI runner observation.");
            var attachment = await ReadPrimaryVnicAttachmentAsync(template, instance.Id, cancellationToken);
            var vnicResponse = await transport.GetVnicAsync(
                new GetVnicRequest { VnicId = attachment.VnicId },
                cancellationToken);
            var vnic = vnicResponse.Vnic ??
                throw new InvalidDataException("OCI returned an empty CI runner VNIC observation.");
            RequireLaunchTemplate(instance, attachment, vnic, template);
            var etag = response.Etag ?? string.Empty;
            verified[listed.Id] = new(etag, instance.LifecycleState);
            observed.Add(Observation(instance, etag));
        }
        foreach (var id in verified.Keys.Where(id => instances.All(instance => instance.Id != id)).ToArray())
            verified.Remove(id);
        return Array.AsReadOnly(observed.ToArray());
    }

    private async Task<Oci.CoreService.Responses.GetInstanceResponse?> TryGetInstanceAsync(
        string instanceId,
        CancellationToken cancellationToken)
    {
        try
        {
            return await transport.GetInstanceAsync(
                new GetInstanceRequest { InstanceId = instanceId },
                cancellationToken);
        }
        catch (OciException failure) when (failure.StatusCode == HttpStatusCode.NotFound)
        {
            // Eventual consistency: the instance vanished between the list and this read (the
            // terminate path re-observes every tick). A 404 here must not fail the poll tick.
            return null;
        }
    }

    private static OciCiRunnerNodeObservation Observation(Instance instance, string etag)
    {
        var tags = instance.FreeformTags ??
            throw new InvalidDataException("An owned OCI CI runner has no ownership tags.");
        if (!tags.TryGetValue("terrascale-runner", out var runner) ||
            !tags.TryGetValue("terrascale-runner-sequence", out var sequenceText) ||
            !long.TryParse(sequenceText, System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var sequence) || sequence <= 0 ||
            instance.TimeCreated is not { } created)
            throw new InvalidDataException("An owned OCI CI runner has invalid identity tags.");
        var termination = instance.PreemptibleInstanceConfig?.PreemptionAction as TerminatePreemptionAction;
        return new(
            instance.Id,
            etag,
            runner,
            sequence,
            State(instance.LifecycleState),
            ActiveJob: false,
            new DateTimeOffset(DateTime.SpecifyKind(created, DateTimeKind.Utc)),
            Preemptible: termination is not null,
            PreserveBootVolume: termination?.PreserveBootVolume ?? true,
            new ReadOnlyDictionary<string, string>(
                new Dictionary<string, string>(tags, StringComparer.Ordinal)));
    }

    private async Task<VnicAttachment> ReadPrimaryVnicAttachmentAsync(
        OciCiRunnerLaunchTemplate template,
        string instanceId,
        CancellationToken cancellationToken)
    {
        var attachments = new List<VnicAttachment>();
        string? page = null;
        do
        {
            var response = await transport.ListVnicAttachmentsAsync(
                new ListVnicAttachmentsRequest
                {
                    CompartmentId = template.CompartmentId,
                    InstanceId = instanceId,
                    Limit = 100,
                    Page = page,
                },
                cancellationToken);
            attachments.AddRange(response.Items ?? []);
            if (attachments.Count > 8)
                throw new InvalidDataException("The OCI CI runner VNIC observation exceeded its bound.");
            page = response.OpcNextPage;
        } while (!string.IsNullOrEmpty(page));
        return attachments.Count == 1
            ? attachments[0]
            : throw new InvalidDataException("An OCI CI runner must have exactly one VNIC attachment.");
    }

    internal static void RequireLaunchTemplate(
        Instance instance,
        VnicAttachment attachment,
        Vnic vnic,
        OciCiRunnerLaunchTemplate template)
    {
        ArgumentNullException.ThrowIfNull(instance);
        ArgumentNullException.ThrowIfNull(attachment);
        ArgumentNullException.ThrowIfNull(vnic);
        ArgumentNullException.ThrowIfNull(template);
        RequireBootstrap(instance);
        var source = instance.SourceDetails as InstanceSourceViaImageDetails;
        if (instance.CompartmentId != template.CompartmentId ||
            instance.AvailabilityDomain != template.AvailabilityDomain ||
            instance.FaultDomain != template.FaultDomain ||
            instance.Shape != OciCiRunnerRequestCompiler.Shape ||
            instance.ShapeConfig?.Ocpus != OciCiRunnerRequestCompiler.Ocpus ||
            instance.ShapeConfig.MemoryInGBs != OciCiRunnerRequestCompiler.MemoryInGbs ||
            instance.ImageId != template.ImageId || source?.ImageId != template.ImageId ||
            source.BootVolumeSizeInGBs != 50 || source.BootVolumeVpusPerGB != 10 ||
            instance.LaunchOptions?.IsPvEncryptionInTransitEnabled != true ||
            !string.IsNullOrEmpty(instance.InstanceConfigurationId) ||
            !string.IsNullOrEmpty(instance.CapacityReservationId) ||
            attachment.InstanceId != instance.Id || attachment.CompartmentId != template.CompartmentId ||
            attachment.AvailabilityDomain != template.AvailabilityDomain ||
            attachment.SubnetId != template.SubnetId || attachment.NicIndex != 0 ||
            attachment.LifecycleState != VnicAttachment.LifecycleStateEnum.Attached ||
            attachment.VnicId != vnic.Id || vnic.CompartmentId != template.CompartmentId ||
            vnic.AvailabilityDomain != template.AvailabilityDomain || vnic.SubnetId != template.SubnetId ||
            vnic.IsPrimary != true || vnic.LifecycleState != Vnic.LifecycleStateEnum.Available ||
            !string.IsNullOrEmpty(vnic.PublicIp) || vnic.Ipv6Addresses is { Count: > 0 } ||
            vnic.SkipSourceDestCheck == true || vnic.NsgIds is null ||
            !vnic.NsgIds.Order(StringComparer.Ordinal).SequenceEqual(
                template.NetworkSecurityGroupIds.Order(StringComparer.Ordinal)))
            throw new InvalidDataException("An OCI CI runner does not match its exact launch template.");
    }

    private static void RequireBootstrap(Instance instance)
    {
        if (instance.Metadata is not { Count: 1 } metadata ||
            !metadata.TryGetValue("user_data", out var encoded) ||
            encoded.Length is < 1 or > ((MaximumBootstrapBytes + 2) / 3) * 4 ||
            instance.FreeformTags is not { } tags ||
            !tags.TryGetValue("terrascale-bootstrap-sha256", out var expected))
            throw new InvalidDataException("An OCI CI runner has no exact bootstrap metadata.");
        var decoded = new byte[MaximumBootstrapBytes + 1];
        if (!Convert.TryFromBase64String(encoded, decoded, out var bytes) ||
            bytes is < 1 or > MaximumBootstrapBytes ||
            Convert.ToBase64String(decoded, 0, bytes) != encoded ||
            Convert.ToHexStringLower(SHA256.HashData(decoded.AsSpan(0, bytes))) != expected)
            throw new InvalidDataException("An OCI CI runner bootstrap differs from its ownership digest.");
    }

    public async Task<OciCiRunnerMutationReceipt> ExecuteAsync(
        OciCiRunnerCapacityAction action,
        CancellationToken cancellationToken)
    {
        switch (action)
        {
            case LaunchOciCiRunnerAction launch:
                {
                    var response = await transport.LaunchInstanceAsync(
                        OciCiRunnerRequestCompiler.Launch(launch),
                        cancellationToken);
                    var instance = response.Instance ??
                        throw new InvalidDataException("OCI returned no launched CI runner instance.");
                    _ = new ProviderResourceId(instance.Id);
                    return new(
                        instance.Id,
                        response.Etag ?? string.Empty,
                        response.OpcRequestId ?? string.Empty,
                        response.OpcWorkRequestId ?? string.Empty);
                }
            case TerminateOciCiRunnerAction terminate:
                {
                    Oci.CoreService.Responses.TerminateInstanceResponse response;
                    try
                    {
                        response = await transport.TerminateInstanceAsync(
                            OciCiRunnerRequestCompiler.Terminate(terminate),
                            cancellationToken);
                    }
                    catch (OciException failure) when (failure.StatusCode == HttpStatusCode.NotFound)
                    {
                        // Idempotent goal state: an instance that no longer exists is terminated.
                        // Terminating instances briefly keep appearing in lists, so this 404 must
                        // not surface as a failure of the poll tick that planned the retire.
                        return new(terminate.InstanceId, terminate.ETag, string.Empty, string.Empty);
                    }
                    return new(
                        terminate.InstanceId,
                        terminate.ETag,
                        response.OpcRequestId ?? string.Empty,
                        response.OpcWorkRequestId ?? string.Empty);
                }
            default:
                throw new ArgumentOutOfRangeException(nameof(action));
        }
    }

    internal static OciCiRunnerNodeState State(Instance.LifecycleStateEnum? state)
    {
        if (state == Instance.LifecycleStateEnum.Terminated) return OciCiRunnerNodeState.Terminated;
        if (state == Instance.LifecycleStateEnum.Terminating) return OciCiRunnerNodeState.Terminating;
        if (state == Instance.LifecycleStateEnum.Running) return OciCiRunnerNodeState.Running;
        if (state == Instance.LifecycleStateEnum.Stopped) return OciCiRunnerNodeState.Stopped;
        return OciCiRunnerNodeState.Launching;
    }

    public void Dispose() => transport.Dispose();
}

/// <summary>
/// Splits OCI provider API failures into operational ones — 429 throttle, 409 capacity
/// conflicts (OutOfHostCapacity), 408 request timeouts, 412 stale ETag fences, 5xx, and
/// transport-level failures that never received a status — which must retry, and durable
/// rejections (auth, not-found, malformed), which stay terminal. One operational failure must
/// never permanently consume a CI event.
/// </summary>
internal static class OciCiRunnerProviderFailures
{
    internal static bool IsTransient(Exception exception) =>
        exception is OciException failure && (int)failure.StatusCode is 0 or 408 or 409 or 412 or 429 or >= 500;
}
