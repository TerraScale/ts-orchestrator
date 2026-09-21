using System.Net;
using Oci.Common.Model;
using Oci.CoreService.Models;
using Oci.CoreService.Requests;
using TerraScale.Orchestrator.ControlPlane.Providers;
using TerraScale.Orchestrator.ControlPlane.TerraBase;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Nodes;

/// <summary>
/// The orchestrator-side half of member-host readiness: the reconciler supplies it, the fleet
/// never reads ORCH_RUNTIME itself. The instance identity is the provider instance id the host
/// observations are keyed by.
/// </summary>
internal interface IMemberHostObservationSource
{
    /// <summary>True once a fresh enrollment report binds this exact host to its admitted artifact.</summary>
    ValueTask<bool> HasHostReportedAsync(string instance, CancellationToken cancellationToken);

    /// <summary>The live member health from the member's own reports; null while it is not reporting.</summary>
    ValueTask<MemberHealth?> ObserveMemberHealthAsync(string instance, CancellationToken cancellationToken);
}

/// <summary>Publishes one fenced host-agent command on the exact subject the fleet computed.</summary>
internal interface IMemberHostCommandChannel
{
    ValueTask PublishAsync(string subject, CancellationToken cancellationToken);
}

/// <summary>The validated member-host bootstrap envelope shared by every region template.</summary>
internal sealed record OciMemberHostBootstrap
{
    internal OciMemberHostBootstrap(string cloudInitBase64, string sha256)
    {
        // The digest itself is re-verified inside every launch plan; this constructor adds the
        // operator-boundary checks the CI pool configuration applies to its bootstrap files.
        var decoded = new byte[32 * 1024 + 1];
        if (!Convert.TryFromBase64String(cloudInitBase64, decoded, out var bytes) ||
            bytes is < 1 or > 32 * 1024 ||
            ContainsCredential(System.Text.Encoding.UTF8.GetString(decoded.AsSpan(0, bytes))))
            throw new ArgumentException("The member host bootstrap is invalid or carries a plaintext credential.");
        CloudInitBase64 = cloudInitBase64;
        Sha256 = sha256;
    }

    internal string CloudInitBase64 { get; }
    internal string Sha256 { get; }

    private static bool ContainsCredential(string value) =>
        value.Contains("BEGIN NATS USER JWT", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("BEGIN USER NKEY SEED", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("PRIVATE KEY-----", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// One cell's member-host fleet shape: the NATS cell every drain command is addressed inside,
/// and the pinned launch template of every TerraBase region this fleet serves.
/// ponytail: single availability domain per region template; the two permanent seats of a region
/// get different templates when they must not share a domain.
/// </summary>
internal sealed class OciMemberHostFleetConfiguration
{
    internal OciMemberHostFleetConfiguration(
        string cell,
        IReadOnlyDictionary<string, OciCiRunnerLaunchTemplate> templates,
        OciMemberHostBootstrap bootstrap)
    {
        Cell = OciMemberHostLaunchPlan.Bounded(cell, 128, nameof(cell));
        ArgumentNullException.ThrowIfNull(templates);
        if (templates.Count is < 1 or > 8)
            throw new ArgumentException("A member host fleet serves one to eight region templates.", nameof(templates));
        foreach (var (region, template) in templates)
        {
            if (!TerraBaseRegionCode.TryCreate(region, out _) || template is null)
                throw new ArgumentException("A member host fleet template is not a valid region template.", nameof(templates));
        }
        Templates = new Dictionary<string, OciCiRunnerLaunchTemplate>(templates, StringComparer.Ordinal);
        Bootstrap = bootstrap ?? throw new ArgumentNullException(nameof(bootstrap));
    }

    internal string Cell { get; }
    internal IReadOnlyDictionary<string, OciCiRunnerLaunchTemplate> Templates { get; }
    internal OciMemberHostBootstrap Bootstrap { get; }

    internal IReadOnlyCollection<string> Compartments =>
        Templates.Values.Select(static template => template.CompartmentId).Distinct(StringComparer.Ordinal).ToArray();

    internal OciMemberHostLaunchPlan Plan(MemberHostRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        _ = OciMemberHostLaunchPlan.Bounded(request.Database, 128, nameof(request.Database));
        _ = OciMemberHostLaunchPlan.Bounded(request.MemberId, 128, nameof(request.MemberId));
        _ = OciMemberHostLaunchPlan.Bounded(request.PartitionId, 128, nameof(request.PartitionId));
        _ = OciMemberHostLaunchPlan.Bounded(request.CreateKey, 256, nameof(request.CreateKey));
        if (!Templates.TryGetValue(request.Region, out var template))
            throw new ArgumentException($"The member host fleet has no template for region {request.Region}.");
        return new(template, request.Database, request.MemberId, request.Region,
            Bootstrap.CloudInitBase64, Bootstrap.Sha256);
    }
}

/// <summary>Bounded wait bounds for the fleet's readiness and retirement verifications.</summary>
internal sealed record OciMemberHostFleetOptions
{
    internal static OciMemberHostFleetOptions Default { get; } = new(TimeSpan.FromMinutes(10), TimeSpan.FromSeconds(5));

    internal OciMemberHostFleetOptions(TimeSpan waitDeadline, TimeSpan pollInterval)
    {
        if (waitDeadline < TimeSpan.FromMilliseconds(100) || waitDeadline > TimeSpan.FromHours(1) ||
            pollInterval < TimeSpan.FromMilliseconds(10) || pollInterval > TimeSpan.FromMinutes(5) ||
            pollInterval >= waitDeadline)
            throw new ArgumentOutOfRangeException(nameof(waitDeadline));
        WaitDeadline = waitDeadline;
        PollInterval = pollInterval;
    }

    internal TimeSpan WaitDeadline { get; }
    internal TimeSpan PollInterval { get; }
}

/// <summary>
/// The production member-host fleet over OCI compute. Every observation is ownership-tag scoped,
/// every create is idempotent by its durable create key, every retirement is ETag-fenced and
/// verified boot-volume-absent before the caller's state machine may advance, and every mutation
/// re-checks the caller's authority immediately before the provider call.
/// ponytail: v1 observes with one listing per configured compartment and one shared bootstrap;
/// a multi-AD solver and per-database bootstraps arrive with multi-partition databases.
/// </summary>
internal sealed class OciMemberHostFleet : IMemberHostFleet, IDisposable
{
    private const int MaximumObservedHosts = 128;

    private readonly IOciMemberHostComputeTransport transport;
    private readonly OciMemberHostFleetConfiguration configuration;
    private readonly Func<bool> authorityStillValid;
    private readonly IMemberHostObservationSource observations;
    private readonly IMemberHostCommandChannel commands;
    private readonly OciMemberHostVolumeAdapter volumes;
    private readonly OciMemberHostFleetOptions options;
    private readonly TimeProvider clock;

    internal OciMemberHostFleet(
        IOciMemberHostComputeTransport transport,
        OciMemberHostFleetConfiguration configuration,
        Func<bool> authorityStillValid,
        IMemberHostObservationSource observations,
        IMemberHostCommandChannel commands,
        TimeProvider clock,
        OciMemberHostFleetOptions? options = null)
    {
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.authorityStillValid = authorityStillValid ?? throw new ArgumentNullException(nameof(authorityStillValid));
        this.observations = observations ?? throw new ArgumentNullException(nameof(observations));
        this.commands = commands ?? throw new ArgumentNullException(nameof(commands));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        this.options = options ?? OciMemberHostFleetOptions.Default;
        volumes = new OciMemberHostVolumeAdapter(transport, authorityStillValid, clock, this.options);
    }

    public async Task<IReadOnlyList<MemberHostObservation>> ObserveAsync(CancellationToken cancellationToken)
    {
        // One filtered listing per distinct template compartment; ownership tags narrow it to the
        // hosts this fleet may ever act on, in every availability domain the templates pin.
        var instances = new List<Instance>();
        foreach (var compartment in configuration.Compartments)
            await ListOwnedAsync(compartment, instances, cancellationToken);
        var observed = new List<MemberHostObservation>(instances.Count);
        foreach (var listed in instances.OrderBy(static instance => instance.Id, StringComparer.Ordinal))
        {
            var tags = listed.FreeformTags ??
                throw new InvalidDataException("An owned member host has no ownership tags.");
            if (!tags.TryGetValue(OciMemberHostRequestCompiler.MemberTag, out var member) ||
                !tags.TryGetValue(OciMemberHostRequestCompiler.RegionTag, out var region))
                throw new InvalidDataException("An owned member host has invalid identity tags.");
            var response = await TryGetInstanceAsync(listed.Id, cancellationToken);
            if (response is null) continue;
            var instance = response.Instance ??
                throw new InvalidDataException("OCI returned an empty member host observation.");
            // Ownership, ETags and attachments can change without a lifecycle transition.
            // Never let the initial read cache authorize a later storage operation.
            RequireOwned(instance);
            if (instance.Id != listed.Id || instance.FreeformTags.GetValueOrDefault(OciMemberHostRequestCompiler.MemberTag) != member ||
                instance.FreeformTags.GetValueOrDefault(OciMemberHostRequestCompiler.RegionTag) != region)
                throw new InvalidDataException("The member host identity changed during observation.");
            await VerifyMemberHostAsync(instance, cancellationToken);
            var volumeId = await volumes.ObserveDataVolumeAsync(instance.CompartmentId, instance.Id, cancellationToken);
            var etag = response.Etag ?? string.Empty;
            var health = (instance.LifecycleState == Instance.LifecycleStateEnum.Running
                ? await observations.ObserveMemberHealthAsync(listed.Id, cancellationToken) : null) ??
                new MemberHealth(false, 0, nameof(TerraBaseRole.Unknown), 0, 0);
            observed.Add(new(
                new(listed.Id),
                etag,
                member,
                region,
                OciMemberHostStates.State(instance.LifecycleState),
                instance.FreeformTags.TryGetValue(OciMemberHostRequestCompiler.CordonTag, out var cordoned) && cordoned == "true",
                health,
                volumeId));
        }
        return Array.AsReadOnly(observed.ToArray());
    }

    public async Task<ProviderResourceId> ProvisionAsync(MemberHostRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireAuthority();
        var plan = configuration.Plan(request);
        var existing = await OciMemberHostInstances.FindByCreateKeyAsync(
            transport, plan.Template.CompartmentId, request.CreateKey, cancellationToken);
        var instanceId = existing?.Id;
        if (instanceId is null)
        {
            RequireAuthority();
            var response = await transport.LaunchInstanceAsync(
                OciMemberHostRequestCompiler.Launch(plan, request.CreateKey), cancellationToken);
            instanceId = response.Instance?.Id ??
                throw new InvalidDataException("OCI returned no launched member host instance.");
        }
        await WaitUntilReadyAsync(instanceId, plan, request.CreateKey, cancellationToken);
        return new(instanceId);
    }

    public async Task CordonAsync(ProviderResourceId id, CancellationToken cancellationToken)
    {
        var instance = await ReadOwnedAsync(id, cancellationToken);
        if (instance.Instance.FreeformTags?.TryGetValue(OciMemberHostRequestCompiler.CordonTag, out var cordoned) == true &&
            cordoned == "true")
            return;
        RequireAuthority();
        _ = await transport.UpdateInstanceAsync(
            OciMemberHostRequestCompiler.Cordon(
                instance.Instance.Id, instance.ETag, instance.Instance.FreeformTags!),
            cancellationToken);
    }

    public async Task DrainAsync(ProviderResourceId id, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(id);
        OciMemberHostLaunchPlan.Bounded(id.InstanceId, 255, nameof(id));
        RequireAuthority();
        // Fenced drain command: the taxonomy hashes the agent identity into the subject, so the
        // raw provider instance id never becomes a subject token.
        var subject = NatsSubjectTaxonomy.HostAgentCommandSubject(configuration.Cell, id.InstanceId, "drain");
        await commands.PublishAsync(subject, cancellationToken);
    }

    public async Task RetireAsync(ProviderResourceId id, string etag, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(id);
        if (string.IsNullOrWhiteSpace(etag))
            throw new ArgumentException("Member host retirement requires the exact ETag fence.", nameof(etag));
        RequireAuthority();
        var instance = await TryGetInstanceAsync(id.InstanceId, cancellationToken);
        if (instance is null)
            return;
        var compartment = instance.Instance?.CompartmentId ??
            throw new InvalidDataException("OCI returned an empty member host observation.");
        RequireOwned(instance.Instance!);
        RequireAuthority();
        try
        {
            _ = await transport.TerminateInstanceAsync(
                OciMemberHostRequestCompiler.Terminate(id.InstanceId, etag), cancellationToken);
        }
        catch (OciException failure) when (failure.StatusCode == HttpStatusCode.NotFound)
        {
            // Idempotent goal state: an instance that no longer exists took its boot volume with it.
        }
        // Boot-volume absence is verified before this method returns, so the caller's state
        // machine may only advance to Audited on evidence, never on the terminate acknowledgement.
        await WaitUntilBootVolumeAbsentAsync(compartment, id.InstanceId, cancellationToken);
    }

    public async Task<MemberVolumeOutcome> DetachVolumeAsync(
        string volumeId, ProviderResourceId id, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(volumeId))
            throw new ArgumentException("Member host volume detachment requires the exact volume.", nameof(volumeId));
        var instance = await ReadOwnedAsync(id, cancellationToken);
        return Outcome(await volumes.DetachAsync(
            instance.Instance.CompartmentId!, volumeId, id.InstanceId, cancellationToken));
    }

    public async Task<MemberVolumeOutcome> AttachVolumeAsync(
        string volumeId, ProviderResourceId id, string createKey, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(volumeId))
            throw new ArgumentException("Member host volume attachment requires the exact volume.", nameof(volumeId));
        OciMemberHostLaunchPlan.Bounded(createKey, 256, nameof(createKey));
        var instance = await ReadOwnedAsync(id, cancellationToken);
        return Outcome(await volumes.AttachAsync(
            instance.Instance.CompartmentId!, volumeId, id.InstanceId, createKey, cancellationToken));
    }

    private static MemberVolumeOutcome Outcome(OciMemberHostVolumeOutcome outcome) =>
        outcome == OciMemberHostVolumeOutcome.Completed
            ? MemberVolumeOutcome.Completed
            : MemberVolumeOutcome.OutcomeUnknown;

    public void Dispose() => transport.Dispose();

    private async Task WaitUntilReadyAsync(string instanceId, OciMemberHostLaunchPlan plan,
        string createKey, CancellationToken cancellationToken)
    {
        var deadline = clock.GetUtcNow() + options.WaitDeadline;
        Instance.LifecycleStateEnum? lifecycle = null;
        var hostReported = false;
        while (true)
        {
            var response = await TryGetInstanceAsync(instanceId, cancellationToken) ??
                throw new InvalidDataException($"The member host {instanceId} vanished before it reported ready.");
            var instance = response.Instance;
            if (instance is null || instance.Id != instanceId || instance.CompartmentId != plan.Template.CompartmentId ||
                instance.ImageId != plan.Template.ImageId || instance.FreeformTags is not { } tags ||
                OciMemberHostRequestCompiler.Tags(plan, createKey).Any(pair => tags.GetValueOrDefault(pair.Key) != pair.Value) ||
                instance.Metadata?.GetValueOrDefault("user_data") != plan.BootstrapCloudInitBase64)
                throw new InvalidDataException("The provisioned member host does not match its exact identity and bootstrap binding.");
            lifecycle = response.Instance?.LifecycleState;
            hostReported = lifecycle == Instance.LifecycleStateEnum.Running &&
                await observations.HasHostReportedAsync(instanceId, cancellationToken);
            if (hostReported)
                return;
            if (lifecycle is Instance.LifecycleStateEnum.Terminating or Instance.LifecycleStateEnum.Terminated)
                throw new InvalidDataException(
                    $"The member host {instanceId} reached lifecycle {lifecycle} before it reported ready.");
            if (clock.GetUtcNow() >= deadline)
            {
                var evidence = lifecycle?.ToString() ?? "unknown";
                throw new InvalidOperationException(
                    $"The member host {instanceId} did not become ready within {options.WaitDeadline}: " +
                    $"lifecycle={evidence}, hostReported={hostReported}.");
            }
            await Task.Delay(options.PollInterval, cancellationToken);
        }
    }

    private async Task WaitUntilBootVolumeAbsentAsync(string compartmentId, string instanceId, CancellationToken cancellationToken)
    {
        var deadline = clock.GetUtcNow() + options.WaitDeadline;
        while (true)
        {
            var attachments = new List<BootVolumeAttachment>();
            string? page = null;
            do
            {
                var response = await transport.ListBootVolumeAttachmentsAsync(
                    new ListBootVolumeAttachmentsRequest
                    {
                        CompartmentId = compartmentId,
                        InstanceId = instanceId,
                        Limit = 100,
                        Page = page,
                    },
                    cancellationToken);
                attachments.AddRange(response.Items ?? []);
                if (attachments.Count > 8)
                    throw new InvalidDataException("The member host boot-volume observation exceeded its bound.");
                page = response.OpcNextPage;
            }
            while (!string.IsNullOrEmpty(page));
            if (attachments.Count == 0)
                return;
            if (clock.GetUtcNow() >= deadline)
                throw new InvalidOperationException(
                    $"The retired member host {instanceId} still has {attachments.Count} boot volume attachment(s); " +
                    "the retirement is not audited.");
            await Task.Delay(options.PollInterval, cancellationToken);
        }
    }

    private async Task ListOwnedAsync(string compartmentId, List<Instance> instances, CancellationToken cancellationToken)
    {
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
                if (instance.FreeformTags is null || !OciMemberHostInstances.Owned(instance.FreeformTags))
                    continue;
                instances.Add(instance);
                if (instances.Count > MaximumObservedHosts)
                    throw new InvalidDataException("The member host observation exceeded its bound.");
            }
            page = response.OpcNextPage;
        }
        while (!string.IsNullOrEmpty(page));
    }

    private async Task<(Instance Instance, string ETag)> ReadOwnedAsync(ProviderResourceId id, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(id);
        var response = await TryGetInstanceAsync(id.InstanceId, cancellationToken) ??
            throw new InvalidDataException($"The member host {id.InstanceId} no longer exists.");
        var instance = response.Instance ??
            throw new InvalidDataException("OCI returned an empty member host observation.");
        RequireOwned(instance);
        return (instance, response.Etag ?? string.Empty);
    }

    private async Task<Oci.CoreService.Responses.GetInstanceResponse?> TryGetInstanceAsync(
        string instanceId, CancellationToken cancellationToken)
    {
        OciMemberHostLaunchPlan.Bounded(instanceId, 255, nameof(instanceId));
        try
        {
            return await transport.GetInstanceAsync(
                new GetInstanceRequest { InstanceId = instanceId }, cancellationToken);
        }
        catch (OciException failure) when (failure.StatusCode == HttpStatusCode.NotFound)
        {
            // Eventual consistency between the listing and this read; the next observation reconciles.
            return null;
        }
    }

    private async Task VerifyMemberHostAsync(Instance instance, CancellationToken cancellationToken)
    {
        var tags = instance.FreeformTags ??
            throw new InvalidDataException("An owned member host has no ownership tags.");
        if (!tags.TryGetValue(OciMemberHostRequestCompiler.RegionTag, out var region) ||
            !configuration.Templates.TryGetValue(region, out var template))
            throw new InvalidDataException($"The member host {instance.Id} has no configured region template.");
        var attachments = new List<VnicAttachment>();
        string? page = null;
        do
        {
            var response = await transport.ListVnicAttachmentsAsync(
                new ListVnicAttachmentsRequest
                {
                    CompartmentId = template.CompartmentId,
                    InstanceId = instance.Id,
                    Limit = 100,
                    Page = page,
                },
                cancellationToken);
            attachments.AddRange(response.Items ?? []);
            if (attachments.Count > 8)
                throw new InvalidDataException("The member host VNIC observation exceeded its bound.");
            page = response.OpcNextPage;
        }
        while (!string.IsNullOrEmpty(page));
        var attachment = attachments.Count == 1
            ? attachments[0]
            : throw new InvalidDataException("A member host must have exactly one VNIC attachment.");
        var vnicResponse = await transport.GetVnicAsync(
            new GetVnicRequest { VnicId = attachment.VnicId }, cancellationToken);
        var vnic = vnicResponse.Vnic ??
            throw new InvalidDataException("OCI returned an empty member host VNIC observation.");
        OciCiRunnerComputeAdapter.RequireLaunchTemplate(instance, attachment, vnic, template);
    }

    private static void RequireOwned(Instance instance)
    {
        var tags = instance.FreeformTags;
        if (tags is null || !OciMemberHostInstances.Owned(tags))
            throw new InvalidOperationException(
                $"The instance {instance.Id} is not an owned member host of this fleet.");
    }

    private void RequireAuthority()
    {
        if (!authorityStillValid())
            throw new InvalidOperationException(
                "Member host fleet authority was lost; the provider mutation was not issued.");
    }
}
