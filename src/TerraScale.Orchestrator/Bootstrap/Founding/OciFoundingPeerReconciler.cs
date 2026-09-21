using System.Security.Cryptography;
using System.Text;
using Oci.CoreService.Models;
using Oci.CoreService.Requests;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.Bootstrap.Founding;

internal sealed record OciFoundingPeerStatus(string Slot, string? InstanceId, string State);
internal sealed record OciFoundingStatus(int SchemaVersion, string BootstrapId, string State, int ProgressPercent,
    IReadOnlyList<OciFoundingPeerStatus> Peers, string[] Needs);

/// <summary>
/// Creates only the two peers named by a verified grant. No delete, seed mutation,
/// IAM mutation, authority-store downgrade, or workload admission occurs here.
/// </summary>
internal sealed class OciFoundingPeerReconciler(
    IOciCiRunnerComputeTransport transport,
    TimeProvider timeProvider)
{
    private const string BootstrapTag = "terrascale-founding-id";
    private const string SlotTag = "terrascale-founding-slot";
    private const string PlanTag = "terrascale-founding-plan-sha256";

    internal async Task<OciFoundingStatus> TickAsync(VerifiedOciFoundingPlan verified, OciFoundingState state,
        string localInstanceId, CancellationToken cancellationToken)
    {
        var plan = verified.Plan;
        if (localInstanceId != plan.SeedInstanceId)
            throw new InvalidOperationException("Only the exact seed identity may use the founding grant.");
        var seedResponse = await transport.GetInstanceAsync(new() { InstanceId = plan.SeedInstanceId }, cancellationToken)
            .ConfigureAwait(false);
        var seed = seedResponse.Instance;
        if (seed is null || seed.Id != plan.SeedInstanceId || seed.CompartmentId != plan.CompartmentId ||
            seed.AvailabilityDomain != plan.AvailabilityDomain || seed.FaultDomain != plan.SeedFaultDomain ||
            seed.LifecycleState != Instance.LifecycleStateEnum.Running || seed.FreeformTags is not { } seedTags ||
            seedTags.GetValueOrDefault("ManagedBy") != "ts-infra" ||
            seedTags.GetValueOrDefault("Role") != "initial-controller" || seedTags.GetValueOrDefault("Region") != "GRU")
            throw new InvalidDataException("The seed is not the exact running ts-infra bootstrap controller.");
        var seedVnic = await ReadVnicAsync(seed, plan, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException("The founding seed network is not available.");
        if (plan.Peers.Any(peer => peer.PrivateIp == seedVnic.PrivateIp))
            throw new InvalidDataException("Founding peers must not reuse the seed address.");

        var statuses = new List<OciFoundingPeerStatus>(2);
        foreach (var peer in plan.Peers.OrderBy(peer => peer.Slot, StringComparer.Ordinal))
        {
            var instanceId = state.Peers.GetValueOrDefault(peer.Slot);
            Instance? instance;
            if (instanceId is not null)
            {
                var response = await transport.GetInstanceAsync(new() { InstanceId = instanceId }, cancellationToken).ConfigureAwait(false);
                instance = response.Instance ?? throw new InvalidDataException("A recorded founding peer is no longer observable.");
                if (instance.Id != instanceId) throw new InvalidDataException("The founding peer identity changed.");
            }
            else
            {
                instance = await FindPeerAsync(verified, peer, cancellationToken).ConfigureAwait(false);
            }

            if (instance is null)
            {
                plan.RequireCreateWindow(timeProvider.GetUtcNow());
                state.Record(peer.Slot, null); // A lost response never changes the retry token.
                var request = CompileLaunch(verified, peer);
                plan.RequireCreateWindow(timeProvider.GetUtcNow());
                cancellationToken.ThrowIfCancellationRequested();
                var response = await transport.LaunchInstanceAsync(request, cancellationToken).ConfigureAwait(false);
                var launchedId = response.Instance?.Id;
                if (!OciFoundingPlan.RegionalOcid(launchedId, "instance") || launchedId == plan.SeedInstanceId)
                    throw new InvalidDataException("OCI returned an invalid founding peer identity.");
                state.Record(peer.Slot, launchedId);
                statuses.Add(new(peer.Slot, launchedId, "submitted"));
                continue;
            }

            RequirePeer(verified, peer, instance);
            state.Record(peer.Slot, instance.Id);
            var running = instance.LifecycleState == Instance.LifecycleStateEnum.Running;
            if (running)
            {
                var vnic = await ReadVnicAsync(instance, plan, cancellationToken).ConfigureAwait(false);
                if (vnic is null)
                    running = false;
                else if (vnic.PrivateIp != peer.PrivateIp)
                    throw new InvalidDataException("The founding peer address does not match its grant.");
            }
            statuses.Add(new(peer.Slot, instance.Id, running ? "running" : "provisioning"));
        }
        var count = statuses.Count(peer => peer.State == "running");
        return new(1, plan.BootstrapId, count == 2 ? "peers-running" : "peers-pending", count * 50,
            statuses, count == 2 ? ["regional-nats-quorum", "controller-admission", "seed-ownership-handoff"] : ["peer-provisioning"]);
    }

    internal static LaunchInstanceRequest CompileLaunch(VerifiedOciFoundingPlan verified, OciFoundingPeer peer)
    {
        var plan = verified.Plan;
        var token = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{OciFoundingPlan.GrantPurpose}:{plan.SeedInstanceId}:{plan.BootstrapId}:{peer.Slot}")));
        return new()
        {
            OpcRetryToken = token,
            LaunchInstanceDetails = new()
            {
                CompartmentId = plan.CompartmentId,
                AvailabilityDomain = plan.AvailabilityDomain,
                FaultDomain = peer.FaultDomain,
                DisplayName = DisplayName(plan, peer),
                Shape = "VM.Standard.A1.Flex",
                ShapeConfig = new() { Ocpus = plan.Ocpus, MemoryInGBs = plan.MemoryGb },
                SourceDetails = new InstanceSourceViaImageDetails { ImageId = plan.ImageId, BootVolumeSizeInGBs = 50, BootVolumeVpusPerGB = 10 },
                CreateVnicDetails = new()
                {
                    SubnetId = plan.SubnetId, NsgIds = plan.NetworkSecurityGroupIds.ToList(), PrivateIp = peer.PrivateIp,
                    AssignPublicIp = false, AssignIpv6Ip = false, SkipSourceDestCheck = false, AssignPrivateDnsRecord = false
                },
                InstanceOptions = new() { AreLegacyImdsEndpointsDisabled = true },
                IsPvEncryptionInTransitEnabled = true,
                Metadata = new(StringComparer.Ordinal) { ["user_data"] = peer.BootstrapBase64 },
                FreeformTags = new(StringComparer.Ordinal)
                {
                    ["terrascale-owner"] = "orchestrator", ["terrascale-role"] = "controller", ["terrascale-cell"] = "gru",
                    [BootstrapTag] = plan.BootstrapId, [SlotTag] = peer.Slot, [PlanTag] = verified.Digest
                }
            }
        };
    }

    private async Task<Instance?> FindPeerAsync(VerifiedOciFoundingPlan verified, OciFoundingPeer peer, CancellationToken cancellationToken)
    {
        var matches = new List<Instance>();
        var pages = new HashSet<string>(StringComparer.Ordinal);
        string? page = null;
        do
        {
            var response = await transport.ListInstancesAsync(new()
            {
                CompartmentId = verified.Plan.CompartmentId, AvailabilityDomain = verified.Plan.AvailabilityDomain,
                DisplayName = DisplayName(verified.Plan, peer), Limit = 100, Page = page
            }, cancellationToken).ConfigureAwait(false);
            foreach (var candidate in response.Items ?? [])
            {
                if (candidate.DisplayName != DisplayName(verified.Plan, peer))
                    throw new InvalidDataException("The founding lookup returned a different peer name.");
                matches.Add(candidate);
                if (matches.Count > 1) throw new InvalidDataException("The founding peer has colliding provider identities.");
            }
            page = response.OpcNextPage;
            if (!string.IsNullOrEmpty(page) && (!pages.Add(page) || pages.Count > 4))
                throw new InvalidDataException("The founding peer lookup exceeded its page bound.");
        } while (!string.IsNullOrEmpty(page));
        if (matches.Count == 0) return null;
        var detail = await transport.GetInstanceAsync(new() { InstanceId = matches[0].Id }, cancellationToken).ConfigureAwait(false);
        if (detail.Instance is null || detail.Instance.Id != matches[0].Id)
            throw new InvalidDataException("The founding peer detail is incomplete.");
        return detail.Instance;
    }

    private static void RequirePeer(VerifiedOciFoundingPlan verified, OciFoundingPeer peer, Instance instance)
    {
        var plan = verified.Plan;
        if (!OciFoundingPlan.RegionalOcid(instance.Id, "instance") || instance.Id == plan.SeedInstanceId ||
            instance.DisplayName != DisplayName(plan, peer) || instance.CompartmentId != plan.CompartmentId ||
            instance.AvailabilityDomain != plan.AvailabilityDomain || instance.FaultDomain != peer.FaultDomain ||
            instance.Shape != "VM.Standard.A1.Flex" || instance.ShapeConfig?.Ocpus != plan.Ocpus ||
            instance.ShapeConfig.MemoryInGBs != plan.MemoryGb || instance.ImageId != plan.ImageId ||
            instance.SourceDetails is not InstanceSourceViaImageDetails source || source.ImageId != plan.ImageId ||
            source.BootVolumeSizeInGBs != 50 || source.BootVolumeVpusPerGB != 10 ||
            instance.LaunchOptions?.IsPvEncryptionInTransitEnabled != true ||
            instance.InstanceOptions?.AreLegacyImdsEndpointsDisabled != true ||
            instance.PreemptibleInstanceConfig is not null || !string.IsNullOrEmpty(instance.InstanceConfigurationId) ||
            !string.IsNullOrEmpty(instance.CapacityReservationId) || instance.Metadata is not { Count: 1 } metadata ||
            metadata.GetValueOrDefault("user_data") != peer.BootstrapBase64 || instance.FreeformTags is not { } tags ||
            tags.GetValueOrDefault("terrascale-owner") != "orchestrator" || tags.GetValueOrDefault("terrascale-role") != "controller" ||
            tags.GetValueOrDefault("terrascale-cell") != "gru" || tags.GetValueOrDefault(BootstrapTag) != plan.BootstrapId ||
            tags.GetValueOrDefault(SlotTag) != peer.Slot || tags.GetValueOrDefault(PlanTag) != verified.Digest ||
            instance.LifecycleState is not (Instance.LifecycleStateEnum.Provisioning or Instance.LifecycleStateEnum.Starting or Instance.LifecycleStateEnum.Running))
            throw new InvalidDataException("The founding peer differs from its exact grant or cannot form the quorum.");
    }

    private async Task<Vnic?> ReadVnicAsync(Instance instance, OciFoundingPlan plan, CancellationToken cancellationToken)
    {
        var response = await transport.ListVnicAttachmentsAsync(new()
        {
            CompartmentId = plan.CompartmentId, InstanceId = instance.Id, Limit = 8
        }, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(response.OpcNextPage) || response.Items is { Count: > 1 })
            throw new InvalidDataException("Founding requires exactly one private VNIC.");
        if (response.Items is not { Count: 1 }) return null;
        var attachment = response.Items[0];
        if (attachment.InstanceId != instance.Id || attachment.CompartmentId != plan.CompartmentId ||
            attachment.AvailabilityDomain != plan.AvailabilityDomain || attachment.SubnetId != plan.SubnetId ||
            attachment.NicIndex != 0)
            throw new InvalidDataException("The founding VNIC attachment is outside its grant.");
        if (attachment.LifecycleState != VnicAttachment.LifecycleStateEnum.Attached) return null;
        var detail = await transport.GetVnicAsync(new() { VnicId = attachment.VnicId }, cancellationToken).ConfigureAwait(false);
        var vnic = detail.Vnic;
        if (vnic is null || vnic.Id != attachment.VnicId || vnic.SubnetId != plan.SubnetId ||
            vnic.CompartmentId != plan.CompartmentId || vnic.AvailabilityDomain != plan.AvailabilityDomain || vnic.IsPrimary != true ||
            !string.IsNullOrEmpty(vnic.PublicIp) || vnic.Ipv6Addresses is { Count: > 0 } || vnic.SkipSourceDestCheck == true ||
            string.IsNullOrWhiteSpace(vnic.PrivateIp) || vnic.NsgIds is null ||
            !vnic.NsgIds.Order(StringComparer.Ordinal).SequenceEqual(plan.NetworkSecurityGroupIds.Order(StringComparer.Ordinal)))
            throw new InvalidDataException("The founding VNIC is not the exact private network binding.");
        return vnic.LifecycleState == Vnic.LifecycleStateEnum.Available ? vnic : null;
    }

    private static string DisplayName(OciFoundingPlan plan, OciFoundingPeer peer) => $"ts-gru-found-{plan.BootstrapId}-{peer.Slot}";
}
