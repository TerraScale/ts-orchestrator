using System.Net;
using Oci.Common.Model;
using Oci.CoreService.Models;
using Oci.CoreService.Requests;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.Nodes;

/// <summary>The outcome of one provider volume mutation; unknown is held for durable reconciliation.</summary>
internal enum OciMemberHostVolumeOutcome { Completed = 1, OutcomeUnknown = 2 }

/// <summary>
/// The provider side of the storage attachment planner's decisions: idempotent detach, and
/// attach keyed by a deterministic retry token. After a possibly-executed mutation whose response
/// was lost, it reobserves and reports unknown — it never issues a second logical mutation, the
/// OciBlockVolumeExpansionAdapter discipline.
/// </summary>
internal sealed class OciMemberHostVolumeAdapter
{
    private readonly IOciMemberHostComputeTransport transport;
    private readonly Func<bool> authorityStillValid;
    private readonly OciMemberHostFleetOptions options;
    private readonly TimeProvider clock;

    internal OciMemberHostVolumeAdapter(
        IOciMemberHostComputeTransport transport,
        Func<bool> authorityStillValid,
        TimeProvider clock,
        OciMemberHostFleetOptions? options = null)
    {
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));
        this.authorityStillValid = authorityStillValid ?? throw new ArgumentNullException(nameof(authorityStillValid));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        this.options = options ?? OciMemberHostFleetOptions.Default;
    }

    /// <summary>Reads current data attachment identity; a boot volume never satisfies this contract.</summary>
    internal async Task<string?> ObserveDataVolumeAsync(
        string compartmentId, string instanceId, CancellationToken cancellationToken)
    {
        var attachments = await ListAttachmentsAsync(compartmentId, null, instanceId, cancellationToken);
        return attachments.Count switch
        {
            0 => null,
            1 when attachments[0].LifecycleState == VolumeAttachment.LifecycleStateEnum.Attached => attachments[0].VolumeId,
            1 => null,
            _ => throw new InvalidDataException("A member host has more than one live data-volume attachment."),
        };
    }

    /// <summary>
    /// Detaches one volume from one instance exactly as the attachment planner emitted it. The
    /// exact attachment id is the fence; a volume with no live attachment is already detached.
    /// </summary>
    internal async ValueTask<OciMemberHostVolumeOutcome> DetachAsync(
        string compartmentId, string volumeId, string instanceId, CancellationToken cancellationToken)
    {
        RequireAuthority();
        var attachment = await FindAttachmentAsync(compartmentId, volumeId, cancellationToken);
        if (attachment is null)
            return OciMemberHostVolumeOutcome.Completed;
        if (attachment.InstanceId != instanceId)
            return OciMemberHostVolumeOutcome.OutcomeUnknown;
        try
        {
            RequireAuthority();
            _ = await transport.DetachVolumeAsync(
                new DetachVolumeRequest { VolumeAttachmentId = attachment.Id }, cancellationToken);
        }
        catch (OciException failure) when (failure.StatusCode == HttpStatusCode.NotFound)
        {
            // A missing attachment is not proof that the volume has no other writer.
            return await ReobserveDetachedAsync(compartmentId, volumeId, cancellationToken);
        }
        catch (Exception exception) when (!Fatal(exception, cancellationToken))
        {
            // The response was lost after a possible mutation: reobserve, never a second detach.
            return await ReobserveDetachedAsync(compartmentId, volumeId, cancellationToken);
        }
        return await WaitUntilDetachedAsync(compartmentId, volumeId, attachment.Id, cancellationToken);
    }

    /// <summary>Attaches one volume to one instance; the create key is the idempotency token.</summary>
    internal async ValueTask<OciMemberHostVolumeOutcome> AttachAsync(
        string compartmentId, string volumeId, string instanceId, string createKey, CancellationToken cancellationToken)
    {
        RequireAuthority();
        var existing = await FindAttachmentAsync(compartmentId, volumeId, cancellationToken);
        if (existing is not null && existing.InstanceId != instanceId)
            return OciMemberHostVolumeOutcome.OutcomeUnknown;
        if (existing is null)
        {
            try
            {
                RequireAuthority();
                _ = await transport.AttachVolumeAsync(
                    new AttachVolumeRequest
                    {
                        OpcRetryToken = OciMemberHostLaunchPlan.Bounded(createKey, 256, nameof(createKey)),
                        AttachVolumeDetails = new AttachParavirtualizedVolumeDetails
                        {
                            InstanceId = instanceId,
                            VolumeId = volumeId,
                            IsReadOnly = false,
                            IsShareable = false,
                            IsPvEncryptionInTransitEnabled = true,
                        },
                    },
                    cancellationToken);
            }
            catch (Exception exception) when (!Fatal(exception, cancellationToken))
            {
                // The response was lost after a possible mutation: reobserve, never a second attach.
                return await ReobserveAttachedAsync(compartmentId, volumeId, instanceId, cancellationToken);
            }
        }
        return await WaitUntilAttachedAsync(compartmentId, volumeId, instanceId, cancellationToken);
    }

    private async ValueTask<OciMemberHostVolumeOutcome> ReobserveDetachedAsync(
        string compartmentId, string volumeId, CancellationToken cancellationToken)
    {
        try
        {
            // Never a second logical mutation after a lost response: the reobservation either
            // confirms the goal state or leaves the outcome held for durable reconciliation.
            var observed = await FindAttachmentAsync(compartmentId, volumeId, cancellationToken);
            return observed is null
                ? OciMemberHostVolumeOutcome.Completed
                : OciMemberHostVolumeOutcome.OutcomeUnknown;
        }
        catch (Exception exception) when (!Fatal(exception, cancellationToken))
        {
            return OciMemberHostVolumeOutcome.OutcomeUnknown;
        }
    }

    private async ValueTask<OciMemberHostVolumeOutcome> ReobserveAttachedAsync(
        string compartmentId, string volumeId, string instanceId, CancellationToken cancellationToken)
    {
        try
        {
            // Never a second logical mutation after a lost response: the reobservation either
            // confirms the goal state or leaves the outcome held for durable reconciliation.
            var observed = await FindAttachmentAsync(compartmentId, volumeId, cancellationToken);
            return observed is not null && observed.InstanceId == instanceId &&
                observed.LifecycleState == VolumeAttachment.LifecycleStateEnum.Attached
                    ? OciMemberHostVolumeOutcome.Completed
                    : OciMemberHostVolumeOutcome.OutcomeUnknown;
        }
        catch (Exception exception) when (!Fatal(exception, cancellationToken))
        {
            return OciMemberHostVolumeOutcome.OutcomeUnknown;
        }
    }

    /// <summary>Caller cancellation always propagates; fatal failures are never swallowed.</summary>
    private static bool Fatal(Exception exception, CancellationToken cancellationToken) =>
        exception is OutOfMemoryException or StackOverflowException or AccessViolationException ||
        (exception is OperationCanceledException && cancellationToken.IsCancellationRequested);

    private async ValueTask<OciMemberHostVolumeOutcome> WaitUntilDetachedAsync(
        string compartmentId, string volumeId, string attachmentId, CancellationToken cancellationToken)
    {
        var deadline = clock.GetUtcNow() + options.WaitDeadline;
        while (true)
        {
            var attachment = await FindAttachmentAsync(compartmentId, volumeId, cancellationToken);
            if (attachment is null)
                return OciMemberHostVolumeOutcome.Completed;
            if (attachment.Id != attachmentId)
                return OciMemberHostVolumeOutcome.OutcomeUnknown;
            if (clock.GetUtcNow() >= deadline)
                return OciMemberHostVolumeOutcome.OutcomeUnknown;
            await Task.Delay(options.PollInterval, cancellationToken);
        }
    }

    private async ValueTask<OciMemberHostVolumeOutcome> WaitUntilAttachedAsync(
        string compartmentId, string volumeId, string instanceId, CancellationToken cancellationToken)
    {
        var deadline = clock.GetUtcNow() + options.WaitDeadline;
        while (true)
        {
            var attachment = await FindAttachmentAsync(compartmentId, volumeId, cancellationToken);
            if (attachment is not null && attachment.InstanceId != instanceId)
                return OciMemberHostVolumeOutcome.OutcomeUnknown;
            if (attachment?.LifecycleState == VolumeAttachment.LifecycleStateEnum.Attached)
                return OciMemberHostVolumeOutcome.Completed;
            if (clock.GetUtcNow() >= deadline)
                return OciMemberHostVolumeOutcome.OutcomeUnknown;
            await Task.Delay(options.PollInterval, cancellationToken);
        }
    }

    private async Task<VolumeAttachment?> FindAttachmentAsync(
        string compartmentId, string volumeId, CancellationToken cancellationToken)
    {
        RequireDataVolumeId(volumeId);
        var attachments = await ListAttachmentsAsync(compartmentId, volumeId, null, cancellationToken);
        return attachments.Count switch
        {
            0 => null,
            1 => attachments[0],
            _ => throw new InvalidDataException("One member host volume has more than one live attachment."),
        };
    }

    private async Task<IReadOnlyList<VolumeAttachment>> ListAttachmentsAsync(
        string compartmentId, string? volumeId, string? instanceId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(compartmentId))
            throw new ArgumentException("Member host volume resolution requires a compartment.");
        var attachments = new List<VolumeAttachment>();
        var pages = new HashSet<string>(StringComparer.Ordinal);
        string? page = null;
        do
        {
            var response = await transport.ListVolumeAttachmentsAsync(
                new ListVolumeAttachmentsRequest
                {
                    CompartmentId = compartmentId,
                    VolumeId = volumeId,
                    InstanceId = instanceId,
                    Limit = 100,
                    Page = page,
                },
                cancellationToken);
            attachments.AddRange(response.Items ?? []);
            if (attachments.Count > 8 || pages.Count >= 8)
                throw new InvalidDataException("The member host volume observation exceeded its bound.");
            page = response.OpcNextPage;
            if (!string.IsNullOrEmpty(page) && !pages.Add(page))
                throw new InvalidDataException("The member host volume observation repeated a page.");
        }
        while (!string.IsNullOrEmpty(page));
        foreach (var attachment in attachments)
        {
            RequireDataVolumeId(attachment.VolumeId);
            if (attachment.CompartmentId != compartmentId || string.IsNullOrWhiteSpace(attachment.Id) ||
                string.IsNullOrWhiteSpace(attachment.InstanceId) ||
                volumeId is not null && attachment.VolumeId != volumeId ||
                instanceId is not null && attachment.InstanceId != instanceId ||
                attachment.IsShareable != false || attachment.IsReadOnly != false)
                throw new InvalidDataException("The data-volume attachment has an unexpected identity or access mode.");
        }
        return attachments.Where(static attachment =>
            attachment.LifecycleState is not VolumeAttachment.LifecycleStateEnum.Detached).ToArray();
    }

    private static void RequireDataVolumeId(string? volumeId)
    {
        if (volumeId is not { Length: > 13 and <= 255 } ||
            !volumeId.StartsWith("ocid1.volume.", StringComparison.Ordinal) ||
            volumeId.Any(static c => char.IsWhiteSpace(c) || char.IsControl(c)))
            throw new InvalidDataException("Member storage requires an exact OCI data-volume OCID.");
    }

    private void RequireAuthority()
    {
        if (!authorityStillValid())
            throw new InvalidOperationException(
                "Member host fleet authority was lost; the provider mutation was not issued.");
    }
}
