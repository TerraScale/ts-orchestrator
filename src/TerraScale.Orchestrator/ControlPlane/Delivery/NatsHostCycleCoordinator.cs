using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using NATS.Client.Core;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

internal sealed record HostConvergenceCycle(AdmittedRole Role, string Digest, string AttemptId, string CycleId, ulong Fence);

internal interface IHostCycleCoordinator
{
    Task FlushAsync(AdmittedRole role, CancellationToken cancellationToken);
    Task<HostConvergenceCycle?> BeginAsync(AdmittedRole role, string environment, string cell, string digest, CancellationToken cancellationToken);
    Task FinishAsync(HostConvergenceCycle cycle, bool succeeded, CancellationToken cancellationToken);
}

/// <summary>
/// Keeps one pending operation per admitted role through ambiguous replies. A failed outcome
/// exchange is retried before another cycle can start. Process restarts get a new session;
/// they cannot inherit an active cycle from the previous process.
/// </summary>
internal sealed class NatsHostCycleCoordinator(INatsConnection connection, string cell, string nodeId,
    Func<RegionalHostSessionSigner> currentSigner, TimeProvider? clock = null) : IHostCycleCoordinator
{
    private readonly TimeProvider time = clock ?? TimeProvider.System;
    private readonly Dictionary<AdmittedRole, Slot> slots = AdmittedRoleCatalog.All.ToDictionary(value => value.Role, _ => new Slot());

    public async Task FlushAsync(AdmittedRole role, CancellationToken cancellationToken)
    {
        var slot = slots[role];
        await slot.Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (slot.Outcome is { } outcome) await FinishPendingAsync(slot, outcome, cancellationToken).ConfigureAwait(false);
        }
        finally { slot.Gate.Release(); }
    }

    public async Task<HostConvergenceCycle?> BeginAsync(AdmittedRole role, string environment, string requestedCell, string digest,
        CancellationToken cancellationToken)
    {
        _ = AdmittedRoleCatalog.Get(role);
        var slot = slots[role];
        await slot.Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (slot.Outcome is { } outcome)
            {
                await FinishPendingAsync(slot, outcome, cancellationToken).ConfigureAwait(false);
                return null;
            }
            // A receipt already handed to the caller cannot start two concurrent executions.
            if (slot.Cycle is not null) return null;
            if (slot.Begin is null || slot.Begin.ArtifactDigest != digest)
                slot.Begin = currentSigner().SignCycle(role, digest, RegionalHostCycleOperation.Begin, Guid.NewGuid().ToString("N"));
            var request = Refresh(slot.Begin, RegionalHostCycleOperation.Begin, null, 0);
            if (requestedCell != cell || request.Enrollment.Scope.Environment != environment)
                throw new InvalidOperationException("The cycle scope does not match this enrolled host.");
            var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
            RequireAccepted(response);
            if (response.Disposition != RegionalHostCycleDisposition.Active)
            {
                slot.Begin = null;
                return null;
            }
            return slot.Cycle = new(role, digest, request.AttemptId, response.CycleId!, response.Fence);
        }
        finally { slot.Gate.Release(); }
    }

    public async Task FinishAsync(HostConvergenceCycle cycle, bool succeeded, CancellationToken cancellationToken)
    {
        var slot = slots[cycle.Role];
        // Retain the chosen outcome even when the caller has already cancelled. The
        // bounded network exchange can then fail without forgetting what must be retried.
        await slot.Gate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            if (slot.Cycle != cycle || slot.Outcome is { } pending && pending != succeeded)
                throw new InvalidOperationException("The outcome must match this host's current cycle and pending result.");
            slot.Outcome = succeeded;
            await FinishPendingAsync(slot, succeeded, cancellationToken).ConfigureAwait(false);
        }
        finally { slot.Gate.Release(); }
    }

    private async Task FinishPendingAsync(Slot slot, bool succeeded, CancellationToken cancellationToken)
    {
        var cycle = slot.Cycle ?? throw new InvalidOperationException("A pending outcome has no cycle receipt.");
        var request = Refresh(slot.Begin ?? throw new InvalidOperationException("A pending cycle has no begin request."), succeeded ? RegionalHostCycleOperation.Complete : RegionalHostCycleOperation.Fail,
            cycle.CycleId, cycle.Fence);
        RequireAccepted(await SendAsync(request, cancellationToken).ConfigureAwait(false));
        slot.Begin = null;
        slot.Cycle = null;
        slot.Outcome = null;
    }

    private RegionalHostCycleRequest Refresh(RegionalHostCycleRequest original, RegionalHostCycleOperation operation, string? cycleId, ulong fence)
    {
        var request = currentSigner().SignCycle(original.Role, original.ArtifactDigest, operation, original.AttemptId, cycleId, fence);
        if (request.Enrollment.Digest != original.Enrollment.Digest || request.SessionId != original.SessionId || request.Epoch != original.Epoch)
            throw new InvalidOperationException("A cycle cannot move to a different enrollment or process session.");
        return request;
    }

    private static void RequireAccepted(RegionalHostCycleResponse response)
    {
        if (!response.Accepted) throw new InvalidOperationException($"The cycle operation was denied: {response.Decision}.");
    }

    internal async Task<RegionalHostCycleResponse> SendAsync(RegionalHostCycleRequest request, CancellationToken cancellationToken)
    {
        if (request.Enrollment.Region != cell.ToUpperInvariant() || request.Enrollment.NodeId != nodeId)
            throw new InvalidOperationException("The cycle request does not match this host identity.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        var reply = RegionalHostCycleRequest.ReplySubject(cell, nodeId, request.RequestId);
        await using var subscription = await connection.SubscribeCoreAsync<string>(reply,
            opts: new NatsSubOpts { MaxMsgs = 1, ChannelOpts = new NatsSubChannelOpts { Capacity = 1, FullMode = BoundedChannelFullMode.DropWrite } },
            cancellationToken: deadline.Token).ConfigureAwait(false);
        await connection.PingAsync(deadline.Token).AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
        await connection.PublishAsync(RegionalHostCycleRequest.Subject(cell, nodeId), request.Serialize(), replyTo: reply,
            cancellationToken: deadline.Token).ConfigureAwait(false);
        var message = await subscription.Msgs.ReadAsync(deadline.Token).ConfigureAwait(false);
        if (message.Data is not { Length: > 0 and <= 4096 } json || Encoding.UTF8.GetByteCount(json) > 4096)
            throw new InvalidDataException("The cycle response exceeds its wire bounds.");
        var response = JsonSerializer.Deserialize<RegionalHostCycleResponse>(json, RegionalHostSessionAuthority.JsonOptions)
            ?? throw new InvalidDataException("The cycle response is missing.");
        response.RequireBinding(request, time.GetUtcNow());
        deadline.Token.ThrowIfCancellationRequested();
        return response;
    }

    private sealed class Slot
    {
        internal SemaphoreSlim Gate { get; } = new(1, 1);
        internal RegionalHostCycleRequest? Begin { get; set; }
        internal HostConvergenceCycle? Cycle { get; set; }
        internal bool? Outcome { get; set; }
    }
}
