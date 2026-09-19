using System.Text.Json;
using NATS.Client.Core;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.ControlPlane.TerraBase;

namespace TerraScale.Orchestrator.Nodes;

/// <summary>
/// The NATS-backed member-host seams over the controller's own durable stores: readiness
/// and member health read the host convergence observations members publish into
/// <c>ORCH_RUNTIME</c> under <c>host.{instance}.terrabase-server</c>, and drain commands
/// publish on the controller's cell connection at the subject the fleet computed. A
/// schema-1 observation carries no member health and reads as not reporting; an unreadable
/// record is the member's own evidence gap, never a fleet failure.
/// </summary>
internal sealed class NatsMemberHostSeams : IMemberHostObservationSource, IMemberHostCommandChannel
{
    private readonly INatsKVStore runtimeStore;
    private readonly INatsConnection connection;

    internal NatsMemberHostSeams(INatsKVStore runtimeStore, INatsConnection connection)
    {
        this.runtimeStore = runtimeStore ?? throw new ArgumentNullException(nameof(runtimeStore));
        this.connection = connection ?? throw new ArgumentNullException(nameof(connection));
    }

    public async ValueTask<bool> HasHostReportedAsync(string instance, CancellationToken cancellationToken)
    {
        try
        {
            var entry = await runtimeStore.GetEntryAsync<string>(
                ObservationKey(instance), cancellationToken: cancellationToken).ConfigureAwait(false);
            entry.EnsureSuccess();
            return true;
        }
        catch (Exception exception) when (exception is NatsKVKeyNotFoundException or NatsKVKeyDeletedException)
        {
            return false;
        }
    }

    public async ValueTask<MemberHealth?> ObserveMemberHealthAsync(string instance, CancellationToken cancellationToken)
    {
        HostConvergenceObservation? observation;
        try
        {
            var entry = await runtimeStore.GetEntryAsync<string>(
                ObservationKey(instance), cancellationToken: cancellationToken).ConfigureAwait(false);
            entry.EnsureSuccess();
            observation = JsonSerializer.Deserialize(
                entry.Value!, HostConvergenceJsonContext.Default.HostConvergenceObservation);
        }
        catch (Exception exception) when (
            exception is NatsKVKeyNotFoundException or NatsKVKeyDeletedException or NatsKVException or JsonException)
        {
            return null;
        }
        if (observation?.MemberUp is not { } up)
            return null;
        return new(
            up,
            observation.MemberReplicationLagSequences ?? 0,
            observation.MemberRole ?? nameof(TerraBaseRole.Unknown),
            observation.MemberPeerAckCount ?? 0,
            observation.MemberMinReplicas ?? 0);
    }

    public async ValueTask PublishAsync(string subject, CancellationToken cancellationToken) =>
        await connection.PublishAsync(subject, cancellationToken: cancellationToken).ConfigureAwait(false);

    private static string ObservationKey(string instance) =>
        $"host.{instance}.{TerraBasePlacementReconciler.MemberArtifactKey}";
}
