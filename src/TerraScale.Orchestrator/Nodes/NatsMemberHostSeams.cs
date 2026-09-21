using System.Text.Json;
using NATS.Client.Core;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.ControlPlane.TerraBase;

namespace TerraScale.Orchestrator.Nodes;

/// <summary>
/// Enrollment permits storage recovery before service startup; serving health separately
/// requires exact, fresh convergence evidence. Both bind to the admitted delivery target.
/// </summary>
internal sealed class NatsMemberHostSeams : IMemberHostObservationSource, IMemberHostCommandChannel
{
    private readonly INatsKVStore runtimeStore;
    private readonly INatsKVStore deliveryStore;
    private readonly INatsConnection connection;
    private readonly string cell;
    private readonly string environment;
    private readonly TimeProvider clock;

    internal NatsMemberHostSeams(INatsKVStore runtimeStore, INatsKVStore deliveryStore,
        INatsConnection connection, string cell, string environment, TimeProvider clock)
    {
        this.runtimeStore = runtimeStore ?? throw new ArgumentNullException(nameof(runtimeStore));
        this.deliveryStore = deliveryStore ?? throw new ArgumentNullException(nameof(deliveryStore));
        this.connection = connection ?? throw new ArgumentNullException(nameof(connection));
        this.cell = cell;
        this.environment = environment;
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
    }

    public async ValueTask<bool> HasHostReportedAsync(string instance, CancellationToken cancellationToken)
        => await ReadAdmittedDigestAsync(instance, cancellationToken).ConfigureAwait(false) is not null;

    private async Task<string?> ReadAdmittedDigestAsync(string instance, CancellationToken cancellationToken)
    {
        try
        {
            var digest = await HostDesiredArtifactReader.ReadAsync(deliveryStore,
                TerraBasePlacementReconciler.MemberArtifactKey, environment, cell, cancellationToken).ConfigureAwait(false);
            if (digest is null) return null;
            var entry = await runtimeStore.GetEntryAsync<string>(
                HostAdmissionObservation.Key(instance, TerraBasePlacementReconciler.MemberArtifactKey),
                cancellationToken: cancellationToken).ConfigureAwait(false);
            entry.EnsureSuccess();
            var observation = JsonSerializer.Deserialize(entry.Value ?? string.Empty,
                HostAdmissionObservationJsonContext.Default.HostAdmissionObservation);
            return observation is { SchemaVersion: HostAdmissionObservation.CurrentSchemaVersion, Ready: true } &&
                observation.Instance == instance && observation.Cell == cell && observation.Environment == environment &&
                observation.ArtifactKey == TerraBasePlacementReconciler.MemberArtifactKey && observation.Digest == digest &&
                Fresh(observation.ObservedAt) ? digest : null;
        }
        catch (Exception exception) when (exception is NatsKVKeyNotFoundException or NatsKVKeyDeletedException or NatsKVException or JsonException)
        {
            return null;
        }
    }

    public async ValueTask<MemberHealth?> ObserveMemberHealthAsync(string instance, CancellationToken cancellationToken)
    {
        HostConvergenceObservation? observation;
        try
        {
            var digest = await ReadAdmittedDigestAsync(instance, cancellationToken).ConfigureAwait(false);
            if (digest is null) return null;
            var entry = await runtimeStore.GetEntryAsync<string>(
                ObservationKey(instance), cancellationToken: cancellationToken).ConfigureAwait(false);
            entry.EnsureSuccess();
            observation = JsonSerializer.Deserialize(
                entry.Value ?? string.Empty, HostConvergenceJsonContext.Default.HostConvergenceObservation);
            if (observation is null) return null;
            observation.Validate();
            if (observation is not { SchemaVersion: HostConvergenceObservation.CurrentSchemaVersion, State: "converged", Error: null } ||
                observation.Instance != instance || observation.Cell != cell ||
                observation.ArtifactKey != TerraBasePlacementReconciler.MemberArtifactKey || observation.Digest != digest ||
                !Fresh(observation.ObservedAt)) return null;
        }
        catch (Exception exception) when (
            exception is NatsKVKeyNotFoundException or NatsKVKeyDeletedException or NatsKVException or JsonException or InvalidOperationException)
        {
            return null;
        }
        if (observation.MemberUp is not { } up || observation.MemberReplicationLagSequences is not { } lag ||
            observation.MemberPeerAckCount is not { } acknowledgements || observation.MemberMinReplicas is not { } minimum ||
            !Enum.TryParse<TerraBaseRole>(observation.MemberRole, ignoreCase: true, out var role) || !Enum.IsDefined(role) ||
            !string.Equals(observation.MemberRole, role.ToString(), StringComparison.OrdinalIgnoreCase) ||
            up && role == TerraBaseRole.Unknown)
            return null;
        return new(up, lag, role.ToString(), acknowledgements, minimum);
    }

    private bool Fresh(DateTimeOffset observedAt)
    {
        var now = clock.GetUtcNow();
        return observedAt >= now.AddMinutes(-10) && observedAt <= now;
    }

    public async ValueTask PublishAsync(string subject, CancellationToken cancellationToken) =>
        await connection.PublishAsync(subject, cancellationToken: cancellationToken).ConfigureAwait(false);

    private static string ObservationKey(string instance) =>
        $"host.{instance}.{TerraBasePlacementReconciler.MemberArtifactKey}";
}
