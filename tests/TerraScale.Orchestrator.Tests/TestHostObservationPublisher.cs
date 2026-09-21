using System.Text.Json;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Tests;

/// <summary>Core execution test sink. Signed broker transport is qualified in the real R3 relay tests.</summary>
internal sealed class TestHostObservationPublisher(INatsKVStore store) : IHostObservationPublisher
{
    public async Task PublishAsync(HostAdmissionObservation report, CancellationToken cancellationToken) =>
        _ = await store.PutAsync(HostAdmissionObservation.Key(report.Instance, report.ArtifactKey),
            JsonSerializer.Serialize(report, HostAdmissionObservationJsonContext.Default.HostAdmissionObservation), cancellationToken: cancellationToken);

    public async Task PublishAsync(HostConvergenceObservation report, CancellationToken cancellationToken) =>
        _ = await store.PutAsync($"host.{report.Instance}.{report.ArtifactKey}",
            JsonSerializer.Serialize(report, HostConvergenceJsonContext.Default.HostConvergenceObservation), cancellationToken: cancellationToken);
}
