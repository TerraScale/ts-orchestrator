using System.Text.Json;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Policy/convergence test seam: assumes the authorization boundary already succeeded.
/// SessionAuthorizedHostReportReaderTests separately exercise that boundary with real R3 state.
/// This deliberately does not represent the production stored-report wire format.
/// </summary>
internal sealed class AssumedAuthorizedHostReportReader(INatsKVStore store) : IAuthorizedHostReportReader
{
    public async Task<AuthorizedHostReport?> ReadAsync(string key, CancellationToken cancellationToken)
    {
        var entry = await store.GetEntryAsync<string>(key, cancellationToken: cancellationToken);
        entry.EnsureSuccess();
        var admission = key.StartsWith("host.admission.", StringComparison.Ordinal);
        return new(
            admission ? JsonSerializer.Deserialize(entry.Value!, HostAdmissionObservationJsonContext.Default.HostAdmissionObservation) : null,
            admission ? null : JsonSerializer.Deserialize(entry.Value!, HostConvergenceJsonContext.Default.HostConvergenceObservation),
            new("test-enrollment", 1, "test-process", 1), DateTimeOffset.MaxValue);
    }
}
