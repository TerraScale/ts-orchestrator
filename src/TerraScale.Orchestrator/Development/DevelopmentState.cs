using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Development;

public enum DevelopmentResourceState
{
    Planned,
    Starting,
    Ready,
    Degraded,
    Stopped,
    Failed
}

public sealed record DevelopmentResourceObservation(
    string Name,
    string Cell,
    DevelopmentResourceKind Kind,
    int Replica,
    DevelopmentResourceState State,
    bool Healthy,
    int? ProcessId,
    string? ContainerId,
    string? Endpoint,
    string Detail,
    DateTimeOffset ObservedAt);

public sealed record DevelopmentRuntimeState(
    int SchemaVersion,
    string Profile,
    long Generation,
    DateTimeOffset StartedAt,
    DateTimeOffset ObservedAt,
    IReadOnlyList<DevelopmentResourceObservation> Resources,
    DevelopmentReconciliationState Reconciliation,
    IReadOnlyList<DevelopmentReconciliationProgress>? Reconciliations = null,
    IReadOnlyList<DevelopmentIncident>? Incidents = null);

public sealed record DevelopmentReconciliationProgress(
    string ReconciliationId,
    string RequestId,
    string Repository,
    string PreviousCommit,
    string CurrentCommit,
    string State,
    IReadOnlyList<string> Resources,
    string Detail,
    DateTimeOffset StartedAt,
    DateTimeOffset UpdatedAt);

public sealed record DevelopmentIncident(
    string Code,
    string Resource,
    string Cell,
    string Repository,
    string Severity,
    bool Actionable,
    bool Transient,
    string Evidence,
    int Occurrences,
    DateTimeOffset ObservedAt);

public sealed record DevelopmentEndpointMap(
    int SchemaVersion,
    long Generation,
    IReadOnlyDictionary<string, string> Endpoints);

internal static class DevelopmentStateStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public static async Task WriteAsync(
        string stateFile,
        string endpointsFile,
        DevelopmentRuntimeState state,
        DevelopmentEndpointMap? endpoints,
        CancellationToken cancellationToken)
    {
        await WriteAtomicAsync(stateFile, state, cancellationToken);
        if (endpoints is not null)
        {
            await WriteAtomicAsync(endpointsFile, endpoints, cancellationToken);
        }
    }

    public static async Task<DevelopmentRuntimeState?> ReadAsync(
        string stateFile,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(stateFile))
        {
            return null;
        }

        try
        {
            await using var stream = File.OpenRead(stateFile);
            return await JsonSerializer.DeserializeAsync<DevelopmentRuntimeState>(
                stream,
                SerializerOptions,
                cancellationToken);
        }
        catch (JsonException)
        {
            // Development observations are disposable projections, not desired state.
            // A renamed or removed resource kind must not prevent a newer runtime from
            // reconciling a fresh generation and atomically replacing the snapshot.
            return null;
        }
    }

    private static async Task WriteAtomicAsync<T>(
        string path,
        T value,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        await File.WriteAllTextAsync(
            temporary,
            JsonSerializer.Serialize(value, SerializerOptions),
            cancellationToken);
        File.Move(temporary, path, overwrite: true);
    }
}
