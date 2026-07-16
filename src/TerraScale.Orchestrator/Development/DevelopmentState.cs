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
    DevelopmentReconciliationState Reconciliation);

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

        await using var stream = File.OpenRead(stateFile);
        return await JsonSerializer.DeserializeAsync<DevelopmentRuntimeState>(
            stream,
            SerializerOptions,
            cancellationToken);
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
