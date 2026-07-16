using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator;

internal sealed record OrchestratorRuntimeConfiguration(
    int SchemaVersion,
    string Cell,
    string NatsUrl,
    int Replicas,
    string Instance)
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public static OrchestratorRuntimeConfiguration? Load(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }
        var fullPath = Path.GetFullPath(path);
        using var stream = File.OpenRead(fullPath);
        var configuration = JsonSerializer.Deserialize<OrchestratorRuntimeConfiguration>(stream, SerializerOptions)
            ?? throw new InvalidOperationException("Orchestrator runtime configuration is empty.");
        if (configuration.SchemaVersion != 1)
        {
            throw new InvalidOperationException(
                $"Unsupported Orchestrator runtime configuration schema {configuration.SchemaVersion}.");
        }
        return configuration;
    }

    public string? GetEnvironmentValue(string key) => key switch
    {
        "TS_ORCH_CELL" => Cell,
        "TS_ORCH_NATS_URL" => NatsUrl,
        "TS_ORCH_REPLICAS" => Replicas.ToString(System.Globalization.CultureInfo.InvariantCulture),
        "TS_ORCH_INSTANCE" => Instance,
        _ => null
    };
}
