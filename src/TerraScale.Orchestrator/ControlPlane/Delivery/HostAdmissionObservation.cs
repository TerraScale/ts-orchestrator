using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.KeyValueStore;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>Enrollment readiness before installation, volume recovery, or service startup.</summary>
internal sealed record HostAdmissionObservation(int SchemaVersion, string Cell, string Instance,
    string Environment, string ArtifactKey, string Digest, bool Ready, DateTimeOffset ObservedAt)
{
    internal const int CurrentSchemaVersion = 1;
    internal static string Key(string instance, string artifactKey) => $"host.admission.{instance}.{artifactKey}";
}

[JsonSerializable(typeof(HostAdmissionObservation))]
internal sealed partial class HostAdmissionObservationJsonContext : JsonSerializerContext;

/// <summary>The exact admitted target consumed by both host convergence and member readiness.</summary>
internal static class HostDesiredArtifactReader
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        AllowDuplicateProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    internal static async Task<string?> ReadAsync(INatsKVStore delivery, string artifactKey,
        string environment, string cell, CancellationToken cancellationToken)
    {
        string? json;
        try
        {
            var entry = await delivery.GetEntryAsync<string>(DirectDeliveryTargetKey.For(artifactKey, environment, cell),
                cancellationToken: cancellationToken).ConfigureAwait(false);
            entry.EnsureSuccess();
            json = entry.Value;
        }
        catch (Exception exception) when (exception is NatsKVKeyNotFoundException or NatsKVKeyDeletedException or NatsKVException)
        { return null; }
        var state = JsonSerializer.Deserialize<DesiredArtifactState>(json ?? string.Empty, JsonOptions);
        return ValidDigest(state?.ArtifactDigest) ? state!.ArtifactDigest!.ToLowerInvariant() : null;
    }

    internal static bool ValidDigest(string? digest) => digest is { Length: 71 } &&
        digest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) &&
        !digest.AsSpan(7).ContainsAnyExcept("0123456789abcdefABCDEF");

    private sealed record DesiredArtifactState(string? ArtifactDigest, string? ManifestDigest, string? Kind);
}
