using System.Collections.Frozen;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TsOrch.Protocol;

public sealed class EventKindJsonConverter : JsonConverter<EventKind>
{
    private static readonly FrozenDictionary<string, EventKind> Known = Enum.GetValues<EventKind>()
        .Where(static kind => kind is not EventKind.Unknown)
        .ToFrozenDictionary(WireName, StringComparer.Ordinal);

    public override bool HandleNull => true;

    public override EventKind Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) => reader.TokenType switch
    {
        JsonTokenType.String => reader.GetString() is { } wire && Known.TryGetValue(wire, out var kind) ? kind : EventKind.Unknown,
        JsonTokenType.Null => EventKind.Unknown,
        _ => throw new JsonException($"Expected an event kind string but found {reader.TokenType}."),
    };

    public override void Write(Utf8JsonWriter writer, EventKind value, JsonSerializerOptions options) =>
        writer.WriteStringValue(WireName(value));

    public static string WireName(EventKind kind) => kind switch
    {
        EventKind.Unknown => "unknown",
        EventKind.DeployStarted => "deploy_started",
        EventKind.CanaryStarted => "canary_started",
        EventKind.CanaryPassed => "canary_passed",
        EventKind.Rollback => "rollback",
        EventKind.RolloutSucceeded => "rollout_succeeded",
        EventKind.RolloutFailed => "rollout_failed",
        EventKind.ReplicaScaleUp => "replica_scale_up",
        EventKind.ReplicaScaleDown => "replica_scale_down",
        EventKind.PoolScaleUp => "pool_scale_up",
        EventKind.PoolScaleDown => "pool_scale_down",
        EventKind.PoolWorkerReplaced => "pool_worker_replaced",
        EventKind.PoolScaleBlocked => "pool_scale_blocked",
        EventKind.NodeEnrolled => "node_enrolled",
        EventKind.NodeConnected => "node_connected",
        EventKind.NodeLost => "node_lost",
        EventKind.NodeDrained => "node_drained",
        EventKind.Failover => "failover",
        EventKind.OomKill => "oom_kill",
        EventKind.VolumeGrown => "volume_grown",
        EventKind.SecretRotated => "secret_rotated",
        EventKind.TlsRenewed => "tls_renewed",
        EventKind.Chaos => "chaos",
        EventKind.ContainerExec => "container_exec",
        _ => throw new UnreachableException(),
    };
}
