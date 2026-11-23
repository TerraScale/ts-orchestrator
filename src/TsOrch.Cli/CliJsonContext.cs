using System.Text.Json.Serialization;

namespace TsOrch.Cli;

internal enum ApplyOutcome
{
    [JsonStringEnumMemberName("added")] Added,
    [JsonStringEnumMemberName("changed")] Changed,
    [JsonStringEnumMemberName("unchanged")] Unchanged,
}

internal sealed record class CliSession(string Url, string Token, long ExpiresAt, string Owner, OperatorRole Role);

internal sealed record class ServicesDocument(IReadOnlyList<ServiceSpec> Services);

internal sealed record class SeedRequest(FleetConfig Fleet, IReadOnlyList<ServiceSpec> Services, bool ReplaceServices);

internal sealed record class SeedServices(IReadOnlyList<string> Added, IReadOnlyList<string> Replaced, IReadOnlyList<string> Skipped);

internal sealed record class SeedResponse(IReadOnlyList<string> Regions, SeedServices Services);

internal sealed record class ServiceListResponse(IReadOnlyList<ServiceSpec> Services);

internal sealed record class NodeListResponse(IReadOnlyList<NodeInfo> Nodes);

internal sealed record class RolloutListResponse(IReadOnlyList<RolloutInfo> Rollouts);

internal sealed record class EventListResponse(IReadOnlyList<EventRecord> Events);

internal sealed record class DiffResponse(IReadOnlyList<DiffItem> Diff);

internal sealed record class AppliedService(string Name, ApplyOutcome Result, string? RolloutId = null);

internal sealed record class ApplyResponse(IReadOnlyList<AppliedService> Applied);

internal sealed record class DeletedServiceResponse(string Deleted);

internal sealed record class RebootResponse(string NodeId, string InstanceId, string Action);

internal sealed record class SecretsRefreshRequest(string Service);

internal sealed record class SecretsRefreshResponse(string Service, IReadOnlyList<string> Nodes);

internal sealed record class LogLine(string NodeId, string PlacementId, LogChannel Stream, string Line);

internal sealed record class ImdsNodeMetadata(
    [property: JsonPropertyName("ts_region")] string? Region = null,
    [property: JsonPropertyName("ts_pool")] PoolKind? Pool = null);

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UseStringEnumConverter = true,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true)]
[JsonSerializable(typeof(CliSession))]
[JsonSerializable(typeof(ServicesDocument))]
[JsonSerializable(typeof(SeedRequest))]
[JsonSerializable(typeof(SeedResponse))]
[JsonSerializable(typeof(ServiceListResponse))]
[JsonSerializable(typeof(NodeListResponse))]
[JsonSerializable(typeof(NodeInfo))]
[JsonSerializable(typeof(RolloutListResponse))]
[JsonSerializable(typeof(EventListResponse))]
[JsonSerializable(typeof(EventRecord))]
[JsonSerializable(typeof(DiffResponse))]
[JsonSerializable(typeof(ApplyResponse))]
[JsonSerializable(typeof(DeletedServiceResponse))]
[JsonSerializable(typeof(RebootResponse))]
[JsonSerializable(typeof(SecretsRefreshRequest))]
[JsonSerializable(typeof(SecretsRefreshResponse))]
[JsonSerializable(typeof(LogLine))]
[JsonSerializable(typeof(ImdsNodeMetadata))]
[JsonSerializable(typeof(HealthState))]
[JsonSerializable(typeof(PoolKind))]
[JsonSerializable(typeof(CpuArch))]
[JsonSerializable(typeof(NodeStatus))]
[JsonSerializable(typeof(PlacementMode))]
[JsonSerializable(typeof(PriorityTier))]
[JsonSerializable(typeof(RolloutPhase))]
[JsonSerializable(typeof(EventKind))]
[JsonSerializable(typeof(OperatorRole))]
[JsonSerializable(typeof(ApplyOutcome))]
internal sealed partial class CliJsonContext : JsonSerializerContext;
