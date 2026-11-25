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

internal sealed record class SeedRequest(
    FleetConfig Fleet,
    IReadOnlyList<ServiceSpec> Services,
    bool ReplaceServices,
    IReadOnlyDictionary<string, string>? InstancePoolIds = null);

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

internal sealed record class DeletedNodeResponse(string Deleted);

internal sealed record class NodeUpgradeRequest(string Version, string Url, string Sha256, string? NodeId = null);

internal sealed record class NodeUpgradeResponse(string Version, IReadOnlyList<string> Nodes);

internal sealed record class TlsErrorInfo(long At, string Message);

internal sealed record class TlsStatusResponse(
    bool Configured,
    IReadOnlyList<string> Domains,
    long? NotAfter = null,
    long? RenewedAt = null,
    TlsErrorInfo? Error = null);

internal sealed record class TlsEnsureResponse(
    bool Renewed,
    IReadOnlyList<string> Domains,
    long NotAfter,
    IReadOnlyList<string> PushedTo);

internal sealed record class RebootResponse(string NodeId, string InstanceId, string Action);

internal sealed record class SecretsRefreshRequest(string Service);

internal sealed record class SecretsRefreshResponse(string Service, IReadOnlyList<string> Nodes);

internal sealed record class LogLine(string NodeId, string PlacementId, LogChannel Stream, string Line);

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UseStringEnumConverter = true,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true)]
[JsonSerializable(typeof(CliSession))]
[JsonSerializable(typeof(NetBirdStatusReport))]
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
[JsonSerializable(typeof(DeletedNodeResponse))]
[JsonSerializable(typeof(NodeUpgradeRequest))]
[JsonSerializable(typeof(NodeUpgradeResponse))]
[JsonSerializable(typeof(TlsStatusResponse))]
[JsonSerializable(typeof(TlsEnsureResponse))]
[JsonSerializable(typeof(RebootResponse))]
[JsonSerializable(typeof(SecretsRefreshRequest))]
[JsonSerializable(typeof(SecretsRefreshResponse))]
[JsonSerializable(typeof(LogLine))]
[JsonSerializable(typeof(HealthState))]
[JsonSerializable(typeof(PoolKind))]
[JsonSerializable(typeof(CpuArch))]
[JsonSerializable(typeof(NodeStatus))]
[JsonSerializable(typeof(PlacementMode))]
[JsonSerializable(typeof(PriorityTier))]
[JsonSerializable(typeof(RolloutPhase))]
[JsonSerializable(typeof(OperatorRole))]
[JsonSerializable(typeof(ApplyOutcome))]
internal sealed partial class CliJsonContext : JsonSerializerContext;
