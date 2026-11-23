using System.Text.Json.Serialization;

namespace TsOrch.Protocol;

public enum OperatorRole
{
    [JsonStringEnumMemberName("admin")] Admin,
    [JsonStringEnumMemberName("deploy")] Deploy,
    [JsonStringEnumMemberName("read")] Read,
}

public enum DiffKind
{
    [JsonStringEnumMemberName("added")] Added,
    [JsonStringEnumMemberName("changed")] Changed,
    [JsonStringEnumMemberName("removed")] Removed,
}

public enum AtlasPlacementState
{
    [JsonStringEnumMemberName("any")] Any,
    [JsonStringEnumMemberName("known")] Known,
}

public sealed record class SshChallengeRequest(string Fingerprint);

public sealed record class SshChallengeResponse(string ChallengeId, string Nonce, string Namespace, long ExpiresAt);

public sealed record class SshVerifyRequest(string ChallengeId, string PublicKey, string Signature);

public sealed record class SshVerifyResponse(string Token, string Owner, OperatorRole Role, long ExpiresAt);

public sealed record class NodeEnrollRequest(
    string EnrollmentSecret,
    string InstanceId,
    string Region,
    PoolKind PoolKind,
    string VcnIp);

public sealed record class NodeEnrollResponse(string NodeId, string Token, string WsUrl);

public sealed record class DeployRequest(string Service, string Image, string? Region = null);

public sealed record class RollbackRequest(string Service, string? Region = null);

public sealed record class RegionSummary(
    string Label,
    HealthState Health,
    int Nodes,
    int NodesReady,
    int StatefulNodes,
    int WorkerNodes,
    long CpuTotalMilli,
    long CpuRequestedMilli,
    long MemTotalMiB,
    long MemRequestedMiB,
    int Databases,
    double PackingPct);

public sealed record class ServiceSummary(
    string Name,
    PlacementMode Mode,
    PriorityTier Priority,
    string Image,
    IReadOnlyList<string> Regions,
    int Desired,
    int Ready);

public sealed record class StatusResponse(
    long Ts,
    IReadOnlyList<RegionSummary> Regions,
    IReadOnlyList<NodeInfo> Nodes,
    IReadOnlyList<ServiceSummary> Services,
    IReadOnlyList<PlacementInfo> Placements,
    IReadOnlyList<RolloutInfo> Rollouts);

public sealed record class TopResponse(long Ts, IReadOnlyList<MetricsPoint10s> Nodes);

public sealed record class DiffItem(string Service, DiffKind Kind, IReadOnlyList<string> Fields);

public sealed record class ExecRequest(string NodeId, string Service, IReadOnlyList<string> Command, int TimeoutSeconds);

public sealed record class ExecResponse(int ExitCode, string Stdout, string Stderr);

[JsonPolymorphic(TypeDiscriminatorPropertyName = "kind", UnknownDerivedTypeHandling = JsonUnknownDerivedTypeHandling.FailSerialization)]
[JsonDerivedType(typeof(KillNodeChaos), "kill_node")]
[JsonDerivedType(typeof(Inject5xxChaos), "inject_5xx")]
[JsonDerivedType(typeof(CpuLoadChaos), "cpu_load")]
[JsonDerivedType(typeof(BumpSecretChaos), "bump_secret")]
[JsonDerivedType(typeof(FillDiskChaos), "fill_disk")]
public closed record class ChaosRequest;

public sealed record class KillNodeChaos(string NodeId) : ChaosRequest;

public sealed record class Inject5xxChaos(string Service, double RatePct, int DurationSeconds) : ChaosRequest;

public sealed record class CpuLoadChaos(string NodeId, double CpuPct, int DurationSeconds) : ChaosRequest;

public sealed record class BumpSecretChaos(string SecretName) : ChaosRequest;

public sealed record class FillDiskChaos(string NodeId, double UsedPct) : ChaosRequest;

public sealed record class AtlasRegion(
    string Id,
    string Name,
    string Country,
    double Lat,
    double Lon,
    string Api,
    string Auth,
    bool Ok);

public sealed record class AtlasService(
    string Id,
    string Name,
    string Url,
    string? Health = null);

public sealed record class AtlasTopology(
    int V,
    long Updated,
    IReadOnlyList<AtlasRegion> Regions,
    IReadOnlyList<AtlasService> Services);

public sealed record class AtlasPlacement(
    int V,
    string Project,
    string Database,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] string? Region,
    long Updated);

public sealed record class AtlasPublishRequest(AtlasTopology? Topology = null, IReadOnlyList<AtlasPlacement>? Placements = null);

public sealed record class AtlasDiscoveryRegion(
    string Id,
    string Name,
    string Country,
    double Lat,
    double Lon,
    string Api,
    string Auth,
    HealthState Health,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] double? DistanceKm);

public sealed record class AtlasDiscoveryResponse(
    int V,
    long Updated,
    bool Stale,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] string? Closest,
    IReadOnlyList<AtlasDiscoveryRegion> Regions,
    IReadOnlyList<AtlasService> Services);

public sealed record class AtlasResolveResponse(
    [property: JsonPropertyOrder(-3)] int V,
    [property: JsonPropertyOrder(-2)] string Project,
    string Region,
    string Api,
    string Auth,
    HealthState Health,
    AtlasPlacementState Placement,
    bool Stale,
    string Pin,
    long Expires,
    [property: JsonPropertyOrder(-1)] string? Database = null);

public sealed record class AtlasJwk(string Kty, string Crv, string X, string Y, string Kid, string Alg, string Use);

public sealed record class AtlasKeysResponse(IReadOnlyList<AtlasJwk> Keys);

public sealed record class ErrorDetail(string Code, string Message, string? Fix = null);

public sealed record class ErrorResponse(ErrorDetail Error);
