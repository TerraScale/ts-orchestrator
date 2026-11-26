using System.Text.Json.Serialization;

namespace TsOrch.Protocol;

public enum PlacementMode
{
    [JsonStringEnumMemberName("daemon")] Daemon,
    [JsonStringEnumMemberName("replicated")] Replicated,
    [JsonStringEnumMemberName("stateful")] Stateful,
}

public enum PriorityTier
{
    [JsonStringEnumMemberName("high")] High,
    [JsonStringEnumMemberName("normal")] Normal,
    [JsonStringEnumMemberName("low")] Low,
}

public enum PoolKind
{
    [JsonStringEnumMemberName("stateful")] Stateful,
    [JsonStringEnumMemberName("worker")] Worker,
}

public enum CpuArch
{
    [JsonStringEnumMemberName("arm64")] Arm64,
    [JsonStringEnumMemberName("x64")] X64,
}

public enum NodeStatus
{
    [JsonStringEnumMemberName("pending")] Pending,
    [JsonStringEnumMemberName("active")] Active,
    [JsonStringEnumMemberName("draining")] Draining,
    [JsonStringEnumMemberName("drained")] Drained,
    [JsonStringEnumMemberName("down")] Down,
}

public enum PlacementState
{
    [JsonStringEnumMemberName("pending")] Pending,
    [JsonStringEnumMemberName("unschedulable")] Unschedulable,
    [JsonStringEnumMemberName("pulling")] Pulling,
    [JsonStringEnumMemberName("starting")] Starting,
    [JsonStringEnumMemberName("ready")] Ready,
    [JsonStringEnumMemberName("draining")] Draining,
    [JsonStringEnumMemberName("stopped")] Stopped,
    [JsonStringEnumMemberName("failed")] Failed,
}

public enum RolloutPhase
{
    [JsonStringEnumMemberName("pending")] Pending,
    [JsonStringEnumMemberName("canary")] Canary,
    [JsonStringEnumMemberName("baking")] Baking,
    [JsonStringEnumMemberName("waves")] Waves,
    [JsonStringEnumMemberName("succeeded")] Succeeded,
    [JsonStringEnumMemberName("rolled_back")] RolledBack,
    [JsonStringEnumMemberName("failed")] Failed,
}

public enum RolloutRegionPhase
{
    [JsonStringEnumMemberName("canary")] Canary,
    [JsonStringEnumMemberName("baking")] Baking,
    [JsonStringEnumMemberName("waves")] Waves,
    [JsonStringEnumMemberName("succeeded")] Succeeded,
    [JsonStringEnumMemberName("skipped")] Skipped,
}

[JsonConverter(typeof(EventKindJsonConverter))]
public enum EventKind
{
    Unknown,
    DeployStarted,
    CanaryStarted,
    CanaryPassed,
    Rollback,
    RolloutSucceeded,
    RolloutFailed,
    ReplicaScaleUp,
    ReplicaScaleDown,
    PoolScaleUp,
    PoolScaleDown,
    PoolScaleBlocked,
    NodeEnrolled,
    NodeConnected,
    NodeLost,
    NodeDrained,
    Failover,
    OomKill,
    VolumeGrown,
    SecretRotated,
    TlsRenewed,
    Chaos,
    ContainerExec,
}

public enum HealthState
{
    [JsonStringEnumMemberName("ok")] Ok,
    [JsonStringEnumMemberName("unknown")] Unknown,
    [JsonStringEnumMemberName("down")] Down,
}

public sealed record class FleetConfig(
    BackplaneConfig Backplane,
    OciConfig Oci,
    DnsConfig Dns,
    AtlasConfig Atlas,
    IReadOnlyList<string> RolloutOrder,
    IReadOnlyList<RegionConfig> Regions,
    [property: JsonPropertyName("netbird")] NetBirdConfig? NetBird = null);

public sealed record class NetBirdConfig(
    string ManagementUrl,
    string DnsDomain,
    string NetworkRange,
    string SetupKeySecret,
    string OperatorsSetupKeySecret,
    string AdminPatSecret,
    string OwnerEmail,
    string OwnerPasswordSecret);

public sealed record class BackplaneConfig(string LocationHint, string OrchHost, string AtlasHost);

public sealed record class OciConfig(string TenancyId, RegistryConfig Registry, VaultConfig Vault);

public sealed record class RegistryConfig(string Namespace, string RepoPrefix);

public sealed record class VaultConfig(string Region, string VaultId);

public sealed record class DnsConfig(
    string Zone,
    string CompartmentId,
    IReadOnlyList<string> SteeredNames,
    int TtlSeconds,
    string HealthCheckPath);

public sealed record class AtlasConfig(IReadOnlyList<string> RequiredServices, IReadOnlyList<AtlasService> Services);

public sealed record class RegionConfig(
    string Label,
    string OciRegion,
    string CompartmentId,
    RegionLocation Location,
    RegionNetwork Network,
    RegionEndpoints Endpoints,
    RegionPools Pools,
    string? InstancePoolId = null);

public sealed record class RegionLocation(string Name, string Country, double Lat, double Lon, IReadOnlyList<string> Continents);

public sealed record class RegionNetwork(string VcnCidr, string PublicSubnetCidr, string PrivateSubnetCidr);

public sealed record class RegionEndpoints(string Api, string Auth);

public sealed record class RegionPools(StatefulPool Stateful, WorkerPool Worker);

public sealed record class ComputeShape(string Name, int Ocpus, int MemoryGiB, int BootGiB);

public sealed record class StatefulPool(
    int Count,
    ComputeShape Shape,
    int DataGiB,
    int DataVpusPerGiB);

public sealed record class WorkerPool(int Min, int Max, ComputeShape Shape);

public sealed record class HttpRouteRule(
    IReadOnlyList<string> PathPatterns,
    IReadOnlyList<string>? Methods = null);

public sealed record class ServiceSpec(
    string Name,
    PlacementMode Mode,
    PriorityTier Priority,
    string Image,
    IReadOnlyList<string> Regions,
    int Replicas,
    int MinReplicas,
    int MaxReplicas,
    int CpuRequestMilli,
    int CpuLimitMilli,
    int MemRequestMiB,
    int MemLimitMiB,
    int PidsLimit,
    int Port,
    string ReadyPath,
    int ReadyTimeoutSeconds,
    IReadOnlyList<string> Hostnames,
    IReadOnlyDictionary<string, string> Env,
    IReadOnlyDictionary<string, SecretRef> Secrets,
    IReadOnlyList<MountSpec> Mounts,
    IReadOnlyList<string> Args,
    IReadOnlyList<int> UdpPorts,
    PostgresSpec? Postgres = null,
    AutoscaleSpec? Autoscale = null,
    IReadOnlyList<string>? PathPrefixes = null,
    bool MatchGrpc = false,
    IReadOnlyList<string>? BlockedPaths = null,
    IReadOnlyList<ConfigFileSpec>? ConfigFiles = null,
    int? InternalPort = null,
    bool ClusterPeers = false,
    IReadOnlyList<string>? PathPatterns = null,
    IReadOnlyList<string>? Methods = null,
    IReadOnlyList<HttpRouteRule>? RouteRules = null);

public sealed record class ConfigFileSpec(string Target, string Template);

public sealed record class SecretRef(string Vault, string Name);

public sealed record class MountSpec(string Source, string Target);

public sealed record class PostgresSpec(int Port, IReadOnlyList<string> Hostnames);

public sealed record class AutoscaleSpec(
    double TargetCpuPct,
    double TargetP95Ms,
    int ScaleUpCooldownSeconds,
    int ScaleDownCooldownSeconds);

public sealed record class VolumeInfo(string MountPath, string Device, int SizeGiB, double UsedPct);

public sealed record class NodeInfo(
    string Id,
    string Region,
    PoolKind PoolKind,
    string VcnIp,
    CpuArch Arch,
    string Shape,
    string FaultDomain,
    int CpuTotalMilli,
    int MemTotalMiB,
    int DiskTotalGiB,
    IReadOnlyDictionary<string, string> Labels,
    IReadOnlyList<VolumeInfo> Volumes,
    NodeStatus Status,
    bool DrainRequested,
    long LastSeenAt,
    string AgentVersion,
    int? CpuRequestedMilli = null,
    int? MemRequestedMiB = null,
    string? NetbirdIp = null);

public sealed record class PlacementInfo(
    string Id,
    string ServiceName,
    string Region,
    int Slot,
    string DesiredImage,
    PlacementState State,
    long UpdatedAt,
    string? NodeId = null,
    string? ActiveImage = null,
    string? ActiveConfigHash = null,
    int? HostPort = null,
    int? PostgresHostPort = null,
    int? InternalHostPort = null,
    string? CandidateImage = null,
    string? CandidateError = null);

public sealed record class DesiredPlacement(
    string PlacementId,
    int Slot,
    ServiceSpec Service,
    int? HostPort = null,
    int? PostgresHostPort = null,
    int? InternalHostPort = null);

public sealed record class PlacementReport(
    string PlacementId,
    string ServiceName,
    PlacementState State,
    string Image,
    string ConfigHash,
    int? HostPort = null,
    string? Error = null,
    int? PostgresHostPort = null,
    int? InternalHostPort = null,
    string? CandidateImage = null,
    string? CandidateError = null);

public sealed record class RolloutInfo(
    string Id,
    string ServiceName,
    string TargetImage,
    RolloutPhase Phase,
    int CurrentWave,
    int TotalWaves,
    long StartedAt,
    string? Region = null,
    string? PreviousImage = null,
    string? CurrentRegion = null,
    double? BaselineP95Ms = null,
    double? Baseline5xxPct = null,
    long? CanaryStartedAt = null,
    long? WaveStartedAt = null,
    long? FinishedAt = null,
    string? Error = null,
    IReadOnlyList<string>? RegionOrder = null,
    IReadOnlyList<string>? ActiveRegions = null,
    IReadOnlyList<RolloutRegionProgress>? RegionProgress = null);

public sealed record class RolloutRegionProgress(
    string Region,
    RolloutRegionPhase Phase,
    long? CanaryStartedAt = null,
    long? WaveStartedAt = null);

public sealed record class EventRecord(
    long Id,
    long Ts,
    EventKind Kind,
    string Subject,
    IReadOnlyDictionary<string, string> Detail,
    string? Region = null);

public sealed record class TlsBundle(IReadOnlyList<string> Domains, string CertPem, string KeyPem, long NotAfter);
