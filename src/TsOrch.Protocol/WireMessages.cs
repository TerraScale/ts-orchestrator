using System.Text.Json.Serialization;

namespace TsOrch.Protocol;

public enum LogChannel
{
    [JsonStringEnumMemberName("stdout")] Stdout,
    [JsonStringEnumMemberName("stderr")] Stderr,
}

[JsonPolymorphic(TypeDiscriminatorPropertyName = "type", UnknownDerivedTypeHandling = JsonUnknownDerivedTypeHandling.FailSerialization)]
[JsonDerivedType(typeof(Hello), "hello")]
[JsonDerivedType(typeof(Heartbeat), "heartbeat")]
[JsonDerivedType(typeof(PlacementEvent), "placement_event")]
[JsonDerivedType(typeof(DrainComplete), "drain_complete")]
[JsonDerivedType(typeof(VolumeGrown), "volume_grown")]
[JsonDerivedType(typeof(LogChunk), "log_chunk")]
[JsonDerivedType(typeof(ExecResult), "exec_result")]
public closed record class AgentMessage;

public sealed record class Hello(
    string NodeId,
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
    string AgentVersion,
    string? NetbirdIp = null) : AgentMessage;

public sealed record class Heartbeat(
    long Ts,
    IReadOnlyList<PlacementReport> Placements,
    HostMetrics HostMetrics,
    IReadOnlyList<ContainerMetrics> ContainerMetrics,
    EdgeMetricsSnapshot? EdgeMetrics = null,
    string? NetbirdIp = null,
    IReadOnlyList<VolumeInfo>? Volumes = null) : AgentMessage;

public sealed record class PlacementEvent(
    string PlacementId,
    PlacementState State,
    string Image,
    string ConfigHash,
    int? HostPort = null,
    string? Error = null,
    int? PostgresHostPort = null,
    int? InternalHostPort = null,
    string? CandidateImage = null,
    string? CandidateError = null) : AgentMessage;

public sealed record class DrainComplete(string NodeId) : AgentMessage;

public sealed record class VolumeGrown(string NodeId, string VolumePath, int NewSizeGiB) : AgentMessage;

public sealed record class LogChunk(string RequestId, LogChannel Stream, string Line) : AgentMessage;

public sealed record class ExecResult(string RequestId, int ExitCode, string Stdout, string Stderr) : AgentMessage;

[JsonPolymorphic(TypeDiscriminatorPropertyName = "type", UnknownDerivedTypeHandling = JsonUnknownDerivedTypeHandling.FailSerialization)]
[JsonDerivedType(typeof(SyncDesired), "sync_desired")]
[JsonDerivedType(typeof(SyncRoutes), "sync_routes")]
[JsonDerivedType(typeof(SyncTls), "sync_tls")]
[JsonDerivedType(typeof(RefreshSecrets), "refresh_secrets")]
[JsonDerivedType(typeof(Drain), "drain")]
[JsonDerivedType(typeof(GrowVolume), "grow_volume")]
[JsonDerivedType(typeof(StreamLogs), "stream_logs")]
[JsonDerivedType(typeof(StopLogs), "stop_logs")]
[JsonDerivedType(typeof(ExecCommand), "exec_command")]
[JsonDerivedType(typeof(UpgradeAgent), "upgrade_agent")]
public closed record class BackplaneMessage;

public sealed record class SyncDesired(long Revision, IReadOnlyList<DesiredPlacement> Placements) : BackplaneMessage;

public sealed record class SyncRoutes(
    long Revision,
    IReadOnlyList<HttpRouteEntry> HttpRoutes,
    IReadOnlyList<PostgresRouteEntry> PostgresRoutes,
    IReadOnlyList<InternalRouteEntry>? InternalRoutes = null,
    IReadOnlyList<ClusterPeer>? ClusterPeers = null) : BackplaneMessage;

public sealed record class SyncTls(
    long Revision,
    IReadOnlyList<string> Domains,
    string CertPem,
    string KeyPem,
    long NotAfter) : BackplaneMessage;

public sealed record class RefreshSecrets(string ServiceName) : BackplaneMessage;

public sealed record class Drain(string Reason) : BackplaneMessage;

public sealed record class GrowVolume(string MountPath) : BackplaneMessage;

public sealed record class StreamLogs(string RequestId, string ContainerName, int Tail, bool Follow) : BackplaneMessage;

public sealed record class StopLogs(string RequestId) : BackplaneMessage;

public sealed record class ExecCommand(
    string RequestId,
    string ContainerName,
    IReadOnlyList<string> Command,
    int TimeoutSeconds) : BackplaneMessage;

public sealed record class UpgradeAgent(string Version, string Url, string Sha256) : BackplaneMessage;
