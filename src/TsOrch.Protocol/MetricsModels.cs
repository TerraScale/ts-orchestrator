namespace TsOrch.Protocol;

public sealed record class HostMetrics(
    long Ts,
    double CpuPct,
    double CpuPsi10,
    int MemTotalMiB,
    int MemUsedMiB,
    double MemPsi10,
    double IoPsi10,
    double DiskUsedPct,
    long NetRxBps,
    long NetTxBps,
    double Load1);

public sealed record class ContainerMetrics(
    string PlacementId,
    string ServiceName,
    double CpuPct,
    int MemUsedMiB,
    int MemLimitMiB,
    int Pids,
    long NetRxBps,
    long NetTxBps,
    int Restarts,
    int OomKills);

public sealed record class EdgeServiceMetrics(
    string ServiceName,
    double Rps,
    double ErrorRate5xxPct,
    double P50Ms,
    double P95Ms,
    double P99Ms,
    long Requests,
    long Responses5xx,
    int ActiveConnections);

public sealed record class EdgeMetricsSnapshot(
    long Ts,
    int WindowSeconds,
    IReadOnlyList<EdgeServiceMetrics> Services,
    int PostgresConnections);

public sealed record class MetricsPoint10s(
    string NodeId,
    long Ts,
    double CpuPct,
    double CpuPsi10,
    int MemUsedMiB,
    double MemPsi10,
    double DiskUsedPct,
    long NetRxBps,
    long NetTxBps,
    IReadOnlyList<ContainerMetrics> Containers,
    EdgeMetricsSnapshot? Edge = null);

public sealed record class MetricsPoint1m(
    string NodeId,
    long Ts,
    double CpuAvg,
    double CpuP95,
    double CpuPsiAvg,
    double MemAvgMiB,
    double DiskPct,
    double EdgeRps,
    double Edge5xx,
    double EdgeP95Ms);
