using System.Diagnostics;
using System.Text.Json.Serialization;

namespace TsOrch.Agent;

public enum PortProtocol
{
    Tcp,
    Udp,
}

public sealed record class PortMapping(string HostIp, int? HostPort, int ContainerPort, PortProtocol Protocol);

public sealed record class BindMount(string Source, string Target, bool ReadOnly);

public sealed record class ContainerResources(
    string? CgroupParent,
    long MemoryReservationBytes,
    long MemoryBytes,
    long NanoCpus,
    long CpuShares,
    long PidsLimit,
    int OomScoreAdj)
{
    private const long BytesPerMiB = 1024L * 1024L;

    public static ContainerResources For(ServiceSpec service, bool enableCgroupParent)
    {
        ArgumentNullException.ThrowIfNull(service);
        return new ContainerResources(
            enableCgroupParent ? CgroupSliceFor(service.Priority) : null,
            service.MemRequestMiB * BytesPerMiB,
            service.MemLimitMiB * BytesPerMiB,
            Math.Min(service.CpuLimitMilli * 1_000_000L, Math.Max(1, Environment.ProcessorCount) * 1_000_000_000L),
            CpuSharesFor(service.Priority),
            service.PidsLimit,
            OomScoreAdjFor(service.Priority));
    }

    private static string CgroupSliceFor(PriorityTier priority) => priority switch
    {
        PriorityTier.High => "ts-core.slice",
        PriorityTier.Normal => "ts-apps.slice",
        PriorityTier.Low => "ts-apps.slice",
        _ => throw new UnreachableException(),
    };

    private static long CpuSharesFor(PriorityTier priority) => priority switch
    {
        PriorityTier.High => 500,
        PriorityTier.Normal => 100,
        PriorityTier.Low => 50,
        _ => throw new UnreachableException(),
    };

    private static int OomScoreAdjFor(PriorityTier priority) => priority switch
    {
        PriorityTier.High => -200,
        PriorityTier.Normal => 200,
        PriorityTier.Low => 500,
        _ => throw new UnreachableException(),
    };
}

public sealed record class DockerContainerSpec(
    string Name,
    string Image,
    string LabelPrefix,
    string PlacementId,
    string ServiceName,
    string ConfigHash,
    IReadOnlyDictionary<string, string> Env,
    IReadOnlyList<BindMount> Mounts,
    IReadOnlyList<string> Args,
    IReadOnlyList<PortMapping> Ports,
    ContainerResources Resources,
    bool Stateful);

public sealed record class PublishedPort(string HostIp, int HostPort, int ContainerPort, PortProtocol Protocol);

public sealed record class ManagedContainer(
    string Id,
    string Name,
    string Image,
    string ImageId,
    string PlacementId,
    string ServiceName,
    string ConfigHash,
    bool Running,
    IReadOnlyList<PublishedPort> Ports,
    bool? Stateful,
    long Created = 0);

public sealed record class ContainerState(
    string Id,
    bool Running,
    bool OomKilled,
    int ExitCode,
    int RestartCount,
    IReadOnlyList<PublishedPort> Ports,
    string Status = "");

public sealed record class DockerImage(
    string Id,
    IReadOnlyList<string> RepoTags,
    IReadOnlyList<string> RepoDigests,
    DateTimeOffset Created);

public sealed record class ContainerStatsSample(
    long CpuTotalNanos,
    long SystemCpuNanos,
    int OnlineCpus,
    long MemUsageBytes,
    long MemLimitBytes,
    long Pids,
    long RxBytes,
    long TxBytes);

public sealed record class ExecOutput(int ExitCode, string Stdout, string Stderr);

public static class ContainerLabels
{
    public static string Managed(string prefix) => $"{prefix}.managed";

    public static string PlacementId(string prefix) => $"{prefix}.placement-id";

    public static string Service(string prefix) => $"{prefix}.service";

    public static string ConfigHash(string prefix) => $"{prefix}.config-hash";

    public static string Stateful(string prefix) => $"{prefix}.stateful";

    public static string Image(string prefix) => $"{prefix}.image";
}

internal sealed record class DockerEmpty;

internal sealed record class DockerPortBinding(string? HostIp, string? HostPort);

internal sealed record class DockerRestartPolicy(string Name);

internal sealed record class DockerHostConfig(
    IReadOnlyList<string> Binds,
    IReadOnlyDictionary<string, IReadOnlyList<DockerPortBinding>> PortBindings,
    IReadOnlyList<string> ExtraHosts,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? CgroupParent,
    long MemoryReservation,
    long Memory,
    long NanoCpus,
    long CpuShares,
    long PidsLimit,
    int OomScoreAdj,
    DockerRestartPolicy RestartPolicy);

internal sealed record class DockerCreateContainerRequest(
    string Image,
    IReadOnlyList<string> Env,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<string>? Cmd,
    IReadOnlyDictionary<string, string> Labels,
    IReadOnlyDictionary<string, DockerEmpty> ExposedPorts,
    DockerHostConfig HostConfig);

internal sealed record class DockerIdResponse(string Id);

internal sealed record class DockerSummaryPort(string? IP, int PrivatePort, int? PublicPort, string? Type);

internal sealed record class DockerContainerSummary(
    string Id,
    IReadOnlyList<string>? Names,
    string? Image,
    string? ImageID,
    IReadOnlyDictionary<string, string>? Labels,
    string? State,
    IReadOnlyList<DockerSummaryPort>? Ports,
    long Created = 0);

internal sealed record class DockerInspectState(bool Running, bool OOMKilled, int ExitCode, string? Status = null);

internal sealed record class DockerNetworkSettings(IReadOnlyDictionary<string, IReadOnlyList<DockerPortBinding>?>? Ports);

internal sealed record class DockerContainerInspect(
    string Id,
    int RestartCount,
    DockerInspectState State,
    DockerNetworkSettings? NetworkSettings);

internal sealed record class DockerImageSummary(
    string Id,
    IReadOnlyList<string>? RepoTags,
    IReadOnlyList<string>? RepoDigests,
    long Created);

internal sealed record class DockerExecCreateRequest(bool AttachStdout, bool AttachStderr, bool AttachStdin, IReadOnlyList<string> Cmd);

internal sealed record class DockerExecStartRequest(bool Detach, bool Tty);

internal sealed record class DockerExecInspect(bool Running, int? ExitCode);

internal sealed record class DockerErrorDetail([property: JsonPropertyName("message")] string? Message);

internal sealed record class DockerProgressLine(
    [property: JsonPropertyName("error")] string? Error,
    [property: JsonPropertyName("errorDetail")] DockerErrorDetail? ErrorDetail);

internal sealed record class DockerErrorResponse([property: JsonPropertyName("message")] string? Message);

internal sealed record class DockerEventActor(string ID, IReadOnlyDictionary<string, string>? Attributes);

internal sealed record class DockerOomEvent(DockerEventActor? Actor, [property: JsonPropertyName("timeNano")] long TimeNano);

internal sealed record class DockerCpuUsage([property: JsonPropertyName("total_usage")] long TotalUsage);

internal sealed record class DockerCpuStats(
    [property: JsonPropertyName("cpu_usage")] DockerCpuUsage? CpuUsage,
    [property: JsonPropertyName("system_cpu_usage")] long? SystemCpuUsage,
    [property: JsonPropertyName("online_cpus")] int? OnlineCpus);

internal sealed record class DockerMemoryStats(
    [property: JsonPropertyName("usage")] long? Usage,
    [property: JsonPropertyName("limit")] long? Limit);

internal sealed record class DockerPidsStats([property: JsonPropertyName("current")] long? Current);

internal sealed record class DockerNetworkStats(
    [property: JsonPropertyName("rx_bytes")] long RxBytes,
    [property: JsonPropertyName("tx_bytes")] long TxBytes);

internal sealed record class DockerStats(
    [property: JsonPropertyName("cpu_stats")] DockerCpuStats? CpuStats,
    [property: JsonPropertyName("memory_stats")] DockerMemoryStats? MemoryStats,
    [property: JsonPropertyName("pids_stats")] DockerPidsStats? PidsStats,
    [property: JsonPropertyName("networks")] IReadOnlyDictionary<string, DockerNetworkStats>? Networks);

[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.Never)]
[JsonSerializable(typeof(DockerCreateContainerRequest))]
[JsonSerializable(typeof(DockerIdResponse))]
[JsonSerializable(typeof(IReadOnlyList<DockerContainerSummary>))]
[JsonSerializable(typeof(DockerContainerInspect))]
[JsonSerializable(typeof(IReadOnlyList<DockerImageSummary>))]
[JsonSerializable(typeof(DockerExecCreateRequest))]
[JsonSerializable(typeof(DockerExecStartRequest))]
[JsonSerializable(typeof(DockerExecInspect))]
[JsonSerializable(typeof(DockerProgressLine))]
[JsonSerializable(typeof(DockerErrorResponse))]
[JsonSerializable(typeof(DockerStats))]
[JsonSerializable(typeof(DockerOomEvent))]
internal sealed partial class DockerJsonContext : JsonSerializerContext;
