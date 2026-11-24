using System.Diagnostics;
using System.Globalization;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Text.RegularExpressions;

namespace TsOrch.Agent;

public readonly record struct DockerRequestCompleted;

public sealed record class DockerResourceMissing(string Message);

public sealed record class DockerResourceBusy(string Message);

public sealed record class DockerDaemonUnavailable(string Message);

public sealed record class DockerResponseInvalid(string Message);

public sealed record class DockerExecCommandMissing(string Message);

public sealed record class DockerExecTimedOut(string Message);

public readonly union DockerImagePull(DockerRequestCompleted, DockerResourceMissing, DockerDaemonUnavailable, DockerResponseInvalid, DockerImagePullRejected);

public sealed record class DockerImagePullRejected(string Image, string Error)
{
    public string Message => $"Pull of {Image} failed: {Error}";
}

public readonly union DockerContainerStart(DockerRequestCompleted, DockerResourceMissing, DockerDaemonUnavailable, DockerResponseInvalid);

public readonly union DockerLogRead(DockerRequestCompleted, DockerResourceMissing, DockerDaemonUnavailable, DockerResponseInvalid);

public readonly union DockerManagedContainers(IReadOnlyList<ManagedContainer>, DockerDaemonUnavailable, DockerResponseInvalid);

public readonly union DockerContainerImageIds(IReadOnlySet<string>, DockerDaemonUnavailable, DockerResponseInvalid);

public readonly union DockerContainerCreation(string, DockerResourceMissing, DockerResourceBusy, DockerDaemonUnavailable, DockerResponseInvalid);

public readonly union DockerContainerStop(DockerRequestCompleted, DockerDaemonUnavailable, DockerResponseInvalid);

public readonly union DockerContainerRemoval(DockerRequestCompleted, DockerResourceBusy, DockerDaemonUnavailable, DockerResponseInvalid);

public readonly union DockerContainerInspection(ContainerState, DockerResourceMissing, DockerDaemonUnavailable, DockerResponseInvalid);

public readonly union DockerContainerStats(ContainerStatsSample, DockerResourceMissing, DockerDaemonUnavailable, DockerResponseInvalid);

public readonly union DockerExec(ExecOutput, DockerExecCommandMissing, DockerResourceMissing, DockerResourceBusy, DockerExecTimedOut, DockerDaemonUnavailable, DockerResponseInvalid);

public readonly union DockerImageRemoval(DockerRequestCompleted, DockerResourceMissing, DockerResourceBusy, DockerDaemonUnavailable, DockerResponseInvalid);

public readonly union DockerImages(IReadOnlyList<DockerImage>, DockerDaemonUnavailable, DockerResponseInvalid);

internal readonly union DockerExecStatus(DockerExecInspect, DockerResourceMissing, DockerResourceBusy, DockerDaemonUnavailable, DockerResponseInvalid);

internal readonly union DockerHttpExchange(HttpResponseMessage, DockerResourceMissing, DockerResourceBusy, DockerDaemonUnavailable, DockerResponseInvalid);

public sealed partial class DockerEngineClient(AgentOptions options, TimeProvider timeProvider, ILogger<DockerEngineClient> logger) : IDisposable
{
    private const string ApiVersion = "v1.45";
    private const int MaxLogLineChars = 16 * 1024;
    private const int MaxExecOutputChars = 1024 * 1024;
    private const string EphemeralHostPort = "";
    private const int MaxPullAttempts = 3;
    private static readonly TimeSpan ApiTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan PullTimeout = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan PullRetryBaseDelay = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ExecCleanupTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ExecPidPollInterval = TimeSpan.FromMilliseconds(50);
    private static readonly TimeSpan EventSubscriptionTimeout = TimeSpan.FromMinutes(5);
    private static readonly string[] DefaultExtraHosts = ["host.docker.internal:host-gateway"];

    private readonly HttpClient _http = new(CreateHandler(options.DockerSocketPath), disposeHandler: true)
    {
        BaseAddress = new Uri($"http://docker/{ApiVersion}/"),
        Timeout = Timeout.InfiniteTimeSpan,
    };

    public void Dispose() => _http.Dispose();

    public async Task<DockerImagePull> PullImageAsync(string image, string? registryAuth, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(image);
        if (image.Contains("@sha256:", StringComparison.Ordinal) && await ImageExistsAsync(image, cancellationToken))
        {
            return new DockerRequestCompleted();
        }

        var authHeader = registryAuth ?? options.RegistryAuth;
        var reference = ImageReference.WithDefaultTag(image);
        DockerImagePull outcome = new DockerDaemonUnavailable("Image pull did not execute.");
        for (var attempt = 0; attempt < MaxPullAttempts; attempt++)
        {
            outcome = await PullImageOnceAsync(image, reference, authHeader, cancellationToken);
            if (!IsTransientPullFailure(outcome) || attempt + 1 >= MaxPullAttempts)
            {
                return outcome;
            }

            await Task.Delay(TimeSpan.FromTicks(PullRetryBaseDelay.Ticks * (attempt + 1)), timeProvider, cancellationToken);
        }

        return outcome;
    }

    private async Task<bool> ImageExistsAsync(string image, CancellationToken cancellationToken)
    {
        var outcome = await GetAsync($"images/{Uri.EscapeDataString(image)}/json", cancellationToken);
        if (outcome is HttpResponseMessage response)
        {
            response.Dispose();
            return true;
        }

        return false;
    }

    private async Task<DockerImagePull> PullImageOnceAsync(string image, string reference, string? registryAuth, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"images/create?fromImage={Uri.EscapeDataString(reference)}");
        if (!string.IsNullOrWhiteSpace(registryAuth))
        {
            request.Headers.Add("X-Registry-Auth", registryAuth);
        }

        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        operation.CancelAfter(PullTimeout);
        try
        {
            var outcome = await SendAsync(request, HttpCompletionOption.ResponseHeadersRead, operation.Token);
            return outcome switch
            {
                HttpResponseMessage response => await ReadPullProgressAsync(response, image, operation.Token),
                DockerResourceMissing failure => failure,
                DockerResourceBusy failure => new DockerResponseInvalid(failure.Message),
                DockerDaemonUnavailable failure => failure,
                DockerResponseInvalid failure => failure,
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new DockerDaemonUnavailable("Image pull exceeded the Docker operation deadline.");
        }
    }

    internal static bool IsAuthRejection(string error) =>
        HttpAuthStatusPattern().IsMatch(error)
        || error.Contains("unauthorized", StringComparison.OrdinalIgnoreCase)
        || error.Contains("authentication required", StringComparison.OrdinalIgnoreCase)
        || error.Contains("denied", StringComparison.OrdinalIgnoreCase);

    [GeneratedRegex(@"\b40[13]\b", RegexOptions.CultureInvariant)]
    private static partial Regex HttpAuthStatusPattern();

    private static bool IsTransientPullFailure(DockerImagePull outcome) => outcome switch
    {
        DockerDaemonUnavailable unavailable => !IsAuthRejection(unavailable.Message),
        DockerImagePullRejected rejected => IsTransientRegistryError(rejected.Error),
        DockerRequestCompleted or DockerResourceMissing or DockerResponseInvalid => false,
    };

    private static bool IsTransientRegistryError(string error) =>
        error.Contains("timeout", StringComparison.OrdinalIgnoreCase)
        || error.Contains("EOF", StringComparison.OrdinalIgnoreCase)
        || error.Contains("connection reset", StringComparison.OrdinalIgnoreCase)
        || error.Contains("temporary failure", StringComparison.OrdinalIgnoreCase)
        || error.Contains("502", StringComparison.Ordinal)
        || error.Contains("503", StringComparison.Ordinal)
        || error.Contains("504", StringComparison.Ordinal)
        || error.Contains("429", StringComparison.Ordinal);

    public async Task<DockerManagedContainers> ListManagedContainersAsync(string labelPrefix, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(labelPrefix);
        var filters = $$"""{"label":["{{ContainerLabels.Managed(labelPrefix)}}=true"]}""";
        var outcome = await GetAsync($"containers/json?all=true&filters={Uri.EscapeDataString(filters)}", cancellationToken);
        return outcome switch
        {
            HttpResponseMessage response => await ReadJsonAsync(response, DockerJsonContext.Default.IReadOnlyListDockerContainerSummary,
                listed => Managed(listed, labelPrefix),
                static failure => (DockerManagedContainers)failure,
                static failure => (DockerManagedContainers)failure, cancellationToken),
            DockerResourceMissing failure => new DockerResponseInvalid(failure.Message),
            DockerResourceBusy failure => new DockerResponseInvalid(failure.Message),
            DockerDaemonUnavailable failure => failure,
            DockerResponseInvalid failure => failure,
        };
    }

    public async Task<DockerContainerImageIds> ListContainerImageIdsAsync(CancellationToken cancellationToken)
    {
        var outcome = await GetAsync("containers/json?all=true", cancellationToken);
        return outcome switch
        {
            HttpResponseMessage response => await ReadJsonAsync(response, DockerJsonContext.Default.IReadOnlyListDockerContainerSummary,
                static document => ImageIds(document),
                static failure => (DockerContainerImageIds)failure,
                static failure => (DockerContainerImageIds)failure, cancellationToken),
            DockerResourceMissing failure => new DockerResponseInvalid(failure.Message),
            DockerResourceBusy failure => new DockerResponseInvalid(failure.Message),
            DockerDaemonUnavailable failure => failure,
            DockerResponseInvalid failure => failure,
        };
    }

    public async Task<DockerContainerCreation> CreateContainerAsync(DockerContainerSpec spec, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(spec);
        var labels = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [ContainerLabels.Managed(spec.LabelPrefix)] = "true",
            [ContainerLabels.PlacementId(spec.LabelPrefix)] = spec.PlacementId,
            [ContainerLabels.Service(spec.LabelPrefix)] = spec.ServiceName,
            [ContainerLabels.ConfigHash(spec.LabelPrefix)] = spec.ConfigHash,
            [ContainerLabels.Image(spec.LabelPrefix)] = spec.Image,
            [ContainerLabels.Stateful(spec.LabelPrefix)] = spec.Stateful ? "true" : "false",
        };
        Dictionary<string, DockerEmpty> exposed = [with(StringComparer.Ordinal)];
        Dictionary<string, IReadOnlyList<DockerPortBinding>> bindings = [with(StringComparer.Ordinal)];
        foreach (var port in spec.Ports)
        {
            var key = PortKey(port.ContainerPort, port.Protocol);
            exposed[key] = new DockerEmpty();
            var binding = new DockerPortBinding(port.HostIp, port.HostPort is { } hostPort ? hostPort.ToString(CultureInfo.InvariantCulture) : EphemeralHostPort);
            bindings[key] = bindings.TryGetValue(key, out var existing) ? [.. existing, binding] : [binding];
        }

        var body = new DockerCreateContainerRequest(
            spec.PullImage ?? spec.Image,
            [.. spec.Env.OrderBy(static pair => pair.Key, StringComparer.Ordinal).Select(static pair => $"{pair.Key}={pair.Value}")],
            spec.Args.Count == 0 ? null : spec.Args,
            labels,
            exposed,
            new DockerHostConfig(
                [.. spec.Mounts.Select(static mount => mount.ReadOnly ? $"{mount.Source}:{mount.Target}:ro" : $"{mount.Source}:{mount.Target}")],
                bindings,
                DefaultExtraHosts,
                spec.Resources.CgroupParent,
                spec.Resources.MemoryReservationBytes,
                spec.Resources.MemoryBytes,
                spec.Resources.NanoCpus,
                spec.Resources.CpuShares,
                spec.Resources.PidsLimit,
                spec.Resources.OomScoreAdj,
                new DockerRestartPolicy("unless-stopped"),
                ["ALL"],
                spec.CapAdd,
                ["no-new-privileges:true"],
                Init: true));
        using var request = new HttpRequestMessage(HttpMethod.Post, $"containers/create?name={Uri.EscapeDataString(spec.Name)}")
        {
            Content = JsonContent.Create(body, DockerJsonContext.Default.DockerCreateContainerRequest),
        };
        var outcome = await SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken);
        return outcome switch
        {
            HttpResponseMessage response => await ReadJsonAsync(response, DockerJsonContext.Default.DockerIdResponse,
                static document => document.Id,
                static failure => (DockerContainerCreation)failure,
                static failure => (DockerContainerCreation)failure, cancellationToken),
            DockerResourceMissing failure => failure,
            DockerResourceBusy failure => failure,
            DockerDaemonUnavailable failure => failure,
            DockerResponseInvalid failure => failure,
        };
    }

    public async Task<DockerContainerStart> StartContainerAsync(string containerId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"containers/{Uri.EscapeDataString(containerId)}/start");
        var outcome = await SendForDoneAsync(request, cancellationToken);
        return outcome switch
        {
            DockerRequestCompleted done => done,
            DockerResourceMissing failure => failure,
            DockerResourceBusy failure => new DockerResponseInvalid(failure.Message),
            DockerDaemonUnavailable failure => failure,
            DockerResponseInvalid failure => failure,
        };
    }

    public async Task<DockerContainerStop> StopContainerAsync(string containerId, int timeoutSeconds, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(timeoutSeconds);
        using var request = new HttpRequestMessage(HttpMethod.Post, string.Create(CultureInfo.InvariantCulture, $"containers/{Uri.EscapeDataString(containerId)}/stop?t={timeoutSeconds}"));
        var outcome = await SendForDoneAsync(request, cancellationToken, TimeSpan.FromSeconds(timeoutSeconds + 15));
        return outcome switch
        {
            DockerRequestCompleted done => done,
            DockerResourceMissing => new DockerRequestCompleted(),
            DockerResourceBusy failure => new DockerResponseInvalid(failure.Message),
            DockerDaemonUnavailable failure => failure,
            DockerResponseInvalid failure => failure,
        };
    }

    public async Task<DockerContainerRemoval> RemoveContainerAsync(string containerId, bool force, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, $"containers/{Uri.EscapeDataString(containerId)}?force={(force ? "true" : "false")}");
        var outcome = await SendForDoneAsync(request, cancellationToken);
        return outcome switch
        {
            DockerRequestCompleted done => done,
            DockerResourceMissing => new DockerRequestCompleted(),
            DockerResourceBusy failure => failure,
            DockerDaemonUnavailable failure => failure,
            DockerResponseInvalid failure => failure,
        };
    }

    public async Task<DockerContainerInspection> InspectContainerAsync(string containerId, CancellationToken cancellationToken)
    {
        var outcome = await GetAsync($"containers/{Uri.EscapeDataString(containerId)}/json", cancellationToken);
        return outcome switch
        {
            HttpResponseMessage response => await ReadJsonAsync(response, DockerJsonContext.Default.DockerContainerInspect,
                static document => State(document),
                static failure => (DockerContainerInspection)failure,
                static failure => (DockerContainerInspection)failure, cancellationToken),
            DockerResourceMissing failure => failure,
            DockerResourceBusy failure => new DockerResponseInvalid(failure.Message),
            DockerDaemonUnavailable failure => failure,
            DockerResponseInvalid failure => failure,
        };
    }

    public async Task<DockerContainerStats> GetContainerStatsAsync(string containerId, CancellationToken cancellationToken)
    {
        var outcome = await GetAsync($"containers/{Uri.EscapeDataString(containerId)}/stats?stream=false&one-shot=true", cancellationToken);
        return outcome switch
        {
            HttpResponseMessage response => await ReadJsonAsync(response, DockerJsonContext.Default.DockerStats,
                static document => Sample(document),
                static failure => (DockerContainerStats)failure,
                static failure => (DockerContainerStats)failure, cancellationToken),
            DockerResourceMissing failure => failure,
            DockerResourceBusy failure => new DockerResponseInvalid(failure.Message),
            DockerDaemonUnavailable failure => failure,
            DockerResponseInvalid failure => failure,
        };
    }

    public async Task<DockerLogRead> StreamLogsAsync(
        string containerId,
        int tail,
        bool follow,
        Func<LogChannel, string, CancellationToken, ValueTask> onLine,
        CancellationToken cancellationToken,
        TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(onLine);
        ArgumentOutOfRangeException.ThrowIfNegative(tail);
        if (timeout is { } customTimeout)
        {
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(customTimeout, TimeSpan.Zero);
        }

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            string.Create(CultureInfo.InvariantCulture, $"containers/{Uri.EscapeDataString(containerId)}/logs?stdout=true&stderr=true&follow={(follow ? "true" : "false")}&tail={tail}"));
        using var deadline = follow ? null : new CancellationTokenSource(timeout ?? ApiTimeout, timeProvider);
        using var operation = deadline is null
            ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken)
            : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            var outcome = await SendAsync(request, HttpCompletionOption.ResponseHeadersRead, operation.Token);
            return outcome switch
            {
                HttpResponseMessage response => await ReadLogsAsync(response, containerId, onLine, operation.Token),
                DockerResourceMissing failure => failure,
                DockerResourceBusy failure => new DockerResponseInvalid(failure.Message),
                DockerDaemonUnavailable failure => failure,
                DockerResponseInvalid failure => failure,
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new DockerDaemonUnavailable("Log read exceeded the Docker operation deadline.");
        }
    }

    public async Task<DockerExec> ExecOnceAsync(
        string containerId,
        IReadOnlyList<string> command,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (command.Count == 0)
        {
            return new DockerExecCommandMissing("Exec command must not be empty.");
        }

        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);
        using var timeoutSource = new CancellationTokenSource(timeout, timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutSource.Token);
        using var createRequest = new HttpRequestMessage(HttpMethod.Post, $"containers/{Uri.EscapeDataString(containerId)}/exec")
        {
            Content = JsonContent.Create(new DockerExecCreateRequest(true, true, false, command), DockerJsonContext.Default.DockerExecCreateRequest),
        };
        try
        {
            var submitted = await SendAsync(createRequest, HttpCompletionOption.ResponseContentRead, linked.Token);
            return submitted switch
            {
                HttpResponseMessage response => await ReadExecIdAsync(containerId, response, linked.Token),
                DockerResourceMissing failure => failure,
                DockerResourceBusy failure => failure,
                DockerDaemonUnavailable failure => failure,
                DockerResponseInvalid failure => failure,
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new DockerExecTimedOut(string.Create(CultureInfo.InvariantCulture, $"Exec in {containerId} exceeded {timeout.TotalSeconds:0} s."));
        }
    }

    public async Task<DockerImages> ListImagesAsync(CancellationToken cancellationToken)
    {
        var outcome = await GetAsync("images/json", cancellationToken);
        return outcome switch
        {
            HttpResponseMessage response => await ReadJsonAsync(response, DockerJsonContext.Default.IReadOnlyListDockerImageSummary,
                static document => Images(document),
                static failure => (DockerImages)failure,
                static failure => (DockerImages)failure, cancellationToken),
            DockerResourceMissing failure => new DockerResponseInvalid(failure.Message),
            DockerResourceBusy failure => new DockerResponseInvalid(failure.Message),
            DockerDaemonUnavailable failure => failure,
            DockerResponseInvalid failure => failure,
        };
    }

    public async Task<DockerImageRemoval> RemoveImageAsync(string imageId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, $"images/{Uri.EscapeDataString(imageId)}?force=false&noprune=false");
        return await SendForDoneAsync(request, cancellationToken);
    }

    internal async Task<string?> WatchOomEventsAsync(long since, Action<DockerOomEvent> onEvent, CancellationToken cancellationToken)
    {
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        operation.CancelAfter(EventSubscriptionTimeout);
        var filters = Uri.EscapeDataString("""{"type":["container"],"event":["oom"]}""");
        using var request = new HttpRequestMessage(HttpMethod.Get, string.Create(CultureInfo.InvariantCulture, $"events?since={since}&filters={filters}"));
        try
        {
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, operation.Token);
            if (!response.IsSuccessStatusCode)
            {
                return await ReadErrorMessageAsync(response, operation.Token);
            }

            await using var stream = await response.Content.ReadAsStreamAsync(operation.Token);
            using var reader = new StreamReader(stream);
            while (await reader.ReadLineAsync(operation.Token) is { } line)
            {
                if (line.Length > 0 && JsonSerializer.Deserialize(line, DockerJsonContext.Default.DockerOomEvent) is { } oom)
                {
                    onEvent(oom);
                }
            }

            return "Docker OOM event stream closed.";
        }
        catch (HttpRequestException exception)
        {
            return exception.Message;
        }
        catch (IOException exception)
        {
            return exception.Message;
        }
        catch (JsonException exception)
        {
            return exception.Message;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    private static SocketsHttpHandler CreateHandler(string socketPath) => new()
    {
        PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30),
        ConnectCallback = async (_, cancellationToken) =>
        {
            var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            NetworkStream? stream = null;
            try
            {
                await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), cancellationToken);
                stream = new NetworkStream(socket, ownsSocket: true);
                return stream;
            }
            finally
            {
                if (stream is null)
                {
                    socket.Dispose();
                }
            }
        },
    };

    private static DockerManagedContainers Managed(IReadOnlyList<DockerContainerSummary> listed, string labelPrefix)
    {
        List<ManagedContainer> containers = [with(capacity: listed.Count)];
        foreach (var summary in listed)
        {
            var labels = summary.Labels ?? new Dictionary<string, string>();
            if (!labels.TryGetValue(ContainerLabels.PlacementId(labelPrefix), out var placementId)
                || !labels.TryGetValue(ContainerLabels.Service(labelPrefix), out var serviceName)
                || !labels.TryGetValue(ContainerLabels.ConfigHash(labelPrefix), out var configHash)
                || !labels.TryGetValue(ContainerLabels.Image(labelPrefix), out var image))
            {
                return new DockerResponseInvalid($"Managed container {summary.Id} is missing placement metadata.");
            }

            containers.Add(new ManagedContainer(
                summary.Id,
                summary.Names is [var first, ..] ? first.TrimStart('/') : summary.Id,
                image,
                summary.ImageID ?? summary.Image ?? image,
                placementId,
                serviceName,
                configHash,
                string.Equals(summary.State, "running", StringComparison.Ordinal),
                [.. Published(summary.Ports ?? [])],
                bool.TryParse(labels.GetValueOrDefault(ContainerLabels.Stateful(labelPrefix)), out var stateful) ? stateful : null,
                summary.Created,
                summary.Image is { Length: > 0 } pulled ? pulled : image));
        }

        return containers;
    }

    private static IEnumerable<PublishedPort> Published(IReadOnlyList<DockerSummaryPort> ports)
    {
        foreach (var port in ports)
        {
            if (port.PublicPort is { } publicPort and > 0)
            {
                yield return new PublishedPort(port.IP ?? "0.0.0.0", publicPort, port.PrivatePort, ParseProtocol(port.Type));
            }
        }
    }

    private static HashSet<string> ImageIds(IReadOnlyList<DockerContainerSummary> listed) =>
        listed.Select(static summary => summary.ImageID).OfType<string>().Where(static imageId => imageId.Length > 0).ToHashSet(StringComparer.Ordinal);

    private static ContainerState State(DockerContainerInspect inspected)
    {
        List<PublishedPort> ports = [];
        foreach (var (key, bindings) in inspected.NetworkSettings?.Ports ?? new Dictionary<string, IReadOnlyList<DockerPortBinding>?>())
        {
            if (bindings is null || !TryParsePortKey(key, out var containerPort, out var protocol))
            {
                continue;
            }

            foreach (var binding in bindings)
            {
                if (int.TryParse(binding.HostPort, NumberStyles.None, CultureInfo.InvariantCulture, out var hostPort) && hostPort > 0)
                {
                    ports.Add(new PublishedPort(binding.HostIp ?? "0.0.0.0", hostPort, containerPort, protocol));
                }
            }
        }

        return new ContainerState(inspected.Id, inspected.State.Running, inspected.State.OOMKilled, inspected.State.ExitCode, inspected.RestartCount, ports, inspected.State.Status ?? string.Empty);
    }

    private static ContainerStatsSample Sample(DockerStats stats)
    {
        long rx = 0;
        long tx = 0;
        foreach (var network in (stats.Networks ?? new Dictionary<string, DockerNetworkStats>()).Values)
        {
            rx += network.RxBytes;
            tx += network.TxBytes;
        }

        return new ContainerStatsSample(
            stats.CpuStats?.CpuUsage?.TotalUsage ?? 0,
            stats.CpuStats?.SystemCpuUsage ?? 0,
            stats.CpuStats?.OnlineCpus ?? Environment.ProcessorCount,
            stats.MemoryStats?.Usage ?? 0,
            stats.MemoryStats?.Limit ?? 0,
            stats.PidsStats?.Current ?? 0,
            rx,
            tx);
    }

    private static IReadOnlyList<DockerImage> Images(IReadOnlyList<DockerImageSummary> listed) =>
    [
        .. listed.Select(static image => new DockerImage(
            image.Id,
            image.RepoTags ?? [],
            image.RepoDigests ?? [])),
    ];

    private static async Task<DockerImagePull> ReadPullProgressAsync(HttpResponseMessage response, string image, CancellationToken cancellationToken)
    {
        using (response)
        {
            try
            {
                await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
                using var reader = new StreamReader(stream);
                while (await reader.ReadLineAsync(cancellationToken) is { } line)
                {
                    if (line.Length == 0)
                    {
                        continue;
                    }

                    var progress = JsonSerializer.Deserialize(line, DockerJsonContext.Default.DockerProgressLine);
                    if ((progress?.ErrorDetail?.Message ?? progress?.Error) is { } error)
                    {
                        return new DockerImagePullRejected(image, error);
                    }
                }

                return new DockerRequestCompleted();
            }
            catch (Exception exception) when (exception is HttpRequestException or IOException)
            {
                return new DockerDaemonUnavailable($"Pull of {image} failed: {exception.Message}");
            }
            catch (JsonException exception)
            {
                return new DockerResponseInvalid($"Pull of {image} returned malformed progress: {exception.Message}");
            }
        }
    }

    private static async Task<DockerLogRead> ReadLogsAsync(
        HttpResponseMessage response,
        string containerId,
        Func<LogChannel, string, CancellationToken, ValueTask> onLine,
        CancellationToken cancellationToken)
    {
        using (response)
        {
            var stdout = new LineAssembler(MaxLogLineChars);
            var stderr = new LineAssembler(MaxLogLineChars);
            try
            {
                await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
                await DockerStreamDemultiplexer.ReadFramesAsync(
                    stream,
                    (channel, payload, frameToken) => (channel == LogChannel.Stderr ? stderr : stdout).AppendAsync(payload, (line, lineToken) => onLine(channel, line, lineToken), frameToken),
                    cancellationToken);
            }
            catch (Exception exception) when (exception is HttpRequestException or IOException)
            {
                return new DockerDaemonUnavailable($"Log stream for {containerId} ended: {exception.Message}");
            }

            await stdout.FlushAsync((line, lineToken) => onLine(LogChannel.Stdout, line, lineToken), cancellationToken);
            await stderr.FlushAsync((line, lineToken) => onLine(LogChannel.Stderr, line, lineToken), cancellationToken);
            return new DockerRequestCompleted();
        }
    }

    private async Task<DockerExec> ReadExecIdAsync(string containerId, HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var identity = await ReadJsonAsync(response, DockerJsonContext.Default.DockerIdResponse,
            static id => id.Id,
            static failure => (DockerContainerCreation)failure,
            static failure => (DockerContainerCreation)failure, cancellationToken);
        return identity switch
        {
            string id => await RunExecAsync(containerId, id, cancellationToken),
            DockerResourceMissing failure => failure,
            DockerResourceBusy failure => failure,
            DockerDaemonUnavailable failure => failure,
            DockerResponseInvalid failure => failure,
        };
    }

    private async Task<DockerExec> RunExecAsync(string containerId, string execId, CancellationToken cancellationToken)
    {
        using var startRequest = new HttpRequestMessage(HttpMethod.Post, $"exec/{Uri.EscapeDataString(execId)}/start")
        {
            Content = JsonContent.Create(new DockerExecStartRequest(false, false), DockerJsonContext.Default.DockerExecStartRequest),
        };
        try
        {
            var outcome = await SendAsync(startRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            return outcome switch
            {
                HttpResponseMessage started => await CaptureExecAsync(execId, started, cancellationToken),
                DockerResourceMissing failure => failure,
                DockerResourceBusy failure => failure,
                DockerDaemonUnavailable failure => failure,
                DockerResponseInvalid failure => failure,
            };
        }
        finally
        {
            if (cancellationToken.IsCancellationRequested
                && await TerminateExecAsync(containerId, execId) is { } failure)
            {
                AgentLog.ExecCleanupFailed(logger, execId, failure);
            }
        }
    }

    private async Task<string?> TerminateExecAsync(string containerId, string execId)
    {
        if (!DockerExecProcess.IsSupported)
        {
            return "Exec cleanup requires the agent and Docker daemon to share a Linux host.";
        }

        using var deadline = new CancellationTokenSource(ExecCleanupTimeout, timeProvider);
        var cancellationToken = deadline.Token;
        using var timer = new PeriodicTimer(ExecPidPollInterval, timeProvider);
        try
        {
            do
            {
                var lookup = await InspectExecAsync(execId, cancellationToken);
                var (state, failure) = lookup switch
                {
                    DockerExecInspect status => (status, (string?)null),
                    DockerResourceMissing => ((DockerExecInspect?)null, null),
                    DockerResourceBusy failed => ((DockerExecInspect?)null, failed.Message),
                    DockerDaemonUnavailable failed => ((DockerExecInspect?)null, failed.Message),
                    DockerResponseInvalid failed => ((DockerExecInspect?)null, failed.Message),
                    null => ((DockerExecInspect?)null, "Docker returned no exec status."),
                };
                if (state is null || !state.Running)
                {
                    return failure;
                }

                if (state.Pid > 1)
                {
                    return await TerminateExecProcessAsync(containerId, execId, state.Pid, cancellationToken);
                }
            }
            while (await timer.WaitForNextTickAsync(cancellationToken));

            return "The Docker exec PID was unavailable.";
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested)
        {
            return "Docker exec cleanup timed out.";
        }
        catch (Exception exception) when (exception is DirectoryNotFoundException or FileNotFoundException)
        {
            return null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return exception.Message;
        }
    }

    private async Task<string?> TerminateExecProcessAsync(string containerId, string execId, int pid, CancellationToken cancellationToken)
    {
        using var process = DockerExecProcess.Open(pid);
        var lookup = await InspectExecAsync(execId, cancellationToken);
        return lookup switch
        {
            DockerExecInspect { Running: false } or DockerResourceMissing => null,
            DockerExecInspect status when status.Pid == pid && !process.IsInvalid && DockerExecProcess.IsInContainer(pid, containerId)
                => DockerExecProcess.TerminateTree(process, pid, cancellationToken),
            DockerExecInspect => "The Docker exec PID could not be verified on this host.",
            DockerResourceBusy failed => failed.Message,
            DockerDaemonUnavailable failed => failed.Message,
            DockerResponseInvalid failed => failed.Message,
        };
    }

    private async Task<DockerExec> CaptureExecAsync(string execId, HttpResponseMessage started, CancellationToken cancellationToken)
    {
        var stdout = new BoundedTextCapture(MaxExecOutputChars);
        var stderr = new BoundedTextCapture(MaxExecOutputChars);
        using (started)
        {
            try
            {
                await using var stream = await started.Content.ReadAsStreamAsync(cancellationToken);
                await DockerStreamDemultiplexer.ReadFramesAsync(
                    stream,
                    (channel, payload, _) =>
                    {
                        (channel == LogChannel.Stderr ? stderr : stdout).Append(payload.Span);
                        return ValueTask.CompletedTask;
                    },
                    cancellationToken);
            }
            catch (Exception exception) when (exception is HttpRequestException or IOException)
            {
                return new DockerDaemonUnavailable($"Exec {execId} output broke off: {exception.Message}");
            }
        }

        var outcome = await InspectExecAsync(execId, cancellationToken);
        return outcome switch
        {
            DockerExecInspect { Running: false, ExitCode: { } exitCode } => new ExecOutput(exitCode, stdout.ToString(), stderr.ToString()),
            DockerExecInspect => new DockerDaemonUnavailable($"Exec {execId} output ended before the process exited."),
            DockerResourceMissing failure => failure,
            DockerResourceBusy failure => failure,
            DockerDaemonUnavailable failure => failure,
            DockerResponseInvalid failure => failure,
        };
    }

    private async Task<DockerExecStatus> InspectExecAsync(string execId, CancellationToken cancellationToken)
    {
        var outcome = await GetAsync($"exec/{Uri.EscapeDataString(execId)}/json", cancellationToken);
        return outcome switch
        {
            HttpResponseMessage response => await ReadJsonAsync(response, DockerJsonContext.Default.DockerExecInspect,
                static state => (DockerExecStatus)state,
                static failure => (DockerExecStatus)failure,
                static failure => (DockerExecStatus)failure, cancellationToken),
            DockerResourceMissing failure => failure,
            DockerResourceBusy failure => failure,
            DockerDaemonUnavailable failure => failure,
            DockerResponseInvalid failure => failure,
        };
    }

    private static string PortKey(int containerPort, PortProtocol protocol) => protocol switch
    {
        PortProtocol.Tcp => string.Create(CultureInfo.InvariantCulture, $"{containerPort}/tcp"),
        PortProtocol.Udp => string.Create(CultureInfo.InvariantCulture, $"{containerPort}/udp"),
        _ => throw new UnreachableException(),
    };

    private static bool TryParsePortKey(string key, out int containerPort, out PortProtocol protocol)
    {
        var slash = key.IndexOf('/', StringComparison.Ordinal);
        protocol = slash < 0 ? PortProtocol.Tcp : ParseProtocol(key[(slash + 1)..]);
        return int.TryParse(slash < 0 ? key : key[..slash], NumberStyles.None, CultureInfo.InvariantCulture, out containerPort);
    }

    private static PortProtocol ParseProtocol(string? value) =>
        string.Equals(value, "udp", StringComparison.OrdinalIgnoreCase) ? PortProtocol.Udp : PortProtocol.Tcp;

    private async Task<DockerHttpExchange> GetAsync(string path, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        return await SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken);
    }

    private static async Task<TOutcome> ReadJsonAsync<T, TOutcome>(
        HttpResponseMessage response,
        JsonTypeInfo<T> typeInfo,
        Func<T, TOutcome> project,
        Func<DockerDaemonUnavailable, TOutcome> unavailable,
        Func<DockerResponseInvalid, TOutcome> invalid,
        CancellationToken cancellationToken)
        where T : class
    {
        using var ownedResponse = response;
        T? document;
        var endpoint = response.RequestMessage?.RequestUri?.AbsolutePath;
        try
        {
            document = await response.Content.ReadFromJsonAsync(typeInfo, cancellationToken);
        }
        catch (HttpRequestException exception)
        {
            return unavailable(new DockerDaemonUnavailable($"Docker response for {endpoint} was unreadable: {exception.Message}"));
        }
        catch (IOException exception)
        {
            return unavailable(new DockerDaemonUnavailable($"Docker response for {endpoint} was unreadable: {exception.Message}"));
        }
        catch (JsonException exception)
        {
            return invalid(new DockerResponseInvalid($"Docker response for {endpoint} was malformed: {exception.Message}"));
        }

        return document is not null
            ? project(document)
            : invalid(new DockerResponseInvalid($"Docker returned an empty body for {endpoint}."));
    }

    private async Task<DockerImageRemoval> SendForDoneAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken,
        TimeSpan? timeout = null)
    {
        var outcome = await SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken, timeout);
        return outcome switch
        {
            HttpResponseMessage response => Release(response),
            DockerResourceMissing failure => failure,
            DockerResourceBusy failure => failure,
            DockerDaemonUnavailable failure => failure,
            DockerResponseInvalid failure => failure,
        };
    }

    private static DockerRequestCompleted Release(HttpResponseMessage response)
    {
        response.Dispose();
        return new DockerRequestCompleted();
    }

    private async Task<DockerHttpExchange> SendAsync(
        HttpRequestMessage request,
        HttpCompletionOption completion,
        CancellationToken cancellationToken,
        TimeSpan? timeout = null)
    {
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (completion == HttpCompletionOption.ResponseContentRead)
        {
            operation.CancelAfter(timeout ?? ApiTimeout);
        }

        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, completion, operation.Token);
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException)
        {
            return new DockerDaemonUnavailable($"Docker Engine is unreachable: {exception.Message}");
        }

        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new DockerDaemonUnavailable($"Docker operation {request.Method} {request.RequestUri?.AbsolutePath} timed out.");
        }

        if (response.IsSuccessStatusCode || (int)response.StatusCode == 304)
        {
            return response;
        }

        using (response)
        {
            var message = await ReadErrorMessageAsync(response, cancellationToken);
            return (int)response.StatusCode switch
            {
                404 => new DockerResourceMissing(message),
                409 => new DockerResourceBusy(message),
                >= 500 => new DockerDaemonUnavailable(message),
                _ => new DockerResponseInvalid(message),
            };
        }
    }

    private static async Task<string> ReadErrorMessageAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var status = string.Create(CultureInfo.InvariantCulture, $"Docker {(int)response.StatusCode} for {response.RequestMessage?.Method} {response.RequestMessage?.RequestUri?.AbsolutePath}");
        try
        {
            var body = await response.Content.ReadFromJsonAsync(DockerJsonContext.Default.DockerErrorResponse, cancellationToken);
            return body?.Message is { Length: > 0 } message ? $"{status}: {message}" : status;
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or JsonException or NotSupportedException)
        {
            return status;
        }
    }
}

public static class ImageReference
{
    public static string WithDefaultTag(string image)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(image);
        if (image.Contains('@', StringComparison.Ordinal))
        {
            return image;
        }

        var lastSlash = image.LastIndexOf('/');
        return image.IndexOf(':', lastSlash + 1) >= 0 ? image : $"{image}:latest";
    }
}
