using System.Diagnostics;
using System.Globalization;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace TsOrch.Agent;

public sealed class DockerEngineClient(AgentOptions options, TimeProvider timeProvider) : IDisposable
{
    private const string ApiVersion = "v1.45";
    private const int MaxLogLineChars = 16 * 1024;
    private const int MaxExecOutputChars = 1024 * 1024;
    private const string EphemeralHostPort = "";

    private readonly HttpClient _http = new(CreateHandler(options.DockerSocketPath), disposeHandler: true)
    {
        BaseAddress = new Uri($"http://docker/{ApiVersion}/"),
        Timeout = Timeout.InfiniteTimeSpan,
    };

    public void Dispose() => _http.Dispose();

    public async Task<Result<Done, NotFound, Unavailable, InternalFailure>> PullImageAsync(string image, string? registryAuth, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(image);
        using var request = new HttpRequestMessage(HttpMethod.Post, $"images/create?fromImage={Uri.EscapeDataString(ImageReference.WithDefaultTag(image))}");
        if (registryAuth is not null)
        {
            request.Headers.Add("X-Registry-Auth", registryAuth);
        }

        return await SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken) switch
        {
            HttpResponseMessage response => await ReadPullProgressAsync(response, image, cancellationToken),
            NotFound failure => failure,
            Conflict failure => new InternalFailure(failure.Message),
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };
    }

    public async Task<Result<IReadOnlyList<ManagedContainer>, Unavailable, InternalFailure>> ListManagedContainersAsync(string labelPrefix, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(labelPrefix);
        var filters = $$"""{"label":["{{ContainerLabels.Managed(labelPrefix)}}=true"]}""";
        return await GetJsonAsync($"containers/json?all=true&filters={Uri.EscapeDataString(filters)}", DockerJsonContext.Default.IReadOnlyListDockerContainerSummary, cancellationToken) switch
        {
            IReadOnlyList<DockerContainerSummary> listed => Managed(listed, labelPrefix),
            NotFound failure => new InternalFailure(failure.Message),
            Conflict failure => new InternalFailure(failure.Message),
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };
    }

    public async Task<Result<IReadOnlySet<string>, Unavailable, InternalFailure>> ListContainerImageIdsAsync(CancellationToken cancellationToken) =>
        await GetJsonAsync("containers/json?all=true", DockerJsonContext.Default.IReadOnlyListDockerContainerSummary, cancellationToken) switch
        {
            IReadOnlyList<DockerContainerSummary> listed => ImageIds(listed),
            NotFound failure => new InternalFailure(failure.Message),
            Conflict failure => new InternalFailure(failure.Message),
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };

    public async Task<Result<string, NotFound, Conflict, Unavailable, InternalFailure>> CreateContainerAsync(DockerContainerSpec spec, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(spec);
        var labels = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [ContainerLabels.Managed(spec.LabelPrefix)] = "true",
            [ContainerLabels.PlacementId(spec.LabelPrefix)] = spec.PlacementId,
            [ContainerLabels.Service(spec.LabelPrefix)] = spec.ServiceName,
            [ContainerLabels.ConfigHash(spec.LabelPrefix)] = spec.ConfigHash,
            [ContainerLabels.Image(spec.LabelPrefix)] = spec.Image,
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
            spec.Image,
            [.. spec.Env.OrderBy(static pair => pair.Key, StringComparer.Ordinal).Select(static pair => $"{pair.Key}={pair.Value}")],
            spec.Args.Count == 0 ? null : spec.Args,
            labels,
            exposed,
            new DockerHostConfig(
                [.. spec.Mounts.Select(static mount => mount.ReadOnly ? $"{mount.Source}:{mount.Target}:ro" : $"{mount.Source}:{mount.Target}")],
                bindings,
                spec.Resources.CgroupParent,
                spec.Resources.MemoryReservationBytes,
                spec.Resources.MemoryBytes,
                spec.Resources.NanoCpus,
                spec.Resources.CpuShares,
                spec.Resources.PidsLimit,
                spec.Resources.OomScoreAdj,
                new DockerRestartPolicy("unless-stopped")));
        using var request = new HttpRequestMessage(HttpMethod.Post, $"containers/create?name={Uri.EscapeDataString(spec.Name)}")
        {
            Content = JsonContent.Create(body, DockerJsonContext.Default.DockerCreateContainerRequest),
        };
        return await SendForJsonAsync(request, DockerJsonContext.Default.DockerIdResponse, cancellationToken) switch
        {
            DockerIdResponse response => response.Id,
            NotFound failure => failure,
            Conflict failure => failure,
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };
    }

    public async Task<Result<Done, NotFound, Unavailable, InternalFailure>> StartContainerAsync(string containerId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"containers/{Uri.EscapeDataString(containerId)}/start");
        return await SendForDoneAsync(request, cancellationToken) switch
        {
            Done done => done,
            NotFound failure => failure,
            Conflict failure => new InternalFailure(failure.Message),
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };
    }

    public async Task<Result<Done, Unavailable, InternalFailure>> StopContainerAsync(string containerId, int timeoutSeconds, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(timeoutSeconds);
        using var request = new HttpRequestMessage(HttpMethod.Post, string.Create(CultureInfo.InvariantCulture, $"containers/{Uri.EscapeDataString(containerId)}/stop?t={timeoutSeconds}"));
        return await SendForDoneAsync(request, cancellationToken) switch
        {
            Done done => done,
            NotFound => new Done(),
            Conflict failure => new InternalFailure(failure.Message),
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };
    }

    public async Task<Result<Done, Conflict, Unavailable, InternalFailure>> RemoveContainerAsync(string containerId, bool force, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, $"containers/{Uri.EscapeDataString(containerId)}?force={(force ? "true" : "false")}");
        return await SendForDoneAsync(request, cancellationToken) switch
        {
            Done done => done,
            NotFound => new Done(),
            Conflict failure => failure,
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };
    }

    public async Task<Result<ContainerState, NotFound, Unavailable, InternalFailure>> InspectContainerAsync(string containerId, CancellationToken cancellationToken) =>
        await GetJsonAsync($"containers/{Uri.EscapeDataString(containerId)}/json", DockerJsonContext.Default.DockerContainerInspect, cancellationToken) switch
        {
            DockerContainerInspect inspected => State(inspected),
            NotFound failure => failure,
            Conflict failure => new InternalFailure(failure.Message),
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };

    public async Task<Result<ContainerStatsSample, NotFound, Unavailable, InternalFailure>> GetContainerStatsAsync(string containerId, CancellationToken cancellationToken) =>
        await GetJsonAsync($"containers/{Uri.EscapeDataString(containerId)}/stats?stream=false&one-shot=true", DockerJsonContext.Default.DockerStats, cancellationToken) switch
        {
            DockerStats stats => Sample(stats),
            NotFound failure => failure,
            Conflict failure => new InternalFailure(failure.Message),
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };

    public async Task<Result<Done, NotFound, Unavailable, InternalFailure>> StreamLogsAsync(
        string containerId,
        int tail,
        bool follow,
        Func<LogChannel, string, CancellationToken, ValueTask> onLine,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(onLine);
        ArgumentOutOfRangeException.ThrowIfNegative(tail);
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            string.Create(CultureInfo.InvariantCulture, $"containers/{Uri.EscapeDataString(containerId)}/logs?stdout=true&stderr=true&follow={(follow ? "true" : "false")}&tail={tail}"));
        return await SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken) switch
        {
            HttpResponseMessage response => await ReadLogsAsync(response, containerId, onLine, cancellationToken),
            NotFound failure => failure,
            Conflict failure => new InternalFailure(failure.Message),
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };
    }

    public async Task<Result<ExecOutput, Validation, NotFound, Conflict, RequestTimeout, Unavailable, InternalFailure>> ExecOnceAsync(
        string containerId,
        IReadOnlyList<string> command,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (command.Count == 0)
        {
            return new Validation("Exec command must not be empty.");
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
            return await SendForJsonAsync(createRequest, DockerJsonContext.Default.DockerIdResponse, linked.Token) switch
            {
                DockerIdResponse created => await RunExecAsync(created.Id, linked.Token) switch
                {
                    ExecOutput output => output,
                    NotFound failure => failure,
                    Conflict failure => failure,
                    Unavailable failure => failure,
                    InternalFailure failure => failure,
                },
                NotFound failure => failure,
                Conflict failure => failure,
                Unavailable failure => failure,
                InternalFailure failure => failure,
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new RequestTimeout(string.Create(CultureInfo.InvariantCulture, $"Exec in {containerId} exceeded {timeout.TotalSeconds:0} s."));
        }
    }

    public async Task<Result<IReadOnlyList<DockerImage>, Unavailable, InternalFailure>> ListImagesAsync(CancellationToken cancellationToken) =>
        await GetJsonAsync("images/json", DockerJsonContext.Default.IReadOnlyListDockerImageSummary, cancellationToken) switch
        {
            IReadOnlyList<DockerImageSummary> listed => Images(listed),
            NotFound failure => new InternalFailure(failure.Message),
            Conflict failure => new InternalFailure(failure.Message),
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };

    public async Task<Result<Done, NotFound, Conflict, Unavailable, InternalFailure>> RemoveImageAsync(string imageId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, $"images/{Uri.EscapeDataString(imageId)}?force=false&noprune=false");
        return await SendForDoneAsync(request, cancellationToken);
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

    private static List<ManagedContainer> Managed(IReadOnlyList<DockerContainerSummary> listed, string labelPrefix)
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
                continue;
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
                [.. Published(summary.Ports ?? [])]));
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

        return new ContainerState(inspected.Id, inspected.State.Running, inspected.State.OOMKilled, inspected.State.ExitCode, inspected.RestartCount, ports);
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
            image.RepoDigests ?? [],
            DateTimeOffset.FromUnixTimeSeconds(image.Created))),
    ];

    private static async Task<Result<Done, NotFound, Unavailable, InternalFailure>> ReadPullProgressAsync(HttpResponseMessage response, string image, CancellationToken cancellationToken)
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
                        return new Unavailable($"Pull of {image} failed: {error}");
                    }
                }

                return new Done();
            }
            catch (Exception exception) when (exception is HttpRequestException or IOException)
            {
                return new Unavailable($"Pull of {image} failed: {exception.Message}");
            }
            catch (JsonException exception)
            {
                return new InternalFailure($"Pull of {image} returned malformed progress: {exception.Message}");
            }
        }
    }

    private static async Task<Result<Done, NotFound, Unavailable, InternalFailure>> ReadLogsAsync(
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
                return new Unavailable($"Log stream for {containerId} ended: {exception.Message}");
            }

            await stdout.FlushAsync((line, lineToken) => onLine(LogChannel.Stdout, line, lineToken), cancellationToken);
            await stderr.FlushAsync((line, lineToken) => onLine(LogChannel.Stderr, line, lineToken), cancellationToken);
            return new Done();
        }
    }

    private async Task<Result<ExecOutput, NotFound, Conflict, Unavailable, InternalFailure>> RunExecAsync(string execId, CancellationToken cancellationToken)
    {
        using var startRequest = new HttpRequestMessage(HttpMethod.Post, $"exec/{Uri.EscapeDataString(execId)}/start")
        {
            Content = JsonContent.Create(new DockerExecStartRequest(false, false), DockerJsonContext.Default.DockerExecStartRequest),
        };
        return await SendAsync(startRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken) switch
        {
            HttpResponseMessage started => await CaptureExecAsync(execId, started, cancellationToken),
            NotFound failure => failure,
            Conflict failure => failure,
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };
    }

    private async Task<Result<ExecOutput, NotFound, Conflict, Unavailable, InternalFailure>> CaptureExecAsync(string execId, HttpResponseMessage started, CancellationToken cancellationToken)
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
                return new Unavailable($"Exec {execId} output broke off: {exception.Message}");
            }
        }

        return await GetJsonAsync($"exec/{Uri.EscapeDataString(execId)}/json", DockerJsonContext.Default.DockerExecInspect, cancellationToken) switch
        {
            DockerExecInspect { Running: false, ExitCode: { } exitCode } => new ExecOutput(exitCode, stdout.ToString(), stderr.ToString()),
            DockerExecInspect => new Unavailable($"Exec {execId} output ended before the process exited."),
            NotFound failure => failure,
            Conflict failure => failure,
            Unavailable failure => failure,
            InternalFailure failure => failure,
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

    private async Task<Result<T, NotFound, Conflict, Unavailable, InternalFailure>> GetJsonAsync<T>(string path, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken)
        where T : notnull
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        return await SendForJsonAsync(request, typeInfo, cancellationToken);
    }

    private async Task<Result<T, NotFound, Conflict, Unavailable, InternalFailure>> SendForJsonAsync<T>(HttpRequestMessage request, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken)
        where T : notnull =>
        await SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken) switch
        {
            HttpResponseMessage response => await ReadJsonAsync(response, request, typeInfo, cancellationToken),
            NotFound failure => failure,
            Conflict failure => failure,
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };

    private static async Task<Result<T, NotFound, Conflict, Unavailable, InternalFailure>> ReadJsonAsync<T>(
        HttpResponseMessage response,
        HttpRequestMessage request,
        JsonTypeInfo<T> typeInfo,
        CancellationToken cancellationToken)
        where T : notnull
    {
        using (response)
        {
            try
            {
                return await response.Content.ReadFromJsonAsync(typeInfo, cancellationToken) is { } value
                    ? value
                    : new InternalFailure($"Docker returned an empty body for {request.RequestUri}.");
            }
            catch (Exception exception) when (exception is HttpRequestException or IOException)
            {
                return new Unavailable($"Docker response for {request.RequestUri} was unreadable: {exception.Message}");
            }
            catch (JsonException exception)
            {
                return new InternalFailure($"Docker response for {request.RequestUri} was malformed: {exception.Message}");
            }
        }
    }

    private async Task<Result<Done, NotFound, Conflict, Unavailable, InternalFailure>> SendForDoneAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        await SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken) switch
        {
            HttpResponseMessage response => Release(response),
            NotFound failure => failure,
            Conflict failure => failure,
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };

    private static Done Release(HttpResponseMessage response)
    {
        response.Dispose();
        return new Done();
    }

    private async Task<Result<HttpResponseMessage, NotFound, Conflict, Unavailable, InternalFailure>> SendAsync(
        HttpRequestMessage request,
        HttpCompletionOption completion,
        CancellationToken cancellationToken)
    {
        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, completion, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException)
        {
            return new Unavailable($"Docker Engine is unreachable: {exception.Message}");
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
                404 => new NotFound(message),
                409 => new Conflict(message),
                >= 500 => new Unavailable(message),
                _ => new InternalFailure(message),
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
