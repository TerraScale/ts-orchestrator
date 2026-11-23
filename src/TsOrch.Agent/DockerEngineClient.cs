using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Microsoft.Extensions.Options;

namespace TsOrch.Agent;

public sealed class DockerEngineClient : IDisposable
{
    private const string ApiVersion = "v1.45";
    private const int MaxLogLineChars = 16 * 1024;
    private const int MaxExecOutputChars = 1024 * 1024;
    private const string EphemeralHostPort = "";

    private readonly HttpClient _http;
    private readonly TimeProvider _timeProvider;

    public DockerEngineClient(IOptions<AgentOptions> options, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        var socketPath = options.Value.DockerSocketPath;
        _timeProvider = timeProvider;
        var handler = new SocketsHttpHandler
        {
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30),
            ConnectCallback = async (_, cancellationToken) =>
            {
                var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                try
                {
                    await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
        };
        _http = new HttpClient(handler, disposeHandler: true)
        {
            BaseAddress = new Uri($"http://docker/{ApiVersion}/"),
            Timeout = Timeout.InfiniteTimeSpan,
        };
    }

    public void Dispose() => _http.Dispose();

    public async Task<OrchResult<Done>> PullImageAsync(string image, string? registryAuth, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(image);
        using var request = new HttpRequestMessage(HttpMethod.Post, $"images/create?fromImage={Uri.EscapeDataString(ImageReference.WithDefaultTag(image))}");
        if (registryAuth is not null)
        {
            request.Headers.Add("X-Registry-Auth", registryAuth);
        }

        var sentResult = await SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!sentResult.TryGetValue(out var sent, out var sendError))
        {
            return sendError;
        }

        using var response = sent;
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
                var error = progress?.ErrorDetail?.Message ?? progress?.Error;
                if (error is not null)
                {
                    return new Unavailable($"Pull of {image} failed: {error}");
                }
            }

            return new Done();
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or JsonException)
        {
            return new Unavailable($"Pull of {image} failed: {exception.Message}");
        }
    }

    public async Task<OrchResult<IReadOnlyList<ManagedContainer>>> ListManagedContainersAsync(string labelPrefix, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(labelPrefix);
        var filters = $$"""{"label":["{{ContainerLabels.Managed(labelPrefix)}}=true"]}""";
        var listedResult = await GetJsonAsync($"containers/json?all=true&filters={Uri.EscapeDataString(filters)}", DockerJsonContext.Default.IReadOnlyListDockerContainerSummary, cancellationToken);
        if (!listedResult.TryGetValue(out var listed, out var error))
        {
            return error;
        }

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
                [.. (summary.Ports ?? []).Where(static port => port.PublicPort is > 0).Select(static port => new PublishedPort(port.IP ?? "0.0.0.0", port.PublicPort!.Value, port.PrivatePort, ParseProtocol(port.Type)))]));
        }

        return containers;
    }

    public async Task<OrchResult<IReadOnlySet<string>>> ListContainerImageIdsAsync(CancellationToken cancellationToken)
    {
        var listedResult = await GetJsonAsync("containers/json?all=true", DockerJsonContext.Default.IReadOnlyListDockerContainerSummary, cancellationToken);
        if (!listedResult.TryGetValue(out var listed, out var error))
        {
            return error;
        }

        HashSet<string> imageIds = new(StringComparer.Ordinal);
        foreach (var summary in listed)
        {
            if (summary.ImageID is { Length: > 0 } imageId)
            {
                imageIds.Add(imageId);
            }
        }

        return imageIds;
    }

    public async Task<OrchResult<string>> CreateContainerAsync(DockerContainerSpec spec, CancellationToken cancellationToken)
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
        var exposed = new Dictionary<string, DockerEmpty>(StringComparer.Ordinal);
        var bindings = new Dictionary<string, IReadOnlyList<DockerPortBinding>>(StringComparer.Ordinal);
        foreach (var port in spec.Ports)
        {
            var key = PortKey(port.ContainerPort, port.Protocol);
            exposed[key] = new DockerEmpty();
            var binding = new DockerPortBinding(port.HostIp, port.HostPort is { } hostPort ? hostPort.ToString(CultureInfo.InvariantCulture) : EphemeralHostPort);
            IReadOnlyList<DockerPortBinding> merged = bindings.TryGetValue(key, out var existing) ? [.. existing, binding] : [binding];
            bindings[key] = merged;
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
        var created = await SendForJsonAsync(request, DockerJsonContext.Default.DockerIdResponse, cancellationToken);
        return created switch
        {
            DockerIdResponse response => response.Id,
            OrchError error => error,
        };
    }

    public async Task<OrchResult<Done>> StartContainerAsync(string containerId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"containers/{Uri.EscapeDataString(containerId)}/start");
        return await SendForDoneAsync(request, cancellationToken);
    }

    public async Task<OrchResult<Done>> StopContainerAsync(string containerId, int timeoutSeconds, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(timeoutSeconds);
        using var request = new HttpRequestMessage(HttpMethod.Post, string.Create(CultureInfo.InvariantCulture, $"containers/{Uri.EscapeDataString(containerId)}/stop?t={timeoutSeconds}"));
        var result = await SendForDoneAsync(request, cancellationToken);
        return result is NotFound ? new Done() : result;
    }

    public async Task<OrchResult<Done>> RemoveContainerAsync(string containerId, bool force, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, $"containers/{Uri.EscapeDataString(containerId)}?force={(force ? "true" : "false")}");
        var result = await SendForDoneAsync(request, cancellationToken);
        return result is NotFound ? new Done() : result;
    }

    public async Task<OrchResult<ContainerState>> InspectContainerAsync(string containerId, CancellationToken cancellationToken)
    {
        var inspectedResult = await GetJsonAsync($"containers/{Uri.EscapeDataString(containerId)}/json", DockerJsonContext.Default.DockerContainerInspect, cancellationToken);
        if (!inspectedResult.TryGetValue(out var inspected, out var error))
        {
            return error;
        }

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

    public async Task<OrchResult<ContainerStatsSample>> GetContainerStatsAsync(string containerId, CancellationToken cancellationToken)
    {
        var fetchedResult = await GetJsonAsync($"containers/{Uri.EscapeDataString(containerId)}/stats?stream=false&one-shot=true", DockerJsonContext.Default.DockerStats, cancellationToken);
        if (!fetchedResult.TryGetValue(out var fetched, out var error))
        {
            return error;
        }

        long rx = 0;
        long tx = 0;
        foreach (var network in (fetched.Networks ?? new Dictionary<string, DockerNetworkStats>()).Values)
        {
            rx += network.RxBytes;
            tx += network.TxBytes;
        }

        return new ContainerStatsSample(
            fetched.CpuStats?.CpuUsage?.TotalUsage ?? 0,
            fetched.CpuStats?.SystemCpuUsage ?? 0,
            fetched.CpuStats?.OnlineCpus ?? Environment.ProcessorCount,
            fetched.MemoryStats?.Usage ?? 0,
            fetched.MemoryStats?.Limit ?? 0,
            fetched.PidsStats?.Current ?? 0,
            rx,
            tx);
    }

    public async Task<OrchResult<Done>> StreamLogsAsync(
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
        var sentResult = await SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!sentResult.TryGetValue(out var sent, out var sendError))
        {
            return sendError;
        }

        using var response = sent;
        var stdout = new LineAssembler(MaxLogLineChars);
        var stderr = new LineAssembler(MaxLogLineChars);
        try
        {
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            await DockerStreamDemultiplexer.ReadFramesAsync(
                stream,
                (channel, payload, token) => (channel == LogChannel.Stderr ? stderr : stdout).AppendAsync(payload, (line, lineToken) => onLine(channel, line, lineToken), token),
                cancellationToken);
            await stdout.FlushAsync((line, token) => onLine(LogChannel.Stdout, line, token), cancellationToken);
            await stderr.FlushAsync((line, token) => onLine(LogChannel.Stderr, line, token), cancellationToken);
            return new Done();
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException)
        {
            return new Unavailable($"Log stream for {containerId} ended: {exception.Message}");
        }
    }

    public async Task<OrchResult<ExecOutput>> ExecOnceAsync(string containerId, IReadOnlyList<string> command, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (command.Count == 0)
        {
            return new Validation("Exec command must not be empty.");
        }

        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);
        using var timeoutSource = new CancellationTokenSource(timeout, _timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutSource.Token);
        try
        {
            using var createRequest = new HttpRequestMessage(HttpMethod.Post, $"containers/{Uri.EscapeDataString(containerId)}/exec")
            {
                Content = JsonContent.Create(new DockerExecCreateRequest(true, true, false, command), DockerJsonContext.Default.DockerExecCreateRequest),
            };
            var createdResult = await SendForJsonAsync(createRequest, DockerJsonContext.Default.DockerIdResponse, linked.Token);
            if (!createdResult.TryGetValue(out var created, out var createError))
            {
                return createError;
            }

            var execId = created.Id;
            using var startRequest = new HttpRequestMessage(HttpMethod.Post, $"exec/{Uri.EscapeDataString(execId)}/start")
            {
                Content = JsonContent.Create(new DockerExecStartRequest(false, false), DockerJsonContext.Default.DockerExecStartRequest),
            };
            var startedResult = await SendAsync(startRequest, HttpCompletionOption.ResponseHeadersRead, linked.Token);
            if (!startedResult.TryGetValue(out var started, out var startError))
            {
                return startError;
            }

            var stdout = new BoundedTextCapture(MaxExecOutputChars);
            var stderr = new BoundedTextCapture(MaxExecOutputChars);
            using (started)
            {
                await using var stream = await started.Content.ReadAsStreamAsync(linked.Token);
                await DockerStreamDemultiplexer.ReadFramesAsync(
                    stream,
                    (channel, payload, _) =>
                    {
                        (channel == LogChannel.Stderr ? stderr : stdout).Append(payload.Span);
                        return ValueTask.CompletedTask;
                    },
                    linked.Token);
            }

            var inspected = await GetJsonAsync($"exec/{Uri.EscapeDataString(execId)}/json", DockerJsonContext.Default.DockerExecInspect, linked.Token);
            return inspected switch
            {
                DockerExecInspect { Running: false, ExitCode: { } exitCode } => new ExecOutput(exitCode, stdout.ToString(), stderr.ToString()),
                DockerExecInspect => new Unavailable($"Exec {execId} output ended before the process exited."),
                OrchError error => error,
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new Unavailable(string.Create(CultureInfo.InvariantCulture, $"Exec in {containerId} exceeded {timeout.TotalSeconds:0} s."));
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException)
        {
            return new Unavailable($"Exec in {containerId} failed: {exception.Message}");
        }
    }

    public async Task<OrchResult<IReadOnlyList<DockerImage>>> ListImagesAsync(CancellationToken cancellationToken)
    {
        var listedResult = await GetJsonAsync("images/json", DockerJsonContext.Default.IReadOnlyListDockerImageSummary, cancellationToken);
        if (!listedResult.TryGetValue(out var listed, out var error))
        {
            return error;
        }

        IReadOnlyList<DockerImage> images =
        [
            .. listed.Select(static image => new DockerImage(
                image.Id,
                image.RepoTags ?? [],
                image.RepoDigests ?? [],
                DateTimeOffset.FromUnixTimeSeconds(image.Created))),
        ];
        return new OrchResult<IReadOnlyList<DockerImage>>(images);
    }

    public async Task<OrchResult<Done>> RemoveImageAsync(string imageId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, $"images/{Uri.EscapeDataString(imageId)}?force=false&noprune=false");
        return await SendForDoneAsync(request, cancellationToken);
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

    private async Task<OrchResult<T>> GetJsonAsync<T>(string path, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        return await SendForJsonAsync(request, typeInfo, cancellationToken);
    }

    private async Task<OrchResult<T>> SendForJsonAsync<T>(HttpRequestMessage request, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken)
    {
        var sentResult = await SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken);
        if (!sentResult.TryGetValue(out var sent, out var error))
        {
            return error;
        }

        using var response = sent;
        try
        {
            var value = await response.Content.ReadFromJsonAsync(typeInfo, cancellationToken);
            return value is null
                ? new Internal($"Docker returned an empty body for {request.RequestUri}.")
                : new OrchResult<T>(value);
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or JsonException)
        {
            return new Unavailable($"Docker response for {request.RequestUri} was unreadable: {exception.Message}");
        }
    }

    private async Task<OrchResult<Done>> SendForDoneAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var sentResult = await SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken);
        if (!sentResult.TryGetValue(out var sent, out var error))
        {
            return error;
        }

        sent.Dispose();
        return new Done();
    }

    private async Task<OrchResult<HttpResponseMessage>> SendAsync(HttpRequestMessage request, HttpCompletionOption completion, CancellationToken cancellationToken)
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

        if (response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NotModified)
        {
            return response;
        }

        using (response)
        {
            var message = await ReadErrorMessageAsync(response, cancellationToken);
            return response.StatusCode switch
            {
                HttpStatusCode.NotFound => new NotFound(message),
                HttpStatusCode.Conflict => new Conflict(message),
                HttpStatusCode.BadRequest => new Validation(message),
                HttpStatusCode.Unauthorized => new Unauthorized(message),
                HttpStatusCode.Forbidden => new Forbidden(message),
                >= HttpStatusCode.InternalServerError => new Unavailable(message),
                _ => new Internal(message),
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
