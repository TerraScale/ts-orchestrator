using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Lab.SmolVm;

internal sealed record SmolVmApiMount(
    [property: JsonPropertyName("source")] string Source,
    [property: JsonPropertyName("target")] string Target,
    [property: JsonPropertyName("readonly")] bool ReadOnly);

internal sealed record SmolVmApiPort(
    [property: JsonPropertyName("host")] ushort Host,
    [property: JsonPropertyName("guest")] ushort Guest);

internal sealed record SmolVmApiRestart(
    [property: JsonPropertyName("policy")] string Policy,
    [property: JsonPropertyName("maxRetries")] uint MaximumRetries);

internal sealed record SmolVmCreateMachineRequest(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("cpus")] byte CpuCount,
    [property: JsonPropertyName("memoryMb")] uint MemoryMiB,
    [property: JsonPropertyName("mounts")] IReadOnlyList<SmolVmApiMount> Mounts,
    [property: JsonPropertyName("ports")] IReadOnlyList<SmolVmApiPort> Ports,
    [property: JsonPropertyName("network")] bool Network,
    [property: JsonPropertyName("gpu")] bool Gpu,
    [property: JsonPropertyName("storageGb")] ulong StorageGiB,
    [property: JsonPropertyName("overlayGb")] ulong OverlayGiB,
    [property: JsonPropertyName("allowedCidrs")] IReadOnlyList<string> AllowedCidrs,
    [property: JsonPropertyName("networkBackend")] string NetworkBackend,
    [property: JsonPropertyName("restart")] SmolVmApiRestart Restart,
    [property: JsonPropertyName("from")] string From)
{
    public static SmolVmCreateMachineRequest FromPlan(SmolVmMachinePlan plan) => new(
        plan.Name,
        plan.Resources.CpuCount,
        plan.Resources.MemoryMiB,
        [],
        plan.Ports.Select(port => new SmolVmApiPort(port.HostPort, port.GuestPort)).ToArray(),
        true,
        false,
        plan.Resources.StorageGiB,
        plan.Resources.OverlayGiB,
        plan.AllowedEgressCidrs,
        "virtio-net",
        new("always", 0),
        plan.BaseArtifactPath);
}

internal sealed record SmolVmMachineInfo(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("cpus")] byte CpuCount,
    [property: JsonPropertyName("memoryMb")] uint MemoryMiB,
    [property: JsonPropertyName("pid")] int? ProcessId,
    [property: JsonPropertyName("mounts")] IReadOnlyList<SmolVmApiMount> Mounts,
    [property: JsonPropertyName("ports")] IReadOnlyList<SmolVmApiPort> Ports,
    [property: JsonPropertyName("network")] bool Network,
    [property: JsonPropertyName("networkBackend")] string? NetworkBackend,
    [property: JsonPropertyName("allowedCidrs")] IReadOnlyList<string>? AllowedCidrs,
    [property: JsonPropertyName("storageGb")] ulong? StorageGiB,
    [property: JsonPropertyName("overlayGb")] ulong? OverlayGiB,
    [property: JsonPropertyName("createdAt")] ulong CreatedAt);

internal sealed record SmolVmMachineList(
    [property: JsonPropertyName("machines")] IReadOnlyList<SmolVmMachineInfo> Machines);

internal sealed record SmolVmEnvironmentValue(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("value")] string Value);

internal sealed record SmolVmExecRequest(
    [property: JsonPropertyName("command")] IReadOnlyList<string> Command,
    [property: JsonPropertyName("env")] IReadOnlyList<SmolVmEnvironmentValue> Environment,
    [property: JsonPropertyName("workdir")] string? WorkingDirectory,
    [property: JsonPropertyName("timeoutSecs")] ulong? TimeoutSeconds,
    [property: JsonPropertyName("stdin")] string? StandardInput);

internal sealed record SmolVmExecResponse(
    [property: JsonPropertyName("exitCode")] int ExitCode,
    [property: JsonPropertyName("stdout")] string StandardOutput,
    [property: JsonPropertyName("stderr")] string StandardError,
    [property: JsonPropertyName("stdoutB64")] string StandardOutputBase64,
    [property: JsonPropertyName("stderrB64")] string StandardErrorBase64);

internal sealed record SmolVmResizeRequest(
    [property: JsonPropertyName("storageGb")] ulong? StorageGiB,
    [property: JsonPropertyName("overlayGb")] ulong? OverlayGiB);

internal sealed class SmolVmApiException(
    HttpStatusCode statusCode,
    string errorCode,
    string message) : Exception(message)
{
    public HttpStatusCode StatusCode { get; } = statusCode;
    public string ErrorCode { get; } = errorCode;
}

internal interface ISmolVmApiClient
{
    Task<IReadOnlyList<SmolVmMachineInfo>> ListMachinesAsync(CancellationToken cancellationToken);
    Task<SmolVmMachineInfo?> GetMachineAsync(string name, CancellationToken cancellationToken);
    Task<SmolVmMachineInfo> CreateMachineAsync(SmolVmCreateMachineRequest request, CancellationToken cancellationToken);
    Task<SmolVmMachineInfo> StartMachineAsync(string name, CancellationToken cancellationToken);
    Task<SmolVmExecResponse> ExecAsync(string name, SmolVmExecRequest request, CancellationToken cancellationToken);
    Task<HttpResponseMessage> OpenExecStreamAsync(string name, SmolVmExecRequest request, CancellationToken cancellationToken);
    Task<HttpResponseMessage> OpenLogsAsync(string name, CancellationToken cancellationToken);
    Task<byte[]> DownloadFileAsync(string name, string guestPath, CancellationToken cancellationToken);
    Task UploadFileAsync(string name, string guestPath, Stream content, CancellationToken cancellationToken);
    Task<SmolVmMachineInfo> ResizeMachineAsync(string name, SmolVmResizeRequest request, CancellationToken cancellationToken);
    Task<SmolVmMachineInfo> StopMachineAsync(string name, CancellationToken cancellationToken);
    Task DeleteMachineAsync(string name, CancellationToken cancellationToken);
}

internal sealed class SmolVmV1_5OpenApiClient : ISmolVmApiClient, IDisposable
{
    public const string ApiVersion = "1.5.0";
    private const int MaximumControlResponseBytes = 4 * 1024 * 1024;
    private const int MaximumFileResponseBytes = 64 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };
    private readonly HttpClient httpClient;

    internal SmolVmV1_5OpenApiClient(HttpClient httpClient)
    {
        this.httpClient = httpClient;
        this.httpClient.BaseAddress ??= new Uri("http://smolvm.local");
    }

    public static SmolVmV1_5OpenApiClient ConnectUnixSocket(
        string socketPath,
        TimeSpan requestTimeout)
    {
        if (!Path.IsPathFullyQualified(socketPath))
        {
            throw new ArgumentException("The SmolVM socket path must be absolute.", nameof(socketPath));
        }
        var handler = new SocketsHttpHandler
        {
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
            }
        };
        return new(new HttpClient(handler, disposeHandler: true) { Timeout = requestTimeout });
    }

    public async Task<IReadOnlyList<SmolVmMachineInfo>> ListMachinesAsync(CancellationToken cancellationToken) =>
        (await SendJsonAsync<SmolVmMachineList>(HttpMethod.Get, "/api/v1/machines", null, cancellationToken)).Machines;

    public async Task<SmolVmMachineInfo?> GetMachineAsync(string name, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, MachinePath(name));
        using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }
        await RequireSuccessAsync(response, cancellationToken);
        return await ReadJsonAsync<SmolVmMachineInfo>(response.Content, MaximumControlResponseBytes, cancellationToken);
    }

    public Task<SmolVmMachineInfo> CreateMachineAsync(
        SmolVmCreateMachineRequest request,
        CancellationToken cancellationToken) =>
        SendJsonAsync<SmolVmMachineInfo>(HttpMethod.Post, "/api/v1/machines", request, cancellationToken);

    public Task<SmolVmMachineInfo> StartMachineAsync(string name, CancellationToken cancellationToken) =>
        SendJsonAsync<SmolVmMachineInfo>(HttpMethod.Post, $"{MachinePath(name)}/start", null, cancellationToken);

    public Task<SmolVmExecResponse> ExecAsync(
        string name,
        SmolVmExecRequest request,
        CancellationToken cancellationToken) =>
        SendJsonAsync<SmolVmExecResponse>(HttpMethod.Post, $"{MachinePath(name)}/exec", request, cancellationToken);

    public Task<HttpResponseMessage> OpenExecStreamAsync(
        string name,
        SmolVmExecRequest request,
        CancellationToken cancellationToken) =>
        SendStreamingAsync(HttpMethod.Post, $"{MachinePath(name)}/exec/stream", request, cancellationToken);

    public Task<HttpResponseMessage> OpenLogsAsync(string name, CancellationToken cancellationToken) =>
        SendStreamingAsync(HttpMethod.Get, $"{MachinePath(name)}/logs", null, cancellationToken);

    public async Task<byte[]> DownloadFileAsync(
        string name,
        string guestPath,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, FilePath(name, guestPath));
        using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        await RequireSuccessAsync(response, cancellationToken);
        return await ReadBoundedBytesAsync(response.Content, MaximumFileResponseBytes, cancellationToken);
    }

    public async Task UploadFileAsync(
        string name,
        string guestPath,
        Stream content,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, FilePath(name, guestPath))
        {
            Content = new StreamContent(content)
        };
        request.Content.Headers.ContentType = new("application/octet-stream");
        using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        await RequireSuccessAsync(response, cancellationToken);
    }

    public Task<SmolVmMachineInfo> ResizeMachineAsync(
        string name,
        SmolVmResizeRequest request,
        CancellationToken cancellationToken) =>
        SendJsonAsync<SmolVmMachineInfo>(HttpMethod.Post, $"{MachinePath(name)}/resize", request, cancellationToken);

    public Task<SmolVmMachineInfo> StopMachineAsync(string name, CancellationToken cancellationToken) =>
        SendJsonAsync<SmolVmMachineInfo>(HttpMethod.Post, $"{MachinePath(name)}/stop", null, cancellationToken);

    public async Task DeleteMachineAsync(string name, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, MachinePath(name));
        using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.StatusCode != HttpStatusCode.NotFound)
        {
            await RequireSuccessAsync(response, cancellationToken);
        }
    }

    private async Task<T> SendJsonAsync<T>(
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body, options: JsonOptions);
        }
        using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        await RequireSuccessAsync(response, cancellationToken);
        return await ReadJsonAsync<T>(response.Content, MaximumControlResponseBytes, cancellationToken);
    }

    private async Task<HttpResponseMessage> SendStreamingAsync(
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body, options: JsonOptions);
        }
        var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        try
        {
            await RequireSuccessAsync(response, cancellationToken);
            return response;
        }
        catch
        {
            response.Dispose();
            throw;
        }
    }

    private static async Task RequireSuccessAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }
        var bytes = await ReadBoundedBytesAsync(response.Content, MaximumControlResponseBytes, cancellationToken);
        try
        {
            using var document = JsonDocument.Parse(bytes);
            var root = document.RootElement;
            var message = root.TryGetProperty("error", out var error) ? error.GetString() : null;
            var code = root.TryGetProperty("code", out var errorCode) ? errorCode.GetString() : null;
            throw new SmolVmApiException(
                response.StatusCode,
                code ?? "HTTP_ERROR",
                message ?? $"SmolVM returned HTTP {(int)response.StatusCode}.");
        }
        catch (JsonException)
        {
            throw new SmolVmApiException(
                response.StatusCode,
                "INVALID_ERROR_RESPONSE",
                $"SmolVM returned HTTP {(int)response.StatusCode} with an invalid error body.");
        }
    }

    private static async Task<T> ReadJsonAsync<T>(
        HttpContent content,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        var bytes = await ReadBoundedBytesAsync(content, maximumBytes, cancellationToken);
        return JsonSerializer.Deserialize<T>(bytes, JsonOptions) ??
            throw new InvalidOperationException("SmolVM returned an empty JSON value.");
    }

    private static async Task<byte[]> ReadBoundedBytesAsync(
        HttpContent content,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is > 0 && content.Headers.ContentLength > maximumBytes)
        {
            throw new InvalidOperationException("SmolVM response exceeded the configured size limit.");
        }
        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        using var output = new MemoryStream();
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                return output.ToArray();
            }
            if (output.Length + read > maximumBytes)
            {
                throw new InvalidOperationException("SmolVM response exceeded the configured size limit.");
            }
            output.Write(buffer, 0, read);
        }
    }

    private static string MachinePath(string name)
    {
        ValidateName(name);
        return $"/api/v1/machines/{Uri.EscapeDataString(name)}";
    }

    private static string FilePath(string name, string guestPath)
    {
        if (string.IsNullOrWhiteSpace(guestPath) || !guestPath.StartsWith("/", StringComparison.Ordinal))
        {
            throw new ArgumentException("Guest file paths must be absolute.", nameof(guestPath));
        }
        var segments = guestPath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Any(segment => segment is "." or ".."))
        {
            throw new ArgumentException("Guest file paths cannot contain traversal segments.", nameof(guestPath));
        }
        var encoded = string.Join('/', segments.Select(Uri.EscapeDataString));
        if (encoded.Length == 0)
        {
            throw new ArgumentException("A guest file path cannot name the filesystem root.", nameof(guestPath));
        }
        return $"{MachinePath(name)}/files/{encoded}";
    }

    private static void ValidateName(string name) => _ = new RuntimeAllocationId(name);

    public void Dispose() => httpClient.Dispose();
}
