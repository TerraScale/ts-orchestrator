using System.Net.Sockets;

namespace TerraScale.Orchestrator.Development;

internal sealed record DevelopmentResourceHealth(bool Healthy, string Detail);

internal static class DevelopmentHealthProbe
{
    public static async Task<IReadOnlyDictionary<string, DevelopmentResourceHealth>> ProbeAsync(
        DevelopmentTopology topology,
        DevelopmentProcessSupervisor supervisor,
        CancellationToken cancellationToken)
    {
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        var resources = topology.Cells.SelectMany(cell => cell.Resources)
            .Concat(topology.GlobalResources)
            .ToArray();
        var results = await Task.WhenAll(resources.Select(resource =>
            ProbeOneAsync(resource, supervisor, client, cancellationToken)));
        return results.ToDictionary(result => result.Name, result => result.Health, StringComparer.Ordinal);
    }

    internal static string? HealthPath(DevelopmentResourceKind kind) => kind switch
    {
        DevelopmentResourceKind.TerraBase => "/build/version",
        DevelopmentResourceKind.Authentication or
        DevelopmentResourceKind.Api or
        DevelopmentResourceKind.EmailEmulator or
        DevelopmentResourceKind.StripeEmulator => "/health/ready",
        DevelopmentResourceKind.Dashboard => "/api/stack",
        _ => null
    };

    private static async Task<(string Name, DevelopmentResourceHealth Health)> ProbeOneAsync(
        DevelopmentResourcePlan resource,
        DevelopmentProcessSupervisor supervisor,
        HttpClient client,
        CancellationToken cancellationToken)
    {
        if (!supervisor.Processes.TryGetValue(resource.Name, out var process))
        {
            return (resource.Name, new(false, "Process has not started."));
        }
        if (process.HasExited)
        {
            return (resource.Name, new(false, $"Exited with code {process.ExitCode}."));
        }

        try
        {
            switch (resource.Kind)
            {
                case DevelopmentResourceKind.ControllerAgent:
                    return (resource.Name, new(true, $"Process {process.Id} ready."));
                case DevelopmentResourceKind.ControlNats:
                case DevelopmentResourceKind.ProductNats:
                    await ProbeTcpAsync(resource.Port, cancellationToken);
                    return (resource.Name, new(true, $"NATS endpoint {resource.Port} ready."));
                case DevelopmentResourceKind.TerraBase:
                    await ProbeHttpAsync(client, resource.Port, HealthPath(resource.Kind)!, cancellationToken);
                    await ProbeTcpAsync(resource.SecondaryPort!.Value, cancellationToken);
                    return (resource.Name, new(true, $"HTTP {resource.Port} and TCP {resource.SecondaryPort} ready."));
                default:
                    await ProbeHttpAsync(client, resource.Port, HealthPath(resource.Kind)!, cancellationToken);
                    return (resource.Name, new(true, $"HTTP {resource.Port} ready."));
            }
        }
        catch (Exception exception) when (exception is HttpRequestException or SocketException or TaskCanceledException)
        {
            return (resource.Name, new(false, $"Health probe failed: {exception.Message}"));
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            return (resource.Name, new(false, $"Health probe timed out: {exception.Message}"));
        }
    }

    private static async Task ProbeHttpAsync(
        HttpClient client,
        int port,
        string path,
        CancellationToken cancellationToken)
    {
        using var response = await client.GetAsync($"http://127.0.0.1:{port}{path}", cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    private static async Task ProbeTcpAsync(int port, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", port, timeout.Token);
    }
}
