using System.Net.Sockets;
using NATS.Client.Core;
using NATS.Net;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Development;

internal sealed record DevelopmentResourceHealth(bool Healthy, string Detail);

internal static class DevelopmentHealthProbe
{
    private static readonly HttpClient HttpProbeClient = new() { Timeout = TimeSpan.FromSeconds(3) };

    public static async Task<IReadOnlyDictionary<string, DevelopmentResourceHealth>> ProbeAsync(
        DevelopmentTopology topology,
        DevelopmentProcessSupervisor supervisor,
        DevelopmentNatsSecurity natsSecurity,
        CancellationToken cancellationToken)
    {
        var resources = topology.Cells.SelectMany(cell => cell.Resources)
            .Concat(topology.GlobalResources)
            .ToArray();
        var results = await Task.WhenAll(resources.Select(resource =>
            ProbeOneAsync(topology, resource, supervisor, natsSecurity, cancellationToken)));
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
        DevelopmentTopology topology,
        DevelopmentResourcePlan resource,
        DevelopmentProcessSupervisor supervisor,
        DevelopmentNatsSecurity natsSecurity,
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
                    await ProbeControllerAsync(topology, resource, natsSecurity, cancellationToken);
                    return (resource.Name, new(true, $"Controller {process.Id} authority endpoint ready."));
                case DevelopmentResourceKind.ControlNats:
                case DevelopmentResourceKind.ProductNats:
                    await ProbeNatsAsync(resource, natsSecurity, cancellationToken);
                    return (resource.Name, new(true, $"Authenticated NATS endpoint {resource.Port} ready."));
                case DevelopmentResourceKind.TerraBase:
                    await ProbeHttpAsync(resource.Port, HealthPath(resource.Kind)!, cancellationToken);
                    await ProbeTcpAsync(resource.SecondaryPort!.Value, cancellationToken);
                    return (resource.Name, new(true, $"HTTP {resource.Port} and TCP {resource.SecondaryPort} ready."));
                default:
                    await ProbeHttpAsync(resource.Port, HealthPath(resource.Kind)!, cancellationToken);
                    return (resource.Name, new(true, $"HTTP {resource.Port} ready."));
            }
        }
        catch (Exception exception) when (
            exception is HttpRequestException or SocketException or TaskCanceledException or NatsException)
        {
            return (resource.Name, new(false, $"Health probe failed: {exception.Message}"));
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            return (resource.Name, new(false, $"Health probe timed out: {exception.Message}"));
        }
    }

    private static async Task ProbeHttpAsync(
        int port,
        string path,
        CancellationToken cancellationToken)
    {
        using var response = await HttpProbeClient.GetAsync($"http://127.0.0.1:{port}{path}", cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    private static async Task ProbeTcpAsync(int port, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", port, timeout.Token);
    }

    private static async Task ProbeControllerAsync(
        DevelopmentTopology topology,
        DevelopmentResourcePlan resource,
        DevelopmentNatsSecurity natsSecurity,
        CancellationToken cancellationToken)
    {
        var cell = topology.Cells.Single(candidate => candidate.Cell == resource.Cell);
        var controlNats = cell.OfKind(DevelopmentResourceKind.ControlNats)[0];
        var options = new NatsOpts
        {
            Url = $"nats://127.0.0.1:{controlNats.Port}",
            RetryOnInitialConnect = false,
            RequestTimeout = TimeSpan.FromSeconds(3)
        };
        options = options with
        {
            AuthOpts = new NatsAuthOpts
            {
                NKeyFile = natsSecurity.Cell(resource.Cell).Controllers[resource.Replica].SeedFile
            },
            TlsOpts = TlsOptions(
                natsSecurity.Cell(resource.Cell).Tls.Control.Clients[resource.Name])
        };
        await using var client = new NatsClient(options);
        await client.ConnectAsync();
        var response = await client.RequestAsync<string, string>(
            new NatsTopology(
                resource.Cell,
                1,
                resource.Replica.ToString(System.Globalization.CultureInfo.InvariantCulture))
                .InstanceHealthSubject,
            "health",
            cancellationToken: cancellationToken);
        if (response.Data != "ready")
        {
            throw new NatsException("The controller authority endpoint is not ready.");
        }
    }

    private static async Task ProbeNatsAsync(
        DevelopmentResourcePlan resource,
        DevelopmentNatsSecurity natsSecurity,
        CancellationToken cancellationToken)
    {
        await using var client = new NatsClient(NatsDevelopmentCluster.ClientOptions(
            resource,
            natsSecurity.Cell(resource.Cell)));
        await client.ConnectAsync();
        await client.PingAsync(cancellationToken);
    }

    internal static NatsTlsOpts TlsOptions(DevelopmentTlsIdentity identity) => new()
    {
        Mode = TlsMode.Require,
        CaFile = identity.CaFile,
        CertFile = identity.CertificateFile,
        KeyFile = identity.KeyFile
    };
}
