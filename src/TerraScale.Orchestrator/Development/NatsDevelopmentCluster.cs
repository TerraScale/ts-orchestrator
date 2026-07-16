using System.Net.Sockets;

namespace TerraScale.Orchestrator.Development;

internal static class NatsDevelopmentCluster
{
    public static IReadOnlyList<DevelopmentResourcePlan> Start(
        DevelopmentProcessSupervisor supervisor,
        DevelopmentCellPlan cell,
        DevelopmentResourceKind kind,
        string dataDirectory)
    {
        if (kind is not DevelopmentResourceKind.ControlNats and not DevelopmentResourceKind.ProductNats)
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        var resources = cell.OfKind(kind);
        if (resources.Count != 3)
        {
            throw new InvalidOperationException($"{cell.Cell} {kind} must have exactly three replicas.");
        }

        var clusterName = kind == DevelopmentResourceKind.ControlNats
            ? $"orchestrator-{cell.Cell}"
            : $"product-{cell.Cell}";
        var domain = kind == DevelopmentResourceKind.ControlNats
            ? $"ORCH_{cell.Cell.ToUpperInvariant()}"
            : $"PRODUCT_{cell.Cell.ToUpperInvariant()}";
        var natsServer = ResolveNatsServer();
        foreach (var resource in resources)
        {
            var routes = CreateRoutes(resources, resource);
            var routeConfiguration = routes.Count == 0
                ? string.Empty
                : $"  routes: [{string.Join(", ", routes.Select(route => $"\"{route}\""))}]";
            var root = Path.Combine(dataDirectory, resource.Name);
            Directory.CreateDirectory(root);
            var config = Path.Combine(root, "nats.conf");
            File.WriteAllText(config, $$"""
                server_name: "{{resource.Name}}"
                host: "127.0.0.1"
                port: {{resource.Port}}
                jetstream {
                  domain: "{{domain}}"
                  store_dir: "{{Path.Combine(root, "store")}}"
                }
                cluster {
                  name: "{{clusterName}}"
                  host: "127.0.0.1"
                  port: {{resource.ClusterPort}}
                {{routeConfiguration}}
                }
                """);
            supervisor.Start(resource.Name, natsServer, ["--config", config], root);
        }
        return resources;
    }

    internal static IReadOnlyList<string> CreateRoutes(
        IReadOnlyList<DevelopmentResourcePlan> resources,
        DevelopmentResourcePlan resource)
    {
        var seed = resources.OrderBy(candidate => candidate.Replica).First();
        return resource.Name == seed.Name
            ? []
            : [$"nats-route://127.0.0.1:{seed.ClusterPort}"];
    }

    public static async Task WaitReadyAsync(
        IReadOnlyList<DevelopmentResourcePlan> resources,
        DevelopmentProcessSupervisor supervisor,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(2));
        foreach (var resource in resources)
        {
            while (true)
            {
                supervisor.ThrowIfAnyExited();
                try
                {
                    using var client = new TcpClient();
                    await client.ConnectAsync("127.0.0.1", resource.Port, timeout.Token);
                    break;
                }
                catch (SocketException) when (!timeout.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(200), timeout.Token);
                }
            }
        }
    }

    private static string ResolveNatsServer()
    {
        var configured = Environment.GetEnvironmentVariable("TERRASCALE_NATS_SERVER");
        if (!string.IsNullOrWhiteSpace(configured) && File.Exists(configured))
        {
            return configured;
        }
        var local = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".local",
            "bin",
            "nats-server");
        return File.Exists(local) ? local : "nats-server";
    }
}
