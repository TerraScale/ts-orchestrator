using System.Net.Sockets;
using NATS.Client.Core;
using NATS.Net;

namespace TerraScale.Orchestrator.Development;

internal static class NatsDevelopmentCluster
{
    public static IReadOnlyList<DevelopmentResourcePlan> Start(
        DevelopmentProcessSupervisor supervisor,
        DevelopmentCellPlan cell,
        DevelopmentResourceKind kind,
        string dataDirectory,
        DevelopmentNatsCellSecurity security)
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
            var authorization = kind == DevelopmentResourceKind.ControlNats
                ? ControlAuthorization(cell, security)
                : ProductAuthorization(security);
            var planeTls = kind == DevelopmentResourceKind.ControlNats
                ? security.Tls.Control
                : security.Tls.Product;
            var tls = planeTls.Servers[resource.Name];
            File.WriteAllText(config, $$"""
                server_name: "{{resource.Name}}"
                host: "127.0.0.1"
                port: {{resource.Port}}
                {{authorization}}
                {{TlsConfiguration(tls.Client)}}
                jetstream {
                  domain: "{{domain}}"
                  store_dir: "{{Path.Combine(root, "store")}}"
                }
                cluster {
                  name: "{{clusterName}}"
                  host: "127.0.0.1"
                  port: {{resource.ClusterPort}}
                  {{TlsConfiguration(tls.Route)}}
                {{routeConfiguration}}
                }
                """);
            if (!OperatingSystem.IsLinux())
            {
                throw new PlatformNotSupportedException("The Orchestrator development runtime requires Linux.");
            }
            File.SetUnixFileMode(config, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            supervisor.Start(resource.Name, natsServer, ["--config", config], root);
        }
        return resources;
    }

    internal static string ControlAuthorization(
        DevelopmentCellPlan cell,
        DevelopmentNatsCellSecurity security)
    {
        if (security.Cell != cell.Cell || security.Controllers.Count != 3)
        {
            throw new InvalidOperationException("Control NATS security must match the exact regional R3 topology.");
        }
        var root = $"ts.orch.v1.{cell.Cell}.>";
        var controllerUsers = string.Join(
            Environment.NewLine,
            security.Controllers.OrderBy(pair => pair.Key).Select(pair => $$"""
                    { nkey: "{{pair.Value.PublicKey}}", permissions: {
                      publish: { allow: ["{{root}}", "$JS.>", "$KV.>", "$O.>", "$SRV.>", "_INBOX.>"] }
                      subscribe: { allow: ["{{root}}", "$JS.>", "$KV.>", "$O.>", "$SRV.>", "_INBOX.>"] }
                    } },
                """));
        return $$"""
                authorization {
                  users: [
                {{controllerUsers}}
                    { nkey: "{{security.Operator.PublicKey}}", permissions: {
                      publish: { allow: ["ts.orch.v1.{{cell.Cell}}.query.status"] }
                      subscribe: { allow: ["_INBOX.>"] }
                    } }
                  ]
                }
            """;
    }

    internal static string ProductAuthorization(DevelopmentNatsCellSecurity security) => $$"""
            authorization {
              users: [
                { user: "{{security.Product.Username}}", password: "{{security.Product.Password}}", permissions: {
                  publish: { allow: [">"] }
                  subscribe: { allow: [">"] }
                } }
              ]
            }
        """;

    internal static string TlsConfiguration(DevelopmentTlsIdentity identity) => $$"""
            tls {
              cert_file: "{{identity.CertificateFile}}"
              key_file: "{{identity.KeyFile}}"
              ca_file: "{{identity.CaFile}}"
              verify: true
              timeout: 3
            }
        """;

    internal static IReadOnlyList<string> CreateRoutes(
        IReadOnlyList<DevelopmentResourcePlan> resources,
        DevelopmentResourcePlan resource)
    {
        var ordered = resources.OrderBy(candidate => candidate.Replica).ToArray();
        var index = Array.FindIndex(ordered, candidate => candidate.Name == resource.Name);
        if (index < 0)
        {
            throw new ArgumentException("The NATS member is not part of the cluster.", nameof(resource));
        }
        var next = ordered[(index + 1) % ordered.Length];
        return [$"nats-route://127.0.0.1:{next.ClusterPort}"];
    }

    public static async Task WaitReadyAsync(
        IReadOnlyList<DevelopmentResourcePlan> resources,
        DevelopmentProcessSupervisor supervisor,
        DevelopmentNatsCellSecurity security,
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
                    await using var client = new NatsClient(ClientOptions(resource, security));
                    await client.ConnectAsync();
                    await client.PingAsync(timeout.Token);
                    break;
                }
                catch (Exception exception) when (
                    exception is NatsException or SocketException or IOException &&
                    !timeout.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(200), timeout.Token);
                }
            }
        }
    }

    internal static NatsOpts ClientOptions(
        DevelopmentResourcePlan resource,
        DevelopmentNatsCellSecurity security)
    {
        if (resource.Cell != security.Cell)
        {
            throw new InvalidOperationException("NATS probe credentials must match the resource cell.");
        }

        var options = new NatsOpts
        {
            Url = $"nats://127.0.0.1:{resource.Port}",
            RetryOnInitialConnect = false,
            RequestTimeout = TimeSpan.FromSeconds(3)
        };
        return resource.Kind switch
        {
            DevelopmentResourceKind.ControlNats => options with
            {
                AuthOpts = new NatsAuthOpts { NKeyFile = security.Operator.SeedFile },
                TlsOpts = DevelopmentHealthProbe.TlsOptions(
                    security.Tls.Control.Clients["operator-read"])
            },
            DevelopmentResourceKind.ProductNats => options with
            {
                AuthOpts = new NatsAuthOpts
                {
                    Username = security.Product.Username,
                    Password = security.Product.Password
                },
                TlsOpts = DevelopmentHealthProbe.TlsOptions(
                    security.Tls.Product.Clients[$"{security.Cell}-api"])
            },
            _ => throw new ArgumentOutOfRangeException(
                nameof(resource),
                resource.Kind,
                "Only NATS resources have NATS probe options.")
        };
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
