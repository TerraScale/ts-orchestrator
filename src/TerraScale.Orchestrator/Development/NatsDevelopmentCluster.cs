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
        if (resources.Count != 1)
        {
            throw new InvalidOperationException($"{cell.Cell} {kind} must have exactly one development replica.");
        }

        var clusterName = kind == DevelopmentResourceKind.ControlNats
            ? $"orchestrator-{cell.Cell}"
            : $"product-{cell.Cell}";
        var domain = kind == DevelopmentResourceKind.ControlNats
            ? $"ORCH_{cell.Cell.ToUpperInvariant()}"
            : $"PRODUCT_{cell.Cell.ToUpperInvariant()}";
        foreach (var resource in resources)
        {
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
            var clusterConfiguration = ClusterConfiguration(
                resources,
                resource,
                clusterName,
                tls.Route);
            File.WriteAllText(config, $$"""
                server_name: "{{resource.Name}}"
                host: "0.0.0.0"
                port: {{resource.Port}}
                {{authorization}}
                {{TlsConfiguration(tls.Client)}}
                jetstream {
                  domain: "{{domain}}"
                  store_dir: "{{Path.Combine(root, "store")}}"
                }
                {{clusterConfiguration}}
                """);
            if (!OperatingSystem.IsLinux())
            {
                throw new PlatformNotSupportedException("The Orchestrator development runtime requires Linux.");
            }
            File.SetUnixFileMode(config, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            supervisor.Start(
                resource.Name,
                DevelopmentContainerImages.Nats,
                ["--config", config],
                root);
        }
        return resources;
    }

    internal static string ControlAuthorization(
        DevelopmentCellPlan cell,
        DevelopmentNatsCellSecurity security)
    {
        if (security.Cell != cell.Cell || security.Controllers.Count == 0)
        {
            throw new InvalidOperationException("Control NATS security must match the exact lean regional topology.");
        }
        var root = $"ts.orch.v1.{cell.Cell}";
        var controllerSubjects = new[]
        {
            $"{root}.desired.>", $"{root}.event.>", $"{root}.operation.>", $"{root}.query.>",
            $"{root}.internal.operation-journal.create", $"{root}.internal.operation-journal.update"
        };
        var controllerJetStreamSubjects = new[]
        {
            "CELL_SPEC", "CELL_OPERATIONS", "CELL_EVENTS", "KV_ORCH_LEADERS", "KV_ORCH_RUNTIME",
            "KV_ORCH_DELIVERY", "OBJ_CELL_BUNDLES"
        }.Select(stream => $"$JS.API.STREAM.INFO.{stream}").Concat(new[]
        {
            "$JS.API.CONSUMER.CREATE.CELL_EVENTS.runtime_startup.>", "$JS.API.CONSUMER.DURABLE.CREATE.CELL_EVENTS.runtime_startup.>", "$JS.API.CONSUMER.INFO.CELL_EVENTS.runtime_startup", "$JS.API.CONSUMER.MSG.NEXT.CELL_EVENTS.runtime_startup",
            "$JS.ACK.CELL_EVENTS.runtime_startup.>", "$JS.FC.CELL_EVENTS.runtime_startup.>", "$JS.API.STREAM.MSG.GET.OBJ_CELL_BUNDLES",
            "$JS.API.CONSUMER.CREATE.OBJ_CELL_BUNDLES.>", "$JS.FC.OBJ_CELL_BUNDLES.>",
            "$JS.API.CONSUMER.DELETE.OBJ_CELL_BUNDLES.>", "$JS.FC.KV_ORCH_RUNTIME.>",
            "$JS.API.DIRECT.GET.KV_ORCH_LEADERS", "$JS.API.CONSUMER.CREATE.KV_ORCH_RUNTIME.>"
        }).ToArray();
        var journalJetStreamDenials = string.Join(", ", new[]
        {
            "$JS.API.DIRECT.GET.KV_ORCH_OPERATIONS",
            "$JS.API.STREAM.MSG.GET.KV_ORCH_OPERATIONS",
            "$JS.API.STREAM.INFO.KV_ORCH_OPERATIONS",
            "$JS.API.STREAM.SNAPSHOT.KV_ORCH_OPERATIONS",
            "$JS.API.STREAM.RESTORE.KV_ORCH_OPERATIONS",
            "$JS.SNAPSHOT.RESTORE.KV_ORCH_OPERATIONS.>",
            "$JS.SNAPSHOT.ACK.KV_ORCH_OPERATIONS.>",
            "$JS.API.DIRECT.GET.KV_ORCH_OPERATION_PROOFS",
            "$JS.API.STREAM.MSG.GET.KV_ORCH_OPERATION_PROOFS",
            "$JS.API.STREAM.INFO.KV_ORCH_OPERATION_PROOFS",
            "$JS.API.STREAM.SNAPSHOT.KV_ORCH_OPERATION_PROOFS",
            "$JS.API.STREAM.RESTORE.KV_ORCH_OPERATION_PROOFS",
            "$JS.SNAPSHOT.RESTORE.KV_ORCH_OPERATION_PROOFS.>",
            "$JS.SNAPSHOT.ACK.KV_ORCH_OPERATION_PROOFS.>",
            "$JS.API.CONSUMER.CREATE.KV_ORCH_OPERATIONS",
            "$JS.API.CONSUMER.CREATE.KV_ORCH_OPERATIONS.>",
            "$JS.API.CONSUMER.DURABLE.CREATE.KV_ORCH_OPERATIONS.>",
            "$JS.API.CONSUMER.INFO.KV_ORCH_OPERATIONS.>",
            "$JS.API.CONSUMER.LIST.KV_ORCH_OPERATIONS",
            "$JS.API.CONSUMER.NAMES.KV_ORCH_OPERATIONS",
            "$JS.API.CONSUMER.DELETE.KV_ORCH_OPERATIONS.>",
            "$JS.API.CONSUMER.MSG.NEXT.KV_ORCH_OPERATIONS.>",
            "$JS.ACK.KV_ORCH_OPERATIONS.>",
            "$JS.FC.KV_ORCH_OPERATIONS.>",
            "$JS.API.CONSUMER.CREATE.KV_ORCH_OPERATION_PROOFS",
            "$JS.API.CONSUMER.CREATE.KV_ORCH_OPERATION_PROOFS.>",
            "$JS.API.CONSUMER.DURABLE.CREATE.KV_ORCH_OPERATION_PROOFS.>",
            "$JS.API.CONSUMER.INFO.KV_ORCH_OPERATION_PROOFS.>",
            "$JS.API.CONSUMER.LIST.KV_ORCH_OPERATION_PROOFS",
            "$JS.API.CONSUMER.NAMES.KV_ORCH_OPERATION_PROOFS",
            "$JS.API.CONSUMER.DELETE.KV_ORCH_OPERATION_PROOFS.>",
            "$JS.API.CONSUMER.MSG.NEXT.KV_ORCH_OPERATION_PROOFS.>",
            "$JS.ACK.KV_ORCH_OPERATION_PROOFS.>",
            "$JS.FC.KV_ORCH_OPERATION_PROOFS.>",
        }.Select(subject => $"\"{subject}\""));
        var controllerUsers = string.Join(
            Environment.NewLine,
            security.Controllers.OrderBy(pair => pair.Key).Select(pair => $$"""
                    { nkey: "{{pair.Value.PublicKey}}", permissions: {
                      publish: { allow: [{{string.Join(", ", controllerSubjects.Select(subject => $"\"{subject}\""))}}, "{{root}}.internal.reply.{{pair.Value.PublicKey}}.>", {{string.Join(", ", controllerJetStreamSubjects.Select(subject => $"\"{subject}\""))}}, "$KV.ORCH_LEADERS.>", "$KV.ORCH_RUNTIME.>", "$KV.ORCH_DELIVERY.>", "$O.CELL_BUNDLES.C.>", "$O.CELL_BUNDLES.M.>", "$SRV.>"], deny: ["$KV.ORCH_OPERATIONS.>", "$KV.ORCH_OPERATION_PROOFS.>", "$JS.API.STREAM.CREATE.>", "$JS.API.STREAM.UPDATE.>", {{journalJetStreamDenials}}] }
                      subscribe: { allow: ["{{root}}.desired.>", "{{root}}.event.>", "{{root}}.operation.>", "{{root}}.query.>", "{{root}}.internal.reply.{{pair.Value.PublicKey}}.>", "{{root}}.internal.operation-journal.reply.{{pair.Value.PublicKey}}.>", {{string.Join(", ", controllerJetStreamSubjects.Select(subject => $"\"{subject}\""))}}, "$KV.ORCH_LEADERS.>", "$KV.ORCH_RUNTIME.>", "$KV.ORCH_DELIVERY.>", "$O.CELL_BUNDLES.C.>", "$O.CELL_BUNDLES.M.>", "$SRV.>"], deny: [{{journalJetStreamDenials}}] }
                    } },
                """));
        return $$"""
                authorization {
                  users: [
                {{controllerUsers}}
                    { nkey: "{{security.JournalWriter.PublicKey}}", permissions: {
                      publish: { allow: ["$KV.ORCH_OPERATIONS.>", "$KV.ORCH_OPERATION_PROOFS.>", "{{root}}.internal.operation-journal.reply.>", "$JS.API.STREAM.INFO.KV_ORCH_OPERATIONS", "$JS.API.STREAM.INFO.KV_ORCH_OPERATION_PROOFS", "$JS.API.DIRECT.GET.KV_ORCH_OPERATIONS", "$JS.API.STREAM.MSG.GET.KV_ORCH_OPERATIONS", "$SRV.>", "_INBOX.>"] }
                      subscribe: { allow: ["$KV.ORCH_OPERATIONS.>", "$KV.ORCH_OPERATION_PROOFS.>", "{{root}}.internal.operation-journal.create", "{{root}}.internal.operation-journal.update", "$SRV.>", "_INBOX.>"] }
                    } },
                    { nkey: "{{security.Infrastructure.PublicKey}}", permissions: {
                      publish: { allow: ["$JS.API.STREAM.CREATE.CELL_SPEC", "$JS.API.STREAM.UPDATE.CELL_SPEC", "$JS.API.STREAM.INFO.CELL_SPEC", "$JS.API.STREAM.CREATE.CELL_OPERATIONS", "$JS.API.STREAM.UPDATE.CELL_OPERATIONS", "$JS.API.STREAM.INFO.CELL_OPERATIONS", "$JS.API.STREAM.CREATE.CELL_EVENTS", "$JS.API.STREAM.UPDATE.CELL_EVENTS", "$JS.API.STREAM.INFO.CELL_EVENTS", "$JS.API.STREAM.CREATE.KV_ORCH_LEADERS", "$JS.API.STREAM.UPDATE.KV_ORCH_LEADERS", "$JS.API.STREAM.INFO.KV_ORCH_LEADERS", "$JS.API.STREAM.CREATE.KV_ORCH_RUNTIME", "$JS.API.STREAM.UPDATE.KV_ORCH_RUNTIME", "$JS.API.STREAM.INFO.KV_ORCH_RUNTIME", "$JS.API.STREAM.CREATE.KV_ORCH_DELIVERY", "$JS.API.STREAM.UPDATE.KV_ORCH_DELIVERY", "$JS.API.STREAM.INFO.KV_ORCH_DELIVERY", "$JS.API.STREAM.CREATE.OBJ_CELL_BUNDLES", "$JS.API.STREAM.UPDATE.OBJ_CELL_BUNDLES", "$JS.API.STREAM.INFO.OBJ_CELL_BUNDLES", "$JS.API.STREAM.CREATE.KV_ORCH_OPERATIONS", "$JS.API.STREAM.UPDATE.KV_ORCH_OPERATIONS", "$JS.API.STREAM.INFO.KV_ORCH_OPERATIONS", "$JS.API.STREAM.CREATE.KV_ORCH_OPERATION_PROOFS", "$JS.API.STREAM.UPDATE.KV_ORCH_OPERATION_PROOFS", "$JS.API.STREAM.INFO.KV_ORCH_OPERATION_PROOFS"] }
                      subscribe: { allow: ["_INBOX.>"] }
                    } },
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

    internal static string ClusterConfiguration(
        IReadOnlyList<DevelopmentResourcePlan> resources,
        DevelopmentResourcePlan resource,
        string clusterName,
        DevelopmentTlsIdentity routeTls)
    {
        if (resources.Count == 1)
        {
            return string.Empty;
        }
        var routes = CreateRoutes(resources, resource);
        return $$"""
                cluster {
                  name: "{{clusterName}}"
                  host: "127.0.0.1"
                  port: {{resource.ClusterPort}}
                  {{TlsConfiguration(routeTls)}}
                  routes: [{{string.Join(", ", routes.Select(route => $"\"{route}\""))}}]
                }
            """;
    }

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
        if (ordered.Length == 1)
        {
            return [];
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
            // Readiness probes use operator-read (control) or platform (product). An
            // invalid on-disk leaf cannot become ready by retrying ConnectAsync; each
            // attempt would only spam NATS with CN=operator-read / CN=*-platform
            // certificate-expired handshake errors (the continuous-lab incident shape).
            var probeTls = resource.Kind is DevelopmentResourceKind.ControlNats
                ? security.Tls.Control.Clients["operator-read"]
                : security.Tls.Product.Clients[$"{security.Cell}-platform"];
            var leafStatus = DevelopmentHealthProbe.DescribeLeafValidity(probeTls.CertificateFile);
            if (leafStatus is not null)
            {
                throw new InvalidOperationException(
                    $"NATS readiness for {resource.Name} cannot proceed: {leafStatus}");
            }

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
                    security.Tls.Product.Clients[$"{security.Cell}-platform"])
            },
            _ => throw new ArgumentOutOfRangeException(
                nameof(resource),
                resource.Kind,
                "Only NATS resources have NATS probe options.")
        };
    }

}
