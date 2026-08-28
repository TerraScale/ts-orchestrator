using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NATS.Client.Core;
using NATS.Net;
using TerraScale.Orchestrator.Messaging;
using Cysharp.Text;

namespace TerraScale.Orchestrator.Development;

internal sealed record DevelopmentResourceHealth(bool Healthy, string Detail, bool ReadinessPending = false);

/// <summary>
/// Thrown when a readiness endpoint answered over HTTP with a server error: the
/// process is alive and serving requests, but its aggregated checks (Authentication
/// InternalRpc peer, regional queue evidence, TerraBase placement) report not-ready
/// right now. Distinct from transport failures so the health loop can wait out
/// transient dependency blips instead of restarting a process that is recovering.
/// </summary>
internal sealed class DevelopmentReadinessPendingException(string message) : Exception(message);

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
            .ToArray();
        var results = await Task.WhenAll(resources.Select(resource =>
            ProbeOneAsync(topology, resource, supervisor, natsSecurity, cancellationToken)));
        return results.ToDictionary(result => result.Name, result => result.Health, StringComparer.Ordinal);
    }

    internal static string HealthPath(DevelopmentResourceKind kind) => kind switch
    {
        DevelopmentResourceKind.TerraBase => "/build/version",
        DevelopmentResourceKind.Authentication or
        DevelopmentResourceKind.Platform => "/health/ready",
        DevelopmentResourceKind.Dashboard => "/health/ready",
        _ => throw new ArgumentOutOfRangeException(
            nameof(kind), kind, "The resource kind does not expose an HTTP health path.")
    };

    /// <summary>
    /// Formats a probe failure so certificate-recovery matching can see OpenSSL/x509 text that
    /// NATS.Net often nests under a generic outer <see cref="NatsException"/> message.
    /// </summary>
    internal static string FormatProbeFailure(Exception exception, DevelopmentTlsIdentity? tlsIdentity = null)
    {
        using var builder = ZString.CreateStringBuilder();
        builder.Append("Health probe failed: ");
        builder.Append(exception.Message);
        for (var inner = exception.InnerException; inner is not null; inner = inner.InnerException)
        {
            builder.Append(" | ");
            builder.Append(inner.Message);
        }

        if (tlsIdentity is not null)
        {
            var leafStatus = DescribeLeafValidity(tlsIdentity.CertificateFile);
            if (leafStatus is not null)
            {
                builder.Append(" | ");
                builder.Append(leafStatus);
            }
        }

        return builder.ToString();
    }

    internal static string? DescribeLeafValidity(string certificateFile)
    {
        try
        {
            if (!File.Exists(certificateFile))
            {
                return "failed to verify certificate: leaf PEM is missing";
            }

            using var certificate = X509Certificate2.CreateFromPem(File.ReadAllText(certificateFile));
            var notAfter = certificate.NotAfter.ToUniversalTime();
            var now = DateTime.UtcNow;
            if (now > notAfter)
            {
                // Match DevelopmentLab.LooksLikeCertificateFailure recovery triggers.
                return $"certificate has expired: current time {now:O} is after {notAfter:O}";
            }

            if (now < certificate.NotBefore.ToUniversalTime())
            {
                return $"certificate is not yet valid: current time {now:O} is before {certificate.NotBefore.ToUniversalTime():O}";
            }

            return null;
        }
        catch (Exception exception) when (
            exception is CryptographicException or ArgumentException or IOException)
        {
            return $"failed to verify certificate: leaf PEM is unreadable ({exception.Message})";
        }
    }

    /// <summary>
    /// Returns an unhealthy probe result when the on-disk leaf must not be presented to
    /// NATS (expired, not yet valid, missing, or unreadable). Callers use this before
    /// <c>ConnectAsync</c> so control-plane health cycles cannot emit server-side
    /// <c>TLS handshake error … CN=operator-read</c> lines while force-remint recovers.
    /// </summary>
    internal static DevelopmentResourceHealth? TryInvalidLeafProbeFailure(DevelopmentTlsIdentity identity)
    {
        var leafStatus = DescribeLeafValidity(identity.CertificateFile);
        if (leafStatus is null)
        {
            return null;
        }

        // Prefix matches FormatProbeFailure so LooksLikeCertificateFailure and log
        // scrapers see the same shape as a post-connect probe failure.
        return new DevelopmentResourceHealth(false, $"Health probe failed: {leafStatus}");
    }

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

        DevelopmentTlsIdentity? probeTls = null;
        try
        {
            switch (resource.Kind)
            {
                case DevelopmentResourceKind.ControllerAgent:
                    probeTls = natsSecurity.Cell(resource.Cell).Tls.Control.Clients[resource.Name];
                    // Refuse expired/missing controller leaves before ConnectAsync so NATS
                    // never logs CN=*-controller-1 handshake failures from the probe path.
                    if (TryInvalidLeafProbeFailure(probeTls) is { } controllerLeafFailure)
                    {
                        return (resource.Name, controllerLeafFailure);
                    }
                    await ProbeControllerAsync(topology, resource, natsSecurity, cancellationToken);
                    return (resource.Name, new(true, $"Controller {process.Id} authority endpoint ready."));
                case DevelopmentResourceKind.ControlNats:
                case DevelopmentResourceKind.ProductNats:
                    probeTls = resource.Kind is DevelopmentResourceKind.ControlNats
                        ? natsSecurity.Cell(resource.Cell).Tls.Control.Clients["operator-read"]
                        : natsSecurity.Cell(resource.Cell).Tls.Product.Clients[
                            ProductClientName(topology, resource.Cell)];
                    // operator-read (control) and Dashboard (product) probes are the only
                    // in-process mTLS clients that present leaves every health cycle. When a
                    // leaf is already past NotAfter, ConnectAsync produces the exact NATS
                    // server log "TLS handshake error … CN=operator-read" that DevHost scrapes.
                    // Fail the probe from on-disk validity instead so recovery can remint
                    // without generating that server-side line.
                    if (TryInvalidLeafProbeFailure(probeTls) is { } natsLeafFailure)
                    {
                        return (resource.Name, natsLeafFailure);
                    }
                    await ProbeNatsAsync(resource, natsSecurity, cancellationToken);
                    return (resource.Name, new(true, $"Authenticated NATS endpoint {resource.Port} ready."));
                case DevelopmentResourceKind.Platform:
                    // Platform HTTP readiness stays green while the product-NATS mTLS leaf is
                    // expired. The platform process keeps reconnecting and is the source of
                    // product-plane server logs "TLS handshake error … CN=*-platform" (for
                    // example gru-product-nats / CN=gru-platform). Surface the invalid leaf
                    // here so force-remint runs even when HTTP /health/ready still passes.
                    probeTls = natsSecurity.Cell(resource.Cell).Tls.Product.Clients[resource.Name];
                    if (TryInvalidLeafProbeFailure(probeTls) is { } platformLeafFailure)
                    {
                        return (resource.Name, platformLeafFailure);
                    }
                    await ProbeHttpAsync(resource.Port, HealthPath(resource.Kind), cancellationToken);
                    return (resource.Name, new(true, $"HTTP {resource.Port} ready."));
                case DevelopmentResourceKind.Dashboard:
                    // The full-stack Vinext Dashboard owns the public API and UI
                    // in one process. It is also the sole product-NATS client in
                    // the regional development graph.
                    probeTls = natsSecurity.Cell(resource.Cell).Tls.Product.Clients[
                        ProductClientName(topology, resource.Cell)];
                    if (TryInvalidLeafProbeFailure(probeTls) is { } dashboardLeafFailure)
                    {
                        return (resource.Name, dashboardLeafFailure);
                    }
                    await ProbeHttpAsync(resource.Port, HealthPath(resource.Kind), cancellationToken);
                    return (resource.Name, new(true, $"HTTP {resource.Port} ready."));
                case DevelopmentResourceKind.TerraBase:
                    await ProbeHttpAsync(resource.Port, HealthPath(resource.Kind), cancellationToken);
                    await ProbeHttpAsync(resource.Port, "/studio/index.html", cancellationToken);
                    await ProbeTcpAsync(
                        DevelopmentGuards.RequireSecondaryPort(resource),
                        cancellationToken);
                    return (resource.Name, new(
                        true,
                        $"HTTP {resource.Port}, Studio, and TCP {resource.SecondaryPort} ready."));
                default:
                    await ProbeHttpAsync(resource.Port, HealthPath(resource.Kind), cancellationToken);
                    return (resource.Name, new(true, $"HTTP {resource.Port} ready."));
            }
        }
        catch (DevelopmentReadinessPendingException exception)
        {
            return (resource.Name, new(
                false,
                FormatProbeFailure(exception),
                ReadinessPending: true));
        }
        catch (Exception exception) when (
            exception is HttpRequestException
                or SocketException
                or TaskCanceledException
                or NatsException
                or AuthenticationException
                or IOException
                // NATS.Net throws raw TimeoutException from its INFO and initial-pong
                // waits; without this arm a load spike past the connect bound escapes
                // the probe boundary and kills the un-guarded 5-second health loop.
                or TimeoutException)
        {
            // Outer NATS messages are often "can not start to connect"; x509 text lives on inners.
            return (resource.Name, new(false, FormatProbeFailure(exception, probeTls)));
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
        if (response.IsSuccessStatusCode)
        {
            return;
        }
        if (IsReadinessPendingResponse(path, response.StatusCode))
        {
            var reason = string.IsNullOrWhiteSpace(response.ReasonPhrase)
                ? response.StatusCode.ToString()
                : response.ReasonPhrase;
            throw new DevelopmentReadinessPendingException(
                $"HTTP {(int)response.StatusCode} ({reason}) from {path}");
        }
        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// A 5xx answer from a readiness endpoint means the process is alive and serving
    /// HTTP while a dependency converges — the same pending contract the startup
    /// wait loops already tolerate. TerraBase probe paths and 4xx answers stay hard
    /// failures: RestartAsync remains the remedy for those.
    /// </summary>
    internal static bool IsReadinessPendingResponse(string path, HttpStatusCode statusCode) =>
        (path == HealthPath(DevelopmentResourceKind.Platform) ||
         path == HealthPath(DevelopmentResourceKind.Dashboard)) && (int)statusCode >= 500;

    private static string ProductClientName(DevelopmentTopology topology, string cell)
    {
        var plan = topology.Cells.Single(candidate => candidate.Cell == cell);
        return DevelopmentWorkloadRuntime.ProductWorkloadClientName(plan);
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
            ConnectTimeout = NatsDevelopmentCluster.ClientConnectTimeout,
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
            ControllerInstanceHealthSubject(resource.Cell, resource.Replica),
            "health",
            cancellationToken: cancellationToken);
        if (response.Data != "ready")
        {
            throw new NatsException("The controller authority endpoint is not ready.");
        }
    }

    internal static string ControllerInstanceHealthSubject(string cell, int replica) =>
        new NatsTopology(cell, 1, DevelopmentLab.ControllerInstance(replica)).InstanceHealthSubject;

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
