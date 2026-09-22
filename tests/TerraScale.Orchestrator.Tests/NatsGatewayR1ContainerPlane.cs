using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// The placement of one RF1 control server inside the fixture's private
/// rootless Podman networks: its container name — which is also its
/// DNS-resolvable gateway address — its host-published loopback client port,
/// and its fixed address on the internal gateway network.
/// </summary>
internal sealed record NatsGatewayR1Placement(
    string ServerName,
    string ContainerName,
    int ClientPort,
    string GatewayNetworkAddress);

/// <summary>
/// Runs the real, digest-pinned NATS image as one hardened rootless Podman
/// container per control server, attached to two private rootless Podman
/// bridge networks:
///
/// <list type="bullet">
/// <item>an <em>internal gateway network</em> with fixed addresses and
/// container-name DNS. It carries every gateway link: servers dial each
/// other's container names, which resolve — through this network's resolver
/// only — to the peers' gateway-network addresses.</item>
/// <item>a <em>client network</em> with DNS disabled and dynamic addresses.
/// It carries only the host-published loopback client ports.</item>
/// </list>
///
/// <see cref="SeverGatewayLinksAsync"/> removes one region's
/// gateway-network interface: every gateway link to and from that region
/// dies at the transport level (established connections drop with the
/// interface, new dials fail because the region's name disappears from the
/// gateway network's resolver) while the server process, its client
/// interface, and its local clients stay alive. Healing re-attaches the
/// same interface with the same fixed address, so the servers' own gateway
/// reconnect logic re-establishes every link without any restart, reload,
/// or new connection on the client side.
///
/// The container hardening mirrors <see cref="ContainerizedNatsCluster"/>
/// exactly — digest-pinned image, no-new-privileges, all capabilities
/// dropped, PID and memory limits, the private fixture root as the only
/// mount, the suite ownership label, and quarantined cleanup — but this
/// plane owns the per-server network fault controls that the shared-pod
/// conformance lane deliberately does not have.
/// </summary>
internal sealed class NatsGatewayR1ContainerPlane : IAsyncDisposable
{
    internal const string OwnershipLabel = "io.terrascale.owner=orchestrator-tests";

    /// <summary>Deterministic prefix of every container and network this plane family creates.</summary>
    internal const string NetworkNamePrefix = "ts-r1-";

    /// <summary>The per-container memory limit; three servers admit exactly 768 MiB.</summary>
    internal const int ServerMemoryLimitMiB = 256;

    // The gateway fixture subnet is far outside rootless Podman's default
    // 10.88/16 bridge range. The NATS fixture lease serializes runs, so one
    // stable gateway range is safe; a leaked network from a quarantined run
    // surfaces as a startup failure with a clear exit code instead of silent
    // cross-talk. The client network uses Podman's dynamic allocation because
    // it carries no fixed-address traffic.
    private const string GatewayNetworkSubnet = "10.213.62.0/24";

    private readonly string gatewayNetwork;
    private readonly string clientNetwork;
    private readonly Dictionary<string, NatsGatewayR1Placement> placements;
    private readonly Dictionary<string, Process> processes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> containers = new(StringComparer.Ordinal);
    private int disposed;

    private NatsGatewayR1ContainerPlane(
        string gatewayNetwork,
        string clientNetwork,
        Dictionary<string, NatsGatewayR1Placement> placements)
    {
        this.gatewayNetwork = gatewayNetwork;
        this.clientNetwork = clientNetwork;
        this.placements = placements;
    }

    /// <summary>
    /// The deterministic gateway-network addresses for the servers with the
    /// given ordinals (11, 12, 13 …).
    /// </summary>
    internal static string GatewayAddressFor(int ordinal) => $"10.213.62.{10 + ordinal}";

    public static async Task<NatsGatewayR1ContainerPlane> CreateAsync(
        IEnumerable<NatsGatewayR1Placement> placements,
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Containerized NATS tests require Linux.");

        var uniqueNames = placements
            .GroupBy(static placement => placement.ServerName, StringComparer.Ordinal)
            .ToArray();
        if (uniqueNames.Any(group => group.Count() > 1))
            throw new InvalidOperationException("Each RF1 control server needs exactly one container placement.");
        var byServer = uniqueNames.ToDictionary(
            static group => group.Key,
            static group => group.Single(),
            StringComparer.Ordinal);

        var suffix = Guid.NewGuid().ToString("N")[..12];
        var plane = new NatsGatewayR1ContainerPlane(
            $"ts-r1-gw-{suffix}",
            $"ts-r1-cl-{suffix}",
            byServer);
        try
        {
            // The gateway network is internal and serves container-name DNS:
            // it is the only resolver the servers see, so gateway dial URLs
            // (container names) always resolve onto this network.
            await CreateNetworkAsync(
                plane.gatewayNetwork,
                ["--internal", "--subnet", GatewayNetworkSubnet],
                cancellationToken);
            // The client network carries only the host-published client ports.
            // DNS stays off it so no server name can ever resolve onto the
            // client path, and its dynamic address keeps the rootless port
            // forwarder on a network that is never severed.
            await CreateNetworkAsync(
                plane.clientNetwork,
                ["--disable-dns"],
                cancellationToken);
            return plane;
        }
        catch
        {
            await plane.DisposeAsync();
            throw;
        }
    }

    /// <summary>
    /// Creates one fixture network, self-healing exactly once when a killed
    /// predecessor's leaked plane still holds the fixed subnet. Concurrent
    /// validation in this checkout is excluded by the repository lease, so an
    /// owned <c>ts-r1-</c> resource at create time is an orphan from a dead
    /// run, not a live peer; a genuinely live foreign holder fails loudly with
    /// the Podman diagnostic on the retried create.
    /// </summary>
    private static async Task CreateNetworkAsync(
        string network,
        IReadOnlyList<string> options,
        CancellationToken cancellationToken)
    {
        try
        {
            await RequireSuccessAsync(
                ["network", "create", "--label", OwnershipLabel, .. options, network],
                cancellationToken);
        }
        catch (InvalidOperationException)
        {
            await RemoveOrphanedPlaneResourcesAsync(cancellationToken);
            await RequireSuccessAsync(
                ["network", "create", "--label", OwnershipLabel, .. options, network],
                cancellationToken);
        }
    }

    private static async Task RemoveOrphanedPlaneResourcesAsync(CancellationToken cancellationToken)
    {
        // Containers first: a leaked server keeps its network attached, and
        // Podman refuses to remove a network an existing container still uses.
        // Match the deterministic fixture prefix even when a predecessor was
        // created before the ownership label was added.
        var containers = (await ListOwnedAsync(
            ["ps", "-a", "--format", "{{.Names}}"],
            cancellationToken))
            .Where(static name => name.StartsWith(NetworkNamePrefix, StringComparison.Ordinal))
            .ToArray();
        foreach (var container in containers)
        {
            await RunAsync(["rm", "--force", "--time", "2", container], cancellationToken);
        }
        var networks = (await ListOwnedAsync(
            ["network", "ls", "--format", "{{.Name}}"],
            cancellationToken))
            .Where(static name => name.StartsWith(NetworkNamePrefix, StringComparison.Ordinal))
            .ToArray();
        foreach (var network in networks)
        {
            await RunAsync(["network", "rm", "--force", network], cancellationToken);
        }
    }

    /// <summary>Starts one server's hardened container and returns its podman CLI process.</summary>
    public Process Start(NatsGatewayR1Placement placement, string configuration)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(placement);
        if (!placements.TryGetValue(placement.ServerName, out var expected) || expected != placement)
            throw new InvalidOperationException("The placement was not declared when the plane was created.");
        var fullConfiguration = Path.GetFullPath(configuration);
        if (!File.Exists(fullConfiguration))
            throw new InvalidOperationException("The NATS configuration must be an existing file inside the private fixture root.");

        var arguments = new List<string>
        {
            "run", "--rm",
            "--name", placement.ContainerName,
            "--label", OwnershipLabel,
            "--network", $"{gatewayNetwork}:ip={placement.GatewayNetworkAddress}",
            "--network", clientNetwork,
            "--publish", $"127.0.0.1:{placement.ClientPort}:{placement.ClientPort}/tcp",
            "--security-opt", "no-new-privileges",
            "--cap-drop", "all",
        };
        if (PodmanCgroupCapabilities.CgroupLimits)
        {
            arguments.Add("--pids-limit");
            arguments.Add("128");
            arguments.Add("--memory");
            arguments.Add($"{ServerMemoryLimitMiB}m");
        }
        else
        {
            arguments.Add("--cgroups=disabled");
        }
        arguments.AddRange([
            "--volume", $"{Path.GetDirectoryName(fullConfiguration)!}:{Path.GetDirectoryName(fullConfiguration)!}:rw",
            TestContainerImages.Nats,
            "--config", fullConfiguration,
        ]);
        var startInfo = new ProcessStartInfo("podman")
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        PodmanCgroupCapabilities.Configure(startInfo);
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("The containerized NATS server did not start.");
        processes[placement.ServerName] = process;
        containers[placement.ServerName] = placement.ContainerName;
        return process;
    }

    /// <summary>
    /// Severs every gateway link of one regional server by removing its
    /// gateway-network interface. The server process, its client interface,
    /// and its local clients are untouched.
    /// </summary>
    public async Task SeverGatewayLinksAsync(string serverName, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (!containers.TryGetValue(serverName, out var container))
            throw new InvalidOperationException($"The server '{serverName}' is not running.");
        // Netavark can remove the interface and then return 125 because its
        // resolver entry is already absent. Accept only that partial-success
        // diagnostic, and only after Podman reports the requested end state.
        var (exitCode, error) = await RunAsync(
            ["network", "disconnect", "--force", gatewayNetwork, container],
            cancellationToken);
        if (exitCode != 0
            && (!IsMissingAardvarkEntry(error)
                || await IsConnectedToNetworkAsync(container, gatewayNetwork, cancellationToken)))
        {
            throw PodmanFailure(exitCode, error);
        }
        // Give the removed interface's TCP fallout time to reach the servers'
        // gateway reconnect logic before the caller asserts link state.
        await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken);
    }

    /// <summary>
    /// Heals one regional server's gateway links by re-attaching its
    /// gateway-network interface with the same fixed address. The servers'
    /// own gateway reconnect logic re-establishes the links; nothing restarts.
    /// </summary>
    public async Task HealGatewayLinksAsync(string serverName, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (!placements.TryGetValue(serverName, out var placement))
            throw new InvalidOperationException($"The server '{serverName}' has no placement.");
        await RequireSuccessAsync(
            [
                "network", "connect",
                "--ip", placement.GatewayNetworkAddress,
                gatewayNetwork,
                placement.ContainerName,
            ],
            cancellationToken);
    }

    /// <summary>True while the given server's container is still tracked by this plane.</summary>
    public bool IsRunning(string serverName) =>
        processes.TryGetValue(serverName, out var process) && !process.HasExited;

    /// <summary>
    /// Peeks one server's host-published client port for its plaintext
    /// <c>INFO</c> preamble — the NATS protocol sends INFO before TLS — to
    /// prove the client path is forwarding before any client connects.
    /// </summary>
    public static async Task<bool> CanReachClientPortAsync(int port, CancellationToken cancellationToken = default)
    {
        try
        {
            using var client = new TcpClient();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            await client.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
            var buffer = new byte[4];
            using var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            readTimeout.CancelAfter(TimeSpan.FromSeconds(2));
            var stream = client.GetStream();
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), readTimeout.Token);
            return read >= 4 && buffer.AsSpan().SequenceEqual("INFO"u8);
        }
        catch (Exception exception) when (
            exception is SocketException or OperationCanceledException or IOException)
        {
            return false;
        }
    }

    public async Task StopAsync(string serverName, Process process, CancellationToken cancellationToken = default)
    {
        if (processes.Remove(serverName) && containers.Remove(serverName, out var container))
        {
            await RunAsync(["stop", "--time", "2", container], cancellationToken);
            await RunAsync(["rm", "--force", container], cancellationToken);
        }
        if (!process.HasExited)
            process.Kill(entireProcessTree: true);
        await process.WaitForExitAsync(cancellationToken).WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);
    }

    /// <summary>Names of every container this plane's fixture family owns right now; empty after clean cleanup.</summary>
    public async Task<IReadOnlyList<string>> ListOwnedContainersAsync(CancellationToken cancellationToken = default)
    {
        // The shared ownership label also matches long-lived infra containers
        // of other sessions on this host, so the proof is scoped to this
        // fixture family's deterministic name prefix.
        var names = await ListOwnedAsync(
            ["ps", "-a", "--filter", $"label={OwnershipLabel}", "--format", "{{.Names}}"],
            cancellationToken);
        return names.Where(static name => name.StartsWith(NetworkNamePrefix, StringComparison.Ordinal)).ToArray();
    }

    /// <summary>Names of every Podman network this plane's fixture family owns right now; empty after clean cleanup.</summary>
    public async Task<IReadOnlyList<string>> ListOwnedNetworksAsync(CancellationToken cancellationToken = default)
    {
        var names = await ListOwnedAsync(
            ["network", "ls", "--filter", $"label={OwnershipLabel}", "--format", "{{.Name}}"],
            cancellationToken);
        return names.Where(static name => name.StartsWith(NetworkNamePrefix, StringComparison.Ordinal)).ToArray();
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        foreach (var container in containers.Values.ToArray())
        {
            await RunAsync(["rm", "--force", "--time", "2", container], CancellationToken.None);
        }
        containers.Clear();
        processes.Clear();
        await RunAsync(["network", "rm", "--force", gatewayNetwork, clientNetwork], CancellationToken.None);
    }

    private static async Task<IReadOnlyList<string>> ListOwnedAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo("podman")
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        PodmanCgroupCapabilities.Configure(startInfo);
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);
        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Podman did not start.");
        var output = await process.StandardOutput.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        return output
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static async Task RequireSuccessAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        var (exitCode, error) = await RunAsync(arguments, cancellationToken);
        if (exitCode != 0)
            throw PodmanFailure(exitCode, error);
    }

    private static async Task<bool> IsConnectedToNetworkAsync(
        string container,
        string network,
        CancellationToken cancellationToken)
    {
        var networks = await ListOwnedAsync(
            [
                "inspect",
                "--format",
                "{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{\"\\n\"}}{{end}}",
                container,
            ],
            cancellationToken);
        return networks.Contains(network, StringComparer.Ordinal);
    }

    private static bool IsMissingAardvarkEntry(string error) =>
        error.Contains(
            "netavark: remove aardvark entries: IO error: No such file or directory",
            StringComparison.Ordinal);

    private static InvalidOperationException PodmanFailure(int exitCode, string error) =>
        new(
            $"Podman exited with code {exitCode} while preparing the RF1 gateway fixture network plane: {error.Trim()}");

    private static async Task<(int ExitCode, string Error)> RunAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo("podman")
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        PodmanCgroupCapabilities.Configure(startInfo);
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);
        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Podman did not start.");
        var output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var error = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        await Task.WhenAll(output, error);
        return (process.ExitCode, error.Result);
    }
}
