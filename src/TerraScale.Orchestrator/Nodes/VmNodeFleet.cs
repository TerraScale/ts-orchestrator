using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using TerraScale.Orchestrator.Scheduler;
using TerraScale.Orchestrator.Scheduler.Autoscaling;

namespace TerraScale.Orchestrator.Nodes;

/// <summary>
/// The Firecracker lane's node fleet: every node is one microVM running a real
/// TerraBase member launched by an injected systemd unit from environment
/// configuration. Guests boot the pinned kernel and the prepared Ubuntu
/// minimal rootfs; the member payload (self-contained TerraBase.Host plus
/// cluster certificates) rides a shared read-only payload disk, the per-node
/// environment file is injected into the node's rootfs copy, and the host
/// observes members over the mTLS peer listener. This is local qualification
/// infrastructure — the test stand-in for OCI hosts, never a production
/// provider.
/// </summary>
public sealed class VmNodeFleet : INodeFleet, IAsyncDisposable
{
    private readonly VmFleetOptions options;
    private readonly Func<NodeProvisionRequest, VmMemberDescription> memberFactory;
    private readonly Dictionary<string, VmNode> nodes = new(StringComparer.Ordinal);
    private readonly Lock gate = new();
    private int provisionedCount;

    public VmNodeFleet(VmFleetOptions options, Func<NodeProvisionRequest, VmMemberDescription> memberFactory)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        this.memberFactory = memberFactory ?? throw new ArgumentNullException(nameof(memberFactory));
        options.Validate();
    }

    /// <inheritdoc />
    public async Task ProvisionAsync(NodeProvisionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var description = memberFactory(request);
        var address = options.AddressFor(++provisionedCount);
        var workingDirectory = Path.Combine(options.RootDirectory, request.NodeId);
        Directory.CreateDirectory(workingDirectory);

        await BuildRootfsAsync(workingDirectory, request.NodeId, address, description);
        var node = await VmNode.StartAsync(options, workingDirectory, request.NodeId, address, description);
        lock (gate)
        {
            nodes[request.NodeId] = node;
        }
    }

    /// <summary>
    /// Restarts one killed node's member on its retained rootfs: the VM power
    /// loss may have torn the member's write-ahead log, and a healthy restart
    /// is the end-to-end proof that recovery truncates to the last committed
    /// frame instead of failing every reopen.
    /// </summary>
    public async Task RestartAsync(string nodeId)
    {
        VmNode node;
        lock (gate)
        {
            node = RequireNode(nodeId);
        }

        await node.StopAsync();
        node.ReleaseResources();
        var restarted = await VmNode.StartAsync(
            options,
            Path.Combine(options.RootDirectory, nodeId),
            nodeId,
            node.Address,
            new VmMemberDescription(node.PeerPort, new Dictionary<string, string>()));
        lock (gate)
        {
            nodes[nodeId] = restarted;
        }
    }

    /// <inheritdoc />
    public Task CordonAsync(string nodeId)
    {
        lock (gate)
        {
            var node = RequireNode(nodeId);
            nodes[nodeId] = node with { State = AutoscalingNodeState.Cordoned };
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async Task DrainAsync(string nodeId)
    {
        VmNode node;
        lock (gate)
        {
            node = RequireNode(nodeId);
            nodes[nodeId] = node with { State = AutoscalingNodeState.Draining };
        }

        // ponytail: drain is a power-off after the drain-safety gate passed;
        // a graceful in-guest shutdown needs the guest agent the VM lane has
        // not grown yet.
        await node.StopAsync();
    }

    /// <inheritdoc />
    public async Task RetireAsync(string nodeId)
    {
        VmNode node;
        lock (gate)
        {
            node = RequireNode(nodeId);
            nodes.Remove(nodeId);
        }

        await node.StopAsync();
        node.DisposeResources();
    }

    /// <inheritdoc />
    public void KillMember(string nodeId)
    {
        lock (gate)
        {
            var node = RequireNode(nodeId);
            node.Kill();
            nodes[nodeId] = node with { State = AutoscalingNodeState.Retired };
        }
    }

    /// <inheritdoc />
    public async Task<AutoscalerSnapshot> ObserveAsync(IReadOnlyList<AllocationDemand>? demand = null)
    {
        List<VmNode> snapshot;
        lock (gate)
        {
            snapshot = [.. nodes.Values];
        }

        var observations = new List<(VmNode Node, MemberObservation Member)>();
        foreach (var node in snapshot)
        {
            observations.Add((node, await node.ObserveAsync()));
        }

        var nodeViews = observations.Select(entry => new NodeObservation(
            entry.Node.NodeId,
            entry.Node.State,
            options.NodeCapacity,
            entry.Member.Up
                ? new ResourceVector(
                    cpu: 10, memory: 500_000_000, blockIo: 0, ephemeralDisk: 0, bandwidth: 0, pids: 1, fileDescriptors: 0, hugePages: 0)
                : ResourceVector.Zero,
            0,
            [new StatefulReplicaHealth("terrabase-member", entry.Node.NodeId, entry.Member.Up, peerAckCount: 1, minReplicas: 2, lagBytes: entry.Member.ReplicationLagSequences)])).ToArray();
        return new AutoscalerSnapshot(nodeViews, demand ?? []);
    }

    /// <inheritdoc />
    public bool IsMemberAlive(string nodeId)
    {
        lock (gate)
        {
            return nodes.TryGetValue(nodeId, out var node) && node.IsAlive;
        }
    }

    public async ValueTask DisposeAsync()
    {
        List<VmNode> remaining;
        lock (gate)
        {
            remaining = [.. nodes.Values];
            nodes.Clear();
        }

        foreach (var node in remaining)
        {
            // Teardown is best-effort per node: one broken node handle must
            // not leak the remaining VMs and their tap devices.
            try
            {
                await node.StopAsync();
                node.DisposeResources();
            }
            catch (InvalidOperationException)
            {
            }
        }

        VmNodeFleet.RunCommand("sudo", $"ip link del br-fc{options.SubnetThirdOctet}", ignoreFailure: true);
    }

    private VmNode RequireNode(string nodeId) =>
        nodes.TryGetValue(nodeId, out var node)
            ? node
            : throw new InvalidOperationException($"Node {nodeId} is not part of this fleet.");

    private async Task BuildRootfsAsync(
        string workingDirectory,
        string nodeId,
        string address,
        VmMemberDescription description)
    {
        var rootfs = Path.Combine(workingDirectory, "rootfs.ext4");
        await RunAsync("cp", $"--sparse=always {options.BaseRootfsPath} {rootfs}");
        await RunAsync("sudo", $"debugfs -w -R \"write {options.DisabledMarkerPath} /etc/cloud/cloud-init.disabled\" {rootfs}", ignoreFailure: true);
        var network = Path.Combine(workingDirectory, "10-eth0.network");
        await File.WriteAllTextAsync(network, $"""
            [Match]
            Name=eth0

            [Network]
            Address={address}/{options.SubnetPrefix}
            LinkLocalAddressing=no
            """);
        await RunAsync("sudo", $"debugfs -w -R \"write {network} /etc/systemd/network/10-eth0.network\" {rootfs}");
        await RunAsync("sudo", $"debugfs -w -R \"sif /etc/systemd/network/10-eth0.network mode 0100644\" {rootfs}");
        var environment = Path.Combine(workingDirectory, "member.env");
        var lines = new List<string>
        {
            "DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1",
            "TERRABASE_MEMBER_ENABLED=true",
            $"TERRABASE_PEER_URL=https://{address}:8422",
        };
        // systemd strips double quotes from unquoted EnvironmentFile values,
        // which would mangle the JSON allowlist; single quotes preserve them.
        lines.AddRange(description.Environment.Select(pair =>
            pair.Value.Contains('"', StringComparison.Ordinal)
                ? $"{pair.Key}='{pair.Value}'"
                : $"{pair.Key}={pair.Value}"));
        await File.WriteAllLinesAsync(environment, lines);
        await RunAsync("sudo", $"debugfs -w -R \"write {environment} /opt/member.env\" {rootfs}");
        await RunAsync("sudo", $"debugfs -w -R \"sif /opt/member.env mode 0100644\" {rootfs}");
        foreach (var (unit, target) in options.GuestUnits)
        {
            await RunAsync("sudo", $"debugfs -w -R \"write {unit} /etc/systemd/system/{target}\" {rootfs}");
            await RunAsync("sudo", $"debugfs -w -R \"sif /etc/systemd/system/{target} mode 0100644\" {rootfs}");
            await RunAsync("sudo", $"debugfs -w -R \"symlink /etc/systemd/system/multi-user.target.wants/{target} /etc/systemd/system/{target}\" {rootfs}", ignoreFailure: true);
        }

        _ = nodeId;
    }

    internal static void RunCommand(string fileName, string arguments, bool ignoreFailure = false)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
        });
        if (process is null)
        {
            throw new InvalidOperationException($"Could not run {fileName} {arguments}.");
        }

        process.WaitForExit(120_000);
        if (process.ExitCode != 0 && !ignoreFailure)
        {
            throw new InvalidOperationException($"{fileName} {arguments} failed with {process.ExitCode}.");
        }
    }

    private static async Task RunAsync(string fileName, string arguments, bool ignoreFailure = false)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
        });
        if (process is null)
        {
            throw new InvalidOperationException($"Could not run {fileName} {arguments}.");
        }

        var exited = await Task.Run(() => process.WaitForExit(300_000), CancellationToken.None);
        if (!exited || (process.ExitCode != 0 && !ignoreFailure))
        {
            throw new InvalidOperationException($"{fileName} {arguments} failed with exit {process.ExitCode}.");
        }
    }
}

/// <summary>
/// The description of one VM member: its peer port and every TERRABASE_*
/// variable except the listener URLs, which the fleet derives from the node's
/// VM address.
/// </summary>
public sealed record VmMemberDescription(
    int PeerPort,
    IReadOnlyDictionary<string, string> Environment);

/// <summary>
/// The prepared inputs of the Firecracker lane: the pinned kernel, the
/// prepared Ubuntu rootfs, the shared read-only member payload disk, the
/// guest systemd units, the firecracker binary, and the cluster certificate
/// used by the host to observe members over mTLS.
/// </summary>
public sealed record VmFleetOptions
{
    public required string RootDirectory { get; init; }

    public required string KernelPath { get; init; }

    public required string BaseRootfsPath { get; init; }

    public required string PayloadDiskPath { get; init; }

    public required string FirecrackerPath { get; init; }

    public required string DisabledMarkerPath { get; init; }

    public required IReadOnlyList<(string UnitPath, string GuestName)> GuestUnits { get; init; }

    public required string ObserverCertificatePath { get; init; }

    public required string ObserverKeyPath { get; init; }

    public required string ObserverAuthorityPath { get; init; }

    public ResourceVector NodeCapacity { get; init; } = new(
        cpu: 200, memory: 4_000_000_000, blockIo: 0, ephemeralDisk: 0, bandwidth: 0, pids: 64, fileDescriptors: 0, hugePages: 0);

    public int VcpuCount { get; init; } = 2;

    public int MemoryMib { get; init; } = 2048;

    public int SubnetThirdOctet { get; init; } = 77;

    public int SubnetPrefix { get; init; } = 24;

    public TimeSpan ReadinessTimeout { get; init; } = TimeSpan.FromSeconds(120);

    public string AddressFor(int ordinal) => $"10.{SubnetThirdOctet}.0.{9 + ordinal}";

    public string TapName(int ordinal) => $"tap-fc{SubnetThirdOctet}-{ordinal}";

    internal void Validate()
    {
        foreach (var path in new[]
                 {
                     KernelPath, BaseRootfsPath, PayloadDiskPath, FirecrackerPath, DisabledMarkerPath,
                     ObserverCertificatePath, ObserverKeyPath, ObserverAuthorityPath,
                 })
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException($"A required VM lane input path is missing: {path}.");
            }
        }

        if (GuestUnits.Count == 0)
        {
            throw new ArgumentException("At least one guest unit is required.");
        }
    }
}

/// <summary>One running Firecracker microVM hosting one member.</summary>
internal sealed record VmNode(
    string NodeId,
    AutoscalingNodeState State,
    Process Firecracker,
    string ApiSocketPath,
    string TapName,
    string Address,
    int PeerPort,
    string WorkingDirectory,
    HttpClient Peer)
    : IAsyncDisposable
{
    public bool IsAlive => Firecracker is { HasExited: false } && ProbeAsync().GetAwaiter().GetResult().Up;

    public static async Task<VmNode> StartAsync(
        VmFleetOptions options,
        string workingDirectory,
        string nodeId,
        string address,
        VmMemberDescription description)
    {
        var ordinal = int.Parse(address[(address.LastIndexOf('.') + 1)..], System.Globalization.CultureInfo.InvariantCulture) - 9;
        var tap = options.TapName(ordinal);
        var bridge = $"br-fc{options.SubnetThirdOctet}";
        // One bridge per fleet carries every node's tap, so the host can
        // route to each VM address on the shared subnet.
        VmNodeFleet.RunCommand("sudo", $"ip link add {bridge} type bridge", ignoreFailure: true);
        VmNodeFleet.RunCommand("sudo", $"ip addr add 10.{options.SubnetThirdOctet}.0.1/{options.SubnetPrefix} dev {bridge}", ignoreFailure: true);
        VmNodeFleet.RunCommand("sudo", $"ip link set {bridge} up");
        VmNodeFleet.RunCommand("sudo", $"ip tuntap del dev {tap} mode tap", ignoreFailure: true);
        VmNodeFleet.RunCommand("sudo", $"ip tuntap add dev {tap} mode tap user {Environment.UserName}");
        VmNodeFleet.RunCommand("sudo", $"ip link set {tap} master {bridge}");
        VmNodeFleet.RunCommand("sudo", $"ip link set {tap} up");

        var apiSocket = Path.Combine(workingDirectory, "fc.sock");
        // A retained working directory still holds the previous boot's API
        // socket; a stale file would satisfy the wait below and every PUT
        // would hit a dead socket.
        try
        {
            File.Delete(apiSocket);
        }
        catch (FileNotFoundException)
        {
        }

        var console = Path.Combine(workingDirectory, "console.log");
        var consoleWriter = new FileStream(console, FileMode.Create, FileAccess.Write, FileShare.Read);
        var firecracker = Process.Start(new ProcessStartInfo
        {
            FileName = options.FirecrackerPath,
            Arguments = $"--api-sock {apiSocket}",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        }) ?? throw new InvalidOperationException($"Firecracker could not be started for {nodeId}.");
        void Record(string line)
        {
            lock (consoleWriter)
            {
                consoleWriter.Write(System.Text.Encoding.UTF8.GetBytes(line + "\n"));
                consoleWriter.Flush();
            }
        }

        firecracker.OutputDataReceived += (_, eventArgs) =>
        {
            if (eventArgs.Data is { Length: > 0 })
            {
                Record(eventArgs.Data);
            }
        };
        firecracker.ErrorDataReceived += (_, eventArgs) =>
        {
            if (eventArgs.Data is { Length: > 0 })
            {
                Record(eventArgs.Data);
            }
        };
        firecracker.BeginOutputReadLine();
        firecracker.BeginErrorReadLine();
        await WaitForAsync(apiSocket, TimeSpan.FromSeconds(10));

        var handler = new SocketsHttpHandler
        {
            ConnectCallback = async (_, cancellationToken) =>
            {
                var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                await socket.ConnectAsync(new UnixDomainSocketEndPoint(apiSocket), cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            },
        };
        var api = new HttpClient(handler) { BaseAddress = new Uri("http://firecracker/") };
        await PutAsync(api, "machine-config",
            $$"""{"vcpu_count":{{options.VcpuCount}},"mem_size_mib":{{options.MemoryMib}}}""");
        await PutAsync(api, "boot-source",
            $$"""{"kernel_image_path":"{{options.KernelPath}}","boot_args":"console=ttyS0 reboot=k panic=-1"}""");
        await PutAsync(api, "drives/rootfs",
            $$"""{"drive_id":"rootfs","path_on_host":"{{workingDirectory}}/rootfs.ext4","is_root_device":true,"is_read_only":false}""");
        await PutAsync(api, "drives/payload",
            $$"""{"drive_id":"payload","path_on_host":"{{options.PayloadDiskPath}}","is_root_device":false,"is_read_only":true}""");
        await PutAsync(api, "network-interfaces/eth0",
            $$"""{"iface_id":"eth0","guest_mac":"02:fc:{{options.SubnetThirdOctet:X2}}:00:00:{{ordinal + 9:X2}}","host_dev_name":"{{tap}}"}""");
        await PutAsync(api, "actions", """{"action_type":"InstanceStart"}""");

        var peer = BuildPeerClient(options);
        var node = new VmNode(nodeId, AutoscalingNodeState.Provisioning, firecracker, apiSocket, tap, address, description.PeerPort, workingDirectory, peer);
        if (!await node.WaitUntilReadyAsync(options.ReadinessTimeout, consoleWriter))
        {
            consoleWriter.Flush();
            var tail = File.Exists(console) ? await File.ReadAllTextAsync(console) : string.Empty;
            await node.StopAsync();
            // The working directory is preserved for diagnosis.
            throw new TimeoutException(
                $"The VM member {nodeId} at {address} did not become ready within {options.ReadinessTimeout}. Working directory {workingDirectory} preserved. Console tail: {(tail.Length > 2000 ? tail[^2000..] : tail)}");
        }

        return node with { State = AutoscalingNodeState.Ready };
    }

    public async Task<MemberObservation> ObserveAsync() => await ProbeAsync();

    public async Task StopAsync()
    {
        try
        {
            if (Firecracker is { HasExited: false } alive)
            {
                alive.Kill(entireProcessTree: true);
                await Task.Run(() => alive.WaitForExit(10_000), CancellationToken.None);
            }
        }
        catch (InvalidOperationException)
        {
            // The process handle was already disposed by a restart — the
            // firecracker behind it is gone.
        }
    }

    public void Kill() => StopAsync().GetAwaiter().GetResult();

    public void DisposeResources()
    {
        ReleaseResources();
        try
        {
            Directory.Delete(WorkingDirectory, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    /// <summary>Releases the process and tap but keeps the rootfs and logs.</summary>
    public void ReleaseResources()
    {
        Peer.Dispose();
        Firecracker.Dispose();
        VmNodeFleet.RunCommand("sudo", $"ip link del {TapName}", ignoreFailure: true);
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        DisposeResources();
    }

    private async Task<MemberObservation> ProbeAsync()
    {
        if (Firecracker.HasExited)
        {
            return new MemberObservation(false, 0);
        }

        try
        {
            using var response = await Peer.GetAsync($"https://{Address}:{PeerPort}/api/v1/health");
            if (!response.IsSuccessStatusCode)
            {
                return new MemberObservation(false, 0);
            }

            return new MemberObservation(true, 0);
        }
        catch (HttpRequestException)
        {
            return new MemberObservation(false, 0);
        }
        catch (TaskCanceledException)
        {
            return new MemberObservation(false, 0);
        }
    }

    private async Task<bool> WaitUntilReadyAsync(TimeSpan timeout, FileStream consoleWriter)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        while (!cancellation.IsCancellationRequested)
        {
            if (Firecracker.HasExited)
            {
                return false;
            }

            var observation = await ProbeAsync();
            if (observation.Up)
            {
                consoleWriter.Flush();
                return true;
            }

            try
            {
                await Task.Delay(1000, cancellation.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        return false;
    }

    private static HttpClient BuildPeerClient(VmFleetOptions options)
    {
        var certificate = X509Certificate2.CreateFromPemFile(options.ObserverCertificatePath, options.ObserverKeyPath);
        var authority = X509Certificate2.CreateFromPem(File.ReadAllText(options.ObserverAuthorityPath));
        var handler = new HttpClientHandler
        {
            ClientCertificates = { certificate },
            ServerCertificateCustomValidationCallback = (_, issued, _, _) => issued is not null && ValidateChain(issued, authority),
        };
        // The member's peer listener speaks HTTP/2 only (mTLS admission
        // before RPC dispatch), so the probe must negotiate h2.
        return new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(5),
            DefaultRequestVersion = HttpVersion.Version20,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
    }

    private static bool ValidateChain(X509Certificate2 issued, X509Certificate2 authority)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(authority);
        // The private cluster CA publishes no CRL or OCSP responder.
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(issued);
    }

    private static async Task PutAsync(HttpClient api, string path, string json)
    {
        using var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");
        using var response = await api.PutAsync(path, content);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"Firecracker API {path} failed: {response.StatusCode} {await response.Content.ReadAsStringAsync()}.");
        }
    }

    private static async Task WaitForAsync(string path, TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        while (!cancellation.IsCancellationRequested)
        {
            if (File.Exists(path))
            {
                return;
            }

            await Task.Delay(100, cancellation.Token);
        }

        throw new TimeoutException($"Firecracker API socket {path} never appeared.");
    }
}
