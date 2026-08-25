using System.Diagnostics;
using System.Text;
using Cysharp.Text;

namespace TerraScale.Orchestrator.Development;

internal static class DevelopmentContainerImages
{
    public const string AspNet = "mcr.microsoft.com/dotnet/aspnet@sha256:385243b43a2e8b30ffde1eab09a3457b7226bc3cbefedbc3a8b06fa35842c7f6";
    public const string RuntimeDependencies = "mcr.microsoft.com/dotnet/runtime-deps@sha256:894098eafc82e5fa02ba9f2b71d426dc78252876b9e914caae77ed95cfce185a";
    public const string Node = "docker.io/library/node@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3";
    public const string Nats = "docker.io/library/nats@sha256:a42e284980d105c1b668d553175b4c7abc9b7187c5e9859baf4f1d564772b85f";

    public static IReadOnlyList<string> All => [AspNet, RuntimeDependencies, Node, Nats];

    public static IReadOnlyList<string> RequiredBy(DevelopmentTopology topology) => topology.Cells
        .SelectMany(cell => cell.Resources)
        .Select(resource => resource.Kind switch
        {
            DevelopmentResourceKind.ControllerAgent => RuntimeDependencies,
            DevelopmentResourceKind.ControlNats or DevelopmentResourceKind.ProductNats => Nats,
            DevelopmentResourceKind.Dashboard => Node,
            _ => AspNet
        })
        .Distinct(StringComparer.Ordinal)
        .ToArray();
}

internal sealed class DevelopmentProcessSupervisor : IAsyncDisposable
{
    internal const string OwnershipLabel = "io.terrascale.owner=devhost-orchestrator";
    internal const long AggregateLocalMemoryLimitBytes = 24L * 1024 * 1024 * 1024;
    internal const long PodMemoryLimitBytes = 20L * 1024 * 1024 * 1024;
    internal const long HostHeadroomBytes = 4L * 1024 * 1024 * 1024;
    internal const int ContainerProcessLimit = 512;

    private readonly Dictionary<string, Process> processes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DevelopmentProcessSpec> specifications = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTimeOffset> startedAt = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource stopping = new();
    private readonly DevelopmentTopology topology;
    private readonly string workspaceRoot;
    private readonly string dataDirectory;
    private readonly string podName;
    private bool initialized;

    public DevelopmentProcessSupervisor(
        DevelopmentTopology topology,
        string workspaceRoot,
        string dataDirectory,
        string instance = "local")
    {
        RequireResourceBudget(topology);
        this.topology = topology;
        this.workspaceRoot = Path.GetFullPath(workspaceRoot);
        this.dataDirectory = Path.GetFullPath(dataDirectory);
        podName = $"terrascale-devhost-{instance}";
    }

    public IReadOnlyDictionary<string, Process> Processes => processes;

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        if (initialized)
        {
            return;
        }
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("The rootless Podman development runtime requires Linux.");
        }

        var rootless = await RunAsync(["info", "--format", "{{.Host.Security.Rootless}}"], cancellationToken);
        if (rootless.ExitCode != 0 || !string.Equals(rootless.Output.Trim(), "true", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The development runtime requires a working rootless Podman installation.");
        }

        await RemoveExistingOwnedPodAsync(cancellationToken);

        foreach (var image in DevelopmentContainerImages.RequiredBy(topology))
        {
            var exists = await RunAsync(["image", "exists", image], cancellationToken);
            if (exists.ExitCode != 0)
            {
                await RequireSuccessAsync(["pull", image], cancellationToken);
            }
        }

        Directory.CreateDirectory(dataDirectory);
        Directory.CreateDirectory(Path.Combine(dataDirectory, "container-environment"));
        await RequireSuccessAsync(PodCreationArguments(topology, podName), cancellationToken);
        initialized = true;
    }

    /// <summary>
    /// Removes a leftover lab pod before create. Soft restarts that SIGKILL the
    /// Orchestrator leave pasta-backed pods in a Degraded state; force-remove even
    /// when inspect is flaky so the next lab can recreate clean networking.
    /// </summary>
    private async Task RemoveExistingOwnedPodAsync(CancellationToken cancellationToken)
    {
        var exists = await RunAsync(["pod", "exists", podName], cancellationToken);
        if (exists.ExitCode != 0)
        {
            return;
        }

        var owner = await RunAsync(
            ["pod", "inspect", podName, "--format", "{{ index .Labels \"io.terrascale.owner\" }}"],
            cancellationToken);
        if (owner.ExitCode == 0 && !IsOwnedPod(owner.Output))
        {
            throw new InvalidOperationException(
                $"Podman pod '{podName}' exists but is not owned by TerraScale DevHost.");
        }

        // Owned label, or inspect failed on a half-dead Degraded pod we own by name.
        await RequireSuccessAsync(OwnedPodRemovalArguments(podName, 15), cancellationToken);
    }

    public Process Start(
        string name,
        string image,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        IReadOnlyDictionary<string, string?>? environment = null)
    {
        if (!initialized)
        {
            throw new InvalidOperationException("The Podman development supervisor has not been initialized.");
        }
        if (processes.ContainsKey(name))
        {
            throw new InvalidOperationException($"Development resource '{name}' is already running.");
        }
        if (!DevelopmentContainerImages.All.Contains(image, StringComparer.Ordinal))
        {
            throw new InvalidOperationException($"Development resource '{name}' requested an unpinned image.");
        }

        var specification = new DevelopmentProcessSpec(
            name,
            image,
            arguments.ToArray(),
            Path.GetFullPath(workingDirectory),
            environment?.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal));
        specifications.Add(name, specification);
        try
        {
            return StartCore(specification);
        }
        catch
        {
            specifications.Remove(name);
            throw;
        }
    }

    public IReadOnlyList<string> ExitedResources() => processes
        .Where(pair => pair.Value.HasExited)
        .Select(pair => pair.Key)
        .ToArray();

    public bool IsWithinStartupGrace(string name, TimeSpan grace) =>
        startedAt.TryGetValue(name, out var value) && DateTimeOffset.UtcNow - value < grace;

    public int? GetContainerProcessId(string name)
    {
        var result = Run(["container", "inspect", ContainerName(name), "--format", "{{.State.Pid}}"]);
        return result.ExitCode == 0 && int.TryParse(result.Output.Trim(), out var value) && value > 0
            ? value
            : null;
    }

    public string GetContainerId(string name) => ContainerName(name);

    /// <summary>
    /// Stops a running development container while retaining its trusted start
    /// specification so <see cref="RestartAsync"/> can bring it back later.
    /// Used before NATS recycle on PKI remint so clients cannot keep presenting
    /// pre-remint (often expired) leaves to freshly restarted servers.
    /// </summary>
    public Task StopAsync(string name) => StopManyAsync([name]);

    /// <summary>
    /// Stops many containers in parallel while retaining trusted start specifications.
    /// Remint recovery uses this so multi-cell controllers/platforms (and NATS) are
    /// torn down together instead of one-by-one with a 15s grace each, which left
    /// still-running peers presenting expired leaves to live NATS for minutes.
    /// </summary>
    public async Task StopManyAsync(IReadOnlyList<string> names, int stopTimeoutSeconds = 1)
    {
        ArgumentNullException.ThrowIfNull(names);
        if (stopTimeoutSeconds < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(stopTimeoutSeconds));
        }

        var victims = new List<(string Name, Process Process)>(names.Count);
        foreach (var name in names)
        {
            if (!specifications.ContainsKey(name))
            {
                throw new InvalidOperationException(
                    $"Development resource '{name}' has no trusted container specification.");
            }
            if (processes.Remove(name, out var previous))
            {
                victims.Add((name, previous));
            }
            startedAt.Remove(name);
        }

        if (victims.Count == 0)
        {
            return;
        }

        await Task.WhenAll(victims.Select(
            victim => RemoveContainerAsync(victim.Name, victim.Process, stopTimeoutSeconds)));
    }

    public async Task<Process> RestartAsync(string name)
    {
        if (!specifications.TryGetValue(name, out var specification))
        {
            throw new InvalidOperationException($"Development resource '{name}' has no trusted container specification.");
        }
        if (processes.Remove(name, out var previous))
        {
            await RemoveContainerAsync(name, previous);
        }
        // Remint stops every peer container; on some podman/pasta hosts the lab pod
        // can vanish between the last rm and the first restart. Recreate before run.
        await EnsureOwnedPodExistsAsync(CancellationToken.None);
        var process = StartCore(specification);
        // podman run --pod fails with exit 125 almost immediately when the pod ID is
        // gone from the database (including a race after exists-check). Recreate once.
        if (await FailedImmediatelyWithMissingPodAsync(process))
        {
            Console.WriteLine(
                $"Development container '{name}' exited 125 (missing pod); recreating owned pod and retrying.");
            processes.Remove(name);
            process.Dispose();
            startedAt.Remove(name);
            await RecreateOwnedPodAsync(CancellationToken.None);
            process = StartCore(specification);
        }

        return process;
    }

    /// <summary>
    /// Ensures the owned lab pod still exists and is in a usable state. Used after
    /// bulk stop (PKI remint) and inside <see cref="RestartAsync"/> so starts do not
    /// fail with "no pod with ID … found in database".
    /// </summary>
    public async Task EnsureOwnedPodExistsAsync(CancellationToken cancellationToken)
    {
        if (!initialized)
        {
            throw new InvalidOperationException("The Podman development supervisor has not been initialized.");
        }

        var exists = await RunAsync(["pod", "exists", podName], cancellationToken);
        if (exists.ExitCode == 0)
        {
            var state = await RunAsync(
                ["pod", "inspect", podName, "--format", "{{.State}}"],
                cancellationToken);
            if (state.ExitCode == 0 && IsUsablePodState(state.Output))
            {
                return;
            }

            // Name is still registered but pasta/network is half-dead (Degraded) or
            // inspect is flaky — force-recreate rather than hand StartCore a ghost ID.
            Console.WriteLine(
                $"Lab pod '{podName}' is present but unusable (state '{FirstLine(state.Output)}'); recreating.");
            _ = await RunAsync(OwnedPodRemovalArguments(podName, 15), cancellationToken);
        }
        else
        {
            Console.WriteLine(
                $"Lab pod '{podName}' missing after container stop; recreating owned pod before restart.");
        }

        await RequireSuccessAsync(PodCreationArguments(topology, podName), cancellationToken);
    }

    /// <summary>
    /// Force-removes the owned lab pod (if any) and creates a fresh one. Call only
    /// when every peer container is already stopped (PKI remint bulk stop); safe
    /// because no live resource still depends on the previous pasta namespace.
    /// </summary>
    public async Task RecreateOwnedPodAsync(CancellationToken cancellationToken)
    {
        if (!initialized)
        {
            throw new InvalidOperationException("The Podman development supervisor has not been initialized.");
        }

        var exists = await RunAsync(["pod", "exists", podName], cancellationToken);
        if (exists.ExitCode == 0)
        {
            Console.WriteLine(
                $"Recreating owned lab pod '{podName}' after bulk container stop.");
            _ = await RunAsync(OwnedPodRemovalArguments(podName, 15), cancellationToken);
        }
        else
        {
            Console.WriteLine(
                $"Lab pod '{podName}' already gone after bulk container stop; creating a fresh owned pod.");
        }

        await RequireSuccessAsync(PodCreationArguments(topology, podName), cancellationToken);
    }

    /// <summary>
    /// Podman pod inspect <c>.State</c> values that can accept <c>podman run --pod</c>.
    /// Degraded / Stopped / Exited pods after bulk force-rm are treated as unusable.
    /// </summary>
    internal static bool IsUsablePodState(string? state)
    {
        var normalized = state?.Trim();
        return string.Equals(normalized, "Running", StringComparison.OrdinalIgnoreCase)
            || string.Equals(normalized, "Created", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Podman exit 125 is the CLI wrapper failure used when <c>run --pod</c> cannot
    /// resolve the pod (including "no pod with ID … found in database").
    /// </summary>
    internal static bool IsMissingPodExitCode(int exitCode) => exitCode == 125;

    /// <summary>
    /// Waits briefly for a fail-fast <c>podman run</c> so RestartAsync can recreate the
    /// pod once instead of letting the lab loop surface "exited unexpectedly".
    /// Healthy starts stay up past this window and return false without extra work.
    /// </summary>
    private static async Task<bool> FailedImmediatelyWithMissingPodAsync(Process process)
    {
        // Missing-pod failures exit within tens of milliseconds. Keep the window short
        // so remint (many sequential RestartAsync calls) does not add multi-second delay.
        if (process.HasExited)
        {
            return IsMissingPodExitCode(process.ExitCode);
        }

        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
            await process.WaitForExitAsync(timeout.Token);
            return IsMissingPodExitCode(process.ExitCode);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    public void UpdateWorkingDirectory(string name, string workingDirectory)
    {
        if (!specifications.TryGetValue(name, out var specification))
        {
            throw new InvalidOperationException($"Development resource '{name}' has no trusted container specification.");
        }
        specifications[name] = specification with { WorkingDirectory = Path.GetFullPath(workingDirectory) };
    }

    private Process StartCore(DevelopmentProcessSpec specification)
    {
        var environmentFile = WriteEnvironmentFile(specification);
        var process = new Process
        {
            StartInfo = new ProcessStartInfo("podman")
            {
                WorkingDirectory = specification.WorkingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            }
        };
        var memory = MemoryLimit(topology, specification.Name);
        Add(process.StartInfo,
        [
            "run", "--rm",
            "--name", ContainerName(specification.Name),
            "--pod", podName,
            "--pull", "never",
            "--label", OwnershipLabel,
            "--label", $"io.terrascale.topology={topology.Profile}",
        ]);
        Add(process.StartInfo, ContainerIsolationArguments(memory));
        Add(process.StartInfo,
        [
            "--stop-timeout", "15",
            "--env-file", environmentFile,
            "--volume", $"{workspaceRoot}:{workspaceRoot}:ro",
            "--volume", $"{dataDirectory}:{dataDirectory}:rw"
        ]);
        if (WritableRuntimeVolume(topology, specification.Name, dataDirectory) is { } runtime)
        {
            PrepareWritableRuntimeVolume(runtime);
            Add(process.StartInfo, ["--volume", $"{runtime.Source}:{runtime.Destination}:rw"]);
        }
        Add(process.StartInfo, ["--workdir", specification.WorkingDirectory, specification.Image]);
        Add(process.StartInfo, specification.Arguments);
        processes.Add(specification.Name, process);
        try
        {
            process.Start();
        }
        catch
        {
            processes.Remove(specification.Name);
            process.Dispose();
            throw;
        }
        startedAt[specification.Name] = DateTimeOffset.UtcNow;
        _ = PumpAsync(specification.Name, process.StandardOutput, Console.Out, stopping.Token);
        _ = PumpAsync(specification.Name, process.StandardError, Console.Error, stopping.Token);
        return process;
    }

    public void ThrowIfAnyExited()
    {
        var exited = processes.FirstOrDefault(pair => pair.Value.HasExited);
        if (!string.IsNullOrEmpty(exited.Key))
        {
            throw new InvalidOperationException(
                $"Development container '{exited.Key}' exited unexpectedly with code {exited.Value.ExitCode}.");
        }
    }

    public async ValueTask DisposeAsync()
    {
        await stopping.CancelAsync();
        // Tear down the whole owned pod in one shot. Sequential per-container
        // stops with 15s timeouts can exceed DevHost's graceful SIGTERM budget
        // (90–180s) on the regional topology, leaving pasta dead and the pod Degraded.
        var processSnapshot = processes.Values.ToArray();
        processes.Clear();
        specifications.Clear();
        startedAt.Clear();
        if (initialized)
        {
            var removal = await RunAsync(OwnedPodRemovalArguments(podName, 20), CancellationToken.None);
            if (removal.ExitCode != 0)
            {
                // Retry once; a stuck container can block the first force-rm.
                _ = await RunAsync(OwnedPodRemovalArguments(podName, 10), CancellationToken.None);
            }
        }
        foreach (var process in processSnapshot)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }
            }
            catch (InvalidOperationException)
            {
            }
            finally
            {
                process.Dispose();
            }
        }
        stopping.Dispose();
    }

    private async Task RemoveContainerAsync(string name, Process process, int stopTimeoutSeconds = 15)
    {
        _ = await RunAsync(
            [
                "rm",
                "--force",
                "--time",
                stopTimeoutSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ContainerName(name)
            ],
            CancellationToken.None);
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
            await process.WaitForExitAsync();
        }
        catch (InvalidOperationException)
        {
        }
        finally
        {
            process.Dispose();
        }
    }

    private string WriteEnvironmentFile(DevelopmentProcessSpec specification)
    {
        var path = Path.Combine(dataDirectory, "container-environment", specification.Name + ".env");
        using var builder = ZString.CreateStringBuilder();
        if (specification.Environment is not null)
        {
            foreach (var (key, value) in specification.Environment.OrderBy(pair => pair.Key, StringComparer.Ordinal))
            {
                if (value is null)
                {
                    continue;
                }
                if (value.Contains('\n') || value.Contains('\r'))
                {
                    throw new InvalidOperationException($"Environment value '{key}' contains a newline.");
                }
                builder.Append(key);
                builder.Append('=');
                builder.Append(value);
                builder.Append('\n');
            }
        }
        File.WriteAllText(path, builder.ToString());
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("Container environment files require Linux permissions.");
        }
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return path;
    }

    internal static long PlannedMemoryLimitBytes(DevelopmentTopology topology) => checked(
        topology.Cells.SelectMany(cell => cell.Resources)
            .Sum(resource => MemoryLimitBytes(resource.Kind)));

    internal static void RequireResourceBudget(DevelopmentTopology topology)
    {
        ArgumentNullException.ThrowIfNull(topology);
        var planned = PlannedMemoryLimitBytes(topology);
        if (planned > PodMemoryLimitBytes ||
            PodMemoryLimitBytes + HostHeadroomBytes > AggregateLocalMemoryLimitBytes)
        {
            throw new InvalidOperationException(
                $"Development topology '{topology.Profile}' plans {planned} bytes, exceeding the " +
                $"{PodMemoryLimitBytes}-byte lab budget inside the {AggregateLocalMemoryLimitBytes}-byte local limit.");
        }
    }

    internal static bool IsOwnedPod(string? owner) =>
        string.Equals(owner?.Trim(), "devhost-orchestrator", StringComparison.Ordinal);

    internal static IReadOnlyList<string> OwnedPodRemovalArguments(string podName, int timeoutSeconds) =>
        ["pod", "rm", "--force", "--time", timeoutSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture), podName];

    internal static IReadOnlyList<string> ContainerIsolationArguments(string memory) =>
    [
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", ContainerProcessLimit.ToString(System.Globalization.CultureInfo.InvariantCulture),
        "--memory", memory,
        "--memory-swap", memory,
    ];

    internal static DevelopmentWritableRuntimeVolume? WritableRuntimeVolume(
        DevelopmentTopology topology,
        string resourceName,
        string dataDirectory)
    {
        var resource = topology.Cells.SelectMany(cell => cell.Resources)
            .Single(candidate => candidate.Name == resourceName);
        if (resource.Kind != DevelopmentResourceKind.TerraBase)
        {
            return null;
        }
        var destination = Path.GetFullPath(DevelopmentArtifactBuilder.DotNetOutputDirectory(
            dataDirectory,
            "TerraBase.Server"));
        var source = Path.GetFullPath(Path.Combine(
            dataDirectory,
            "workloads",
            resourceName,
            "runtime"));
        return new DevelopmentWritableRuntimeVolume(source, destination);
    }

    internal static void PrepareWritableRuntimeVolume(DevelopmentWritableRuntimeVolume runtime)
    {
        ArgumentNullException.ThrowIfNull(runtime);
        if (!Directory.Exists(runtime.Destination))
        {
            throw new DirectoryNotFoundException(
                $"Published TerraBase runtime does not exist: {runtime.Destination}");
        }

        var parent = Path.GetDirectoryName(runtime.Source)
            ?? throw new InvalidOperationException("TerraBase private runtime has no parent directory.");
        Directory.CreateDirectory(parent);
        var staging = runtime.Source + ".new-" + Guid.NewGuid().ToString("N");
        Directory.CreateDirectory(staging);
        try
        {
            foreach (var directory in Directory.EnumerateDirectories(
                         runtime.Destination,
                         "*",
                         SearchOption.AllDirectories))
            {
                Directory.CreateDirectory(Path.Combine(
                    staging,
                    Path.GetRelativePath(runtime.Destination, directory)));
            }
            foreach (var file in Directory.EnumerateFiles(
                         runtime.Destination,
                         "*",
                         SearchOption.AllDirectories))
            {
                var destination = Path.Combine(
                    staging,
                    Path.GetRelativePath(runtime.Destination, file));
                Directory.CreateDirectory(
                    DevelopmentGuards.RequireDirectory(destination, "Runtime volume destination"));
                File.Copy(file, destination, overwrite: true);
            }

            if (Directory.Exists(runtime.Source))
            {
                Directory.Delete(runtime.Source, recursive: true);
            }
            Directory.Move(staging, runtime.Source);
        }
        finally
        {
            if (Directory.Exists(staging))
            {
                Directory.Delete(staging, recursive: true);
            }
        }
    }

    internal sealed record DevelopmentWritableRuntimeVolume(string Source, string Destination);

    internal static IReadOnlyList<string> PodCreationArguments(
        DevelopmentTopology topology,
        string podName)
    {
        var arguments = new List<string>
        {
            "pod", "create",
            "--name", podName,
            "--infra-image", DevelopmentContainerImages.RuntimeDependencies,
            "--infra-command", "sleep infinity",
            "--label", OwnershipLabel,
            "--label", $"io.terrascale.topology={topology.Profile}",
            "--label", "io.terrascale.schema=2",
            "--memory", PodMemoryLimitBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--memory-swap", PodMemoryLimitBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--network", "pasta:--host-lo-to-ns-lo,--log-file=/dev/null",
            "--exit-policy", "continue"
        };
        foreach (var port in PublishedPorts(topology))
        {
            arguments.Add("--publish");
            arguments.Add($"127.0.0.1:{port}:{port}");
        }
        return arguments;
    }

    private static string MemoryLimit(DevelopmentTopology topology, string name)
    {
        var resource = topology.Cells.SelectMany(cell => cell.Resources)
            .Single(candidate => candidate.Name == name);
        return MemoryLimitBytes(resource.Kind).ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    private static long MemoryLimitBytes(DevelopmentResourceKind kind) => kind switch
    {
        // 3 GiB: RF1 product cells load four sharded DBs plus cluster maintenance
        // reports; 2 GiB left maintenance TCP samples timing out under GC pressure.
        DevelopmentResourceKind.TerraBase => 3072L * 1024 * 1024,
        DevelopmentResourceKind.Platform => 640L * 1024 * 1024,
        DevelopmentResourceKind.Authentication or DevelopmentResourceKind.Dashboard => 384L * 1024 * 1024,
        DevelopmentResourceKind.ControllerAgent => 320L * 1024 * 1024,
        DevelopmentResourceKind.ControlNats or DevelopmentResourceKind.ProductNats => 256L * 1024 * 1024,
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    private static IReadOnlyList<int> PublishedPorts(DevelopmentTopology topology) => topology.Cells
        .SelectMany(cell => cell.Resources)
        .SelectMany(resource => new[] { resource.Port, resource.SecondaryPort })
        .Where(port => port.HasValue)
        .Select(port => port ?? throw new InvalidOperationException("A published development port is missing."))
        .Distinct()
        .Order()
        .ToArray();

    private string ContainerName(string name) => $"{podName}-{name}";

    private static void Add(ProcessStartInfo startInfo, IEnumerable<string> arguments)
    {
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
    }

    private static PodmanResult Run(IReadOnlyList<string> arguments)
    {
        using var process = CreatePodmanProcess(arguments);
        try
        {
            process.Start();
        }
        catch (System.ComponentModel.Win32Exception exception)
        {
            return new(-1, string.Empty, exception.Message);
        }
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return new(process.ExitCode, output, error);
    }

    private static async Task<PodmanResult> RunAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        using var process = CreatePodmanProcess(arguments);
        try
        {
            process.Start();
        }
        catch (System.ComponentModel.Win32Exception exception)
        {
            return new(-1, string.Empty, exception.Message);
        }
        var output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var error = process.StandardError.ReadToEndAsync(cancellationToken);
        await ProcessLifecycle.WaitForExitAsync(process, cancellationToken);
        return new(process.ExitCode, await output, await error);
    }

    private static async Task RequireSuccessAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        var result = await RunAsync(arguments, cancellationToken);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException($"Podman operation failed: {FirstLine(result.Error)}");
        }
    }

    private static Process CreatePodmanProcess(IReadOnlyList<string> arguments)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo("podman")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            }
        };
        Add(process.StartInfo, arguments);
        return process;
    }

    private static string FirstLine(string value) =>
        value.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault() ?? "unavailable";

    private static async Task PumpAsync(
        string name,
        StreamReader reader,
        TextWriter writer,
        CancellationToken cancellationToken)
    {
        try
        {
            while (await reader.ReadLineAsync(cancellationToken) is { } line)
            {
                if (!string.IsNullOrWhiteSpace(line))
                {
                    await writer.WriteLineAsync($"[{name}] {line}");
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private sealed record DevelopmentProcessSpec(
        string Name,
        string Image,
        IReadOnlyList<string> Arguments,
        string WorkingDirectory,
        IReadOnlyDictionary<string, string?>? Environment);

    private sealed record PodmanResult(int ExitCode, string Output, string Error);
}
