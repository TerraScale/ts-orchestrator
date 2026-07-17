using System.Diagnostics;
using System.Text;

namespace TerraScale.Orchestrator.Development;

internal static class DevelopmentContainerImages
{
    public const string AspNet = "mcr.microsoft.com/dotnet/aspnet@sha256:1f51d2d65ace46d6395e773fb4cfc1c74d36fb4f08e5cf996e7f6961b45e9283";
    public const string RuntimeDependencies = "mcr.microsoft.com/dotnet/runtime-deps@sha256:894098eafc82e5fa02ba9f2b71d426dc78252876b9e914caae77ed95cfce185a";
    public const string Node = "docker.io/library/node@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3";
    public const string Nats = "docker.io/library/nats@sha256:a42e284980d105c1b668d553175b4c7abc9b7187c5e9859baf4f1d564772b85f";

    public static IReadOnlyList<string> All => [AspNet, RuntimeDependencies, Node, Nats];

    public static IReadOnlyList<string> RequiredBy(DevelopmentTopology topology) => topology.Cells
        .SelectMany(cell => cell.Resources)
        .Concat(topology.GlobalResources)
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
    internal static readonly string OwnershipLabel = "io.terrascale.owner=devhost-orchestrator";
    internal const long AggregateLocalMemoryLimitBytes = 16L * 1024 * 1024 * 1024;
    internal const long PodMemoryLimitBytes = 14L * 1024 * 1024 * 1024;
    internal const long HostHeadroomBytes = 2L * 1024 * 1024 * 1024;
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

        var owner = await RunAsync(
            ["pod", "inspect", podName, "--format", "{{ index .Labels \"io.terrascale.owner\" }}"],
            cancellationToken);
        if (owner.ExitCode == 0)
        {
            if (!IsOwnedPod(owner.Output))
            {
                throw new InvalidOperationException($"Podman pod '{podName}' exists but is not owned by TerraScale DevHost.");
            }
            await RequireSuccessAsync(OwnedPodRemovalArguments(podName, 10), cancellationToken);
        }

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
        return StartCore(specification);
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
        return StartCore(specification);
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
            },
            EnableRaisingEvents = true
        };
        var memory = MemoryLimit(topology, specification.Name);
        Add(process.StartInfo,
        [
            "run", "--rm",
            "--name", ContainerName(specification.Name),
            "--pod", podName,
            "--pull", "never",
            "--label", OwnershipLabel,
            "--label", $"io.terrascale.profile={topology.Profile}",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", ContainerProcessLimit.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--memory", memory,
            "--memory-swap", memory,
            "--stop-timeout", "15",
            "--env-file", environmentFile,
            "--volume", $"{workspaceRoot}:{workspaceRoot}:ro",
            "--volume", $"{dataDirectory}:{dataDirectory}:rw",
            "--workdir", specification.WorkingDirectory,
            specification.Image
        ]);
        Add(process.StartInfo, specification.Arguments);
        process.Start();
        processes.Add(specification.Name, process);
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
        foreach (var (name, process) in processes.Reverse())
        {
            await RemoveContainerAsync(name, process);
        }
        processes.Clear();
        specifications.Clear();
        if (initialized)
        {
            _ = await RunAsync(OwnedPodRemovalArguments(podName, 15), CancellationToken.None);
        }
        stopping.Dispose();
    }

    private async Task RemoveContainerAsync(string name, Process process)
    {
        _ = await RunAsync(["rm", "--force", "--time", "15", ContainerName(name)], CancellationToken.None);
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
        var builder = new StringBuilder();
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
                builder.Append(key).Append('=').Append(value).Append('\n');
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
            .Concat(topology.GlobalResources)
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
            "--label", $"io.terrascale.profile={topology.Profile}",
            "--label", "io.terrascale.schema=2",
            "--memory", PodMemoryLimitBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--memory-swap", PodMemoryLimitBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
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
            .Concat(topology.GlobalResources)
            .Single(candidate => candidate.Name == name);
        return MemoryLimitBytes(resource.Kind).ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    private static long MemoryLimitBytes(DevelopmentResourceKind kind) => kind switch
    {
        DevelopmentResourceKind.TerraBase => 1536L * 1024 * 1024,
        DevelopmentResourceKind.Api => 768L * 1024 * 1024,
        DevelopmentResourceKind.Authentication or DevelopmentResourceKind.Dashboard => 512L * 1024 * 1024,
        DevelopmentResourceKind.ControllerAgent => 384L * 1024 * 1024,
        DevelopmentResourceKind.ControlNats or DevelopmentResourceKind.ProductNats => 256L * 1024 * 1024,
        DevelopmentResourceKind.EmailEmulator or DevelopmentResourceKind.StripeEmulator => 256L * 1024 * 1024,
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    private static IReadOnlyList<int> PublishedPorts(DevelopmentTopology topology) => topology.Cells
        .SelectMany(cell => cell.Resources)
        .Concat(topology.GlobalResources)
        .SelectMany(resource => new[] { resource.Port, resource.SecondaryPort })
        .Where(port => port.HasValue)
        .Select(port => port!.Value)
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
        await process.WaitForExitAsync(cancellationToken);
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
