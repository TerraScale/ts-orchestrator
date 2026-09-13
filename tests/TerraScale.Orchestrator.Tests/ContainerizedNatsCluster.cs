using System.Diagnostics;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Runs the real, digest-pinned NATS image in a private rootless Podman pod.
/// The pod publishes only explicitly reserved loopback ports and lets clustered
/// members continue to route over their shared loopback network namespace.
/// </summary>
internal sealed class ContainerizedNatsCluster : IAsyncDisposable
{
    private const string OwnershipLabel = "io.terrascale.owner=orchestrator-tests";
    private readonly string podName;
    private readonly string root;
    private readonly IReadOnlyList<string> readOnlyRoots;
    private readonly Dictionary<int, string> containers = [];
    private int disposed;

    private ContainerizedNatsCluster(string podName, string root, IReadOnlyList<string> readOnlyRoots)
    {
        this.podName = podName;
        this.root = root;
        this.readOnlyRoots = readOnlyRoots;
    }

    public static async Task<ContainerizedNatsCluster> CreateAsync(
        string root,
        IEnumerable<int> publishedPorts,
        IEnumerable<string>? readOnlyRoots = null,
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Containerized NATS tests require Linux.");

        var fullRoot = Path.GetFullPath(root);
        var privateTemporaryRoot = Path.GetFullPath(Path.GetTempPath());
        var normalizedReadOnlyRoots = (readOnlyRoots ?? [])
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (normalizedReadOnlyRoots.Any(candidate =>
                !Directory.Exists(candidate) || !IsWithinRoot(candidate, privateTemporaryRoot)))
            throw new InvalidOperationException("Additional NATS test mounts must be existing private temporary directories.");
        var podName = $"ts-orch-test-nats-{Guid.NewGuid():N}";
        var arguments = new List<string>
        {
            "pod", "create",
            "--name", podName,
            "--label", OwnershipLabel,
            "--network", "pasta:--host-lo-to-ns-lo,--log-file=/dev/null",
            "--exit-policy", "continue",
        };
        foreach (var port in publishedPorts.Distinct().Order())
        {
            if (port is <= 0 or > ushort.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(publishedPorts), port, "Published ports must be valid TCP ports.");
            arguments.Add("--publish");
            arguments.Add($"127.0.0.1:{port}:{port}/tcp");
        }

        await RequireSuccessAsync(arguments, cancellationToken);
        return new ContainerizedNatsCluster(podName, fullRoot, normalizedReadOnlyRoots);
    }

    public Process Start(string configuration)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        var fullConfiguration = Path.GetFullPath(configuration);
        if (!IsWithinRoot(fullConfiguration, root) || !File.Exists(fullConfiguration))
            throw new InvalidOperationException("The NATS configuration must be an existing file inside the private fixture root.");

        var containerName = $"{podName}-{containers.Count + 1}-{Guid.NewGuid():N}";
        var startInfo = new ProcessStartInfo("podman")
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var argument in new[]
                 {
                     "run", "--rm",
                     "--name", containerName,
                     "--pod", podName,
                     "--label", OwnershipLabel,
                     "--security-opt", "no-new-privileges",
                     "--cap-drop", "all",
                     "--pids-limit", "128",
                     "--memory", "256m",
                     "--volume", $"{root}:{root}:rw",
                     TestContainerImages.Nats,
                     "--config", fullConfiguration,
                 })
            startInfo.ArgumentList.Add(argument);
        foreach (var readOnlyRoot in readOnlyRoots)
        {
            startInfo.ArgumentList.Insert(startInfo.ArgumentList.Count - 3, "--volume");
            startInfo.ArgumentList.Insert(startInfo.ArgumentList.Count - 3, $"{readOnlyRoot}:{readOnlyRoot}:ro");
        }

        var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("The containerized NATS server did not start.");
        containers.Add(process.Id, containerName);
        return process;
    }

    public async Task StopAsync(Process process, CancellationToken cancellationToken = default)
    {
        if (containers.Remove(process.Id, out var containerName))
        {
            await RunAsync(["stop", "--time", "2", containerName], cancellationToken);
            await RunAsync(["rm", "--force", containerName], cancellationToken);
        }
        if (!process.HasExited)
            process.Kill(entireProcessTree: true);
        await process.WaitForExitAsync(cancellationToken).WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        await RunAsync(["pod", "rm", "--force", podName], CancellationToken.None);
        containers.Clear();
    }

    private static bool IsWithinRoot(string path, string expectedRoot)
    {
        var relative = Path.GetRelativePath(expectedRoot, path);
        return relative != ".." &&
               !relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) &&
               !Path.IsPathRooted(relative);
    }

    private static async Task RequireSuccessAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        var exitCode = await RunAsync(arguments, cancellationToken);
        if (exitCode != 0)
            throw new InvalidOperationException($"Podman exited with code {exitCode} while preparing a containerized NATS test cluster.");
    }

    private static async Task<int> RunAsync(
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
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);
        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Podman did not start.");
        var output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var error = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        await Task.WhenAll(output, error);
        return process.ExitCode;
    }
}

