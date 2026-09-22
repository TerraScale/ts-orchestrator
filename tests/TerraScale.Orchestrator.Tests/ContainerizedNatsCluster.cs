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
        PodmanCgroupCapabilities.Configure(startInfo);
        var arguments = new List<string>
        {
            "run", "--rm",
            "--name", containerName,
            "--pod", podName,
            "--label", OwnershipLabel,
            "--security-opt", "no-new-privileges",
            "--cap-drop", "all",
        };
        if (PodmanCgroupCapabilities.CgroupLimits)
        {
            arguments.Add("--pids-limit");
            arguments.Add("128");
            arguments.Add("--memory");
            arguments.Add("256m");
        }
        else
        {
            arguments.Add("--cgroups=disabled");
        }
        arguments.AddRange([
            "--volume", $"{root}:{root}:rw",
            TestContainerImages.Nats,
            "--config", fullConfiguration,
        ]);
        foreach (var argument in arguments)
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
        try
        {
            if (containers.TryGetValue(process.Id, out var containerName))
            {
                await RemoveAndRequireAbsentAsync(
                    ["rm", "--force", "--time", "2", containerName],
                    ["container", "exists", containerName],
                    $"NATS test container '{containerName}'",
                    cancellationToken);
                containers.Remove(process.Id);
            }
        }
        finally
        {
            // Even a failed Podman cleanup command cannot retain the attached
            // client process. The name stays tracked so pod disposal can retry.
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.CompareExchange(ref disposed, 1, 0) != 0) return;
        try
        {
            await RemoveAndRequireAbsentAsync(
                ["pod", "rm", "--force", "--time", "2", podName],
                ["pod", "exists", podName],
                $"NATS test pod '{podName}'",
                CancellationToken.None);
            containers.Clear();
            Volatile.Write(ref disposed, 2);
        }
        finally
        {
            // A failed absence probe must leave cleanup retryable. The owning
            // fixture keeps the local-server lease quarantined until a later
            // disposal proves that the pod is gone.
            if (Volatile.Read(ref disposed) == 1)
                Volatile.Write(ref disposed, 0);
        }
    }

    private static async Task RemoveAndRequireAbsentAsync(
        IReadOnlyList<string> removeArguments,
        IReadOnlyList<string> existsArguments,
        string resource,
        CancellationToken cancellationToken)
    {
        string removalDiagnostic;
        try
        {
            var removal = await RunBoundedAsync(removeArguments, cancellationToken);
            removalDiagnostic = removal.ExitCode == 0
                ? "removal command succeeded"
                : $"removal exit code {removal.ExitCode}: {removal.Diagnostics}";
        }
        catch (TimeoutException exception)
        {
            removalDiagnostic = exception.Message;
        }

        var probe = await RunBoundedAsync(existsArguments, cancellationToken);
        if (probe.ExitCode == 1)
            return;
        if (probe.ExitCode == 0)
        {
            throw new InvalidOperationException(
                $"{resource} still exists after bounded cleanup; {removalDiagnostic}.");
        }
        throw new InvalidOperationException(
            $"Podman could not verify cleanup of {resource}; probe exit code {probe.ExitCode}: " +
            $"{probe.Diagnostics}; {removalDiagnostic}.");
    }

    private static async Task<(int ExitCode, string Diagnostics)> RunBoundedAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            return await RunAsync(arguments, timeout.Token);
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                $"Podman command '{string.Join(' ', arguments)}' exceeded its 10-second cleanup bound",
                exception);
        }
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
        var (exitCode, diagnostics) = await RunAsync(arguments, cancellationToken);
        if (exitCode != 0)
            throw new InvalidOperationException(
                $"Podman exited with code {exitCode} while preparing a containerized NATS test cluster. diagnostics={diagnostics}");
    }

    private static async Task<(int ExitCode, string Diagnostics)> RunAsync(
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
        try
        {
            await process.WaitForExitAsync(cancellationToken);
            await Task.WhenAll(output, error);
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            throw;
        }
        return (process.ExitCode, $"{await output} | {await error}".Trim());
    }
}
