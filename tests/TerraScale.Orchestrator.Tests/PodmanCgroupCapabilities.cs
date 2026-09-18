using System.Diagnostics;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Probes once per process whether podman can enforce cgroup-backed resource
/// limits. CI job containers can mount a read-only or non-delegated cgroup
/// hierarchy, where crun cannot write <c>memory.max</c>/<c>pids.max</c> and
/// every resource-limited container start fails. There, the container helpers
/// drop the limits and disable podman cgroup management instead of failing.
/// </summary>
internal static class PodmanCgroupCapabilities
{
    private static readonly Lazy<bool> CgroupLimitsSupported = new(
        ProbeCgroupLimits, LazyThreadSafetyMode.ExecutionAndPublication);

    public static bool CgroupLimits => CgroupLimitsSupported.Value;

    private static readonly Lazy<string?> OverrideConfigPath = new(
        WriteOverrideConfig, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>
    /// Points a podman invocation at the cgroup-disabled override when the
    /// environment cannot manage cgroups. This is what makes podless pods
    /// work: <c>pod create</c> itself has no cgroup flag, so the infra
    /// container is covered only through containers.conf.
    /// </summary>
    public static void Configure(ProcessStartInfo startInfo)
    {
        if (OverrideConfigPath.Value is { } path)
            startInfo.Environment["CONTAINERS_CONF"] = path;
    }

    private static string? WriteOverrideConfig()
    {
        if (CgroupLimitsSupported.Value)
            return null;
        var path = Path.Combine(Path.GetTempPath(), $"ts-orch-podman-{Guid.NewGuid():N}.conf");
        File.WriteAllText(path, "[containers]\ncgroups=\"disabled\"\n");
        if (OperatingSystem.IsLinux())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return path;
    }

    private static bool ProbeCgroupLimits()
    {
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
                     "--security-opt", "no-new-privileges",
                     "--cap-drop", "all",
                     "--pids-limit", "8",
                     "--memory", "32m",
                     TestContainerImages.Nats,
                     "--help",
                 })
            startInfo.ArgumentList.Add(argument);
        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Podman did not start while probing cgroup limits.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(TimeSpan.FromSeconds(120)))
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
            return false;
        }
        Task.WaitAll(output, error);
        return process.ExitCode == 0;
    }
}
