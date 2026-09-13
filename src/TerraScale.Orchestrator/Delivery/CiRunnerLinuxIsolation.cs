using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace TerraScale.Orchestrator.Delivery;

internal sealed record CiRunnerLinuxIsolationObservation(
    bool ReadOnlyRootFilesystem,
    bool RootlessBuildKit,
    bool HostDockerSocketMounted,
    bool NoNewPrivileges,
    bool UserNamespace,
    bool Seccomp,
    bool CgroupV2,
    int CpuLimitMilliCores,
    long MemoryLimitBytes,
    long EphemeralDiskLimitBytes,
    int PidsLimit);

/// <summary>Reads the kernel-enforced isolation that an ephemeral CI runner actually inherited.</summary>
internal static class CiRunnerLinuxIsolationProbe
{
    private const int MaximumKernelFileCharacters = 1024 * 1024;
    private const string CgroupRoot = "/sys/fs/cgroup";

    [SupportedOSPlatform("linux")]
    internal static CiRunnerLinuxIsolationObservation Observe(
        CiRunnerProcessConfiguration configuration,
        CiRunnerBuildKitDaemon daemon)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(daemon);
        if (GetEffectiveUserId() == 0)
            throw new InvalidDataException("A CI runner process cannot run as root.");
        var cgroup = ReadBounded("/proc/self/cgroup");
        var cgroupDirectory = CgroupDirectory(cgroup);
        var observation = Parse(
            ReadBounded("/proc/self/status"),
            cgroup,
            ReadBounded("/proc/self/mountinfo"),
            ReadBounded(Path.Combine(cgroupDirectory, "memory.max")),
            ReadBounded(Path.Combine(cgroupDirectory, "pids.max")),
            ReadBounded(Path.Combine(cgroupDirectory, "cpu.max")),
            Path.Exists("/run/docker.sock") || Path.Exists("/var/run/docker.sock") ||
                !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_HOST")),
            new DriveInfo(configuration.WorkspaceRoot).TotalSize,
            daemon.RootlessIsolationVerified,
            daemon.RootlessIsolationVerified);
        Require(observation, configuration.CpuMilliCores, configuration.MemoryBytes,
            configuration.EphemeralDiskBytes, configuration.Pids);
        return observation;
    }

    internal static CiRunnerLinuxIsolationObservation Parse(
        string status,
        string cgroup,
        string mountInfo,
        string memoryMax,
        string pidsMax,
        string cpuMax,
        bool hostDockerSocketMounted,
        long ephemeralDiskLimitBytes,
        bool rootlessBuildKit,
        bool userNamespace)
    {
        var noNewPrivileges = StatusValue(status, "NoNewPrivs") == 1;
        var seccomp = StatusValue(status, "Seccomp") == 2;
        _ = CgroupDirectory(cgroup);
        var memory = PositiveLong(memoryMax, "memory.max");
        var pids = checked((int)PositiveLong(pidsMax, "pids.max"));
        var cpu = CpuLimit(cpuMax);
        if (ephemeralDiskLimitBytes <= 0)
            throw new InvalidDataException("The CI runner workspace has no bounded disk.");
        return new(
            RootReadOnly(mountInfo),
            rootlessBuildKit,
            hostDockerSocketMounted,
            noNewPrivileges,
            userNamespace,
            seccomp,
            CgroupV2: true,
            cpu,
            memory,
            ephemeralDiskLimitBytes,
            pids);
    }

    internal static void Require(
        CiRunnerLinuxIsolationObservation observation,
        int cpuMilliCores,
        long memoryBytes,
        long ephemeralDiskBytes,
        int pids)
    {
        ArgumentNullException.ThrowIfNull(observation);
        if (!observation.ReadOnlyRootFilesystem || !observation.RootlessBuildKit ||
            observation.HostDockerSocketMounted || !observation.NoNewPrivileges ||
            !observation.UserNamespace || !observation.Seccomp || !observation.CgroupV2)
            throw new InvalidDataException("The CI runner is missing a required Linux isolation control.");
        if (observation.CpuLimitMilliCores > cpuMilliCores ||
            observation.MemoryLimitBytes > memoryBytes ||
            observation.EphemeralDiskLimitBytes > ephemeralDiskBytes ||
            observation.PidsLimit > pids)
            throw new InvalidDataException("The CI runner exceeds its signed cgroup or disk resource ceiling.");
    }

    private static string CgroupDirectory(string value)
    {
        var lines = Lines(value);
        if (lines is not [var line] || !line.StartsWith("0::", StringComparison.Ordinal))
            throw new InvalidDataException("The CI runner is not in one unambiguous cgroup-v2 hierarchy.");
        var relative = line[3..].TrimStart('/');
        var path = Path.GetFullPath(Path.Combine(CgroupRoot, relative));
        if (path != CgroupRoot && !path.StartsWith(CgroupRoot + '/', StringComparison.Ordinal))
            throw new InvalidDataException("The CI runner cgroup path escapes the unified hierarchy.");
        return path;
    }

    private static bool RootReadOnly(string value)
    {
        var roots = Lines(value)
            .Select(static line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Where(static fields => fields.Length >= 7 && fields[4] == "/")
            .ToArray();
        if (roots is not [var root])
            throw new InvalidDataException("The CI runner root mount is ambiguous.");
        var options = root[5].Split(',', StringSplitOptions.RemoveEmptyEntries);
        return options.Contains("ro", StringComparer.Ordinal) &&
            !options.Contains("rw", StringComparer.Ordinal);
    }

    private static int StatusValue(string value, string key)
    {
        var matches = Lines(value)
            .Where(line => line.StartsWith(key + ':', StringComparison.Ordinal))
            .ToArray();
        if (matches is not [var match] ||
            !int.TryParse(match[(key.Length + 1)..].Trim(), NumberStyles.None,
                CultureInfo.InvariantCulture, out var parsed))
            throw new InvalidDataException($"The CI runner process status has no valid {key} value.");
        return parsed;
    }

    private static int CpuLimit(string value)
    {
        var fields = value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (fields is not [var quotaValue, var periodValue] || quotaValue == "max" ||
            !long.TryParse(quotaValue, NumberStyles.None, CultureInfo.InvariantCulture, out var quota) ||
            !long.TryParse(periodValue, NumberStyles.None, CultureInfo.InvariantCulture, out var period) ||
            quota <= 0 || period <= 0)
            throw new InvalidDataException("The CI runner cpu.max is unbounded or invalid.");
        return checked((int)((checked(quota * 1000) + period - 1) / period));
    }

    private static long PositiveLong(string value, string name)
    {
        if (!long.TryParse(value.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) ||
            parsed <= 0)
            throw new InvalidDataException($"The CI runner {name} is unbounded or invalid.");
        return parsed;
    }

    private static string ReadBounded(string path)
    {
        var value = File.ReadAllText(path);
        if (value.Length is < 1 or > MaximumKernelFileCharacters)
            throw new InvalidDataException("A CI runner kernel isolation file exceeds its bound.");
        return value;
    }

    private static string[] Lines(string value) => value
        .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEffectiveUserId();
}

