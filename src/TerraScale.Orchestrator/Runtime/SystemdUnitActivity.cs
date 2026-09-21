using System.Globalization;

namespace TerraScale.Orchestrator.Runtime;

/// <summary>
/// An instantaneous manager observation, not cgroup-empty or storage-writer proof.
/// Inactive units can still carry queued starts or control processes.
/// </summary>
internal sealed record SystemdUnitActivity(
    SystemdAllocationState State,
    int? MainProcessId,
    int? ControlProcessId,
    uint? PendingJobId)
{
    internal bool HasNoManagerWork => State == SystemdAllocationState.Stopped &&
        MainProcessId is null && ControlProcessId is null && PendingJobId is null;

    internal static SystemdUnitActivity Read(IReadOnlyDictionary<string, string> values)
    {
        var state = values.GetValueOrDefault("ActiveState") switch
        {
            "active" => SystemdAllocationState.Running,
            "activating" or "reloading" => SystemdAllocationState.Starting,
            "deactivating" => SystemdAllocationState.Stopping,
            "inactive" => SystemdAllocationState.Stopped,
            "failed" => SystemdAllocationState.Failed,
            _ => throw new InvalidOperationException("systemd returned an unknown allocation state.")
        };
        var main = ProcessId(values, "MainPID");
        var control = ProcessId(values, "ControlPID");
        if (!values.TryGetValue("Job", out var job))
            throw new InvalidOperationException("systemd omitted its pending-job observation.");
        uint? pending = null;
        if (job.Length != 0)
        {
            if (!uint.TryParse(job, NumberStyles.None, CultureInfo.InvariantCulture, out var id) || id == 0)
                throw new InvalidOperationException("systemd returned an invalid pending-job observation.");
            pending = id;
            // The job property does not describe its type. Any pending job
            // prevents a serving/stopped claim, including a queued stop/restart.
            if (state != SystemdAllocationState.Stopping) state = SystemdAllocationState.Starting;
        }
        else if (state == SystemdAllocationState.Stopped && (main is not null || control is not null))
        {
            state = SystemdAllocationState.Stopping;
        }
        return new(state, main, control, pending);
    }

    internal static Dictionary<string, string> Properties(string output)
    {
        if (output.Length > 16_384)
            throw new InvalidOperationException("The systemd observation exceeds its bounds.");
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.TrimEnd('\r').Split('=', 2);
            if (parts.Length != 2 || parts[0].Length == 0 || !values.TryAdd(parts[0], parts[1]))
                throw new InvalidOperationException("The systemd observation has malformed or duplicate properties.");
        }
        return values;
    }

    private static int? ProcessId(IReadOnlyDictionary<string, string> values, string name)
    {
        if (!values.TryGetValue(name, out var value) ||
            !int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var pid) || pid < 0)
            throw new InvalidOperationException("systemd returned an invalid or missing process observation.");
        return pid == 0 ? null : pid;
    }
}
