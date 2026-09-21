using System.Globalization;

namespace TerraScale.Orchestrator.Tests;

/// <summary>Test-process identity and liveness, independent of PID 1's orphan-reaping behavior.</summary>
internal sealed record LinuxTestProcess(int Pid, long StartTicks, char State)
{
    internal bool Terminated => State is 'Z' or 'X' or 'x';

    internal static LinuxTestProcess? Read(int pid)
    {
        string stat;
        try { stat = File.ReadAllText($"/proc/{pid}/stat"); }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException) { return null; }
        // procfs returns ESRCH if reaping occurs between opening and reading stat.
        // Other I/O errors must still fail the fixture, rather than manufacture exit evidence.
        catch (IOException exception) when (exception.HResult == 3) { return null; }
        var closing = stat.LastIndexOf(')');
        if (closing < 0 || closing + 2 >= stat.Length)
            throw new InvalidDataException("The test process stat is malformed.");
        var fields = stat[(closing + 2)..].Split(' ');
        if (fields.Length <= 19 || fields[0].Length != 1 ||
            !long.TryParse(fields[19], NumberStyles.None, CultureInfo.InvariantCulture, out var started) || started <= 0)
            throw new InvalidDataException("The test process state or identity is malformed.");
        return new(pid, started, fields[0][0]);
    }

    internal static bool HasTerminated(int pid, long startTicks) =>
        Read(pid) is not { } current || current.StartTicks != startTicks || current.Terminated;

    internal static async Task WaitForTerminationAsync(int pid, long startTicks, CancellationToken cancellationToken)
    {
        // The single-threaded orphan workload fixture may remain a zombie forever in a job
        // container. Supervisors still require direct-child reaping for complete thread-group
        // teardown. This observation is not cgroup-empty or storage-fencing proof.
        while (!HasTerminated(pid, startTicks)) await Task.Delay(10, cancellationToken);
    }
}
