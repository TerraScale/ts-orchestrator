using System.Diagnostics;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class ProcessLifecycleTests
{
    [Test]
    public async Task CommandOutputCaptureDrainsAfterItsBound()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var result = await new ProcessHostCommandRunner().RunAsync(
            TestHostExecutables.Resolve("bash"),
            ["-c", "printf '%0100000d' 0"],
            CancellationToken.None);

        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(result.StandardOutput.Length).IsEqualTo(64 * 1024);
    }

    [Test]
    public async Task CancellationStopsDescendants()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var pidFile = Path.GetTempFileName();
        var childProcessId = 0;
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            var execution = new ProcessHostCommandRunner().RunAsync(
                TestHostExecutables.Resolve("bash"),
                ["-c", "sleep 60 & printf '%s' $! > \"$1\"; wait", "terrascale-process-test", pidFile],
                cancellation.Token);
            childProcessId = await ReadProcessIdAsync(pidFile, cancellation.Token);

            await cancellation.CancelAsync();

            await Assert.That(async () => await execution).Throws<OperationCanceledException>();
            await Assert.That(await WaitForExitAsync(childProcessId)).IsTrue();
        }
        finally
        {
            TryKill(childProcessId);
            File.Delete(pidFile);
        }
    }

    private static async Task<int> ReadProcessIdAsync(string path, CancellationToken cancellationToken)
    {
        while (true)
        {
            var value = await File.ReadAllTextAsync(path, cancellationToken);
            if (int.TryParse(value, out var processId) && processId > 0)
            {
                return processId;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(20), cancellationToken);
        }
    }

    private static async Task<bool> WaitForExitAsync(int processId)
    {
        for (var attempt = 0; attempt < 200; attempt++)
        {
            if (HasTerminated(processId))
            {
                return true;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(20));
        }

        return false;
    }

    /// <summary>
    /// Reads the kernel's view of the process: /proc/<pid>/stat disappears
    /// once the process is gone, and a job container whose PID 1 does not
    /// reap orphans keeps a killed process as a state-Z entry forever, which
    /// <see cref="Process.HasExited"/> does not report as exited.
    /// </summary>
    private static bool HasTerminated(int processId)
    {
        try
        {
            var stat = File.ReadAllText($"/proc/{processId}/stat");
            var state = stat.LastIndexOf(')') is var close and >= 0 && close + 2 < stat.Length
                ? stat[close + 2]
                : 'Z';
            return state is 'Z' or 'X' or 'x';
        }
        catch (IOException)
        {
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static void TryKill(int processId)
    {
        if (processId <= 0)
        {
            return;
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            process.Kill(entireProcessTree: true);
        }
        catch (ArgumentException)
        {
        }
        catch (InvalidOperationException)
        {
        }
    }
}
