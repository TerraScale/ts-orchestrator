using System.Diagnostics;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class ProcessLifecycleTests
{
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
                "/usr/bin/bash",
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
            try
            {
                using var process = Process.GetProcessById(processId);
                if (process.HasExited)
                {
                    return true;
                }
            }
            catch (ArgumentException)
            {
                return true;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(20));
        }

        return false;
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
