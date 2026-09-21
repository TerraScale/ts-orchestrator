using System.Diagnostics;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class HostRecoveryProcessTests
{
    [Test]
    public async Task OS_releases_exclusive_inventory_only_when_the_owner_process_exits()
    {
        await using var files = new HostInventoryFixture();
        files.Inventory.Dispose();
        var signal = Path.Combine(files.Directory, "ready");
        using var owner = Start("hold", files.Directory, signal, "unused");
        try
        {
            await WaitForFileAsync(signal, owner);
            await Assert.That(HostWorkloadInventoryTests.Rejected(() => HostWorkloadInventory.Open(files.Directory, files.Identity))).IsTrue();
        }
        finally { await KillAsync(owner); }
        using var next = HostWorkloadInventory.Open(files.Directory, files.Identity);
        await Assert.That(next.Plans).IsEmpty();
    }

    [Test]
    public async Task Killed_supervisor_leaves_a_real_workload_that_the_next_supervisor_recovers_without_NATS()
    {
        await using var files = new HostInventoryFixture();
        files.Inventory.Dispose();
        var signal = Path.Combine(files.Directory, "started");
        var native = Path.Combine(files.Directory, "native-process.json");
        using var owner = Start("crash-after-start", files.Directory, signal, native);
        Process? workload = null;
        long workloadStarted = 0;
        try
        {
            await WaitForFileAsync(signal, owner);
            using var record = JsonDocument.Parse(File.ReadAllText(native));
            workload = Process.GetProcessById(record.RootElement.GetProperty("Pid").GetInt32());
            workloadStarted = record.RootElement.GetProperty("StartedAt").GetInt64();
            await Assert.That(LinuxTestProcess.HasTerminated(workload.Id, workloadStarted)).IsFalse();
            await KillAsync(owner);
            await Assert.That(LinuxTestProcess.HasTerminated(workload.Id, workloadStarted)).IsFalse();
            using (var inspect = HostWorkloadInventory.Open(files.Directory, files.Identity))
                await Assert.That(inspect.Plans.Count).IsEqualTo(1);
            var recovered = Path.Combine(files.Directory, "recovered");
            using var next = Start("recover", files.Directory, recovered, native);
            try
            {
                await next.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
                if (next.ExitCode != 0) throw new InvalidOperationException("Recovery child failed: " + await next.StandardError.ReadToEndAsync());
                using var receipt = JsonDocument.Parse(File.ReadAllText(recovered));
                await Assert.That(receipt.RootElement.GetProperty("State").GetString()).IsEqualTo("ready");
                await Assert.That(receipt.RootElement.GetProperty("StoppedAllocations").GetInt32()).IsEqualTo(1);
                await Assert.That(LinuxTestProcess.HasTerminated(workload.Id, workloadStarted)).IsTrue();
                using var inventory = HostWorkloadInventory.Open(files.Directory, files.Identity);
                await Assert.That(inventory.Plans).IsEmpty();
            }
            finally { await KillAsync(next); }
        }
        finally
        {
            try { await KillAsync(owner); }
            finally
            {
                if (workload is not null)
                {
                    try { await KillAsync(workload, workloadStarted); }
                    finally { workload.Dispose(); }
                }
            }
        }
    }

    private static Process Start(string mode, string directory, string signal, string native)
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "TerraScale.Orchestrator.slnx"))) root = root.Parent;
        if (root is null) throw new InvalidOperationException("Repository root is required for the process harness.");
#if DEBUG
        const string configuration = "Debug";
#else
        const string configuration = "Release";
#endif
        var child = Path.Combine(root.FullName, "tests", "TerraScale.Orchestrator.ControlPlane.JournalChild", "bin", configuration,
            "net11.0", "linux-x64", "TerraScale.Orchestrator.ControlPlane.JournalChild");
        if (!File.Exists(child)) throw new InvalidOperationException("Build the solution before running crash-recovery process tests.");
        return Process.Start(new ProcessStartInfo(child)
        {
            ArgumentList = { "host-recovery", mode, directory, signal, native }, UseShellExecute = false,
            RedirectStandardOutput = true, RedirectStandardError = true
        }) ?? throw new InvalidOperationException("Could not start the host supervisor test child.");
    }

    private static async Task WaitForFileAsync(string path, Process process)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        while (!File.Exists(path))
        {
            if (process.HasExited) throw new InvalidOperationException("Supervisor child failed: " + await process.StandardError.ReadToEndAsync(deadline.Token));
            await Task.Delay(10, deadline.Token);
        }
    }
    private static async Task KillAsync(Process process, long? expectedStart = null)
    {
        if (expectedStart is null)
        {
            // Direct child supervisors must finish their whole thread group and release the
            // inventory lock. A leader's /proc state alone can precede that final teardown.
            if (!process.HasExited) process.Kill();
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(3));
            return;
        }
        var before = LinuxTestProcess.Read(process.Id);
        if (before is null || before.Terminated || before.StartTicks != expectedStart) return;
        if (!process.HasExited) process.Kill();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        await LinuxTestProcess.WaitForTerminationAsync(process.Id, before.StartTicks, deadline.Token);
    }
}
