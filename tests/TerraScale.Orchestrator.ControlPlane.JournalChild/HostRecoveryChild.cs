using System.Diagnostics;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Runtime;

/// <summary>Test-only crash harness. No broker, report ACK, or application installation marker exists.</summary>
internal static class HostRecoveryChild
{
    internal static async Task<int> RunAsync(string[] args)
    {
        if (args is not [_, var mode, var directory, var signal, var nativePath]) return 64;
        var identity = new HostWorkloadIdentity("gru", "host-1", "production");
        using var inventory = HostWorkloadInventory.Open(directory, identity);
        if (mode == "hold")
        {
            await File.WriteAllTextAsync(signal, "owned");
            await Task.Delay(Timeout.InfiniteTimeSpan);
            return 0;
        }
        var native = new ChildNative(nativePath, signal);
        await using var lifetime = new HostWorkloadLifetime(native, CancellationToken.None, inventory, native);
        await lifetime.RequireRecoveredAsync(CancellationToken.None);
        if (mode == "recover")
        {
            await File.WriteAllTextAsync(signal, JsonSerializer.Serialize(lifetime.RecoverySnapshot));
            return 0;
        }
        if (mode != "crash-after-start") return 64;
        await lifetime.ConvergeAsync(HostRuntimePlan.Create(AdmittedRole.TerraBaseMember, RuntimeDriver.NativeSystemd,
            HostConvergenceRuntime.AllocationIdFor(identity.Cell, identity.NodeId, "terrabase-server"),
            new(new string('a', 64)), HostArchitecture.X64), CancellationToken.None);
        return 66; // The simulated lost start response must never return.
    }

    private sealed record NativeRecord(int Pid, long StartedAt, string Fingerprint, string AllocationId);
    private sealed class ChildNative(string path, string signal) : IHostRuntimeConverger, IHostNativeInventoryProbe
    {
        public async Task ConvergeAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
        {
            using var child = Process.Start(new ProcessStartInfo("sleep") { ArgumentList = { "120" }, UseShellExecute = false })!;
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new NativeRecord(child.Id, StartTicks(child.Id),
                CanonicalPlanFingerprint.Compute(plan), plan.AllocationId.Value)), cancellationToken);
            await File.WriteAllTextAsync(signal, "native-started-response-withheld", cancellationToken);
            await Task.Delay(Timeout.InfiniteTimeSpan); // Deliberately ignores cancellation and never responds.
        }
        public async Task StopAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
        {
            var record = Read();
            if (record is null) return;
            if (record.Fingerprint != CanonicalPlanFingerprint.Compute(plan) || record.AllocationId != plan.AllocationId.Value)
                throw new InvalidOperationException("The test child belongs to another plan.");
            using var process = Process.GetProcessById(record.Pid);
            if (StartTicks(record.Pid) != record.StartedAt) throw new InvalidOperationException("Test PID reused.");
            process.Kill();
            await process.WaitForExitAsync(cancellationToken);
            File.Delete(path);
        }
        public Task<SystemdAllocationObservation> ObserveAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
        {
            var record = Read();
            return Task.FromResult(new SystemdAllocationObservation(plan.Systemd!.UnitName,
                record is null ? SystemdAllocationState.Absent : SystemdAllocationState.Running, record?.Pid, "test-process"));
        }
        public Task<HostNativeInventorySnapshot> ReadAsync(HostWorkloadIdentity identity, CancellationToken cancellationToken)
        {
            var record = Read();
            return Task.FromResult(new HostNativeInventorySnapshot([RuntimeDriver.NativeSystemd, RuntimeDriver.OciContainer],
                record is null ? [] : [new(RuntimeDriver.NativeSystemd, record.AllocationId, record.Fingerprint, SystemdAllocationState.Running, record.Pid)]));
        }
        private static long StartTicks(int pid)
        {
            var stat = File.ReadAllText($"/proc/{pid}/stat");
            return long.Parse(stat[(stat.LastIndexOf(')') + 2)..].Split(' ')[19], System.Globalization.CultureInfo.InvariantCulture);
        }
        private NativeRecord? Read() => File.Exists(path) ? JsonSerializer.Deserialize<NativeRecord>(File.ReadAllText(path))! : null;
    }
}
