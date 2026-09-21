using System.Diagnostics;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

/// <summary>Opt-in rehearsal against an isolated real containerd daemon and a loopback registry.</summary>
[NotInParallel("ContainerdLive")]
public sealed class ContainerdLiveTests
{
    [Test]
    public async Task Pinned_image_converges_restarts_and_is_deleted_by_the_real_client()
    {
        Skip.Unless(Environment.GetEnvironmentVariable("TS_ORCH_LIVE_CONTAINERD") == "1",
            "Run the isolated containerd qualification harness to exercise the real runtime.");
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        var client = new NerdctlContainerdClient(Environment.GetEnvironmentVariable("TS_ORCH_LAB_NERDCTL")!);
        var plan = HostRuntimePlan.Create(AdmittedRole.Authentication, RuntimeDriver.OciContainer,
            new RuntimeAllocationId("oci-lab-auth"),
            new ArtifactDigest(Environment.GetEnvironmentVariable("TS_ORCH_LAB_IMAGE_DIGEST")!), HostArchitecture.X64);
        var adapter = new ContainerdHostRuntimeAdapter(client);
        try
        {
            await adapter.ConvergeAsync(plan, timeout.Token);
            var running = await adapter.ObserveAsync(plan, timeout.Token);
            await Assert.That(running.State).IsEqualTo(ContainerdAllocationState.Running);
            await Assert.That(running.ProcessId ?? 0).IsGreaterThan(0);
            var processStatus = await File.ReadAllTextAsync($"/proc/{running.ProcessId}/status", timeout.Token);
            await Assert.That(processStatus).Contains("Uid:\t65532\t65532\t65532\t65532");
            await Assert.That(processStatus).Contains("CapEff:\t0000000000000000");
            await Assert.That(processStatus).Contains("NoNewPrivs:\t1");
            await Assert.That(processStatus).Contains("Seccomp:\t2");
            var cgroup = (await File.ReadAllLinesAsync($"/proc/{running.ProcessId}/cgroup", timeout.Token))
                .Single(line => line.StartsWith("0::", StringComparison.Ordinal))[3..];
            var cgroupRoot = "/sys/fs/cgroup" + cgroup;
            await Assert.That((await File.ReadAllTextAsync(cgroupRoot + "/memory.max", timeout.Token)).Trim())
                .IsEqualTo(plan.Resources.MemoryMaxBytes.ToString(System.Globalization.CultureInfo.InvariantCulture));
            await Assert.That((await File.ReadAllTextAsync(cgroupRoot + "/memory.swap.max", timeout.Token)).Trim()).IsEqualTo("0");
            await Assert.That((await File.ReadAllTextAsync(cgroupRoot + "/pids.max", timeout.Token)).Trim())
                .IsEqualTo(plan.Resources.TasksMax.ToString(System.Globalization.CultureInfo.InvariantCulture));
            var write = await RunLabAsync(["exec", plan.Oci!.ContainerId, "/bin/busybox", "touch", "/write-probe"], timeout.Token);
            await Assert.That(write.ExitCode).IsNotEqualTo(0);
            var wrongPlan = HostRuntimePlan.Create(AdmittedRole.Authentication, RuntimeDriver.OciContainer,
                plan.AllocationId, new ArtifactDigest(new string('b', 64)), HostArchitecture.X64);
            await Assert.That(() => adapter.ConvergeAsync(wrongPlan, timeout.Token)).Throws<InvalidOperationException>();
            await Assert.That(() => adapter.StopAsync(wrongPlan, timeout.Token)).Throws<InvalidOperationException>();
            await adapter.ConvergeAsync(plan, timeout.Token);
            await Assert.That((await adapter.ObserveAsync(plan, timeout.Token)).ProcessId).IsEqualTo(running.ProcessId);
            await client.StopAsync(ContainerdHostRuntimeAdapter.Namespace, plan.Oci!.ContainerId, timeout.Token);
            await adapter.ConvergeAsync(plan, timeout.Token);
            await Assert.That((await adapter.ObserveAsync(plan, timeout.Token)).State).IsEqualTo(ContainerdAllocationState.Running);
            await adapter.DeleteAsync(plan, timeout.Token);
            await Assert.That((await adapter.ObserveAsync(plan, timeout.Token)).State).IsEqualTo(ContainerdAllocationState.Absent);
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await adapter.DeleteAsync(plan, cleanup.Token);
        }
    }

    [Test]
    public async Task Real_image_identity_cannot_be_replaced_by_an_admission_label()
    {
        Skip.Unless(Environment.GetEnvironmentVariable("TS_ORCH_LIVE_CONTAINERD") == "1",
            "Run the isolated containerd qualification harness to exercise the real runtime.");
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(1));
        var client = new NerdctlContainerdClient(Environment.GetEnvironmentVariable("TS_ORCH_LAB_NERDCTL")!);
        var plan = HostRuntimePlan.Create(AdmittedRole.Authentication, RuntimeDriver.OciContainer,
            new RuntimeAllocationId("oci-lab-auth"),
            new ArtifactDigest(Environment.GetEnvironmentVariable("TS_ORCH_LAB_IMAGE_DIGEST")!), HostArchitecture.X64);
        var image = plan.Oci!.ImageReference.Replace("/ts-auth@", "/foreign@", StringComparison.Ordinal);
        try
        {
            await client.PullAsync(ContainerdHostRuntimeAdapter.Namespace, image, plan.Oci.Platform, timeout.Token);
            var create = await RunLabAsync(["create", "--name", plan.Oci.ContainerId,
                "--label", $"terrascale.image={plan.Oci.ImageReference}",
                "--label", $"terrascale.platform={plan.Oci.Platform}",
                "--label", $"terrascale.plan={CanonicalPlanFingerprint.Compute(plan)}", image], timeout.Token);
            await Assert.That(create.ExitCode).IsEqualTo(0);
            var observed = await client.ObserveAsync(ContainerdHostRuntimeAdapter.Namespace, plan.Oci.ContainerId, timeout.Token);
            await Assert.That(observed.ImageReference).IsEqualTo(image);
            var adapter = new ContainerdHostRuntimeAdapter(client);
            await Assert.That(() => adapter.ConvergeAsync(plan, timeout.Token)).Throws<InvalidOperationException>();
            await Assert.That(() => adapter.StopAsync(plan, timeout.Token)).Throws<InvalidOperationException>();
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var deleted = await RunLabAsync(["rm", "-f", plan.Oci.ContainerId], cleanup.Token);
            await Assert.That(deleted.ExitCode).IsEqualTo(0);
        }
    }

    private static async Task<(int ExitCode, string Output)> RunLabAsync(string[] arguments, CancellationToken cancellationToken)
    {
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("TS_ORCH_LAB_NERDCTL")!)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        start.ArgumentList.Add("--namespace");
        start.ArgumentList.Add(ContainerdHostRuntimeAdapter.Namespace);
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var error = process.StandardError.ReadToEndAsync(cancellationToken);
        try { await process.WaitForExitAsync(cancellationToken); }
        catch
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            throw;
        }
        await error;
        return (process.ExitCode, await output);
    }
}
