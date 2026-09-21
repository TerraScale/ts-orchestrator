using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

/// <summary>Opt-in adapter rehearsal with isolated transient units in the local user manager.</summary>
[NotInParallel("SystemdLive")]
public sealed class SystemdQueuedJobLiveTests
{
    [Test]
    public async Task Real_inactive_queued_start_is_cancelled_before_its_dependency_can_release_it()
    {
        Skip.Unless(Environment.GetEnvironmentVariable("TS_ORCH_LIVE_SYSTEMD") == "1",
            "Set TS_ORCH_LIVE_SYSTEMD=1 with a local systemd user manager to qualify queued-job cancellation.");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var commands = new ProcessHostCommandRunner();
        var systemctl = Environment.GetEnvironmentVariable("TS_ORCH_LAB_SYSTEMCTL") ?? "/usr/bin/systemctl";
        var systemdRun = Environment.GetEnvironmentVariable("TS_ORCH_LAB_SYSTEMD_RUN") ?? "/usr/bin/systemd-run";
        var sleep = Environment.GetEnvironmentVariable("TS_ORCH_LAB_SLEEP") ?? "/usr/bin/sleep";
        var allocation = new RuntimeAllocationId("gru-queued-" + Guid.NewGuid().ToString("N"));
        var plan = HostRuntimePlan.Create(AdmittedRole.Orchestrator, RuntimeDriver.NativeSystemd,
            allocation, new ArtifactDigest(new string('a', 64)), HostArchitecture.X64);
        var unit = plan.Systemd!.UnitName;
        var blocker = "ts-orch-test-block-" + Guid.NewGuid().ToString("N") + ".service";
        var adapter = new SystemdHostRuntimeAdapter(new UnitCommands(commands, systemctl, unit), userManager: true);
        try
        {
            var block = await commands.RunAsync(systemdRun,
                ["--user", "--no-block", "--collect", "--unit=" + blocker,
                 "--property=Type=oneshot", "--property=TimeoutStartSec=20s", "--", sleep, "60"], deadline.Token);
            await Assert.That(block.ExitCode).IsEqualTo(0);
            var target = await commands.RunAsync(systemdRun,
                ["--user", "--no-block", "--collect", "--unit=" + unit,
                 "--property=Type=exec", "--property=After=" + blocker, "--property=RuntimeMaxSec=20s",
                 $"--property=Description=TerraScale allocation {plan.AllocationId} plan {CanonicalPlanFingerprint.Compute(plan)}",
                 "--", sleep, "60"], deadline.Token);
            await Assert.That(target.ExitCode).IsEqualTo(0);
            var raw = await commands.RunAsync(systemctl,
                ["--user", "show", unit, "--property=ActiveState", "--property=MainPID", "--property=ControlPID", "--property=Job"], deadline.Token);
            await Assert.That(raw.StandardOutput).Contains("ActiveState=inactive\n");
            await Assert.That(raw.StandardOutput).Contains("MainPID=0\n");
            await Assert.That(raw.StandardOutput).Contains("ControlPID=0\n");
            await Assert.That(raw.StandardOutput).DoesNotContain("Job=\n");
            await Assert.That((await adapter.ObserveAsync(plan, deadline.Token)).State).IsEqualTo(SystemdAllocationState.Starting);
            await adapter.StopAsync(plan, deadline.Token);
            var release = await commands.RunAsync(systemctl, ["--user", "stop", blocker], deadline.Token);
            await Assert.That(release.ExitCode).IsEqualTo(0);
            // Once the dependency is gone, the old queued start must still be absent.
            var after = await adapter.ObserveAsync(plan, deadline.Token);
            await Assert.That(after.State is SystemdAllocationState.Absent or SystemdAllocationState.Stopped).IsTrue();
            await Assert.That(after.MainProcessId).IsNull();
            var jobs = await commands.RunAsync(systemctl, ["--user", "show", unit, "--property=Job"], deadline.Token);
            await Assert.That(jobs.ExitCode).IsEqualTo(0);
            await Assert.That(jobs.StandardOutput.Trim()).IsEqualTo("Job=");
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            // Stop the dependent first so releasing the blocker cannot start it during cleanup.
            var observations = new List<HostCommandResult>();
            foreach (var name in new[] { unit, blocker })
            {
                _ = await commands.RunAsync(systemctl, ["--user", "stop", name], cleanup.Token);
                var stopped = await commands.RunAsync(systemctl,
                    ["--user", "show", name, "--property=ActiveState", "--property=MainPID", "--property=ControlPID", "--property=Job"], cleanup.Token);
                observations.Add(stopped);
            }
            foreach (var stopped in observations)
            {
                await Assert.That(stopped.StandardOutput).Contains("ActiveState=inactive\n");
                await Assert.That(stopped.StandardOutput).Contains("MainPID=0\n");
                await Assert.That(stopped.StandardOutput).Contains("ControlPID=0\n");
                await Assert.That(stopped.StandardOutput).Contains("Job=\n");
            }
        }
    }

    private sealed class UnitCommands(IHostCommandRunner runner, string systemctl, string unit) : IHostCommandRunner
    {
        public Task<HostCommandResult> RunAsync(string executable, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
        {
            if (executable != "/usr/bin/systemctl" || !arguments.Contains(unit) || arguments[0] != "--user" ||
                arguments[1] is not ("show" or "stop"))
                throw new InvalidOperationException("The live adapter may only inspect or stop its exact test unit.");
            // Only the fixed binary path is substituted for NixOS; arguments and adapter behavior are unchanged.
            return runner.RunAsync(systemctl, arguments, cancellationToken);
        }
    }
}
