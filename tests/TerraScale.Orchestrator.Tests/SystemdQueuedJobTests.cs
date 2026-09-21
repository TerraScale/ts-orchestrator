using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class SystemdQueuedJobTests
{
    [Test]
    [Arguments("Job=41\nControlPID=0\n", nameof(SystemdAllocationState.Starting))]
    [Arguments("Job=\nControlPID=72\n", nameof(SystemdAllocationState.Stopping))]
    public async Task Inactive_unit_with_queued_work_is_not_stopped(string evidence, string expected)
    {
        var plan = Plan();
        var runner = new Runner(Loaded(plan, evidence));
        var observation = await new SystemdHostRuntimeAdapter(runner).ObserveAsync(plan, CancellationToken.None);
        await Assert.That(observation.State.ToString()).IsEqualTo(expected);
    }

    [Test]
    public async Task Stop_cancels_a_start_job_even_before_the_main_process_exists()
    {
        var plan = Plan();
        var runner = new Runner(Loaded(plan, "Job=41\nControlPID=0\n"));
        await new SystemdHostRuntimeAdapter(runner).StopAsync(plan, CancellationToken.None);
        await Assert.That(runner.Stops).IsEqualTo(1);
    }

    [Test]
    [Arguments("Job=\nControlPID=0\n", "MainPID=invalid")]
    [Arguments("Job=\nControlPID=-1\n", "MainPID=0")]
    [Arguments("Job=invalid\nControlPID=0\n", "MainPID=0")]
    [Arguments("ControlPID=0\n", "MainPID=0")]
    [Arguments("Job=\n", "MainPID=0")]
    public async Task Missing_or_malformed_process_and_job_evidence_cannot_mean_stopped(string evidence, string pid)
    {
        var plan = Plan();
        var result = Loaded(plan, evidence) with { StandardOutput = Loaded(plan, evidence).StandardOutput.Replace("MainPID=0", pid, StringComparison.Ordinal) };
        var adapter = new SystemdHostRuntimeAdapter(new Runner(result));
        await Assert.That(async () => { await adapter.ObserveAsync(plan, CancellationToken.None); }).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Missing_unit_with_a_pending_job_cannot_mean_absent()
    {
        var adapter = new SystemdHostRuntimeAdapter(new Runner(new(1,
            "LoadState=not-found\nActiveState=inactive\nMainPID=0\nControlPID=0\nJob=41\n", "")));
        await Assert.That(async () => { await adapter.ObserveAsync(Plan(), CancellationToken.None); }).Throws<InvalidOperationException>();
    }

    private static HostRuntimePlan Plan() => HostRuntimePlan.Create(AdmittedRole.Orchestrator,
        RuntimeDriver.NativeSystemd, new RuntimeAllocationId("gru-queued-test"), new ArtifactDigest(new string('a', 64)), HostArchitecture.X64);

    private static HostCommandResult Loaded(HostRuntimePlan plan, string evidence) => new(0,
        "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nResult=success\n" + evidence +
        $"Description=TerraScale allocation {plan.AllocationId} plan {CanonicalPlanFingerprint.Compute(plan)}\n", "");

    private sealed class Runner(HostCommandResult observation) : IHostCommandRunner
    {
        internal int Stops { get; private set; }
        public Task<HostCommandResult> RunAsync(string executable, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
        {
            if (arguments.Contains("show")) return Task.FromResult(observation);
            if (arguments.Contains("stop")) { Stops++; return Task.FromResult(new HostCommandResult(0, "", "")); }
            throw new InvalidOperationException("Unexpected unit command.");
        }
    }
}
