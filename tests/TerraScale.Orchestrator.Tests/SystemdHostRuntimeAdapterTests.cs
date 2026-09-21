using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class SystemdHostRuntimeAdapterTests
{
    private const string Digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Test]
    [Arguments("MainPID=123")]
    [Arguments("ActiveState=active")]
    public async Task AbsentUnitWithConflictingEvidenceCannotBeAdoptedOrStopped(string evidence)
    {
        var observation = new HostCommandResult(1, "LoadState=not-found\nControlPID=0\nJob=\n" +
            (evidence.StartsWith("MainPID", StringComparison.Ordinal) ? "ActiveState=inactive\n" : "MainPID=0\n") + evidence + "\n", "");
        var runner = new RecordingRunner(observation, observation);
        var adapter = new SystemdHostRuntimeAdapter(runner);
        await Assert.That(async () => { await adapter.ObserveAsync(NativePlan(), CancellationToken.None); }).Throws<InvalidOperationException>();
        await Assert.That(() => adapter.StopAsync(NativePlan(), CancellationToken.None)).Throws<InvalidOperationException>();
        await Assert.That(runner.Commands.All(command => command.Arguments.Contains("show"))).IsTrue();
    }

    [Test]
    public async Task AdapterRequiresACommandRunner()
    {
        await Assert.That(() => new SystemdHostRuntimeAdapter(null!))
            .Throws<ArgumentNullException>();
    }

    [Test]
    public async Task ConvergeUsesArgumentListsAndEveryCatalogSecurityProperty()
    {
        var runner = new RecordingRunner(
            new HostCommandResult(1, "LoadState=not-found\nActiveState=inactive\nMainPID=0\nControlPID=0\nJob=\n", "Unit not found"),
            new HostCommandResult(0, string.Empty, string.Empty));
        var adapter = new SystemdHostRuntimeAdapter(runner, userManager: false);
        var plan = NativePlan();

        await adapter.ConvergeAsync(plan, CancellationToken.None);

        var command = runner.Commands.Last();
        await Assert.That(command.Executable).IsEqualTo("/usr/bin/systemd-run");
        await Assert.That(command.Arguments).Contains(plan.Systemd!.UnitName);
        await Assert.That(command.Arguments).Contains(
            $"Description=TerraScale allocation {plan.AllocationId} plan {CanonicalPlanFingerprint.Compute(plan)}");
        await Assert.That(command.Arguments).Contains("NoNewPrivileges=yes");
        await Assert.That(command.Arguments).Contains("ProtectSystem=strict");
        await Assert.That(command.Arguments).Contains("RestrictSUIDSGID=yes");
        await Assert.That(command.Arguments).Contains($"MemoryMax={plan.Resources.MemoryMaxBytes}");
        await Assert.That(command.Arguments).Contains($"CPUWeight={plan.Resources.CpuWeight}");
        await Assert.That(command.Arguments).Contains($"IOWeight={plan.Resources.IoWeight}");
        await Assert.That(command.Arguments).Contains($"Nice={plan.Resources.Nice}");
        await Assert.That(command.Arguments).DoesNotContain("--setenv");
        await Assert.That(command.Arguments).Contains(plan.Systemd.Executable);
    }

    [Test]
    public async Task ObserveMapsSystemdStateWithoutTrustingFreeFormOutput()
    {
        var plan = NativePlan();
        var runner = new RecordingRunner(new HostCommandResult(0,
            $"LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=481\nControlPID=0\nJob=\nResult=success\n" +
            $"Description=TerraScale allocation {plan.AllocationId} plan {CanonicalPlanFingerprint.Compute(plan)}\n",
            string.Empty));
        var adapter = new SystemdHostRuntimeAdapter(runner, userManager: true);

        var observation = await adapter.ObserveAsync(plan, CancellationToken.None);

        await Assert.That(observation.State).IsEqualTo(SystemdAllocationState.Running);
        await Assert.That(observation.MainProcessId).IsEqualTo(481);
        await Assert.That(runner.Commands.Single().Arguments.First()).IsEqualTo("--user");
    }

    [Test]
    public async Task ConvergenceIsIdempotentAndInspectionFailuresStayFailClosed()
    {
        var plan = NativePlan();
        var description = $"Description=TerraScale allocation {plan.AllocationId} plan {CanonicalPlanFingerprint.Compute(plan)}";
        var running = new RecordingRunner(new HostCommandResult(0,
            $"LoadState=loaded\nActiveState=active\nMainPID=481\nControlPID=0\nJob=\nResult=success\n{description}\n",
            string.Empty));

        await new SystemdHostRuntimeAdapter(running).ConvergeAsync(plan, CancellationToken.None);

        await Assert.That(running.Commands).Count().IsEqualTo(1);
        await Assert.That(running.Commands.Single().Executable).IsEqualTo("/usr/bin/systemctl");

        var unavailable = new RecordingRunner(
            new HostCommandResult(1, string.Empty, "D-Bus unavailable"));
        await Assert.That(() => new SystemdHostRuntimeAdapter(unavailable)
                .ConvergeAsync(plan, CancellationToken.None))
            .Throws<InvalidOperationException>();
        await Assert.That(unavailable.Commands).Count().IsEqualTo(1);

        var foreign = new RecordingRunner(new HostCommandResult(0,
            "LoadState=loaded\nActiveState=active\nMainPID=481\nControlPID=0\nJob=\nResult=success\nDescription=foreign\n",
            string.Empty));
        await Assert.That(() => new SystemdHostRuntimeAdapter(foreign)
                .ConvergeAsync(plan, CancellationToken.None))
            .Throws<InvalidOperationException>();
        await Assert.That(foreign.Commands).Count().IsEqualTo(1);
    }

    [Test]
    public async Task AdapterRejectsAPlanWithInjectedExecutableOrProperty()
    {
        var original = NativePlan();
        var injected = original with
        {
            Systemd = original.Systemd! with
            {
                Executable = "/bin/sh",
                Arguments = ["-c", "arbitrary"],
                Properties = original.Systemd.Properties.Concat(["Environment=SECRET=value"]).ToArray()
            }
        };
        var adapter = new SystemdHostRuntimeAdapter(new RecordingRunner());

        await Assert.That(() => adapter.ConvergeAsync(injected, CancellationToken.None))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task StoppingAnExistingUnitRequiresTheExactPreviousPlan()
    {
        var oldPlan = NativePlan();
        var newPlan = NativePlan("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");
        var runningUnderOldPlan = new HostCommandResult(0,
            $"LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=481\nControlPID=0\nJob=\nResult=success\n" +
            $"Description=TerraScale allocation {oldPlan.AllocationId} plan {CanonicalPlanFingerprint.Compute(oldPlan)}\n",
            string.Empty);
        var stopping = new RecordingRunner(
            runningUnderOldPlan, new HostCommandResult(0, string.Empty, string.Empty));

        var denied = new RecordingRunner(runningUnderOldPlan);
        await Assert.That(() => new SystemdHostRuntimeAdapter(denied).StopAsync(newPlan, CancellationToken.None))
            .Throws<InvalidOperationException>();
        await Assert.That(denied.Commands.Count).IsEqualTo(1);
        await new SystemdHostRuntimeAdapter(stopping).StopAsync(oldPlan, CancellationToken.None);

        var stop = stopping.Commands.Last();
        await Assert.That(stop.Executable).IsEqualTo("/usr/bin/systemctl");
        await Assert.That(stop.Arguments).Contains("stop");
        await Assert.That(stop.Arguments).Contains(newPlan.Systemd!.UnitName);

        // The exact-fingerprint fence stays on adoption: observing the old unit under the
        // NEW plan still refuses instead of adopting a mismatched process.
        var observing = new RecordingRunner(runningUnderOldPlan);
        await Assert.That(async () =>
        {
            await new SystemdHostRuntimeAdapter(observing).ObserveAsync(newPlan, CancellationToken.None);
        }).Throws<InvalidOperationException>();

        // A foreign unit squatting on the name is never stopped, let alone adopted.
        var foreign = new RecordingRunner(new HostCommandResult(0,
            "LoadState=loaded\nActiveState=active\nMainPID=481\nControlPID=0\nJob=\nResult=success\nDescription=foreign\n",
            string.Empty));
        await Assert.That(() => new SystemdHostRuntimeAdapter(foreign)
                .StopAsync(newPlan, CancellationToken.None))
            .Throws<InvalidOperationException>();
        await Assert.That(foreign.Commands).Count().IsEqualTo(1);
    }

    private static HostRuntimePlan NativePlan(string digest = Digest) => HostRuntimePlan.Create(
        AdmittedRole.Orchestrator,
        RuntimeDriver.NativeSystemd,
        new RuntimeAllocationId("gru-orchestrator-1"),
        new ArtifactDigest(digest),
        HostArchitecture.Arm64);

    private sealed class RecordingRunner(params HostCommandResult[] results) : IHostCommandRunner
    {
        private readonly Queue<HostCommandResult> _results = new(results);
        public List<(string Executable, IReadOnlyList<string> Arguments)> Commands { get; } = [];

        public Task<HostCommandResult> RunAsync(
            string executable,
            IReadOnlyList<string> arguments,
            CancellationToken cancellationToken)
        {
            Commands.Add((executable, arguments.ToArray()));
            return Task.FromResult(_results.Count == 0
                ? new HostCommandResult(0, string.Empty, string.Empty)
                : _results.Dequeue());
        }
    }
}
