using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeSystemdRuntimeAdmissionTests
{
    private const string Digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Test]
    public async Task AdmitsCanonicalNativeTerraBaseOrchestratorAndNatsPlans()
    {
        foreach (var (role, allocation) in new[]
        {
            (AdmittedRole.TerraBaseMember, "gru-terrabase-1"),
            (AdmittedRole.Orchestrator, "gru-orchestrator-1"),
            (AdmittedRole.ControlNatsServer, "gru-control-nats-1"),
            (AdmittedRole.ProductNatsServer, "gru-product-nats-1")
        })
        {
            var runner = new RecordingRunner(
                new HostCommandResult(1, "LoadState=not-found\n", "Unit not found"),
                new HostCommandResult(0, string.Empty, string.Empty));
            var admission = NativeSystemdRuntimeAdmission.Create(
                NativePlan(role, allocation),
                AdmittedHostProbe(),
                runner);

            await admission.ConvergeAsync(CancellationToken.None);

            await Assert.That(runner.Commands).Count().IsEqualTo(2);
            await Assert.That(runner.Commands[0].Executable).IsEqualTo("/usr/bin/systemctl");
            await Assert.That(runner.Commands[1].Executable).IsEqualTo("/usr/bin/systemd-run");
        }
    }

    [Test]
    public async Task EveryFailedHostAdmissionIsRejectedBeforeAnyRunnerCall()
    {
        var failures = new[]
        {
            new SystemdHostProbeResult(false, true, true, true, true),
            new SystemdHostProbeResult(true, false, true, true, true),
            new SystemdHostProbeResult(true, true, false, true, true),
            new SystemdHostProbeResult(true, true, true, false, true),
            new SystemdHostProbeResult(true, true, true, true, false)
        };

        foreach (var failedProbe in failures)
        {
            var runner = new RecordingRunner();

            await Assert.That(() => NativeSystemdRuntimeAdmission.Create(
                    NativePlan(AdmittedRole.Orchestrator, "gru-orchestrator-1"),
                    new RecordingProbe(failedProbe),
                    runner))
                .Throws<InvalidOperationException>();
            await Assert.That(runner.Commands).IsEmpty();
        }
    }

    [Test]
    public async Task ProductionProbeIsReadOnlyAndUsesTheFixedAdmissionPaths()
    {
        var probe = new LinuxSystemdHostProbe();
        var evidence = probe.Probe();

        await Assert.That(evidence.IsLinux).IsEqualTo(
            OperatingSystem.IsLinux());
        await Assert.That(LinuxSystemdHostProbe.SystemctlPath).IsEqualTo("/usr/bin/systemctl");
        await Assert.That(LinuxSystemdHostProbe.SystemdRunPath).IsEqualTo("/usr/bin/systemd-run");
        await Assert.That(LinuxSystemdHostProbe.SystemdPid1CommPath).IsEqualTo("/proc/1/comm");
        await Assert.That(LinuxSystemdHostProbe.CgroupV2ControllersPath)
            .IsEqualTo("/sys/fs/cgroup/cgroup.controllers");
    }

    [Test]
    public async Task OciPlansAndOciOnlyRolesAreRejectedBeforeExecutorConstruction()
    {
        var runner = new RecordingRunner();
        var ociPlan = HostRuntimePlan.Create(
            AdmittedRole.Platform,
            RuntimeDriver.OciContainer,
            new RuntimeAllocationId("gru-platform-1"),
            new ArtifactDigest(Digest),
            HostArchitecture.Arm64);
        var nativePlanWithOciOnlyRole = NativePlan(AdmittedRole.Orchestrator, "gru-orchestrator-1") with
        {
            Role = AdmittedRole.Platform
        };

        await Assert.That(() => NativeSystemdRuntimeAdmission.Create(
                ociPlan,
                AdmittedHostProbe(),
                runner))
            .Throws<InvalidOperationException>();
        await Assert.That(() => NativeSystemdRuntimeAdmission.Create(
                nativePlanWithOciOnlyRole,
                AdmittedHostProbe(),
                runner))
            .Throws<InvalidOperationException>();
        await Assert.That(runner.Commands).IsEmpty();
    }

    [Test]
    public async Task EveryCanonicalPlanTamperClassIsRejectedBeforeRunnerCall()
    {
        var original = NativePlan(AdmittedRole.Orchestrator, "gru-orchestrator-1");
        var tamperedPlans = new Dictionary<string, HostRuntimePlan>
        {
            ["executable"] = original with
            {
                Systemd = original.Systemd! with { Executable = "/bin/sh" }
            },
            ["arguments"] = original with
            {
                Systemd = original.Systemd! with { Arguments = ["-c", "injected"] }
            },
            ["properties"] = original with
            {
                Systemd = original.Systemd! with
                {
                    Properties = original.Systemd.Properties.Concat(["Environment=SECRET=value"]).ToArray()
                }
            },
            ["resources"] = original with
            {
                Resources = original.Resources with { MemoryMaxBytes = 512L * 1024 * 1024 }
            },
            ["allocation"] = original with
            {
                AllocationId = new RuntimeAllocationId("gru-orchestrator-tampered")
            },
            ["digest"] = original with
            {
                ArtifactDigest = new ArtifactDigest(
                    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
            }
        };

        foreach (var tampered in tamperedPlans)
        {
            var runner = new RecordingRunner();

            await Assert.That(() => NativeSystemdRuntimeAdmission.Create(
                    tampered.Value,
                    AdmittedHostProbe(),
                    runner))
                .Throws<InvalidOperationException>();
            await Assert.That(runner.Commands).IsEmpty();
        }
    }

    [Test]
    public async Task AcceptedAdmissionUsesSystemManagerFixedPathsArgumentListsAndHardenedProperties()
    {
        var plan = NativePlan(AdmittedRole.ControlNatsServer, "gru-control-nats-1");
        var runner = new RecordingRunner(
            new HostCommandResult(1, "LoadState=not-found\n", "Unit not found"),
            new HostCommandResult(0, string.Empty, string.Empty));
        var admission = NativeSystemdRuntimeAdmission.Create(
            plan,
            AdmittedHostProbe(),
            runner);

        await admission.ConvergeAsync(CancellationToken.None);

        var observe = runner.Commands[0];
        var start = runner.Commands[1];
        await Assert.That(observe.Executable).IsEqualTo("/usr/bin/systemctl");
        await Assert.That(observe.Arguments).DoesNotContain("--user");
        await Assert.That(observe.Arguments.First()).IsEqualTo("show");
        await Assert.That(observe.Arguments).Contains(plan.Systemd!.UnitName);
        await Assert.That(start.Executable).IsEqualTo("/usr/bin/systemd-run");
        await Assert.That(start.Arguments).DoesNotContain("--user");
        await Assert.That(start.Arguments).Contains("--unit");
        await Assert.That(start.Arguments).Contains(plan.Systemd.UnitName);
        await Assert.That(start.Arguments).Contains("--");
        await Assert.That(start.Arguments).Contains(plan.Systemd.Executable);
        await Assert.That(start.Arguments).Contains("--config");
        await Assert.That(start.Arguments).Contains("Type=exec");
        await Assert.That(start.Arguments).Contains("NoNewPrivileges=yes");
        await Assert.That(start.Arguments).Contains("PrivateTmp=yes");
        await Assert.That(start.Arguments).Contains("ProtectSystem=strict");
        await Assert.That(start.Arguments).Contains("ProtectHome=yes");
        await Assert.That(start.Arguments).Contains("ProtectKernelTunables=yes");
        await Assert.That(start.Arguments).Contains("ProtectKernelModules=yes");
        await Assert.That(start.Arguments).Contains("ProtectControlGroups=yes");
        await Assert.That(start.Arguments).Contains("RestrictSUIDSGID=yes");
        await Assert.That(start.Arguments).Contains("LockPersonality=yes");
        await Assert.That(start.Arguments).Contains("MemorySwapMax=0");
        await Assert.That(start.Arguments).Contains($"MemoryMax={plan.Resources.MemoryMaxBytes}");
        await Assert.That(start.Arguments).Contains($"MemoryHigh={plan.Resources.MemoryHighBytes}");
        await Assert.That(start.Arguments).Contains($"TasksMax={plan.Resources.TasksMax}");
        await Assert.That(start.Arguments).Contains($"CPUQuota={plan.Resources.CpuQuotaPercent}%");
        await Assert.That(start.Arguments).Contains($"CPUWeight={plan.Resources.CpuWeight}");
        await Assert.That(start.Arguments).Contains($"IOWeight={plan.Resources.IoWeight}");
        await Assert.That(start.Arguments).Contains($"Nice={plan.Resources.Nice}");
    }

    [Test]
    public async Task AdmissionNeverTurnsAllocationInputIntoShellOrPathExecution()
    {
        var plan = NativePlan(AdmittedRole.Orchestrator, "gru-orchestrator-1");
        var runner = new RecordingRunner(
            new HostCommandResult(1, "LoadState=not-found\n", string.Empty),
            new HostCommandResult(0, string.Empty, string.Empty));
        var admission = NativeSystemdRuntimeAdmission.Create(
            plan,
            AdmittedHostProbe(),
            runner);

        await admission.ConvergeAsync(CancellationToken.None);

        await Assert.That(runner.Commands.All(command =>
                command.Executable is "/usr/bin/systemctl" or "/usr/bin/systemd-run"))
            .IsTrue();
        await Assert.That(runner.Commands.SelectMany(command => command.Arguments)
                .Any(argument => argument is "sh" or "bash" or "-c" ||
                    argument.Contains(";", StringComparison.Ordinal) ||
                    argument.Contains("$(", StringComparison.Ordinal)))
            .IsFalse();
    }

    private static ISystemdHostProbe AdmittedHostProbe() =>
        new RecordingProbe(new(true, true, true, true, true));

    private static HostRuntimePlan NativePlan(AdmittedRole role, string allocation) =>
        HostRuntimePlan.Create(
            role,
            RuntimeDriver.NativeSystemd,
            new RuntimeAllocationId(allocation),
            new ArtifactDigest(Digest),
            HostArchitecture.Arm64);

    private sealed class RecordingProbe(SystemdHostProbeResult result) : ISystemdHostProbe
    {
        public SystemdHostProbeResult Probe() => result;
    }

    private sealed class RecordingRunner(params HostCommandResult[] results) : IHostCommandRunner
    {
        private readonly Queue<HostCommandResult> pending = new(results);

        public List<(string Executable, IReadOnlyList<string> Arguments)> Commands { get; } = [];

        public Task<HostCommandResult> RunAsync(
            string executable,
            IReadOnlyList<string> arguments,
            CancellationToken cancellationToken)
        {
            Commands.Add((executable, arguments.ToArray()));
            return Task.FromResult(pending.Count == 0
                ? new HostCommandResult(0, string.Empty, string.Empty)
                : pending.Dequeue());
        }
    }
}
