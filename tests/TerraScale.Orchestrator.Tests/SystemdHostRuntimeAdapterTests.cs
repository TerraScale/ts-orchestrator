using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class SystemdHostRuntimeAdapterTests
{
    private const string Digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Test]
    public async Task ConvergeUsesArgumentListsAndEveryCatalogSecurityProperty()
    {
        var runner = new RecordingRunner();
        var adapter = new SystemdHostRuntimeAdapter(runner, userManager: false);
        var plan = NativePlan();

        await adapter.ConvergeAsync(plan, CancellationToken.None);

        var command = runner.Commands.Single();
        await Assert.That(command.Executable).IsEqualTo("/usr/bin/systemd-run");
        await Assert.That(command.Arguments).Contains(plan.Systemd!.UnitName);
        await Assert.That(command.Arguments).Contains("NoNewPrivileges=yes");
        await Assert.That(command.Arguments).Contains("ProtectSystem=strict");
        await Assert.That(command.Arguments).Contains("RestrictSUIDSGID=yes");
        await Assert.That(command.Arguments).DoesNotContain("--setenv");
        await Assert.That(command.Arguments).Contains(plan.Systemd.Executable);
    }

    [Test]
    public async Task ObserveMapsSystemdStateWithoutTrustingFreeFormOutput()
    {
        var runner = new RecordingRunner
        {
            Next = new(0, "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=481\nResult=success\n", string.Empty)
        };
        var adapter = new SystemdHostRuntimeAdapter(runner, userManager: true);

        var observation = await adapter.ObserveAsync(NativePlan(), CancellationToken.None);

        await Assert.That(observation.State).IsEqualTo(SystemdAllocationState.Running);
        await Assert.That(observation.MainProcessId).IsEqualTo(481);
        await Assert.That(runner.Commands.Single().Arguments.First()).IsEqualTo("--user");
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

    private static HostRuntimePlan NativePlan() => HostRuntimePlan.Create(
        AdmittedRole.Orchestrator,
        RuntimeDriver.NativeSystemd,
        new RuntimeAllocationId("gru-orchestrator-1"),
        new ArtifactDigest(Digest),
        HostArchitecture.Arm64);

    private sealed class RecordingRunner : IHostCommandRunner
    {
        public HostCommandResult Next { get; init; } = new(0, string.Empty, string.Empty);
        public List<(string Executable, IReadOnlyList<string> Arguments)> Commands { get; } = [];

        public Task<HostCommandResult> RunAsync(
            string executable,
            IReadOnlyList<string> arguments,
            CancellationToken cancellationToken)
        {
            Commands.Add((executable, arguments.ToArray()));
            return Task.FromResult(Next);
        }
    }
}
