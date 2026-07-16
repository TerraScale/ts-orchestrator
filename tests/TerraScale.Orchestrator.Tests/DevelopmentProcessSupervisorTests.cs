using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentProcessSupervisorTests
{
    [Test]
    public async Task RestartReplaysOnlyTheTrustedRecordedProcessSpecification()
    {
        await using var supervisor = new DevelopmentProcessSupervisor();
        var original = supervisor.Start(
            "restart-test",
            "/usr/bin/sleep",
            ["30"],
            Path.GetTempPath());
        var originalPid = original.Id;
        original.Kill(entireProcessTree: true);
        await original.WaitForExitAsync();

        var restarted = await supervisor.RestartAsync("restart-test");

        await Assert.That(restarted.Id).IsNotEqualTo(originalPid);
        await Assert.That(restarted.HasExited).IsFalse();
        await Assert.That(supervisor.Processes["restart-test"].Id).IsEqualTo(restarted.Id);
        await Assert.That(supervisor.IsWithinStartupGrace("restart-test", TimeSpan.FromSeconds(10))).IsTrue();
    }

    [Test]
    public async Task UnknownResourceCannotBecomeAnArbitraryRestartTarget()
    {
        await using var supervisor = new DevelopmentProcessSupervisor();

        await Assert.That(async () => await supervisor.RestartAsync("not-admitted"))
            .Throws<InvalidOperationException>();
    }
}
