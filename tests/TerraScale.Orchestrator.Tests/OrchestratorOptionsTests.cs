namespace TerraScale.Orchestrator.Tests;

public sealed class OrchestratorOptionsTests
{
    [Test]
    public async Task ParsesLabPlanWithoutDeploymentEvidence()
    {
        var options = OrchestratorOptions.Parse(
            ["lab", "plan", "--workspace", "/tmp/workspace", "--data-directory", "/tmp/data", "--watch"],
            _ => null);

        await Assert.That(options.Command).IsEqualTo(OrchestratorCommand.Lab);
        await Assert.That(options.LabCommand).IsEqualTo(OrchestratorLabCommand.Plan);
        await Assert.That(options.WorkspaceRoot).IsEqualTo("/tmp/workspace");
        await Assert.That(options.DataDirectory).IsEqualTo("/tmp/data");
        await Assert.That(options.Watch).IsTrue();
    }

    [Test]
    public async Task RejectsUnknownAndDuplicateLabOptions()
    {
        await Assert.That(() => OrchestratorOptions.Parse(["lab", "plan", "--wat"], _ => null))
            .Throws<ArgumentException>();
        await Assert.That(() => OrchestratorOptions.Parse(
                ["lab", "plan", "--workspace", "/one", "--workspace", "/two"],
                _ => null))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task LabUpFailsClosedWithoutEvidence()
    {
        var options = OrchestratorOptions.Parse(["lab", "up"], _ => null);

        var exception = await Assert.That(async () =>
                await Development.DevelopmentLab.ExecuteAsync(options, CancellationToken.None))
            .Throws<InvalidOperationException>();
        await Assert.That(exception!.Message).Contains("--evidence");
    }
}
