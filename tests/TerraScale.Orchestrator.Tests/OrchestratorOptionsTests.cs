namespace TerraScale.Orchestrator.Tests;

public sealed class OrchestratorOptionsTests
{
    [Test]
    public async Task CatalogCommandIsReadOnlyAndRejectsArguments()
    {
        var options = OrchestratorOptions.Parse(["catalog"], _ => null);

        await Assert.That(options.Command).IsEqualTo(OrchestratorCommand.Catalog);
        await Assert.That(() => OrchestratorOptions.Parse(["catalog", "extra"], _ => null))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task ParsesLabPlanWithoutDeploymentEvidence()
    {
        var options = OrchestratorOptions.Parse(
            ["lab", "plan", "--workspace", "/tmp/workspace", "--data-directory", "/tmp/data", "--profile", "dev-containers"],
            _ => null);

        await Assert.That(options.Command).IsEqualTo(OrchestratorCommand.Lab);
        await Assert.That(options.LabCommand).IsEqualTo(OrchestratorLabCommand.Plan);
        await Assert.That(options.WorkspaceRoot).IsEqualTo("/tmp/workspace");
        await Assert.That(options.DataDirectory).IsEqualTo("/tmp/data");
        await Assert.That(options.LabProfile).IsEqualTo(OrchestratorLabProfile.DevContainers);
    }

    [Test]
    public async Task ParsesControlPlaneContainerProfile()
    {
        var options = OrchestratorOptions.Parse(
            ["lab", "plan", "--profile", "dev-containers-control"],
            _ => null);

        await Assert.That(options.LabProfile)
            .IsEqualTo(OrchestratorLabProfile.DevContainersControl);
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

    [Test]
    public async Task ParsesAndValidatesStableControllerInstance()
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["TS_ORCH_INSTANCE"] = "controller-2"
        };

        var options = OrchestratorOptions.Parse(["run"], name => values.GetValueOrDefault(name));

        await Assert.That(options.Instance).IsEqualTo("controller-2");
        await Assert.That(() => OrchestratorOptions.Parse(
                ["run"],
                name => name == "TS_ORCH_INSTANCE" ? "Controller/2" : null))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task ControllerNKeyMustBeAnExistingFile()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        var path = Path.Combine(Path.GetTempPath(), $"ts-orch-option-{Guid.NewGuid():N}.nk");
        try
        {
            await File.WriteAllTextAsync(path, "seed");
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var options = OrchestratorOptions.Parse(
                ["run"],
                name => name == "TS_ORCH_NATS_NKEY_FILE" ? path : null);

            await Assert.That(options.NatsNKeyFile).IsEqualTo(path);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.OtherRead);
            await Assert.That(() => OrchestratorOptions.Parse(
                    ["run"],
                    name => name == "TS_ORCH_NATS_NKEY_FILE" ? path : null))
                .Throws<ArgumentException>();
            await Assert.That(() => OrchestratorOptions.Parse(
                    ["run"],
                    name => name == "TS_ORCH_NATS_NKEY_FILE" ? path + ".missing" : null))
                .Throws<ArgumentException>();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Test]
    public async Task RemovedVmAndWatchOptionsAreRejected()
    {
        await Assert.That(() => OrchestratorOptions.Parse(
            ["lab", "plan", "--profile", "regions-smol"],
            _ => null))
            .Throws<ArgumentException>();
        await Assert.That(() => OrchestratorOptions.Parse(
                ["lab", "plan", "--watch"],
                _ => null))
            .Throws<ArgumentException>();
        await Assert.That(() => OrchestratorOptions.Parse(
                ["lab", "plan", "--base-artifact", "/tmp/base.smolmachine"],
                _ => null))
            .Throws<ArgumentException>();
    }
}
