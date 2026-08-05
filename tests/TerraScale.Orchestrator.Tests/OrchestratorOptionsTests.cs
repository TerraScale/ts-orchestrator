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
            ["lab", "plan", "--workspace", "/tmp/workspace", "--data-directory", "/tmp/data", "--profile", "regional"],
            _ => null);

        await Assert.That(options.Command).IsEqualTo(OrchestratorCommand.Lab);
        await Assert.That(options.LabCommand).IsEqualTo(OrchestratorLabCommand.Plan);
        await Assert.That(options.WorkspaceRoot).IsEqualTo("/tmp/workspace");
        await Assert.That(options.DataDirectory).IsEqualTo("/tmp/data/profiles/regional");
        await Assert.That(options.LabProfile).IsEqualTo(OrchestratorLabProfile.Regional);
    }

    [Test]
    public async Task ParsesControlPlaneContainerProfile()
    {
        var options = OrchestratorOptions.Parse(
            ["lab", "plan", "--profile", "control"],
            _ => null);

        await Assert.That(options.LabProfile)
            .IsEqualTo(OrchestratorLabProfile.Control);
    }

    [Test]
    public async Task ProfilesUseSeparatePersistentDataDirectories()
    {
        var quick = OrchestratorOptions.Parse(
            ["lab", "plan", "--data-directory", "/tmp/data", "--profile", "quick"],
            _ => null);
        var regional = OrchestratorOptions.Parse(
            ["lab", "plan", "--data-directory", "/tmp/data", "--profile", "regional"],
            _ => null);

        await Assert.That(quick.DataDirectory).IsEqualTo("/tmp/data/profiles/quick");
        await Assert.That(regional.DataDirectory).IsEqualTo("/tmp/data/profiles/regional");
        await Assert.That(quick.StateFile).IsEqualTo(regional.StateFile);
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

        var options = OrchestratorOptions.Parse(["check"], name => values.GetValueOrDefault(name));

        await Assert.That(options.Instance).IsEqualTo("controller-2");
        await Assert.That(() => OrchestratorOptions.Parse(
                ["check"],
                name => name == "TS_ORCH_INSTANCE" ? "Controller/2" : null))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task RunRequiresAuthenticatedTlsRegionalControlNats()
    {
        await Assert.That(() => OrchestratorOptions.Parse(["run"], _ => null))
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
            await File.WriteAllTextAsync(path, NATS.Client.Core.NKeys.CreateUserSeed());
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var options = OrchestratorOptions.Parse(
                ["check"],
                name => name == "TS_ORCH_NATS_NKEY_FILE" ? path : null);

            await Assert.That(options.NatsNKeyFile).IsEqualTo(path);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.OtherRead);
            await Assert.That(() => OrchestratorOptions.Parse(
                    ["check"],
                    name => name == "TS_ORCH_NATS_NKEY_FILE" ? path : null))
                .Throws<ArgumentException>();
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            await File.WriteAllTextAsync(path, "not-an-nkey-seed");
            await Assert.That(() => OrchestratorOptions.Parse(
                    ["check"],
                    name => name == "TS_ORCH_NATS_NKEY_FILE" ? path : null))
                .Throws<ArgumentException>();
            await Assert.That(() => OrchestratorOptions.Parse(
                    ["check"],
                    name => name == "TS_ORCH_NATS_NKEY_FILE" ? path + ".missing" : null))
                .Throws<ArgumentException>();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Test]
    public async Task RemovedProfilesAndOptionsAreRejected()
    {
        foreach (var profile in new[] { "regions-smol", "dev-containers", "dev-containers-control" })
        {
            await Assert.That(() => OrchestratorOptions.Parse(
                    ["lab", "plan", "--profile", profile],
                    _ => null))
                .Throws<ArgumentException>();
        }
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
