using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentArtifactBuilderTests
{
    [Test]
    public async Task TerraBaseArtifactAlwaysContainsItsStudioArchive()
    {
        var root = Path.Combine(Path.GetTempPath(), "terrabase-studio-artifact-" + Guid.NewGuid().ToString("N"));
        var workspace = Path.Combine(root, "workspace");
        var data = Path.Combine(root, "data");
        var studioArchive = Path.Combine(
            workspace,
            "TerraBase",
            "src",
            "TerraBase.Studio",
            "wwwroot",
            "dist",
            DevelopmentArtifactBuilder.TerraBaseStudioArchiveName);
        var serverOutput = DevelopmentArtifactBuilder.DotNetOutputDirectory(data, "TerraBase.Server");
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(studioArchive)!);
            Directory.CreateDirectory(serverOutput);
            await File.WriteAllTextAsync(studioArchive, "studio");

            DevelopmentArtifactBuilder.BundleTerraBaseStudio(workspace, data);

            await Assert.That(File.ReadAllText(Path.Combine(
                    serverOutput,
                    DevelopmentArtifactBuilder.TerraBaseStudioArchiveName)))
                .IsEqualTo("studio");
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Test]
    public async Task TerraBaseArtifactRejectsAMissingStudioArchive()
    {
        var root = Path.Combine(Path.GetTempPath(), "terrabase-studio-artifact-" + Guid.NewGuid().ToString("N"));
        var workspace = Path.Combine(root, "workspace");
        var data = Path.Combine(root, "data");
        try
        {
            Directory.CreateDirectory(DevelopmentArtifactBuilder.DotNetOutputDirectory(data, "TerraBase.Server"));

            await Assert.That(() => DevelopmentArtifactBuilder.BundleTerraBaseStudio(workspace, data))
                .Throws<FileNotFoundException>();
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Test]
    public async Task FailureDiagnosticPrefersTheCompilerError()
    {
        var diagnostic = DevelopmentArtifactBuilder.Diagnostic(
            "",
            """
            Determining projects to restore...
            Program.cs(78,13): error CS8321: The local function is never used
            Build FAILED.
            """);

        await Assert.That(diagnostic)
            .IsEqualTo("Program.cs(78,13): error CS8321: The local function is never used");
    }
}
