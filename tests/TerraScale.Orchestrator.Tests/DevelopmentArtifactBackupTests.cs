using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentArtifactBackupTests
{
    [Test]
    public async Task FailedReplacementCanRestoreLastHealthyArtifacts()
    {
        var root = Path.Combine(Path.GetTempPath(), $"ts-orch-artifacts-{Guid.NewGuid():N}");
        var workspace = Path.Combine(root, "workspace");
        var data = Path.Combine(root, "data");
        var platform = Path.Combine(
            workspace, "TerraScale.Internals", "src", "Platform",
            "TerraScale.Platform", "bin", "Release", "net10.0");
        var pointer = Path.Combine(data, "artifacts", "dashboard", "current");
        try
        {
            Directory.CreateDirectory(platform);
            Directory.CreateDirectory(Path.GetDirectoryName(pointer)!);
            await File.WriteAllTextAsync(Path.Combine(platform, "TerraScale.Platform.dll"), "healthy");
            await File.WriteAllTextAsync(pointer, "healthy-dashboard");

            using var backup = DevelopmentArtifactBackup.Capture(
                workspace,
                data,
                "reconcile-1",
                new HashSet<DevelopmentResourceKind>
                {
                    DevelopmentResourceKind.Platform,
                    DevelopmentResourceKind.Dashboard
                });
            await File.WriteAllTextAsync(Path.Combine(platform, "TerraScale.Platform.dll"), "candidate");
            await File.WriteAllTextAsync(pointer, "candidate-dashboard");
            backup.Restore();

            await Assert.That(await File.ReadAllTextAsync(Path.Combine(platform, "TerraScale.Platform.dll")))
                .IsEqualTo("healthy");
            await Assert.That(await File.ReadAllTextAsync(pointer)).IsEqualTo("healthy-dashboard");
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }
}
