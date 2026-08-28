using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentArtifactBackupTests
{
    [Test]
    public async Task FailedReplacementCanRestoreLastHealthyArtifacts()
    {
        var root = Path.Combine(Path.GetTempPath(), $"ts-orch-artifacts-{Guid.NewGuid():N}");
        var data = Path.Combine(root, "data");
        var pointer = Path.Combine(data, "artifacts", "dashboard", "current");
        var healthyArtifact = Path.Combine(data, "artifacts", "dashboard", "healthy-artifact");
        var candidateArtifact = Path.Combine(data, "artifacts", "dashboard", "candidate-artifact");
        try
        {
            Directory.CreateDirectory(DevelopmentGuards.RequireDirectory(pointer, "Dashboard pointer"));
            Directory.CreateDirectory(healthyArtifact);
            Directory.CreateDirectory(candidateArtifact);
            await File.WriteAllTextAsync(
                Path.Combine(healthyArtifact, "server.js"),
                "healthy");
            await File.WriteAllTextAsync(pointer, "healthy-artifact");

            using var backup = DevelopmentArtifactBackup.Capture(
                data,
                "reconcile-1",
                new HashSet<DevelopmentResourceKind>
                {
                    DevelopmentResourceKind.Dashboard
                });
            await File.WriteAllTextAsync(Path.Combine(candidateArtifact, "server.js"), "candidate");
            await File.WriteAllTextAsync(pointer, "candidate-dashboard");
            backup.Restore();

            await Assert.That(await File.ReadAllTextAsync(
                    Path.Combine(healthyArtifact, "server.js")))
                .IsEqualTo("healthy");
            await Assert.That(await File.ReadAllTextAsync(pointer)).IsEqualTo("healthy-artifact");
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
