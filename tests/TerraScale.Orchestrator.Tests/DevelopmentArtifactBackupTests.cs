using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentArtifactBackupTests
{
    [Test]
    public async Task FailedReplacementCanRestoreLastHealthyArtifacts()
    {
        var root = Path.Combine(Path.GetTempPath(), $"ts-orch-artifacts-{Guid.NewGuid():N}");
        var data = Path.Combine(root, "data");
        var dashboardApi = DevelopmentArtifactBuilder.DotNetOutputDirectory(
            data,
            "TerraScale.Dashboard.Api");
        var pointer = Path.Combine(data, "artifacts", "dashboard", "current");
        try
        {
            Directory.CreateDirectory(dashboardApi);
            Directory.CreateDirectory(DevelopmentGuards.RequireDirectory(pointer, "Dashboard pointer"));
            await File.WriteAllTextAsync(
                Path.Combine(dashboardApi, "TerraScale.Dashboard.Api.dll"),
                "healthy");
            await File.WriteAllTextAsync(pointer, "healthy-dashboard");

            using var backup = DevelopmentArtifactBackup.Capture(
                data,
                "reconcile-1",
                new HashSet<DevelopmentResourceKind>
                {
                    DevelopmentResourceKind.Platform,
                    DevelopmentResourceKind.Dashboard
                });
            await File.WriteAllTextAsync(
                Path.Combine(dashboardApi, "TerraScale.Dashboard.Api.dll"),
                "candidate");
            await File.WriteAllTextAsync(pointer, "candidate-dashboard");
            Directory.Delete(dashboardApi, recursive: true);
            backup.Restore();

            await Assert.That(await File.ReadAllTextAsync(
                    Path.Combine(dashboardApi, "TerraScale.Dashboard.Api.dll")))
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
