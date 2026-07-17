using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentDashboardArtifactTests
{
    [Test]
    public async Task SnapshotKeepsRunningBundleImmutableAcrossLaterBuilds()
    {
        var root = Path.Combine(Path.GetTempPath(), $"ts-dashboard-artifact-{Guid.NewGuid():N}");
        var dashboard = Path.Combine(root, "dashboard");
        var data = Path.Combine(root, "data");
        var standalone = Path.Combine(dashboard, "dist", "standalone");
        var chunk = Path.Combine(standalone, "dist", "server", "chunk.js");
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(chunk)!);
            await File.WriteAllTextAsync(Path.Combine(standalone, "server.js"), "import './dist/server/chunk.js';");
            await File.WriteAllTextAsync(chunk, "export const version = 1;");

            var first = DevelopmentDashboardArtifact.Snapshot(dashboard, data);
            await File.WriteAllTextAsync(chunk, "export const version = 2;");
            var second = DevelopmentDashboardArtifact.Snapshot(dashboard, data);

            await Assert.That(second).IsNotEqualTo(first);
            await Assert.That(await File.ReadAllTextAsync(Path.Combine(first, "dist", "server", "chunk.js")))
                .IsEqualTo("export const version = 1;");
            await Assert.That(DevelopmentDashboardArtifact.Resolve(data)).IsEqualTo(second);
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
