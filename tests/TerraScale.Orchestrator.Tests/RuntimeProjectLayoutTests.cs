namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// The runtime owns the operator and repository-validation command surfaces. This keeps the
/// retired standalone CLI/tooling projects from returning to the solution or source tree.
/// </summary>
public sealed class RuntimeProjectLayoutTests
{
    [Test]
    public async Task Solution_and_source_tree_have_one_production_project()
    {
        var root = FindRepositoryRoot();
        var solution = await File.ReadAllTextAsync(Path.Combine(root, "TerraScale.Orchestrator.slnx"));
        var productionProjects = Directory.EnumerateFiles(
                Path.Combine(root, "src"),
                "*.csproj",
                SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(root, path).Replace('\\', '/'))
            .Order(StringComparer.Ordinal)
            .ToArray();

        await Assert.That(productionProjects).IsEquivalentTo(
            new[] { "src/TerraScale.Orchestrator/TerraScale.Orchestrator.csproj" });
        await Assert.That(solution)
            .Contains("<Project Path=\"src/TerraScale.Orchestrator/TerraScale.Orchestrator.csproj\" />");
        await Assert.That(solution).DoesNotContain("TerraScale.Orchestrator.CLI");
        await Assert.That(solution).DoesNotContain("TerraScale.Orchestrator.Tooling");
    }

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null;
             directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "TerraScale.Orchestrator.slnx")))
                return directory.FullName;
        }

        throw new InvalidOperationException("The TerraScale.Orchestrator repository root was not found.");
    }
}
