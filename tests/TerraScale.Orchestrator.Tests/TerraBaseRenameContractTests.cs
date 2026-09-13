namespace TerraScale.Orchestrator.Tests;

/// <summary>Prevents the retired engine product name from returning to active Orchestrator material.</summary>
public sealed class TerraBaseRenameContractTests
{
    private const string RetiredName = "TerraBase" + "V2";

    [Test]
    public async Task Active_repository_material_uses_the_TerraBase_name()
    {
        var root = RepositoryRoot();
        var inspected = new[]
        {
            "GOAL.md",
            "README.md",
            "src",
            "config",
            "docs/adr",
            "docs/architecture",
            "docs/contracts",
            "docs/guides",
        };

        var stale = inspected
            .Select(path => Path.Combine(root, path))
            .Where(path => File.Exists(path) || Directory.Exists(path))
            .SelectMany(EnumerateFiles)
            .Where(IsTextMaterial)
            .SelectMany(path => File.ReadLines(path)
                .Select((line, index) => (Path: Path.GetRelativePath(root, path), Line: index + 1, Text: line)))
            .Where(entry => entry.Text.Contains(RetiredName, StringComparison.OrdinalIgnoreCase))
            .Select(entry => $"{entry.Path}:{entry.Line}")
            .Order(StringComparer.Ordinal)
            .ToArray();

        await Assert.That(string.Join(", ", stale)).IsEqualTo(string.Empty);
    }

    private static IEnumerable<string> EnumerateFiles(string path) =>
        File.Exists(path) ? [path] : Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories);

    private static bool IsTextMaterial(string path) =>
        Path.GetExtension(path) is ".cs" or ".csproj" or ".json" or ".md" or ".props" or ".targets" or ".yml" or ".yaml";

    private static string RepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "TerraScale.Orchestrator.slnx")))
                return current.FullName;
            current = current.Parent;
        }

        throw new InvalidOperationException("Could not locate the TerraScale.Orchestrator repository root.");
    }
}

