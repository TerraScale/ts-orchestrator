namespace TerraScale.Orchestrator.Tests;

public sealed class RetiredRuntimeRepositoryPolicyTests
{
    private static readonly string[] TextExtensions =
    [
        ".cs", ".csproj", ".md", ".json", ".yaml", ".yml", ".xml", ".props", ".targets", ".slnx", ".toml", ".sh"
    ];

    [Test]
    public async Task RetiredVmBackendCannotReturnInTrackedSourceOrDocumentation()
    {
        var root = FindRepositoryRoot();
        var retiredProduct = string.Concat("smol", "vm");
        var genericAliases = new[]
        {
            string.Concat("small", " vm"),
            string.Concat("small", "-vm"),
            string.Concat("small", "_vm")
        };
        var violations = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(IsRepositoryTextFile)
            .Select(path => new
            {
                Path = Path.GetRelativePath(root, path),
                Text = File.ReadAllText(path)
            })
            .Where(file =>
                file.Path.Contains(retiredProduct, StringComparison.OrdinalIgnoreCase) ||
                file.Text.Contains(retiredProduct, StringComparison.OrdinalIgnoreCase) ||
                genericAliases.Any(alias =>
                    file.Path.Contains(alias, StringComparison.OrdinalIgnoreCase) ||
                    file.Text.Contains(alias, StringComparison.OrdinalIgnoreCase)))
            .Select(file => file.Path)
            .Order(StringComparer.Ordinal)
            .ToArray();

        await Assert.That(violations).IsEmpty();
    }

    private static bool IsRepositoryTextFile(string path)
    {
        var segments = Path.GetRelativePath(FindRepositoryRoot(), path)
            .Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        if (segments.Any(segment => segment is ".git" or "bin" or "obj" or "node_modules" or "coverage"))
        {
            return false;
        }

        var extension = Path.GetExtension(path);
        return TextExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase) || extension.Length == 0;
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "ORCHESTRATOR.md")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Could not locate the repository root.");
    }
}
