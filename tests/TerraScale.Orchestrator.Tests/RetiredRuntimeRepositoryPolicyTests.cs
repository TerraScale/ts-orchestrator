using System.Text.RegularExpressions;

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
        var violations = EnumeratePolicyFiles(root)
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

    [Test]
    public async Task RetiredVirtualizedAndWebAssemblyTenantRuntimesCannotReturnInLivingSourceOrDocumentation()
    {
        var root = FindRepositoryRoot();
        var retiredTerms = new[]
        {
            string.Concat("micro", "vm"),
            string.Concat("micro", "-vm"),
            string.Concat("fire", "cracker"),
            string.Concat("cloud", "-hypervisor"),
            string.Concat("cloud", "hypervisor"),
            string.Concat("cro", "svm"),
            string.Concat("jai", "ler"),
            string.Concat("ka", "ta"),
            string.Concat("k", "vm"),
            string.Concat("qe", "mu"),
            string.Concat("vm", "m"),
            string.Concat("wa", "si"),
            string.Concat("wasm", "time"),
            string.Concat("run", "wasi"),
            string.Concat("wasm", "cloud"),
            string.Concat("wa", "sm")
        };
        var pattern = string.Join("|", retiredTerms.Select(Regex.Escape));
        var retiredRuntime = new Regex(@"\b(?:" + pattern + @")\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        var selfFile = Path.GetFullPath(
            Path.Combine(root, "tests", "TerraScale.Orchestrator.Tests", "RetiredRuntimeRepositoryPolicyTests.cs"));
        var violations = EnumeratePolicyFiles(root)
            .Select(path => new
            {
                FullPath = Path.GetFullPath(path),
                Path = Path.GetRelativePath(root, path),
                Text = File.ReadAllText(path)
            })
            .Where(file => !string.Equals(file.FullPath, selfFile, StringComparison.OrdinalIgnoreCase))
            .Where(file => retiredRuntime.IsMatch(file.Text))
            .Select(file => file.Path)
            .Order(StringComparer.Ordinal)
            .ToArray();

        await Assert.That(violations).IsEmpty();
    }

    private static IEnumerable<string> EnumeratePolicyFiles(string root) =>
        Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(IsRepositoryTextFile)
            .Where(path => !IsSupersededDecisionRecord(root, path));

    private static bool IsSupersededDecisionRecord(string root, string path)
    {
        var segments = Path.GetRelativePath(root, path)
            .Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        return segments.Length >= 2 &&
               string.Equals(segments[0], "docs", StringComparison.OrdinalIgnoreCase) &&
               segments[1] is "adr" or "archive";
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
