using System.IO;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Loads the bounded Deploy-handoff fixture corpus and the versioned mapping contract from the
/// repository source tree. Fixture and contract loading is test-only by design: the production
/// mapper is a pure translation and never touches the filesystem.
/// </summary>
internal static class DeployHandoffCorpus
{
    private const string FixtureDirectory = "tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures";
    private const string ContractPath = "docs/contracts/deploy-orchestrator-handoff.md";
    private const int MaximumParentHops = 12;

    private static readonly Lazy<string> RepositoryRoot = new(FindRepositoryRoot);

    public static string Fixture(string fileName) =>
        File.ReadAllText(Path.Combine(RepositoryRoot.Value, FixtureDirectory, fileName));

    public static string Contract() =>
        File.ReadAllText(Path.Combine(RepositoryRoot.Value, ContractPath));

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var hops = 0; directory is not null && hops < MaximumParentHops; hops++)
        {
            if (File.Exists(Path.Combine(directory.FullName, "TerraScale.Orchestrator.slnx")))
                return directory.FullName;
            directory = directory.Parent;
        }

        throw new InvalidOperationException(
            $"The Deploy-handoff corpus could not locate the repository root within {MaximumParentHops} parent " +
            $"directories of the test output; run the test module from the TerraScale.Orchestrator checkout.");
    }
}

