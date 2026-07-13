using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace TerraScale.Orchestrator.ContractTests;

public sealed class RepositoryBoundaryTests
{
    [Test]
    public async Task PureProjectsHaveNoInfrastructurePackageReferences()
    {
        var root = FindRepositoryRoot();
        var pureProjects = new[]
        {
            "src/TerraScale.Orchestrator.Contracts/TerraScale.Orchestrator.Contracts.csproj",
            "src/TerraScale.Orchestrator.Protocol/TerraScale.Orchestrator.Protocol.csproj"
        };

        foreach (var relativePath in pureProjects)
        {
            var text = await File.ReadAllTextAsync(Path.Combine(root, relativePath));
            await Assert.That(text).DoesNotContain("PackageReference");
        }
    }

    [Test]
    public async Task RequirementRegistryContainsUniqueWellFormedIds()
    {
        var root = FindRepositoryRoot();
        var yaml = await File.ReadAllTextAsync(Path.Combine(root, "requirements/registry.yaml"));
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(CamelCaseNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();
        var registry = deserializer.Deserialize<RequirementRegistry>(yaml);
        var entries = registry.Entries ?? [];

        await Assert.That(entries).IsNotEmpty();
        await Assert.That(entries.Select(static entry => entry.Id).Distinct(StringComparer.Ordinal).Count())
            .IsEqualTo(entries.Count);

        foreach (var entry in entries)
        {
            await Assert.That(entry.Id).Matches("^(REQ|INV|ERR|SM|SEC)-[A-Z0-9]+(?:-[A-Z0-9]+)*$");
            await Assert.That(entry.Owner).IsNotNullOrWhiteSpace();
            await Assert.That(entry.AcceptanceLayers).IsNotEmpty();
        }
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "ORCHESTRATOR.md")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Repository root was not found.");
    }

    private sealed class RequirementRegistry
    {
        public List<RegistryEntry>? Entries { get; init; }
    }

    private sealed class RegistryEntry
    {
        public required string Id { get; init; }

        public required string Owner { get; init; }

        public required List<string> AcceptanceLayers { get; init; }
    }
}
