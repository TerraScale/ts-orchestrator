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

    [Test]
    public async Task WorkaroundLedgerHasStableIdsEvidenceAndCanonicalOwners()
    {
        var root = FindRepositoryRoot();
        var yaml = await File.ReadAllTextAsync(Path.Combine(root, "docs/retirement/workaround-ledger.yaml"));
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();
        var ledger = deserializer.Deserialize<WorkaroundLedger>(yaml);
        var entries = ledger.Entries ?? [];
        var canonicalOwners = new HashSet<string>(StringComparer.Ordinal)
        {
            "Integration/contract steward",
            "Core",
            "Messaging/security",
            "Runtime",
            "Cloud",
            "Storage",
            "TerraBase",
            "Delivery",
            "Operations",
            "Cross-repository cleanup",
            "Verification"
        };

        await Assert.That(entries.Count).IsEqualTo(22);
        for (var index = 0; index < entries.Count; index++)
        {
            var entry = entries[index];
            await Assert.That(entry.Id).IsEqualTo($"WRK-{index + 1:000}");
            await Assert.That(entry.Evidence).IsNotEmpty();
            await Assert.That(canonicalOwners).Contains(entry.OwnerWorkstream.Primary);
            foreach (var collaborator in entry.OwnerWorkstream.Collaborators)
            {
                await Assert.That(canonicalOwners).Contains(collaborator);
            }
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

    private sealed class WorkaroundLedger
    {
        public List<WorkaroundEntry>? Entries { get; init; }
    }

    private sealed class WorkaroundEntry
    {
        public required string Id { get; init; }

        public required List<WorkaroundEvidence> Evidence { get; init; }

        public required WorkstreamOwner OwnerWorkstream { get; init; }
    }

    private sealed class WorkaroundEvidence;

    private sealed class WorkstreamOwner
    {
        public required string Primary { get; init; }

        public required List<string> Collaborators { get; init; }
    }
}
