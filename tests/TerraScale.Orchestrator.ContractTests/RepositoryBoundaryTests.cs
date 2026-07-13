using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

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
        var sourceLines = await File.ReadAllLinesAsync(Path.Combine(root, "ORCHESTRATOR.md"));
        var canonicalOwners = new HashSet<string>(StringComparer.Ordinal)
        {
            "Integration/contract steward", "Core", "Messaging/security", "Runtime", "Cloud",
            "Storage", "TerraBase", "Delivery", "Operations", "Cross-repository cleanup", "Verification"
        };

        await Assert.That(entries).IsNotEmpty();
        await Assert.That(entries.Select(static entry => entry.Id).Distinct(StringComparer.Ordinal).Count())
            .IsEqualTo(entries.Count);

        foreach (var entry in entries)
        {
            await Assert.That(entry.Id).Matches("^(REQ|INV|ERR|SM|SEC)-[A-Z0-9]+(?:-[A-Z0-9]+)*$");
            await Assert.That(entry.ContractStatus).IsEqualTo("proposed");
            await Assert.That(canonicalOwners).Contains(entry.Owner);
            await Assert.That(entry.Kind).IsEqualTo(entry.Id.Split('-', 2)[0] switch
            {
                "REQ" => "requirement", "INV" => "invariant", "ERR" => "error",
                "SM" => "state-machine", "SEC" => "security", _ => "invalid"
            });
            await Assert.That(entry.NormativeStatement).IsNotNullOrWhiteSpace();
            await Assert.That(entry.NormativeSource).IsEqualTo("ORCHESTRATOR.md");
            await Assert.That(entry.NormativeStartLine).IsGreaterThanOrEqualTo(1);
            await Assert.That(entry.NormativeEndLine).IsGreaterThanOrEqualTo(entry.NormativeStartLine);
            await Assert.That(entry.NormativeEndLine).IsLessThanOrEqualTo(sourceLines.Length);
            var exactSource = string.Join('\n', sourceLines[(entry.NormativeStartLine - 1)..entry.NormativeEndLine]);
            await Assert.That(exactSource).Contains(entry.NormativeContains);
            var digest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(exactSource)));
            await Assert.That(entry.NormativeSha256).IsEqualTo(digest);
            await Assert.That(entry.AcceptanceLayers).IsNotEmpty();
            await Assert.That(entry.EvidenceState).IsEqualTo("missing");
            await Assert.That(entry.EvidenceTargets.Count).IsEqualTo(entry.AcceptanceLayers.Count);
            await Assert.That(entry.EvidenceTargets.All(static target => !string.IsNullOrWhiteSpace(target))).IsTrue();
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

    [Test]
    public async Task TrackedSourceContainsNoPrivateKeysOrRawOciIdentifiers()
    {
        var root = FindRepositoryRoot();
        var excludedDirectories = new HashSet<string>(StringComparer.Ordinal)
        {
            ".git", "artifacts", "bin", "obj", "TestResults"
        };
        var textExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".cs", ".csproj", ".json", ".md", ".props", ".py", ".slnx", ".targets", ".txt", ".yaml", ".yml"
        };
        var rawOcid = new Regex(
            @"ocid1\.(?:tenancy|user|instance|volume|cluster|nodepool|vcn|subnet|loadbalancer|vault|key|bucket)\.[a-z0-9._-]{16,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

        foreach (var path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            var relativePath = Path.GetRelativePath(root, path);
            if (relativePath.Split(Path.DirectorySeparatorChar).Any(excludedDirectories.Contains) ||
                !textExtensions.Contains(Path.GetExtension(path)))
            {
                continue;
            }

            var text = await File.ReadAllTextAsync(path);
            var privateKeyMarker = "-----BEGIN " + "PRIVATE KEY-----";
            await Assert.That(text).DoesNotContain(privateKeyMarker);
            await Assert.That(rawOcid.IsMatch(text)).IsFalse()
                .Because($"raw OCI identifier found in {relativePath}");
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

        public required string Kind { get; init; }

        public required string ContractStatus { get; init; }

        public required string Owner { get; init; }

        public required string NormativeStatement { get; init; }

        public required string NormativeSource { get; init; }

        public required int NormativeStartLine { get; init; }

        public required int NormativeEndLine { get; init; }

        public required string NormativeContains { get; init; }

        public required string NormativeSha256 { get; init; }

        public required List<string> AcceptanceLayers { get; init; }

        public required string EvidenceState { get; init; }

        public required List<string> EvidenceTargets { get; init; }
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
