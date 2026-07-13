using System.Text.Json.Nodes;
using TerraScale.Orchestrator.Contracts.Resources;
using TerraScale.Orchestrator.SchemaGenerator;

namespace TerraScale.Orchestrator.ContractTests;

public sealed class GeneratedSchemaTests
{
    [Test]
    public async Task CheckedInSchemasDocumentationAndFixturesMatchContractsExactly()
    {
        var root = FindRepositoryRoot();
        foreach (var artifact in SchemaArtifacts.Generate())
        {
            var path = Path.Combine(root, artifact.Key.Replace('/', Path.DirectorySeparatorChar));
            await Assert.That(File.Exists(path)).IsTrue().Because($"missing generated artifact {artifact.Key}");
            await Assert.That(await File.ReadAllTextAsync(path)).IsEqualTo(artifact.Value)
                .Because($"generated artifact is stale: {artifact.Key}");
        }
    }

    [Test]
    public async Task GeneratedRoleSchemaContainsEveryAndOnlyClosedRoleKind()
    {
        var schema = JsonNode.Parse(SchemaArtifacts.Generate()["schemas/v1/admitted-role.schema.json"])!.AsObject();
        var names = schema["properties"]!["kind"]!["enum"]!.AsArray()
            .Select(node => node!.GetValue<string>()).ToArray();

        await Assert.That(names).IsEquivalentTo(Enum.GetNames<RoleKind>());
        await Assert.That(names.Length).IsEqualTo(18); // INV-017
        await Assert.That(schema["additionalProperties"]!.GetValue<bool>()).IsFalse();
    }

    [Test]
    public async Task GeneratedShapesCannotRepresentArbitraryExecutionOrSecretValues()
    {
        var all = string.Join('\n', SchemaArtifacts.Generate().Values);
        foreach (var forbidden in new[] { "executable", "command", "unitText", "hostPath", "privileged", "linuxCapability", "secretValue", "privateKey" })
        {
            await Assert.That(all).DoesNotContain(forbidden); // INV-015, INV-017, SEC-NO-SECRET-OUTPUT
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
}
