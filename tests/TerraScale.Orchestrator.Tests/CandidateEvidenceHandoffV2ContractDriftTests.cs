using System.Security.Cryptography;
using System.Text.Json;
using TerraScale.Orchestrator.Delivery.DeployHandoffV2;

namespace TerraScale.Orchestrator.Tests;

public sealed class CandidateEvidenceHandoffV2ContractDriftTests
{
    private const string CorpusSha256 = "7296415226db0919d1bac3bdfc287dbdede74bacd1a4342944cecda52220137c";

    [Test]
    public async Task CorpusIsBytePinnedAndMatchesDeployWhenTheSiblingRepositoryExists()
    {
        var local = CandidateEvidenceHandoffV2VerifierTests.CorpusBytes();
        await Assert.That(Convert.ToHexStringLower(SHA256.HashData(local))).IsEqualTo(CorpusSha256);

        var sibling = Path.GetFullPath(Path.Combine(
            CandidateEvidenceHandoffV2VerifierTests.RepositoryRoot(),
            "..",
            "TerraScale.Deploy",
            "tests",
            "TerraScale.Deploy.Cli.Tests",
            "SupplyChain",
            "fixtures",
            "candidate-evidence-handoff-v2.json"));
        if (File.Exists(sibling))
            await Assert.That(await File.ReadAllBytesAsync(sibling)).IsEquivalentTo(local);
    }

    [Test]
    public async Task CorpusCoversEverySerializedEnvelopeFieldInBothDirections()
    {
        var raw = CandidateEvidenceHandoffV2VerifierTests.CorpusBytes();
        var envelope = CandidateEvidenceHandoffV2VerifierTests.Envelope();
        var serialized = CandidateEvidenceHandoffV2Verifier.SerializeEnvelope(envelope);

        var rawPaths = JsonPaths(raw);
        var serializedPaths = JsonPaths(serialized);

        await Assert.That(string.Join('\n', serializedPaths.Order()))
            .IsEqualTo(string.Join('\n', rawPaths.Order()));
    }

    [Test]
    public async Task VersionOneMappingAndCorpusRemainByteFrozen()
    {
        var root = CandidateEvidenceHandoffV2VerifierTests.RepositoryRoot();
        var expected = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["src/TerraScale.Orchestrator/Delivery/DeployHandoff/DeployHandoffContracts.cs"] = "58c65b3352d54087f96f959d3b339bfba8d6eb938e7db97d4c95ec9bd13c5fd9",
            ["src/TerraScale.Orchestrator/Delivery/DeployHandoff/DeployHandoffMapper.cs"] = "0d05db3cee2e1ed0c2a20ecb8822d1ee03a29d15884174eef6e3f8aec4de9df6",
            ["src/TerraScale.Orchestrator/Delivery/DeployHandoff/DeployHandoffDeliveryRuntime.cs"] = "66479ebd57131c759a27956697c0049aa1ff9792368c53541f6db450a06cdc8a",
            ["docs/contracts/deploy-orchestrator-handoff.md"] = "02502b85e8e9d926e11507adb319ac19e4812517f89b1315578a51458132b98e",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/ambiguous-generic-content.json"] = "c1ffa93e1f51af0d410fee82ac42661665087267d314161e557c3bdb0b57a745",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/incompatible-rollback-architecture.json"] = "b6f7c2848451d0f622d6d23a64c9ba881aa5c2b19bade97475381b4faf3a6895",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/incompatible-rollback-artifact.json"] = "3b108d90a2d74162c6e1805278a400d2b0c045435a40183b33b435d8712aea04",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/mismatched-manifest.json"] = "ded3a628d2b27d8f9074a7f0a9847497ba203f311dc1b97f8133e1a65a156949",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/missing-rollback-manifest-digest.json"] = "4869725b9a97fa5c22109d2999ae4c647dfec323779d81474cf5fdd229e63d87",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/missing-tree-digest.json"] = "9e6a9b115cdbbdd02feac09d22f486ae39f242656bd0c7c0be6b6dcefd7e133f",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/stale-digest.json"] = "ecb532d58c03df5ea5bcf4d845f4d1f37e2c2f69e93f117c801359a53ae182e5",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/unknown-field.json"] = "8acf01b7a0704b4cdc9c413303cd1439c1c1a18d0b47a9bb77d150d71ccc6ffd",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/valid-first-deployment.json"] = "6db5f178d26633647707d08e3b0e95ff22596b87c66a27316c324c461ad4b222",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/valid-service.json"] = "423176f29198c0b116b73e5b96ba641c690c93d20b3a44c7f1eb6e02d47ce94e",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/wrong-schema-version.json"] = "20d3dc92c1d7a076cfc43dee65940ae66e878c974b6f9ce4179c75f69536adb3",
        };

        foreach (var item in expected)
        {
            var digest = Convert.ToHexStringLower(SHA256.HashData(
                await File.ReadAllBytesAsync(Path.Combine(root, item.Key))));
            await Assert.That(digest).IsEqualTo(item.Value);
        }
    }

    private static HashSet<string> JsonPaths(ReadOnlyMemory<byte> bytes)
    {
        using var document = JsonDocument.Parse(bytes);
        var paths = new HashSet<string>(StringComparer.Ordinal);
        Visit(document.RootElement, "$", paths);
        return paths;
    }

    private static void Visit(JsonElement value, string path, HashSet<string> paths)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in value.EnumerateObject())
            {
                var child = path + "." + property.Name;
                paths.Add(child);
                Visit(property.Value, child, paths);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            var child = path + "[]";
            paths.Add(child);
            foreach (var item in value.EnumerateArray())
                Visit(item, child, paths);
        }
    }
}

