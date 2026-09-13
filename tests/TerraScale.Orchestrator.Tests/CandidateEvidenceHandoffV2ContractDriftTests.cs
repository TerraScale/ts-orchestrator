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
            "ts-deploy",
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
            ["src/TerraScale.Orchestrator/Delivery/DeployHandoff/DeployHandoffContracts.cs"] = "3ddf3076384befa25b07cfdc67f94a38bdb9ecf6c2af7d14f6aa55b0ecaafbf9",
            ["src/TerraScale.Orchestrator/Delivery/DeployHandoff/DeployHandoffMapper.cs"] = "22e561b70f67b8943b3c173daf44feecf67006914d3ff6380e450a479383200d",
            ["src/TerraScale.Orchestrator/Delivery/DeployHandoff/DeployHandoffDeliveryRuntime.cs"] = "d0f42cde065dbc407d223bc7f466f2d184592a757fabbef2170a55da8f276a82",
            ["docs/contracts/deploy-orchestrator-handoff.md"] = "02502b85e8e9d926e11507adb319ac19e4812517f89b1315578a51458132b98e",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/ambiguous-generic-content.json"] = "8c073f95ac27e4e2fd6fb7080fa92c2dd46205b6a9c269bc5319fd0d9b58c661",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/incompatible-rollback-architecture.json"] = "64589203260ae6e738be3f995c2b78a13e7c29260a79cde9f445f579b825b630",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/incompatible-rollback-artifact.json"] = "c0ab795ea020fbb62baee7baceecda3b3016ce97daed5abefd35afb429a6bf0a",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/mismatched-manifest.json"] = "f02e5fa7e2fe93a040efbadf691360af0fcbc4cb53c6f568e4aa5e3769b8d312",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/missing-rollback-manifest-digest.json"] = "5fb73e41c493c93d4a7d6ee265cbf9952ad730364fb04bfe6e51aba42883f8b9",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/missing-tree-digest.json"] = "87eaf5da7af8f010660b8785720b8776eac54fbd98e857319deaf91552290844",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/stale-digest.json"] = "174930981d320af01c6ef5f99ca1e5e532fcee427ba3af8a99ebbe05fb0892ba",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/unknown-field.json"] = "f739ce3bb7cefb9d11458e96aa46ab2c7a05a9f58e432a0b87ec47669f191c9e",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/valid-first-deployment.json"] = "5c19975ab86c1f4e3d131e738d444ea0f31b26e4e8da91c926377f5abd27996c",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/valid-service.json"] = "07768e15bf21d889e117791f01f0807a69beccd239870b8ed64c8082c3fbdef6",
            ["tests/TerraScale.Orchestrator.Tests/DeployHandoff/fixtures/wrong-schema-version.json"] = "78e79d65b7bcbd8ad9e4e3e473cc0f6b04ad012dd3af53ee261b3cefb37d72d0",
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
