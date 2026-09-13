using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery.DeployHandoff;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Contract-drift coverage for the typed Deploy-to-Orchestrator handoff (issue #26): the
/// machine-readable field table in <c>docs/contracts/deploy-orchestrator-handoff.md</c> is the
/// source of truth for the mapping. Adding a <see cref="DeliveryRequest"/> field, a manifest
/// field, or a mapping output without updating the documented table fails here with a bounded
/// actionable error naming the field and the document to update.
/// </summary>
public sealed class DeployHandoffContractDriftTests
{
    private const string ContractPath = "docs/contracts/deploy-orchestrator-handoff.md";
    private const string MappingTableId = "deploy-handoff-mapping-v1";

    [Test]
    public async Task Documented_field_table_covers_every_delivery_request_field()
    {
        var table = MappingTable();
        var documented = DocumentedOutputs(table, "handoffRequest.delivery.");
        var request = DeliveryWireCodec.SerializeRequest(PopulatedDeliveryRequest());
        var wirePaths = JsonPaths(request);

        var unmapped = wirePaths.Where(path => !documented.Contains("handoffRequest.delivery." + path)).Order().ToList();

        if (unmapped.Count > 0)
            Assert.Fail(
                $"DeliveryRequest field(s) {string.Join(", ", unmapped)} are not mapped by the table in {ContractPath} " +
                "(block 'deploy-handoff-mapping-v1'). Add a row for every new DeliveryRequest field in the same " +
                "change as the mapper update.");

        await Assert.That(string.Join(", ", unmapped)).IsEqualTo(string.Empty);
    }

    [Test]
    public async Task Documented_field_table_covers_every_handoff_manifest_field()
    {
        var table = MappingTable();
        var documented = DocumentedInputs(table);
        var manifestPaths = JsonPaths(SerializeManifest(PopulatedManifest()));

        var undocumented = manifestPaths.Where(path => !documented.Contains(path)).Order().ToList();

        if (undocumented.Count > 0)
            Assert.Fail(
                $"Handoff manifest field(s) {string.Join(", ", undocumented)} are not documented in the table in " +
                $"{ContractPath} (block 'deploy-handoff-mapping-v1'). Document every manifest DTO field in the same " +
                "change as the mapper update.");

        await Assert.That(string.Join(", ", undocumented)).IsEqualTo(string.Empty);
    }

    [Test]
    public async Task Documented_input_rows_exist_on_the_handoff_manifest_dto()
    {
        var table = MappingTable();
        var documented = DocumentedInputs(table);
        var manifestPaths = JsonPaths(SerializeManifest(PopulatedManifest()));

        // Reverse direction: a documented input row whose field no longer exists on the
        // manifest DTO (renamed or removed without updating the contract) must fail here.
        var vanished = documented.Where(path => !manifestPaths.Contains(path)).Order().ToList();

        if (vanished.Count > 0)
            Assert.Fail(
                $"The table in {ContractPath} (block 'deploy-handoff-mapping-v1') documents input field(s) " +
                $"{string.Join(", ", vanished)} that no longer exist on the manifest DTO; update the table in the " +
                "same change as the DTO change.");

        await Assert.That(string.Join(", ", vanished)).IsEqualTo(string.Empty);
    }

    [Test]
    public async Task Documented_executable_outputs_are_present_on_the_mapped_request()
    {
        var table = MappingTable();
        var result = DeployHandoffMapper.Map(DeployHandoffCorpus.Fixture("valid-service.json"));

        await Assert.That(result.Decision).IsEqualTo(DeployHandoffMappingDecision.Admitted);
        var wirePaths = JsonPaths(DeliveryWireCodec.SerializeRequest(result.Request!.Delivery));

        var missing = table.GetProperty("fields").EnumerateArray()
            .Where(static entry => entry.TryGetProperty("output", out var output) &&
                                   output.ValueKind is JsonValueKind.String &&
                                   output.GetString()!.StartsWith("handoffRequest.delivery.", StringComparison.Ordinal) &&
                                   entry.TryGetProperty("class", out var classification) &&
                                   classification.GetString() == "executable")
            .Select(static entry => entry.GetProperty("output").GetString()!)
            .Where(output => !wirePaths.Contains(output["handoffRequest.delivery.".Length..]))
            .Order()
            .ToList();

        if (missing.Count > 0)
            Assert.Fail(
                $"Documented executable output(s) {string.Join(", ", missing)} are not produced by the mapper for " +
                $"the valid fixture; keep {ContractPath} (block 'deploy-handoff-mapping-v1') and the mapper in sync.");

        await Assert.That(string.Join(", ", missing)).IsEqualTo(string.Empty);
    }

    [Test]
    public async Task Documented_handoff_only_outputs_are_present_on_the_typed_request()
    {
        var table = MappingTable();
        var result = DeployHandoffMapper.Map(DeployHandoffCorpus.Fixture("valid-service.json"));
        var request = result.Request!;

        var outputs = table.GetProperty("fields").EnumerateArray()
            .Where(static entry => entry.TryGetProperty("output", out var output) &&
                                   output.ValueKind is JsonValueKind.String &&
                                   output.GetString()!.StartsWith("handoffRequest.", StringComparison.Ordinal) &&
                                   !output.GetString()!.StartsWith("handoffRequest.delivery.", StringComparison.Ordinal))
            .Select(static entry => entry.GetProperty("output").GetString()!)
            .Order()
            .ToList();

        await Assert.That(outputs).Contains("handoffRequest.architecture");
        await Assert.That(outputs).Contains("handoffRequest.rollbackArtifact.artifactDigest");
        await Assert.That(outputs).Contains("handoffRequest.rollbackArtifact.manifestDigest");
        await Assert.That(outputs).Contains("handoffRequest.rollbackArtifact.kind");
        await Assert.That(outputs).Contains("handoffRequest.rollbackArtifact.architecture");
        await Assert.That(request.Architecture).IsEqualTo("linux/amd64");
        await Assert.That(request.RollbackArtifact).IsNotNull();
    }

    [Test]
    public async Task Document_pins_the_live_contract_versions()
    {
        var table = MappingTable();

        await Assert.That(table.GetProperty("id").GetString()).IsEqualTo(MappingTableId);
        await Assert.That(table.GetProperty("mappingVersion").GetInt32()).IsEqualTo(DeployHandoffMapping.CurrentVersion);
        await Assert.That(table.GetProperty("manifestSchemaVersions").GetProperty("minimum").GetInt32())
            .IsEqualTo(DeployHandoffManifestSchema.MinimumSupportedVersion);
        await Assert.That(table.GetProperty("manifestSchemaVersions").GetProperty("maximum").GetInt32())
            .IsEqualTo(DeployHandoffManifestSchema.CurrentVersion);
        await Assert.That(table.GetProperty("directDeliveryContract").GetProperty("schemaVersion").GetInt32())
            .IsEqualTo(DeliveryRequest.CurrentSchemaVersion);
    }

    private static JsonElement MappingTable()
    {
        var contract = DeployHandoffCorpus.Contract();
        var extract = ExtractMappingBlock(contract);
        JsonDocument table;
        try
        {
            table = JsonDocument.Parse(extract.Json);
        }
        catch (JsonException exception)
        {
            Assert.Fail(
                $"The machine-readable mapping table in {ContractPath} (block '{MappingTableId}') is not valid " +
                $"JSON: {exception.Message}. Fix the fenced json block before changing the mapper.");
            throw new InvalidOperationException("unreachable");
        }

        if (table.RootElement.ValueKind is not JsonValueKind.Object ||
            table.RootElement.TryGetProperty("id", out var id) is false ||
            id.GetString() != MappingTableId ||
            table.RootElement.TryGetProperty("fields", out var fields) is false ||
            fields.ValueKind is not JsonValueKind.Array)
        {
            Assert.Fail(
                $"The machine-readable mapping table in {ContractPath} must be a JSON object with " +
                $"id '{MappingTableId}' and a 'fields' array; update {ContractPath} alongside mapper changes.");
            throw new InvalidOperationException("unreachable");
        }

        return table.RootElement;
    }

    private static (string Json, int Line) ExtractMappingBlock(string contract)
    {
        var lines = contract.Split('\n');
        for (var index = 0; index < lines.Length; index++)
        {
            if (!lines[index].TrimEnd().Equals("```json", StringComparison.Ordinal))
                continue;

            var end = Array.IndexOf(lines, "```", index + 1);
            if (end < 0)
                break;

            var block = string.Join('\n', lines[(index + 1)..end]);
            if (block.Contains($"\"id\": \"{MappingTableId}\"", StringComparison.Ordinal))
                return (block, index + 2);
        }

        Assert.Fail(
            $"The fenced json mapping table with id '{MappingTableId}' is missing from {ContractPath}. " +
            "Every mapper field change must update that table in the same change.");
        throw new InvalidOperationException("unreachable");
    }

    private static HashSet<string> DocumentedOutputs(JsonElement table, string prefix) =>
        table.GetProperty("fields").EnumerateArray()
            .Where(static entry => entry.TryGetProperty("output", out var output) &&
                                   output.ValueKind is JsonValueKind.String)
            .Select(static entry => entry.GetProperty("output").GetString()!)
            .Where(output => output.StartsWith(prefix, StringComparison.Ordinal))
            .ToHashSet(StringComparer.Ordinal);

    private static HashSet<string> DocumentedInputs(JsonElement table) =>
        table.GetProperty("fields").EnumerateArray()
            .Where(static entry => entry.TryGetProperty("input", out var input) &&
                                   input.ValueKind is JsonValueKind.String)
            .Select(static entry => entry.GetProperty("input").GetString()!)
            .ToHashSet(StringComparer.Ordinal);

    private static string SerializeManifest(DeployHandoffManifest manifest) =>
        DeployHandoffMapper.SerializeManifest(manifest);

    private static HashSet<string> JsonPaths(string json)
    {
        using var document = JsonDocument.Parse(json);
        var paths = new HashSet<string>(StringComparer.Ordinal);
        CollectPaths(document.RootElement, "", paths);
        return paths;
    }

    private static void CollectPaths(JsonElement element, string prefix, HashSet<string> paths)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    var path = prefix.Length == 0 ? property.Name : prefix + "." + property.Name;
                    CollectPaths(property.Value, path, paths);
                }

                break;
            default:
                if (prefix.Length > 0)
                    paths.Add(prefix);
                break;
        }
    }

    private static DeliveryRequest PopulatedDeliveryRequest() => new(
        SchemaVersion: DeliveryRequest.CurrentSchemaVersion,
        OperationId: "drift-probe-operation",
        Source: new DeliverySource("TerraScale/TerraScale.Orchestrator", new string('1', 40), "sha256:" + new string('1', 64)),
        Artifact: new DeliveryArtifact("sha256:" + new string('2', 64), "sha256:" + new string('3', 64), "service"),
        Target: new DeliveryTarget("terrascale-orchestrator", "development", ["gru"]),
        ConfigurationRevision: "sha256:" + new string('6', 64),
        MigrationRevision: "sha256:" + new string('7', 64),
        RequestedBy: "drift-probe",
        Reason: "drift probe");

    private static DeployHandoffManifest PopulatedManifest() => new(
        SchemaVersion: DeployHandoffManifestSchema.CurrentVersion,
        OperationId: "drift-probe-operation",
        Source: new DeployHandoffSource("TerraScale/TerraScale.Orchestrator", new string('1', 40), "sha256:" + new string('1', 64)),
        Artifact: new DeployHandoffArtifact(
            "sha256:" + new string('2', 64), "sha256:" + new string('3', 64), "service", "linux/amd64"),
        Rollback: new DeployHandoffRollback(
            "sha256:" + new string('4', 64), "sha256:" + new string('5', 64), "service", "linux/amd64"),
        Target: new DeployHandoffTarget("terrascale-orchestrator", "development", ["gru"]),
        ConfigurationRevision: "sha256:" + new string('6', 64),
        MigrationRevision: "sha256:" + new string('7', 64),
        RequestedBy: "drift-probe",
        Reason: "drift probe",
        Informational: new DeployHandoffInformational("drift probe", ["release-notices"]));
}

