using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
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

    [Test]
    public async Task DescriptorRoleProjectionRetainsEveryClosedRoleAndSelectedImplementation()
    {
        var descriptor = GeneratedSchema("schemas/v1/role-descriptor.schema.json");
        var roleSchema = descriptor["properties"]!["role"]!.AsObject();
        var roles = AllRoles();

        foreach (var role in roles)
        {
            await Assert.That(AcceptsRole(roleSchema, Project(role))).IsTrue().Because(role.GetType().Name);
        }

        var first = Project(new MetricsStoreRole(new(ImplementationDomain.MetricsStore, new("metrics-a"))));
        var second = Project(new MetricsStoreRole(new(ImplementationDomain.MetricsStore, new("metrics-b"))));
        await Assert.That(AcceptsRole(roleSchema, first)).IsTrue();
        await Assert.That(AcceptsRole(roleSchema, second)).IsTrue();
        await Assert.That(JsonNode.DeepEquals(first, second)).IsFalse();
    }

    [Test]
    public async Task DescriptorRoleProjectionRejectsMissingWrongAndUnexpectedImplementationProvenance()
    {
        var roleSchema = GeneratedSchema("schemas/v1/role-descriptor.schema.json")["properties"]!["role"]!.AsObject();

        await Assert.That(AcceptsRole(roleSchema, new JsonObject { ["kind"] = "MetricsStore" })).IsFalse();
        await Assert.That(AcceptsRole(roleSchema, Role("MetricsStore", "Vpn", "metrics"))).IsFalse();
        await Assert.That(AcceptsRole(roleSchema, Role("RegionalTelemetryAgent", "MetricsStore", "telemetry"))).IsFalse();
        await Assert.That(AcceptsRole(roleSchema, Role("VpnCoordinationRelay", "RegionalTelemetry", "vpn"))).IsFalse();
        await Assert.That(AcceptsRole(roleSchema, Role("Api", "MetricsStore", "metrics"))).IsFalse();
        await Assert.That(AcceptsRole(roleSchema, new JsonObject { ["kind"] = "ArbitraryWorkload" })).IsFalse();
        await Assert.That(AcceptsRole(roleSchema, new JsonObject { ["kind"] = "Api", ["unknown"] = true })).IsFalse();
        await Assert.That(AcceptsRole(roleSchema, Role("MetricsStore", "MetricsStore", "metrics", extraImplementationField: true))).IsFalse();
    }

    [Test]
    public async Task StandaloneAndNestedRoleShapesShareExactlyOneSemanticDefinition()
    {
        var standalone = GeneratedSchema("schemas/v1/admitted-role.schema.json");
        var nested = GeneratedSchema("schemas/v1/role-descriptor.schema.json")["properties"]!["role"]!.AsObject();
        foreach (var name in new[] { "$schema", "$id", "title", "$comment" }) standalone.Remove(name);
        standalone["required"]!.AsArray().RemoveAt(0);
        standalone["properties"]!.AsObject().Remove("apiVersion");

        await Assert.That(JsonNode.DeepEquals(standalone, nested)).IsTrue();
        await Assert.That(nested["additionalProperties"]!.GetValue<bool>()).IsFalse();
        await Assert.That(nested["properties"]!["apiVersion"] is null).IsTrue();
    }

    private static JsonObject GeneratedSchema(string path) =>
        JsonNode.Parse(SchemaArtifacts.Generate()[path])!.AsObject();

    private static JsonObject Project(AdmittedRole role) => role switch
    {
        MetricsStoreRole selected => Role(role.Kind.ToString(), selected.Implementation.Domain.ToString(), selected.Implementation.CatalogEntryId.Value),
        RegionalTelemetryAgentRole selected => Role(role.Kind.ToString(), selected.Implementation.Domain.ToString(), selected.Implementation.CatalogEntryId.Value),
        VpnCoordinationRelayRole selected => Role(role.Kind.ToString(), selected.Implementation.Domain.ToString(), selected.Implementation.CatalogEntryId.Value),
        _ => new JsonObject { ["kind"] = role.Kind.ToString() },
    };

    private static JsonObject Role(string kind, string domain, string catalogEntryId, bool extraImplementationField = false)
    {
        var implementation = new JsonObject { ["domain"] = domain, ["catalogEntryId"] = catalogEntryId };
        if (extraImplementationField) implementation["unknown"] = true;
        return new JsonObject { ["kind"] = kind, ["implementation"] = implementation };
    }

    private static bool AcceptsRole(JsonObject schema, JsonObject candidate)
    {
        var properties = schema["properties"]!.AsObject();
        if (candidate.Any(property => !properties.ContainsKey(property.Key))) return false;
        if (schema["required"]!.AsArray().Any(name => !candidate.ContainsKey(name!.GetValue<string>()))) return false;
        if (candidate["kind"] is not JsonValue kindValue || !kindValue.TryGetValue<string>(out var kind)) return false;
        var kinds = properties["kind"]!["enum"]!.AsArray().Select(value => value!.GetValue<string>());
        if (!kinds.Contains(kind, StringComparer.Ordinal)) return false;

        var conditions = schema["allOf"]!.AsArray();
        var implementationKinds = conditions[0]!["if"]!["properties"]!["kind"]!["enum"]!.AsArray()
            .Select(value => value!.GetValue<string>()).ToHashSet(StringComparer.Ordinal);
        var requiresImplementation = implementationKinds.Contains(kind);
        if (requiresImplementation != candidate.ContainsKey("implementation")) return false;
        if (!requiresImplementation) return true;
        if (candidate["implementation"] is not JsonObject implementation) return false;

        var implementationSchema = properties["implementation"]!.AsObject();
        var implementationProperties = implementationSchema["properties"]!.AsObject();
        if (implementation.Any(property => !implementationProperties.ContainsKey(property.Key))) return false;
        if (implementationSchema["required"]!.AsArray().Any(name => !implementation.ContainsKey(name!.GetValue<string>()))) return false;
        if (implementation["domain"] is not JsonValue domainValue || !domainValue.TryGetValue<string>(out var domain)) return false;
        if (implementation["catalogEntryId"] is not JsonValue idValue || !idValue.TryGetValue<string>(out var id)) return false;
        var idSchema = implementationProperties["catalogEntryId"]!.AsObject();
        if (id.Length < idSchema["minLength"]!.GetValue<int>() || id.Length > idSchema["maxLength"]!.GetValue<int>() ||
            !Regex.IsMatch(id, idSchema["pattern"]!.GetValue<string>(), RegexOptions.CultureInvariant)) return false;

        var expectedDomain = conditions.Skip(1)
            .Single(condition => condition!["if"]!["properties"]!["kind"]!["const"]!.GetValue<string>() == kind)!
            ["then"]!["properties"]!["implementation"]!["properties"]!["domain"]!["const"]!.GetValue<string>();
        return string.Equals(domain, expectedDomain, StringComparison.Ordinal);
    }

    private static IReadOnlyList<AdmittedRole> AllRoles() =>
    [
        new ApiRole(), new AuthenticationRole(), new CustomerDashboardRole(), new TerraBaseMemberRole(),
        new OrchestratorRole(), new ControlNatsServerRole(), new ProductNatsServerRole(), new GrafanaRole(),
        new MetricsStoreRole(new(ImplementationDomain.MetricsStore, new("metrics"))), new LokiRole(), new TempoRole(),
        new AlertmanagerRole(), new OtlpIngestRole(), new SyntheticCheckRole(),
        new RegionalTelemetryAgentRole(new(ImplementationDomain.RegionalTelemetry, new("telemetry"))),
        new VpnCoordinationRelayRole(new(ImplementationDomain.Vpn, new("vpn"))), new RoutePolicyControllerRole(), new CiRunnerRole(),
    ];

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
