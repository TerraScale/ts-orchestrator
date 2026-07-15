using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using TerraScale.Orchestrator.Contracts.Resources;

namespace TerraScale.Orchestrator.SchemaGenerator;

public static class SchemaArtifacts
{
    private const string Draft = "https://json-schema.org/draft/2020-12/schema";
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static IReadOnlyDictionary<string, string> Generate()
    {
        var artifacts = new SortedDictionary<string, string>(StringComparer.Ordinal)
        {
            ["schemas/v1/resource-metadata.schema.json"] = Json(ResourceMetadataSchema()),
            ["schemas/v1/admitted-role.schema.json"] = Json(AdmittedRoleSchema()),
            ["schemas/v1/role-descriptor.schema.json"] = Json(RoleDescriptorSchema()),
            ["schemas/v1/fixtures/resource-metadata.valid.json"] = Json(ValidMetadataFixture()),
            ["schemas/v1/fixtures/admitted-role.valid.json"] = Json(ValidRoleFixture()),
            ["schemas/v1/fixtures/admitted-role.invalid-unknown.json"] = Json(new JsonObject
            {
                ["apiVersion"] = ApiVersion.V1.Value, ["kind"] = "ArbitraryWorkload"
            }),
            ["schemas/v1/admitted-roles.md"] = RoleDocumentation(),
        };
        return artifacts;
    }

    private static JsonObject ResourceMetadataSchema() => Root(
        "https://schemas.terrascale.tech/orchestrator/v1/resource-metadata.schema.json",
        "TerraScale Orchestrator resource metadata",
        Object(
            required: ["apiVersion", "id", "generation", "resourceVersion", "ownership", "creationActor", "auditCorrelationId"],
            properties: new()
            {
                ["apiVersion"] = Const(ApiVersion.V1.Value),
                ["id"] = ResourceIdSchema(),
                ["generation"] = PositiveInteger(),
                ["resourceVersion"] = PositiveInteger(),
                ["ownership"] = Object(["kind", "authorityId"], new()
                {
                    ["kind"] = EnumSchema<AuthorityKind>(), ["authorityId"] = ResourceIdSchema()
                }),
                ["creationActor"] = Object(["kind", "actorId"], new()
                {
                    ["kind"] = EnumSchema<CreationActorKind>(), ["actorId"] = ResourceIdSchema()
                }),
                ["auditCorrelationId"] = ResourceIdSchema(),
            }));

    private static JsonObject AdmittedRoleSchema()
    {
        var root = Root(
            "https://schemas.terrascale.tech/orchestrator/v1/admitted-role.schema.json",
            "Closed TerraScale Orchestrator admitted role",
            AdmittedRoleShape(includeApiVersion: true));
        var conditions = root["allOf"];
        root.Remove("allOf");
        root["$comment"] = "Draft internal contract. A manifest cannot synthesize RoleDescriptor; it may later reference only a reviewed built-in catalog entry.";
        root["allOf"] = conditions;
        return root;
    }

    private static JsonObject AdmittedRoleShape(bool includeApiVersion)
    {
        var implementationKinds = new[] { nameof(RoleKind.MetricsStore), nameof(RoleKind.RegionalTelemetryAgent), nameof(RoleKind.VpnCoordinationRelay) };
        var properties = new JsonObject
        {
            ["kind"] = EnumSchema<RoleKind>(),
            ["implementation"] = Object(["domain", "catalogEntryId"], new()
            {
                ["domain"] = EnumSchema<ImplementationDomain>(), ["catalogEntryId"] = ResourceIdSchema()
            }),
        };
        if (includeApiVersion)
        {
            properties.Insert(0, "apiVersion", Const(ApiVersion.V1.Value));
        }

        var shape = Object(includeApiVersion ? ["apiVersion", "kind"] : ["kind"], properties);
        shape["allOf"] = new JsonArray(
            new JsonObject
            {
                ["if"] = new JsonObject { ["properties"] = new JsonObject { ["kind"] = StringEnum(implementationKinds) } },
                ["then"] = new JsonObject { ["required"] = Strings("implementation") },
                ["else"] = new JsonObject { ["properties"] = new JsonObject { ["implementation"] = false } },
            },
            DomainCondition(RoleKind.MetricsStore, ImplementationDomain.MetricsStore),
            DomainCondition(RoleKind.RegionalTelemetryAgent, ImplementationDomain.RegionalTelemetry),
            DomainCondition(RoleKind.VpnCoordinationRelay, ImplementationDomain.Vpn));
        return shape;
    }

    private static JsonObject RoleDescriptorSchema()
    {
        var root = Root(
            "https://schemas.terrascale.tech/orchestrator/v1/role-descriptor.schema.json",
            "Read-only built-in role descriptor projection",
            Object(
                ["apiVersion", "role", "allowedRuntimes", "ports", "capabilities", "volumePurposes", "secretProfiles", "healthSignals", "failureDomainSpread", "scalingControllerOwner"],
                new()
                {
                    ["apiVersion"] = Const(ApiVersion.V1.Value),
                    ["role"] = AdmittedRoleShape(includeApiVersion: false),
                    ["allowedRuntimes"] = UniqueArray(EnumSchema<RuntimeDriver>(), 1),
                    ["ports"] = UniqueArray(Object(["protocol", "port"], new()
                    {
                        ["protocol"] = EnumSchema<TransportProtocol>(),
                        ["port"] = new JsonObject { ["type"] = "integer", ["minimum"] = 1, ["maximum"] = 65535 },
                    })),
                    ["capabilities"] = UniqueArray(EnumSchema<RoleCapability>()),
                    ["volumePurposes"] = UniqueArray(EnumSchema<VolumePurpose>()),
                    ["secretProfiles"] = UniqueArray(ResourceIdSchema()),
                    ["healthSignals"] = UniqueArray(EnumSchema<HealthSignal>(), 1),
                    ["failureDomainSpread"] = EnumSchema<FailureDomainSpread>(),
                    ["scalingControllerOwner"] = EnumSchema<ScalingControllerOwner>(),
                }));
        root["readOnly"] = true;
        root["$comment"] = "Generated documentation shape only. RoleDescriptor construction is assembly-internal.";
        return root;
    }

    private static JsonObject DomainCondition(RoleKind kind, ImplementationDomain domain) => new()
    {
        ["if"] = new JsonObject { ["properties"] = new JsonObject { ["kind"] = Const(kind.ToString()) } },
        ["then"] = new JsonObject
        {
            ["properties"] = new JsonObject
            {
                ["implementation"] = new JsonObject
                {
                    ["properties"] = new JsonObject { ["domain"] = Const(domain.ToString()) }
                }
            }
        }
    };

    private static JsonObject ValidMetadataFixture() => new()
    {
        ["apiVersion"] = ApiVersion.V1.Value,
        ["id"] = "workload-api",
        ["generation"] = 2,
        ["resourceVersion"] = 9,
        ["ownership"] = new JsonObject { ["kind"] = nameof(AuthorityKind.RegionalController), ["authorityId"] = "gru-controller" },
        ["creationActor"] = new JsonObject { ["kind"] = nameof(CreationActorKind.GitOps), ["actorId"] = "release-controller" },
        ["auditCorrelationId"] = "reconcile-12345678",
    };

    private static JsonObject ValidRoleFixture() => new()
    {
        ["apiVersion"] = ApiVersion.V1.Value,
        ["kind"] = nameof(RoleKind.MetricsStore),
        ["implementation"] = new JsonObject
        {
            ["domain"] = nameof(ImplementationDomain.MetricsStore), ["catalogEntryId"] = "owner-selected-metrics"
        },
    };

    private static string RoleDocumentation()
    {
        var builder = new StringBuilder("# Generated admitted roles v1\n\nGenerated from `RoleKind` and the closed `AdmittedRole` union. Do not edit.\n\n| Value | Role type | Owner selection required |\n|---|---|---|\n");
        var cases = typeof(AdmittedRole).Assembly.GetTypes()
            .Where(type => type.BaseType == typeof(AdmittedRole))
            .ToDictionary(type => type.Name, StringComparer.Ordinal);
        foreach (var kind in Enum.GetValues<RoleKind>())
        {
            var typeName = kind + "Role";
            if (kind == RoleKind.RegionalTelemetryAgent) typeName = nameof(RegionalTelemetryAgentRole);
            if (kind == RoleKind.VpnCoordinationRelay) typeName = nameof(VpnCoordinationRelayRole);
            var selected = kind is RoleKind.MetricsStore or RoleKind.RegionalTelemetryAgent or RoleKind.VpnCoordinationRelay ? "yes" : "no";
            if (!cases.ContainsKey(typeName)) throw new InvalidOperationException($"Role {kind} has no sealed union case.");
            builder.Append('|').Append(kind).Append('|').Append(typeName).Append('|').Append(selected).Append("|\n");
        }
        return builder.ToString();
    }

    private static JsonObject Root(string id, string title, JsonObject body)
    {
        body.Insert(0, "$schema", Draft);
        body.Insert(1, "$id", id);
        body.Insert(2, "title", title);
        return body;
    }

    private static JsonObject Object(string[] required, JsonObject properties) => new()
    {
        ["type"] = "object", ["additionalProperties"] = false,
        ["required"] = Strings(required), ["properties"] = properties,
    };

    private static JsonObject ResourceIdSchema() => new()
    {
        ["type"] = "string", ["minLength"] = 1, ["maxLength"] = ResourceId.MaximumLength,
        ["pattern"] = ResourceId.JsonSchemaPattern,
    };

    private static JsonObject PositiveInteger() => new()
    {
        ["type"] = "integer", ["minimum"] = 1,
        ["maximum"] = JsonValue.Create(ulong.MaxValue),
    };

    private static JsonObject EnumSchema<T>() where T : struct, Enum => StringEnum(Enum.GetNames<T>());

    private static JsonObject StringEnum(IEnumerable<string> values) => new()
    {
        ["type"] = "string", ["enum"] = Strings(values.ToArray()),
    };

    private static JsonObject Const(string value) => new() { ["const"] = value };

    private static JsonObject UniqueArray(JsonNode item, int minimum = 0) => new()
    {
        ["type"] = "array", ["minItems"] = minimum, ["uniqueItems"] = true, ["items"] = item,
    };

    private static JsonArray Strings(params string[] values) => new(values.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray());

    private static string Json(JsonNode value) => value.ToJsonString(JsonOptions) + "\n";
}
