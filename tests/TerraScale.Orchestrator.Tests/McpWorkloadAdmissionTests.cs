using TerraScale.Orchestrator.Runtime;
using TerraScale.Orchestrator.Runtime.Mcp;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Typed role and manifest admission for the MCP workload (TerraScale.Orchestrator#9):
/// undeclared artifacts, settings, secret refs, ports, probes, and ingress are rejected, and
/// secret material never enters the manifest.
/// </summary>
public sealed class McpWorkloadAdmissionTests
{
    private const string Arm64Digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string X64Digest = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    private static McpHttpArtifactQualification Qualification => McpHttpArtifactQualification.Of(
        new McpQualifiedHttpArtifact(Arm64Digest, HostArchitecture.Arm64),
        new McpQualifiedHttpArtifact(X64Digest, HostArchitecture.X64));

    private static string ManifestDocument(
        string digest = Arm64Digest,
        string architecture = "linux/arm64",
        int port = McpWorkloadPorts.HttpListenerPort,
        string? configuration = null,
        string? secretReferences = null,
        string? probes = null) =>
        """
        {
          "schemaVersion": 1,
          "artifact": { "digest": "<digest>", "architecture": "<architecture>" },
          "httpListenerPort": <port>,
          "configuration": <configuration>,
          "secretReferences": <secretReferences>,
          "probes": <probes>
        }
        """
        .Replace("<digest>", digest, StringComparison.Ordinal)
        .Replace("<architecture>", architecture, StringComparison.Ordinal)
        .Replace("<port>", port.ToString(System.Globalization.CultureInfo.InvariantCulture), StringComparison.Ordinal)
        .Replace("<configuration>", configuration ?? DefaultConfiguration, StringComparison.Ordinal)
        .Replace("<secretReferences>", secretReferences ?? DefaultSecretReferences, StringComparison.Ordinal)
        .Replace("<probes>", probes ?? DefaultProbes, StringComparison.Ordinal);

    private const string DefaultConfiguration =
        """{"public-base-url":"https://mcp.terrascale.tech","authentication-issuer-url":"https://auth.terrascale.tech","platform-public-api-base-url":"https://api.terrascale.tech","minimum-log-level":"information"}""";

    private const string DefaultSecretReferences =
        """["vault:terrascale/mcp/oauth-client-secret"]""";

    private const string DefaultProbes =
        """["/health/live","/health/ready"]""";

    [Test]
    public async Task Admits_the_exact_qualified_artifact_with_the_closed_manifest_shape()
    {
        var decision = McpWorkloadAdmission.AdmitDocument(ManifestDocument(), Qualification);

        await Assert.That(decision.Code).IsEqualTo(McpAdmissionCode.Admitted);
        await Assert.That(McpWorkloadAdmission.AdmitManifest(Manifest(), Qualification).Code)
            .IsEqualTo(McpAdmissionCode.Admitted);
    }

    [Test]
    public async Task The_catalog_entry_is_closed_native_and_two_instance()
    {
        var descriptor = AdmittedRoleCatalog.Get(AdmittedRole.McpServer);

        await Assert.That(descriptor.ArtifactKey).IsEqualTo("terrascale-mcp");
        await Assert.That(descriptor.DefaultDriver).IsEqualTo(RuntimeDriver.NativeSystemd);
        await Assert.That(descriptor.AllowedDrivers).DoesNotContain(RuntimeDriver.OciContainer);
        await Assert.That(descriptor.MinimumReplicas).IsEqualTo(2);
        await Assert.That(descriptor.OnePerHost).IsTrue();
        await Assert.That(descriptor.Capabilities).Contains(RoleCapability.PublicHttp);
        await Assert.That(() => AdmittedRoleCatalog.Admit(AdmittedRole.McpServer, RuntimeDriver.OciContainer))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task The_catalog_pins_the_mcp_resource_ceiling_and_rejects_over_ceiling_requests()
    {
        // The ADR-0032 admission ceiling for the stateless HTTP gateway envelope.
        var ceiling = RuntimeResourceLimitPolicy.For(AdmittedRole.McpServer);
        await Assert.That(ceiling).IsEqualTo(new RuntimeResourceLimits(
            512L * 1024 * 1024, 256, 200, 400, 300, 0));
        await Assert.That(ceiling.MemoryHighBytes).IsEqualTo(9 * ceiling.MemoryMaxBytes / 10);

        // An at-ceiling request is admitted unchanged...
        var atCeiling = RuntimeResourceLimitPolicy.For(AdmittedRole.McpServer, new(
            ceiling.MemoryMaxBytes, ceiling.TasksMax, ceiling.CpuQuotaPercent, ceiling.CpuWeight, ceiling.IoWeight, ceiling.Nice));
        await Assert.That(atCeiling).IsEqualTo(ceiling);

        // ...and every over-ceiling dimension is rejected before a plan exists.
        await Assert.That(() => RuntimeResourceLimitPolicy.For(AdmittedRole.McpServer, new(
            ceiling.MemoryMaxBytes + 1, ceiling.TasksMax, ceiling.CpuQuotaPercent, ceiling.CpuWeight, ceiling.IoWeight, ceiling.Nice)))
            .Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => RuntimeResourceLimitPolicy.For(AdmittedRole.McpServer, new(
            ceiling.MemoryMaxBytes, ceiling.TasksMax + 1, ceiling.CpuQuotaPercent, ceiling.CpuWeight, ceiling.IoWeight, ceiling.Nice)))
            .Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => RuntimeResourceLimitPolicy.For(AdmittedRole.McpServer, new(
            ceiling.MemoryMaxBytes, ceiling.TasksMax, ceiling.CpuQuotaPercent + 1, ceiling.CpuWeight, ceiling.IoWeight, ceiling.Nice)))
            .Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => RuntimeResourceLimitPolicy.For(AdmittedRole.McpServer, new(
            ceiling.MemoryMaxBytes, ceiling.TasksMax, ceiling.CpuQuotaPercent, ceiling.CpuWeight + 1, ceiling.IoWeight, ceiling.Nice)))
            .Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task A_typed_manifest_with_null_collections_is_rejected_not_thrown()
    {
        var admitted = McpWorkloadAdmissionTests.Manifest();

        var nullConfiguration = McpWorkloadAdmission.AdmitManifest(
            admitted with { Configuration = null! }, Qualification);
        var nullSecretReferences = McpWorkloadAdmission.AdmitManifest(
            admitted with { SecretReferences = null! }, Qualification);
        var nullProbes = McpWorkloadAdmission.AdmitManifest(
            admitted with { ProbePaths = null! }, Qualification);

        await Assert.That(nullConfiguration.Code).IsEqualTo(McpAdmissionCode.FieldMissing);
        await Assert.That(nullConfiguration.Field).IsEqualTo("configuration");
        await Assert.That(nullSecretReferences.Code).IsEqualTo(McpAdmissionCode.FieldMissing);
        await Assert.That(nullSecretReferences.Field).IsEqualTo("secretReferences");
        await Assert.That(nullProbes.Code).IsEqualTo(McpAdmissionCode.FieldMissing);
        await Assert.That(nullProbes.Field).IsEqualTo("probes");
    }

    [Test]
    public async Task Nothing_is_admitted_without_qualification_evidence()
    {
        var decision = McpWorkloadAdmission.AdmitDocument(ManifestDocument(), McpHttpArtifactQualification.None);

        await Assert.That(decision.Code).IsEqualTo(McpAdmissionCode.ArchitectureNotQualified);
    }

    [Test]
    public async Task Rejects_arbitrary_images_executables_mounts_capabilities_and_env()
    {
        foreach (var (field, hostile) in new[]
                 {
                     ("image", "\"registry.example/terrascale-mcp:latest\""),
                     ("images", "[\"nginx:latest\"]"),
                     ("executable", "\"/usr/local/bin/evil\""),
                     ("command", "[\"sh\",\"-c\",\"curl evil.internal\"]"),
                     ("entrypoint", "\"/bin/sh\""),
                     ("mounts", "[{\"host\":\"/etc\",\"target\":\"/etc\"}]"),
                     ("capabilities", "[\"NET_ADMIN\",\"SYS_ADMIN\"]"),
                     ("environment", "{\"PATH\":\"/evil\"}"),
                     ("ingress", "{\"open\":true}"),
                     ("secret", "\"super-secret-value\""),
                 })
        {
            var json = ManifestDocument().Replace(
                "\"schemaVersion\": 1,",
                $"\"schemaVersion\": 1,\n  \"{field}\": {hostile},",
                StringComparison.Ordinal);
            var decision = McpWorkloadAdmission.AdmitDocument(json, Qualification);

            await Assert.That(decision.Code).IsEqualTo(McpAdmissionCode.AmbiguousContent);
            await Assert.That(decision.Field).IsEqualTo(field);
        }
    }

    [Test]
    public async Task Rejects_unknown_fields_and_duplicate_properties()
    {
        var unknown = McpWorkloadAdmission.AdmitDocument(
            ManifestDocument().Replace("\"probes\"", "\"healthProbes\": [], \"probes\"", StringComparison.Ordinal),
            Qualification);
        var duplicate = McpWorkloadAdmission.AdmitDocument(
            ManifestDocument().Replace("\"schemaVersion\": 1,", "\"schemaVersion\": 1, \"schemaVersion\": 1,", StringComparison.Ordinal),
            Qualification);

        await Assert.That(unknown.Code).IsEqualTo(McpAdmissionCode.FieldUnknown);
        await Assert.That(duplicate.Code).IsEqualTo(McpAdmissionCode.AmbiguousContent);
    }

    [Test]
    public async Task Rejects_undeclared_artifacts_and_architectures()
    {
        var foreign = McpWorkloadAdmission.AdmitDocument(
            ManifestDocument(digest: new string('a', 64)), Qualification);
        var swapped = McpWorkloadAdmission.AdmitDocument(
            ManifestDocument(digest: X64Digest, architecture: "linux/arm64"), Qualification);
        var multi = McpWorkloadAdmission.AdmitDocument(ManifestDocument(architecture: "multi"), Qualification);
        var shortDigest = McpWorkloadAdmission.AdmitDocument(
            ManifestDocument(digest: "not-a-digest"), Qualification);

        await Assert.That(foreign.Code).IsEqualTo(McpAdmissionCode.ArtifactNotQualified);
        await Assert.That(swapped.Code).IsEqualTo(McpAdmissionCode.ArtifactNotQualified);
        await Assert.That(multi.Code).IsEqualTo(McpAdmissionCode.DocumentInvalid);
        await Assert.That(shortDigest.Code).IsEqualTo(McpAdmissionCode.ArtifactNotQualified);
    }

    [Test]
    public async Task Rejects_undeclared_ports()
    {
        var wrongPort = McpWorkloadAdmission.AdmitDocument(
            ManifestDocument(port: McpWorkloadPorts.HttpListenerPort + 1), Qualification);

        await Assert.That(wrongPort.Code).IsEqualTo(McpAdmissionCode.PortNotAdmitted);
        await Assert.That(wrongPort.Field).IsEqualTo("httpListenerPort");
    }

    [Test]
    public async Task Rejects_undeclared_settings_and_secret_shaped_values()
    {
        var unknownKey = McpWorkloadAdmission.AdmitDocument(
            ManifestDocument(configuration: """{"polar-api-key":"pk_live_123"}"""), Qualification);
        var secretValue = McpWorkloadAdmission.AdmitDocument(
            ManifestDocument(configuration: """{"minimum-log-level":"password=hunter2"}"""), Qualification);
        var plainUrl = McpWorkloadAdmission.AdmitDocument(
            ManifestDocument(configuration: """{"public-base-url":"http://mcp.terrascale.tech"}"""), Qualification);

        await Assert.That(unknownKey.Code).IsEqualTo(McpAdmissionCode.ConfigurationKeyNotAdmitted);
        await Assert.That(secretValue.Code).IsEqualTo(McpAdmissionCode.ConfigurationValueRejected);
        await Assert.That(plainUrl.Code).IsEqualTo(McpAdmissionCode.ConfigurationValueRejected);
    }

    [Test]
    public async Task Rejects_undeclared_secret_references_and_secret_bytes()
    {
        var unadmittedName = McpWorkloadAdmission.AdmitDocument(
            ManifestDocument(secretReferences: """["vault:terrascale/mcp/webhook-signing-key"]"""), Qualification);
        var foreignPrefix = McpWorkloadAdmission.AdmitDocument(
            ManifestDocument(secretReferences: """["vault:platform/oauth-client-secret"]"""), Qualification);
        var secretBytes = McpWorkloadAdmission.AdmitDocument(
            ManifestDocument(secretReferences: """["-----BEGIN PRIVATE KEY-----"]"""), Qualification);
        var missing = McpWorkloadAdmission.AdmitDocument(
            ManifestDocument(secretReferences: "[]"), Qualification);

        await Assert.That(unadmittedName.Code).IsEqualTo(McpAdmissionCode.SecretReferenceNotAdmitted);
        await Assert.That(foreignPrefix.Code).IsEqualTo(McpAdmissionCode.SecretReferenceNotAdmitted);
        await Assert.That(secretBytes.Code).IsEqualTo(McpAdmissionCode.SecretReferenceNotAdmitted);
        await Assert.That(missing.Code).IsEqualTo(McpAdmissionCode.FieldMissing);
    }

    [Test]
    public async Task Rejects_undeclared_probes()
    {
        var custom = McpWorkloadAdmission.AdmitDocument(
            ManifestDocument(probes: """["/health/live","/health/ready","/debug/pprof"]"""), Qualification);
        var onlyOne = McpWorkloadAdmission.AdmitDocument(
            ManifestDocument(probes: """["/health/live"]"""), Qualification);

        await Assert.That(custom.Code).IsEqualTo(McpAdmissionCode.ProbePathNotAdmitted);
        await Assert.That(onlyOne.Code).IsEqualTo(McpAdmissionCode.ProbePathNotAdmitted);
    }

    [Test]
    public async Task The_canonical_route_and_health_mapping_expose_no_project_caller_or_credential()
    {
        var json = string.Join(',', McpRouteContract.All.Select(view =>
            System.Text.Json.JsonSerializer.Serialize(view)));

        await Assert.That(McpRouteContract.All.Select(static view => view.Host).Distinct())
            .IsEquivalentTo([McpPublicRoutes.CanonicalHost]);
        await Assert.That(McpPublicRoutes.CanonicalRoute).IsEqualTo("https://mcp.terrascale.tech/mcp");
        await Assert.That(McpRouteContract.All.Select(static view => view.HttpsRequired))
            .DoesNotContain(false);
        await Assert.That(McpRouteContract.All.Select(static view => view.PubliclyRoutable))
            .IsEquivalentTo([true, true, false, false]);
        foreach (var forbidden in new[] { "project", "caller", "credential", "token", "diagnostic", "apikey", "secret" })
            await Assert.That(json).DoesNotContain(forbidden).Because(
                $"the redacted route view must not expose '{forbidden}'");
    }

    [Test]
    public async Task Ingress_stays_closed_until_the_complete_live_evidence_bundle_passes()
    {
        await Assert.That(McpIngressGate.Evaluate(null)).IsEqualTo(McpIngressState.Closed);
        await Assert.That(McpIngressGate.Evaluate(McpIngressEvidence.None)).IsEqualTo(McpIngressState.Closed);
        await Assert.That(McpIngressGate.Evaluate(new McpIngressEvidence(
            AuthenticationVerified: true,
            ScopeDenialVerified: true,
            TenantIsolationVerified: true,
            HealthVerified: true,
            RollbackVerified: false))).IsEqualTo(McpIngressState.Closed);
        await Assert.That(McpIngressGate.Evaluate(new McpIngressEvidence(
            true, true, true, true, true))).IsEqualTo(McpIngressState.Open);
    }

    internal static McpWorkloadManifest Manifest(
        string digest = Arm64Digest,
        HostArchitecture architecture = HostArchitecture.Arm64) => new(
        digest,
        architecture,
        McpWorkloadPorts.HttpListenerPort,
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["public-base-url"] = "https://mcp.terrascale.tech",
            ["authentication-issuer-url"] = "https://auth.terrascale.tech",
            ["platform-public-api-base-url"] = "https://api.terrascale.tech",
            ["minimum-log-level"] = "information",
        },
        [new McpSecretReference("vault:terrascale/mcp/oauth-client-secret")],
        [McpPublicRoutes.LivenessPath, McpPublicRoutes.ReadinessPath]);
}
