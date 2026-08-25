using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery.DeployHandoff;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Compatibility coverage for the typed Deploy-to-Orchestrator handoff mapping (issue #26):
/// every executable field is preserved byte-exact, every documented failure mode is rejected
/// with its bounded actionable error before any target mutation, and the dry-run API returns
/// the same typed decision with no side effects.
/// </summary>
public sealed class DeployHandoffMapperTests
{
    private const string Commit = "26d399281ef72fa9a216919cf339cf57792f9af9";
    private const string TreeDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    private const string ArtifactDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    private const string ArtifactManifestDigest = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    private const string RollbackArtifactDigest = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
    private const string RollbackManifestDigest = "sha256:5555555555555555555555555555555555555555555555555555555555555555";
    private const string ConfigurationRevision = "sha256:6666666666666666666666666666666666666666666666666666666666666666";
    private const string MigrationRevision = "sha256:7777777777777777777777777777777777777777777777777777777777777777";

    private static DeployHandoffAdmissionContext AdmissionContext() => new(
        ExpectedRepository: "TerraScale/TerraScale.Orchestrator",
        ExpectedCommit: Commit,
        ExpectedTreeDigest: TreeDigest,
        ExpectedService: "terrascale-orchestrator",
        ExpectedEnvironment: "development",
        ExpectedRegions: ["gru", "sfo"]);

    [Test]
    public async Task Valid_service_manifest_maps_every_executable_field_byte_exact()
    {
        var result = DeployHandoffMapper.Map(DeployHandoffCorpus.Fixture("valid-service.json"), AdmissionContext());

        await Assert.That(result.Decision).IsEqualTo(DeployHandoffMappingDecision.Admitted);
        var request = result.Request!;
        await Assert.That(request.Delivery.SchemaVersion).IsEqualTo(DeliveryRequest.CurrentSchemaVersion);
        await Assert.That(request.Delivery.OperationId).IsEqualTo("deploy-op-26-valid");
        await Assert.That(request.Delivery.Source!.Repository).IsEqualTo("TerraScale/TerraScale.Orchestrator");
        await Assert.That(request.Delivery.Source.Commit).IsEqualTo(Commit);
        await Assert.That(request.Delivery.Source.TreeDigest).IsEqualTo(TreeDigest);
        await Assert.That(request.Delivery.Artifact!.Digest).IsEqualTo(ArtifactDigest);
        await Assert.That(request.Delivery.Artifact.ManifestDigest).IsEqualTo(ArtifactManifestDigest);
        await Assert.That(request.Delivery.Artifact.Kind).IsEqualTo("service");
        await Assert.That(request.Architecture).IsEqualTo("linux/amd64");
        await Assert.That(request.RollbackArtifact!.ArtifactDigest).IsEqualTo(RollbackArtifactDigest);
        await Assert.That(request.RollbackArtifact.ManifestDigest).IsEqualTo(RollbackManifestDigest);
        await Assert.That(request.RollbackArtifact.Kind).IsEqualTo("service");
        await Assert.That(request.RollbackArtifact.Architecture).IsEqualTo("linux/amd64");
        await Assert.That(request.Delivery.Target!.Service).IsEqualTo("terrascale-orchestrator");
        await Assert.That(request.Delivery.Target.Environment).IsEqualTo("development");
        await Assert.That(request.Delivery.Target.Regions).IsEquivalentTo(["gru", "sfo"]);
        await Assert.That(string.Join(",", request.Delivery.Target.Regions!)).IsEqualTo("gru,sfo");
        await Assert.That(request.Delivery.ConfigurationRevision).IsEqualTo(ConfigurationRevision);
        await Assert.That(request.Delivery.MigrationRevision).IsEqualTo(MigrationRevision);
        await Assert.That(request.Delivery.RequestedBy).IsEqualTo("ci-bot@terrascale.internal");
        await Assert.That(request.Delivery.Reason)
            .IsEqualTo("orchestrator-26 canonical handoff mapping fixture");
        await Assert.That(request.Delivery.AuthorityGeneration).IsEqualTo(1L);
        await Assert.That(request.Delivery.WriterEpoch).IsEqualTo(1L);
        await Assert.That(request.Delivery.Attempt).IsEqualTo(1);
        await Assert.That(result.IsAdmittedForTargetMutation).IsTrue();
    }

    [Test]
    public async Task Valid_manifest_maps_without_an_admission_context()
    {
        var result = DeployHandoffMapper.Map(DeployHandoffCorpus.Fixture("valid-service.json"));

        await Assert.That(result.Decision).IsEqualTo(DeployHandoffMappingDecision.Admitted);
        await Assert.That(result.Request!.Delivery.Artifact!.Digest).IsEqualTo(ArtifactDigest);
    }

    [Test]
    public async Task First_deployment_without_rollback_maps_without_a_rollback_artifact()
    {
        var context = AdmissionContext() with { ExpectedRegions = ["gru"] };
        var result = DeployHandoffMapper.Map(
            DeployHandoffCorpus.Fixture("valid-first-deployment.json"), context);

        await Assert.That(result.Decision).IsEqualTo(DeployHandoffMappingDecision.Admitted);
        await Assert.That(result.Request!.RollbackArtifact).IsNull();
        await Assert.That(result.Request.Delivery.MigrationRevision).IsNull();
        await Assert.That(result.Request.Delivery.Target!.Regions!).IsEquivalentTo(["gru"]);
    }

    [Test]
    public async Task Informational_fields_never_reach_the_executable_request()
    {
        var result = DeployHandoffMapper.Map(DeployHandoffCorpus.Fixture("valid-service.json"), AdmissionContext());

        var wire = DeliveryWireCodec.SerializeRequest(result.Request!.Delivery);
        await Assert.That(wire.Contains("regression fixture for mapping v1")).IsFalse();
        await Assert.That(wire.Contains("release-notices")).IsFalse();
        await Assert.That(wire.Contains("informational")).IsFalse();
    }

    [Test]
    [Arguments("missing-tree-digest.json", DeployHandoffErrorCode.FieldMissing, "source.treeDigest")]
    [Arguments("missing-rollback-manifest-digest.json", DeployHandoffErrorCode.RollbackIncompatible, "rollback.manifestDigest")]
    [Arguments("unknown-field.json", DeployHandoffErrorCode.FieldUnknown, "priority")]
    [Arguments("stale-digest.json", DeployHandoffErrorCode.DigestStale, "source.treeDigest")]
    [Arguments("mismatched-manifest.json", DeployHandoffErrorCode.TargetMismatch, "target.service")]
    [Arguments("incompatible-rollback-artifact.json", DeployHandoffErrorCode.RollbackIncompatible, "rollback.artifactDigest")]
    [Arguments("incompatible-rollback-architecture.json", DeployHandoffErrorCode.RollbackIncompatible, "rollback.architecture")]
    [Arguments("wrong-schema-version.json", DeployHandoffErrorCode.SchemaUnsupported, "schemaVersion")]
    [Arguments("ambiguous-generic-content.json", DeployHandoffErrorCode.AmbiguousContent, "manifests")]
    public async Task Documented_failure_modes_are_rejected_with_their_bounded_error(
        string fixture, string expectedCode, string expectedField)
    {
        var result = DeployHandoffMapper.Map(DeployHandoffCorpus.Fixture(fixture), AdmissionContext());

        await Assert.That(result.Decision).IsEqualTo(DeployHandoffMappingDecision.Rejected);
        await Assert.That(result.Request).IsNull();
        await Assert.That(result.IsAdmittedForTargetMutation).IsFalse();
        await Assert.That(result.Error!.Code).IsEqualTo(expectedCode);
        await Assert.That(result.Error.Message).Contains(expectedField);
        await Assert.That(string.IsNullOrWhiteSpace(result.Error.Remediation)).IsFalse();
    }

    [Test]
    public async Task Malformed_documents_are_rejected_with_a_bounded_error()
    {
        foreach (var document in new[] { "", "   ", "not json", "[]", "{\"schemaVersion\": \"one\"}" })
        {
            var result = DeployHandoffMapper.Map(document, AdmissionContext());
            await Assert.That(result.Decision).IsEqualTo(DeployHandoffMappingDecision.Rejected);
            await Assert.That(result.Request).IsNull();
            await Assert.That(result.Error!.Code).IsEqualTo(DeployHandoffErrorCode.DocumentInvalid);
        }
    }

    [Test]
    public async Task Unbounded_text_is_rejected()
    {
        var manifest = DeployHandoffCorpus.Fixture("valid-service.json")
            .Replace("orchestrator-26 canonical handoff mapping fixture", new string('x', 2_049));

        var result = DeployHandoffMapper.Map(manifest, AdmissionContext());

        await Assert.That(result.Decision).IsEqualTo(DeployHandoffMappingDecision.Rejected);
        await Assert.That(result.Error!.Code).IsEqualTo(DeployHandoffErrorCode.UnboundedText);
        await Assert.That(result.Error.Message).Contains("reason");
    }

    [Test]
    public async Task Secret_bearing_reason_is_rejected()
    {
        var manifest = DeployHandoffCorpus.Fixture("valid-service.json")
            .Replace(
                "orchestrator-26 canonical handoff mapping fixture",
                "password: hunter2 do not log");

        var result = DeployHandoffMapper.Map(manifest, AdmissionContext());

        await Assert.That(result.Decision).IsEqualTo(DeployHandoffMappingDecision.Rejected);
        await Assert.That(result.Error!.Code).IsEqualTo(DeployHandoffErrorCode.SecretRejected);
    }

    [Test]
    public async Task Secret_bearing_text_is_rejected_in_every_admitted_free_text_field()
    {
        var cases = new (string Field, string From, string To)[]
        {
            ("operationId", "deploy-op-26-valid", "token: deploy-op-26-valid"),
            ("source.repository", "TerraScale/TerraScale.Orchestrator", "password=TerraScale/TerraScale.Orchestrator"),
            ("requestedBy", "ci-bot@terrascale.internal", "bearer ci-bot@terrascale.internal"),
            ("target.service", "terrascale-orchestrator", "terrascale-orchestrator;secret=nope"),
            ("target.regions", "\"gru\", \"sfo\"", "\"gru\", \"authorization: yes\""),
            ("informational.notificationChannels", "release-notices", "release-notices, private_key=x"),
        };

        foreach (var (field, from, to) in cases)
        {
            var manifest = DeployHandoffCorpus.Fixture("valid-service.json").Replace(from, to);
            var result = DeployHandoffMapper.Map(manifest, AdmissionContext());
            // The message assertion names the offending field, so a failure identifies its case.
            await Assert.That(result.Decision).IsEqualTo(DeployHandoffMappingDecision.Rejected);
            await Assert.That(result.Error!.Code).IsEqualTo(DeployHandoffErrorCode.SecretRejected);
            await Assert.That(result.Error.Message).Contains(field);
        }
    }

    [Test]
    public async Task Admission_context_cannot_widen_the_contract_schema_range()
    {
        await Assert.That(() => DeployHandoffMapper.Map(
                DeployHandoffCorpus.Fixture("valid-service.json"),
                AdmissionContext() with { MaximumManifestSchemaVersion = 2 }))
            .Throws<ArgumentException>();
        await Assert.That(() => DeployHandoffMapper.Map(
                DeployHandoffCorpus.Fixture("valid-service.json"),
                AdmissionContext() with { MinimumManifestSchemaVersion = 0 }))
            .Throws<ArgumentException>();
        await Assert.That(() => DeployHandoffMapper.Map(
                DeployHandoffCorpus.Fixture("valid-service.json"),
                AdmissionContext() with { MinimumManifestSchemaVersion = 2, MaximumManifestSchemaVersion = 1 }))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task Default_admission_context_admits_exactly_the_contract_schema_range()
    {
        var admitted = DeployHandoffMapper.Map(
            DeployHandoffCorpus.Fixture("valid-service.json"), DeployHandoffAdmissionContext.Default);
        await Assert.That(admitted.Decision).IsEqualTo(DeployHandoffMappingDecision.Admitted);

        var nextSchemaVersion = DeployHandoffCorpus.Fixture("wrong-schema-version.json");
        var futureWithDefault = DeployHandoffMapper.Map(nextSchemaVersion, DeployHandoffAdmissionContext.Default);
        await Assert.That(futureWithDefault.Decision).IsEqualTo(DeployHandoffMappingDecision.Rejected);
        await Assert.That(futureWithDefault.Error!.Code).IsEqualTo(DeployHandoffErrorCode.SchemaUnsupported);
        await Assert.That(futureWithDefault.Error.Message).Contains("1..1");

        // A context may narrow within the contract bounds, and the rejection names that range.
        var narrowed = DeployHandoffMapper.Map(
            nextSchemaVersion, AdmissionContext() with { MaximumManifestSchemaVersion = 1 });
        await Assert.That(narrowed.Error!.Message).Contains("1..1");
    }

    [Test]
    public async Task Duplicated_json_property_names_are_rejected_as_ambiguous_documents()
    {
        var manifest = DeployHandoffCorpus.Fixture("valid-service.json").Replace(
            "\"reason\": \"orchestrator-26 canonical handoff mapping fixture\"",
            "\"reason\": \"first reason\", \"reason\": \"second reason\"");

        var result = DeployHandoffMapper.Map(manifest, AdmissionContext());

        await Assert.That(result.Decision).IsEqualTo(DeployHandoffMappingDecision.Rejected);
        await Assert.That(result.Request).IsNull();
        await Assert.That(result.Error!.Code).IsEqualTo(DeployHandoffErrorCode.DocumentInvalid);
        await Assert.That(result.Error.Message).Contains("reason");
    }

    [Test]
    public async Task Target_environment_outside_the_allow_list_is_rejected()
    {
        var result = DeployHandoffMapper.Map(
            DeployHandoffCorpus.Fixture("valid-service.json").Replace("\"development\"", "\"staging\""),
            AdmissionContext() with { ExpectedEnvironment = "staging" });

        await Assert.That(result.Decision).IsEqualTo(DeployHandoffMappingDecision.Rejected);
        await Assert.That(result.Error!.Code).IsEqualTo(DeployHandoffErrorCode.TargetInvalid);
        await Assert.That(result.Error.Message).Contains("target.environment");
        await Assert.That(result.Error.Message).Contains("staging");
    }

    [Test]
    public async Task Every_allowed_target_environment_maps()
    {
        foreach (var environment in new[] { "local", "development", "production" })
        {
            var result = DeployHandoffMapper.Map(
                DeployHandoffCorpus.Fixture("valid-service.json").Replace("\"development\"", $"\"{environment}\""),
                AdmissionContext() with { ExpectedEnvironment = environment });

            // The environment round-trip assertion names the environment in its failure.
            await Assert.That(result.Decision).IsEqualTo(DeployHandoffMappingDecision.Admitted);
            await Assert.That(result.Request!.Delivery.Target!.Environment).IsEqualTo(environment);
        }
    }

    [Test]
    public async Task Wrong_repository_is_rejected_as_a_source_mismatch()
    {
        var manifest = DeployHandoffCorpus.Fixture("valid-service.json")
            .Replace("TerraScale/TerraScale.Orchestrator", "TerraScale/TerraScale.Deploy");

        var result = DeployHandoffMapper.Map(manifest, AdmissionContext());

        await Assert.That(result.Decision).IsEqualTo(DeployHandoffMappingDecision.Rejected);
        await Assert.That(result.Error!.Code).IsEqualTo(DeployHandoffErrorCode.SourceMismatch);
        await Assert.That(result.Error.Message).Contains("source.repository");
    }

    [Test]
    public async Task Stale_commit_is_rejected_even_when_the_tree_digest_is_current()
    {
        var manifest = DeployHandoffCorpus.Fixture("valid-service.json")
            .Replace(Commit, "0000000000000000000000000000000000000000");

        var result = DeployHandoffMapper.Map(manifest, AdmissionContext());

        await Assert.That(result.Decision).IsEqualTo(DeployHandoffMappingDecision.Rejected);
        await Assert.That(result.Error!.Code).IsEqualTo(DeployHandoffErrorCode.DigestStale);
        await Assert.That(result.Error.Message).Contains("source.commit");
    }

    [Test]
    public async Task Unsupported_artifact_shape_is_rejected()
    {
        var wrongKind = DeployHandoffMapper.Map(
            DeployHandoffCorpus.Fixture("valid-service.json").Replace("\"kind\": \"service\"", "\"kind\": \"cronjob\""),
            AdmissionContext());
        await Assert.That(wrongKind.Error!.Code).IsEqualTo(DeployHandoffErrorCode.ArtifactInvalid);

        var wrongArchitecture = DeployHandoffMapper.Map(
            DeployHandoffCorpus.Fixture("valid-service.json").Replace("linux/amd64", "windows/nt"),
            AdmissionContext());
        await Assert.That(wrongArchitecture.Error!.Code).IsEqualTo(DeployHandoffErrorCode.ArtifactInvalid);

        var malformedDigest = DeployHandoffMapper.Map(
            DeployHandoffCorpus.Fixture("valid-service.json").Replace(
                ArtifactManifestDigest, "sha256:not-a-digest"),
            AdmissionContext());
        await Assert.That(malformedDigest.Error!.Code).IsEqualTo(DeployHandoffErrorCode.DigestInvalid);
        await Assert.That(malformedDigest.Error.Message).Contains("artifact.manifestDigest");
    }

    [Test]
    public async Task Dry_run_returns_the_same_decision_with_no_request_for_rejections()
    {
        var rejected = new (string Fixture, string Code)[]
        {
            ("missing-tree-digest.json", DeployHandoffErrorCode.FieldMissing),
            ("unknown-field.json", DeployHandoffErrorCode.FieldUnknown),
            ("stale-digest.json", DeployHandoffErrorCode.DigestStale),
            ("mismatched-manifest.json", DeployHandoffErrorCode.TargetMismatch),
            ("incompatible-rollback-artifact.json", DeployHandoffErrorCode.RollbackIncompatible),
            ("wrong-schema-version.json", DeployHandoffErrorCode.SchemaUnsupported),
            ("ambiguous-generic-content.json", DeployHandoffErrorCode.AmbiguousContent),
        };

        foreach (var (fixture, code) in rejected)
        {
            var dryRun = DeployHandoffMapper.DryRun(DeployHandoffCorpus.Fixture(fixture), AdmissionContext());
            await Assert.That(dryRun.Decision).IsEqualTo(DeployHandoffMappingDecision.Rejected);
            await Assert.That(dryRun.Request).IsNull();
            // Rejection is decided entirely inside the pure mapper: the result carries no
            // executable data and cannot reach the target-mutation path.
            await Assert.That(dryRun.IsAdmittedForTargetMutation).IsFalse();
            await Assert.That(dryRun.Error!.Code).IsEqualTo(code);
        }
    }

    [Test]
    public async Task Dry_run_agrees_with_the_mapping_decision_for_a_valid_manifest()
    {
        var dryRun = DeployHandoffMapper.DryRun(DeployHandoffCorpus.Fixture("valid-service.json"), AdmissionContext());
        var mapped = DeployHandoffMapper.Map(DeployHandoffCorpus.Fixture("valid-service.json"), AdmissionContext());

        await Assert.That(dryRun.Decision).IsEqualTo(mapped.Decision);
        await Assert.That(dryRun.IsAdmittedForTargetMutation).IsTrue();
        await Assert.That(dryRun.Request).IsNotNull();
        await Assert.That(DeliveryWireCodec.SerializeRequest(dryRun.Request!.Delivery))
            .IsEqualTo(DeliveryWireCodec.SerializeRequest(mapped.Request!.Delivery));
        await Assert.That(dryRun.Request.Architecture).IsEqualTo(mapped.Request!.Architecture);
        await Assert.That(dryRun.Request.RollbackArtifact!.ArtifactDigest)
            .IsEqualTo(mapped.Request.RollbackArtifact!.ArtifactDigest);
    }

    [Test]
    public async Task Mapping_is_deterministic_and_side_effect_free()
    {
        var first = DeployHandoffMapper.Map(DeployHandoffCorpus.Fixture("valid-service.json"), AdmissionContext());
        var second = DeployHandoffMapper.Map(DeployHandoffCorpus.Fixture("valid-service.json"), AdmissionContext());

        await Assert.That(DeliveryWireCodec.SerializeRequest(second.Request!.Delivery))
            .IsEqualTo(DeliveryWireCodec.SerializeRequest(first.Request!.Delivery));
        await Assert.That(second.Request.RollbackArtifact).IsEqualTo(first.Request!.RollbackArtifact);
        await Assert.That(second.Error).IsNull();
    }
}
