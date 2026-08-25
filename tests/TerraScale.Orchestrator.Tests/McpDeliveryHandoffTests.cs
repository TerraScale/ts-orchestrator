using System.Threading;
using System.Threading.Tasks;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Delivery.DeployHandoff;
using TerraScale.Orchestrator.Delivery.Mcp;
using TerraScale.Orchestrator.Runtime;
using TerraScale.Orchestrator.Runtime.Mcp;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// The MCP workload's release-preparation and delivery path (TerraScale.Orchestrator#9): the
/// typed handoff rides the existing Deploy-to-Orchestrator mapping (#26 machinery) and the
/// direct-delivery controls, verifies the exact source revision, artifact digest, architecture,
/// artifact kind, provenance identity, configuration schema, and rollback artifact before the
/// workload is activated, and the admitted target allow-list admits the MCP service while
/// rejecting a foreign one.
/// </summary>
public sealed class McpDeliveryHandoffTests
{
    private const string Commit = "df79db4158ac54520634da3c6c39410ba5d6c242";
    private const string ForeignCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string TreeDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    private const string ForeignTreeDigest = "sha256:9999999999999999999999999999999999999999999999999999999999999999";
    private const string QualifiedArm64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string PreviousQualifiedArm64 = "6666666666666666666666666666666666666666666666666666666666666666";
    private const string OtherQualifiedArm64 = "7777777777777777777777777777777777777777777777777777777777777777";
    private const string QualifiedX64 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    private const string QualifiedArm64Wire = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string LiveArm64Wire = "sha256:6666666666666666666666666666666666666666666666666666666666666666";
    private const string ManifestDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    private const string ConfigurationRevision = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    private const string ForeignConfigurationRevision = "sha256:8888888888888888888888888888888888888888888888888888888888888888";
    private const string PreviousManifestDigest = "sha256:4444444444444444444444444444444444444444444444444444444444444444";

    private static McpHttpArtifactQualification Qualification => McpHttpArtifactQualification.Of(
        new McpQualifiedHttpArtifact(QualifiedArm64, HostArchitecture.Arm64),
        new McpQualifiedHttpArtifact(PreviousQualifiedArm64, HostArchitecture.Arm64),
        new McpQualifiedHttpArtifact(OtherQualifiedArm64, HostArchitecture.Arm64),
        new McpQualifiedHttpArtifact(QualifiedX64, HostArchitecture.X64));

    private static DeployHandoffAdmissionContext Context(
        string? repository = McpDeliveryTarget.SourceRepository) =>
        repository is null
            ? new DeployHandoffAdmissionContext(
                ExpectedService: McpDeliveryTarget.ServiceName,
                ExpectedEnvironment: "development",
                ExpectedRegions: ["gru"])
            : McpDeliveryTarget.AdmissionContext("development", ["gru"]);

    private static string HandoffJson(
        string repository = "TerraScale/TerraScale.MCP",
        string service = "mcp",
        string artifactDigest = QualifiedArm64Wire,
        string architecture = "linux/arm64",
        string kind = "service",
        bool rollback = true,
        string rollbackDigest = PreviousQualifiedArm64,
        string? rollbackArchitecture = null)
    {
        var rollbackJson = rollback
            ? $$"""{"artifactDigest": "sha256:{{rollbackDigest}}", "manifestDigest": "{{PreviousManifestDigest}}", "kind": "{{kind}}", "architecture": "{{rollbackArchitecture ?? architecture}}"}"""
            : "null";
        return $$"""
        {
          "schemaVersion": 1,
          "operationId": "op-mcp-1",
          "source": { "repository": "{{repository}}", "commit": "{{Commit}}", "treeDigest": "{{TreeDigest}}" },
          "artifact": { "digest": "{{artifactDigest}}", "manifestDigest": "{{ManifestDigest}}", "kind": "{{kind}}", "architecture": "{{architecture}}" },
          "rollback": {{rollbackJson}},
          "target": { "service": "{{service}}", "environment": "development", "regions": ["gru"] },
          "configurationRevision": "{{ConfigurationRevision}}",
          "requestedBy": "release-bot",
          "reason": "deploy the qualified MCP HTTP artifact"
        }
        """;
    }

    private static DeployHandoffRequest Request(string json) =>
        DeployHandoffMapper.Map(json, Context()).Request!;

    [Test]
    public async Task The_admission_context_pins_the_mcp_repository_and_service()
    {
        var wrongRepository = DeployHandoffMapper.Map(
            HandoffJson(repository: "TerraScale/evil"), Context());
        var wrongService = DeployHandoffMapper.Map(
            HandoffJson(service: "platform"), Context());

        await Assert.That(wrongRepository.Decision).IsEqualTo(DeployHandoffMappingDecision.Rejected);
        await Assert.That(wrongRepository.Error!.Code).IsEqualTo(DeployHandoffErrorCode.SourceMismatch);
        await Assert.That(wrongService.Decision).IsEqualTo(DeployHandoffMappingDecision.Rejected);
        await Assert.That(wrongService.Error!.Code).IsEqualTo(DeployHandoffErrorCode.TargetMismatch);
    }

    [Test]
    public async Task A_qualified_handoff_maps_onto_the_direct_delivery_request()
    {
        var request = Request(HandoffJson());

        await Assert.That(request.Delivery.Target!.Service).IsEqualTo("mcp");
        await Assert.That(request.Delivery.Source!.Repository).IsEqualTo(McpDeliveryTarget.SourceRepository);
        await Assert.That(request.Delivery.Source.Commit).IsEqualTo(Commit);
        await Assert.That(request.Architecture).IsEqualTo("linux/arm64");
        await Assert.That(request.Delivery.Artifact!.Digest).IsEqualTo(QualifiedArm64Wire);
        await Assert.That(request.Delivery.Artifact.Kind).IsEqualTo("service");
        await Assert.That(request.RollbackArtifact!.Architecture).IsEqualTo("linux/arm64");
    }

    [Test]
    public async Task Release_preparation_verifies_every_identity_before_the_workload_is_activated()
    {
        var request = Request(HandoffJson());

        await Assert.That(McpReleasePreparation.Verify(request, Qualification, null).Code)
            .IsEqualTo(McpReleasePreparationCode.Admitted);

        var unqualified = McpReleasePreparation.Verify(
            Request(HandoffJson(artifactDigest: "sha256:" + new string('e', 64))), Qualification, null);
        var wrongArchitecture = McpReleasePreparation.Verify(
            Request(HandoffJson(architecture: "multi")), Qualification, null);
        var foreignRepository = McpReleasePreparation.Verify(
            DeployHandoffMapper.Map(HandoffJson(repository: "TerraScale/platform"), Context(repository: null)).Request!,
            Qualification,
            null);
        var noQualification = McpReleasePreparation.Verify(request, McpHttpArtifactQualification.None, null);

        await Assert.That(unqualified.Code).IsEqualTo(McpReleasePreparationCode.ArtifactNotQualified);
        await Assert.That(wrongArchitecture.Code).IsEqualTo(McpReleasePreparationCode.ArchitectureNotQualified);
        await Assert.That(foreignRepository.Code).IsEqualTo(McpReleasePreparationCode.SourceRepositoryRejected);
        await Assert.That(noQualification.Code).IsEqualTo(McpReleasePreparationCode.ArchitectureNotQualified);
    }

    [Test]
    public async Task The_artifact_kind_must_be_the_qualified_http_executable_kind()
    {
        // The handoff mapper admits package/site kinds; release preparation must not: the MCP
        // workload runs the qualified self-contained HTTP executable only.
        var packaged = McpReleasePreparation.Verify(
            Request(HandoffJson(kind: "package")), Qualification, null);
        var sited = McpReleasePreparation.Verify(
            Request(HandoffJson(kind: "site")), Qualification, null);

        await Assert.That(packaged.Code).IsEqualTo(McpReleasePreparationCode.ArtifactKindRejected);
        await Assert.That(sited.Code).IsEqualTo(McpReleasePreparationCode.ArtifactKindRejected);
    }

    [Test]
    public async Task Pinned_source_and_configuration_revisions_must_match_exactly()
    {
        var request = Request(HandoffJson());

        var matching = McpReleasePreparation.Verify(request, Qualification, null, new(
            ExpectedCommit: Commit,
            ExpectedTreeDigest: TreeDigest,
            AdmittedConfigurationRevision: ConfigurationRevision));
        var wrongCommit = McpReleasePreparation.Verify(request, Qualification, null, new(
            ExpectedCommit: ForeignCommit));
        var wrongTree = McpReleasePreparation.Verify(request, Qualification, null, new(
            ExpectedTreeDigest: ForeignTreeDigest));
        var wrongConfiguration = McpReleasePreparation.Verify(request, Qualification, null, new(
            AdmittedConfigurationRevision: ForeignConfigurationRevision));

        await Assert.That(matching.Code).IsEqualTo(McpReleasePreparationCode.Admitted);
        await Assert.That(matching.Detail).DoesNotContain("not pinned");
        await Assert.That(wrongCommit.Code).IsEqualTo(McpReleasePreparationCode.SourceRevisionMismatch);
        await Assert.That(wrongTree.Code).IsEqualTo(McpReleasePreparationCode.SourceRevisionMismatch);
        await Assert.That(wrongConfiguration.Code)
            .IsEqualTo(McpReleasePreparationCode.ConfigurationRevisionMismatch);
    }

    [Test]
    public async Task An_unpinned_verification_reports_the_missing_pins_instead_of_claiming_them()
    {
        var unpinned = McpReleasePreparation.Verify(Request(HandoffJson()), Qualification, null);

        await Assert.That(unpinned.Code).IsEqualTo(McpReleasePreparationCode.Admitted);
        await Assert.That(unpinned.Detail).Contains("not pinned");
        await Assert.That(unpinned.Detail).Contains("source commit");
        await Assert.That(unpinned.Detail).Contains("source tree digest");
        await Assert.That(unpinned.Detail).Contains("configuration revision");
        await Assert.That(unpinned.Detail.Length)
            .IsLessThanOrEqualTo(McpReleasePreparationDecision.MaximumDetailLength);
    }

    [Test]
    public async Task A_live_deployment_requires_the_exact_currently_deployed_artifact_as_its_rollback_anchor()
    {
        // Correct upgrade: the workload is live on PreviousQualifiedArm64, deploys
        // QualifiedArm64, and records the live digest as the rollback anchor.
        var correctUpgrade = McpReleasePreparation.Verify(
            Request(HandoffJson()), Qualification, LiveArm64Wire);
        await Assert.That(correctUpgrade.Code).IsEqualTo(McpReleasePreparationCode.Admitted);
        await Assert.That(correctUpgrade.Detail).Contains("verified against the live artifact");

        // A missing anchor leaves a failed activation unrestorable.
        var missing = McpReleasePreparation.Verify(
            Request(HandoffJson(rollback: false)), Qualification, LiveArm64Wire);
        await Assert.That(missing.Code).IsEqualTo(McpReleasePreparationCode.RollbackArtifactRequired);

        // A qualified-but-wrong anchor is still a wrong anchor: only the live digest restores.
        var wrongAnchor = McpReleasePreparation.Verify(
            Request(HandoffJson(rollbackDigest: OtherQualifiedArm64)), Qualification, LiveArm64Wire);
        await Assert.That(wrongAnchor.Code).IsEqualTo(McpReleasePreparationCode.RollbackArtifactRejected);
        await Assert.That(wrongAnchor.Detail).Contains("currently deployed");

        // A rollback artifact on another architecture cannot run on the target: the anchor is
        // the live digest, but it declares the x64 platform for an arm64 deployment. The #26
        // mapper rejects this shape at its own seam, so the request is built directly to prove
        // release preparation refuses it independently.
        var wrongArchitecture = McpReleasePreparation.Verify(
            DirectRequest(rollbackDigest: PreviousQualifiedArm64, rollbackArchitecture: "linux/amd64"),
            Qualification,
            LiveArm64Wire);
        await Assert.That(wrongArchitecture.Code).IsEqualTo(McpReleasePreparationCode.RollbackArtifactRejected);
        await Assert.That(wrongArchitecture.Detail).Contains("same architecture");
    }

    [Test]
    public async Task A_first_deployment_has_nothing_live_to_roll_back_to()
    {
        // Nothing is deployed: an absent rollback is the bootstrap expectation, exactly like
        // the delivery coordinator's pristine-region handling.
        var bare = McpReleasePreparation.Verify(
            Request(HandoffJson(rollback: false)), Qualification, null);
        await Assert.That(bare.Code).IsEqualTo(McpReleasePreparationCode.Admitted);
        await Assert.That(bare.Detail).Contains("no prior artifact exists to roll back to");

        // A declared bootstrap anchor must still be a distinct qualified prior artifact.
        var anchored = McpReleasePreparation.Verify(
            Request(HandoffJson()), Qualification, null);
        await Assert.That(anchored.Code).IsEqualTo(McpReleasePreparationCode.Admitted);
        await Assert.That(anchored.Detail).Contains("bootstrap rollback anchor");

        var unqualifiedAnchor = McpReleasePreparation.Verify(
            Request(HandoffJson(rollbackDigest: new string('e', 64))), Qualification, null);
        await Assert.That(unqualifiedAnchor.Code).IsEqualTo(McpReleasePreparationCode.RollbackArtifactRejected);
    }

    [Test]
    public async Task A_rollback_equal_to_the_artifact_being_deployed_is_rejected_in_both_lanes()
    {
        // The #26 mapper rejects this shape at its own seam, so the requests are constructed
        // directly: release preparation must independently refuse a rollback that names the
        // artifact being deployed, because no exact prior artifact exists for it.
        var selfAnchorLive = McpReleasePreparation.Verify(
            DirectRequest(rollbackDigest: QualifiedArm64), Qualification, QualifiedArm64Wire);
        var selfAnchorFirst = McpReleasePreparation.Verify(
            DirectRequest(rollbackDigest: QualifiedArm64), Qualification, null);

        await Assert.That(selfAnchorLive.Code).IsEqualTo(McpReleasePreparationCode.RollbackArtifactRejected);
        await Assert.That(selfAnchorLive.Detail).Contains("equals the artifact being deployed");
        await Assert.That(selfAnchorFirst.Code).IsEqualTo(McpReleasePreparationCode.RollbackArtifactRejected);
    }

    /// <summary>
    /// Builds a request directly (not through the #26 mapper) for shapes the mapper itself
    /// rejects upstream — release preparation must still refuse them independently.
    /// </summary>
    private static DeployHandoffRequest DirectRequest(
        string rollbackDigest = PreviousQualifiedArm64,
        string rollbackArchitecture = "linux/arm64",
        string kind = "service") => new(
        new DeliveryRequest(
            SchemaVersion: DeliveryRequest.CurrentSchemaVersion,
            OperationId: "op-mcp-direct",
            Source: new DeliverySource(McpDeliveryTarget.SourceRepository, Commit, TreeDigest),
            Artifact: new DeliveryArtifact(QualifiedArm64Wire, ManifestDigest, kind),
            Target: new DeliveryTarget(McpDeliveryTarget.ServiceName, "development", ["gru"]),
            ConfigurationRevision: ConfigurationRevision,
            MigrationRevision: null,
            RequestedBy: "release-bot",
            Reason: "direct release-preparation probe"),
        "linux/arm64",
        new DeployHandoffRollbackArtifact(
            "sha256:" + rollbackDigest, PreviousManifestDigest, kind, rollbackArchitecture));

    [Test]
    public async Task The_mcp_delivery_rides_the_direct_delivery_controls_in_process()
    {
        var target = new RecordingMcpTarget();
        var journal = new InMemoryDeliveryJournal();
        var coordinator = new DirectDeliveryCoordinator(
            new AuthorizingAuthorizer(),
            new VerifyingProvenance(),
            new AdmittedMcpTargetResolver(target),
            journal,
            auditIdFactory: static () => "audit-mcp");

        var receipt = await coordinator.DeliverAsync(Request(HandoffJson()).Delivery);

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        await Assert.That(target.AppliedDigests).IsEquivalentTo([QualifiedArm64Wire]);
        await Assert.That(journal.Records[^1].State).IsEqualTo(DeliveryJournalState.Succeeded);
        await Assert.That(receipt.Provenance.Verified).IsTrue();
        var serialized = DeliveryWireCodec.SerializeReceipt(receipt);
        await Assert.That(serialized).DoesNotContain("secret");
        await Assert.That(serialized).Contains("\"service\":\"mcp\"");
    }

    [Test]
    public async Task The_development_target_allow_list_admits_mcp_and_rejects_foreign_services()
    {
        var resolver = new DirectDeliveryDevelopmentTargetResolver(new RecordingMcpTarget());

        var admitted = await resolver.ResolveAsync(new("mcp", "development", ["gru"]), CancellationToken.None);
        var rejected = await resolver.ResolveAsync(new("mcp-evil", "development", ["gru"]), CancellationToken.None);
        var wrongEnvironment = await resolver.ResolveAsync(new("mcp", "production", ["gru"]), CancellationToken.None);

        await Assert.That(admitted).IsNotNull();
        await Assert.That(rejected).IsNull();
        await Assert.That(wrongEnvironment).IsNull();
    }

    private sealed class AuthorizingAuthorizer : IDeliveryAuthorizer
    {
        public ValueTask<DeliveryAuthorizationResult> AuthorizeAsync(DeliveryRequest request, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new DeliveryAuthorizationResult(true));
    }

    private sealed class VerifyingProvenance : IDeliveryProvenanceVerifier
    {
        public ValueTask<DeliveryProvenanceResult> VerifyAsync(DeliveryRequest request, DeliveryArtifact artifact, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new DeliveryProvenanceResult(true, false, request.ConfigurationRevision, request.MigrationRevision));
    }

    /// <summary>
    /// Admits exactly the typed MCP target, mirroring the development allow-list rule: a
    /// request bound to another service never reaches the mutation path.
    /// </summary>
    private sealed class AdmittedMcpTargetResolver(IDeliveryTarget innerTarget) : IDeliveryTargetResolver
    {
        public ValueTask<IDeliveryTarget?> ResolveAsync(DeliveryTarget candidate, CancellationToken cancellationToken) =>
            ValueTask.FromResult<IDeliveryTarget?>(
                candidate.Service == McpDeliveryTarget.ServiceName ? new BoundMcpTarget(innerTarget, candidate) : null);
    }

    private sealed class BoundMcpTarget(IDeliveryTarget inner, DeliveryTarget admitted) : IDeliveryTarget
    {
        private bool Matches(DeliveryRequest request) => request.Target is { } target &&
            string.Equals(target.Service, admitted.Service, StringComparison.Ordinal) &&
            string.Equals(target.Environment, admitted.Environment, StringComparison.Ordinal) &&
            target.Regions!.SequenceEqual(admitted.Regions ?? []);

        public ValueTask<string?> ObserveCurrentDigestAsync(DeliveryRequest request, string region, CancellationToken cancellationToken) =>
            Matches(request) ? inner.ObserveCurrentDigestAsync(request, region, cancellationToken) : ValueTask.FromResult<string?>(null);

        public ValueTask<DeliveryArtifact?> ObserveCurrentArtifactAsync(DeliveryRequest request, string region, CancellationToken cancellationToken) =>
            Matches(request) ? inner.ObserveCurrentArtifactAsync(request, region, cancellationToken) : ValueTask.FromResult<DeliveryArtifact?>(null);

        public ValueTask<DeliveryMutationResult> ApplyAsync(DeliveryRequest request, DeliveryArtifact artifact, string region, CancellationToken cancellationToken) =>
            Matches(request) ? inner.ApplyAsync(request, artifact, region, cancellationToken)
                : ValueTask.FromResult(new DeliveryMutationResult(false, false, null, DirectDeliveryErrorCode.UnknownTarget));

        public ValueTask<DeliveryMutationResult> ApplyFencedAsync(DeliveryRequest request, DeliveryArtifact artifact, string region, string? expectedPreviousArtifactDigest, CancellationToken cancellationToken) =>
            Matches(request) ? inner.ApplyFencedAsync(request, artifact, region, expectedPreviousArtifactDigest, cancellationToken)
                : ValueTask.FromResult(new DeliveryMutationResult(false, false, null, DirectDeliveryErrorCode.UnknownTarget));

        public ValueTask<DeliveryHealthResult> CheckHealthAsync(DeliveryRequest request, DeliveryArtifact artifact, string region, CancellationToken cancellationToken) =>
            Matches(request) ? inner.CheckHealthAsync(request, artifact, region, cancellationToken)
                : ValueTask.FromResult(new DeliveryHealthResult(false));

        public ValueTask<DeliveryConvergenceResult> CheckConvergenceAsync(DeliveryRequest request, DeliveryArtifact artifact, IReadOnlyList<string> regions, CancellationToken cancellationToken) =>
            Matches(request) ? inner.CheckConvergenceAsync(request, artifact, regions, cancellationToken)
                : ValueTask.FromResult(new DeliveryConvergenceResult(false));

        public ValueTask<DeliveryRollbackResult> RollbackAsync(DeliveryRequest request, string region, string targetArtifactDigest, string? targetManifestDigest, CancellationToken cancellationToken) =>
            Matches(request) && targetManifestDigest is not null
                ? inner.RollbackAsync(request, region, targetArtifactDigest, targetManifestDigest, cancellationToken)
                : ValueTask.FromResult(new DeliveryRollbackResult(false, targetArtifactDigest));
    }

    private sealed class RecordingMcpTarget : IDeliveryTarget
    {
        private readonly Dictionary<string, string?> digests = new(StringComparer.Ordinal);

        public List<string> AppliedDigests { get; } = [];

        public ValueTask<string?> ObserveCurrentDigestAsync(DeliveryRequest request, string region, CancellationToken cancellationToken) =>
            ValueTask.FromResult(digests.TryGetValue(region, out var digest) ? digest : null);

        public ValueTask<DeliveryArtifact?> ObserveCurrentArtifactAsync(DeliveryRequest request, string region, CancellationToken cancellationToken) =>
            ValueTask.FromResult<DeliveryArtifact?>(digests.TryGetValue(region, out var digest) && digest is not null
                ? new DeliveryArtifact(digest, ManifestDigest, "service")
                : null);

        public ValueTask<DeliveryMutationResult> ApplyAsync(DeliveryRequest request, DeliveryArtifact artifact, string region, CancellationToken cancellationToken)
        {
            AppliedDigests.Add(artifact.Digest!);
            var previous = digests.TryGetValue(region, out var digest) ? digest : null;
            digests[region] = artifact.Digest;
            return ValueTask.FromResult(new DeliveryMutationResult(true, true, previous));
        }

        public ValueTask<DeliveryHealthResult> CheckHealthAsync(DeliveryRequest request, DeliveryArtifact artifact, string region, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new DeliveryHealthResult(true, [new($"{region}-mcp", DeliveryHealthStatus.Passed)]));

        public ValueTask<DeliveryConvergenceResult> CheckConvergenceAsync(DeliveryRequest request, DeliveryArtifact artifact, IReadOnlyList<string> regions, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new DeliveryConvergenceResult(true));

        public ValueTask<DeliveryRollbackResult> RollbackAsync(DeliveryRequest request, string region, string targetArtifactDigest, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new DeliveryRollbackResult(true, targetArtifactDigest));
    }
}
