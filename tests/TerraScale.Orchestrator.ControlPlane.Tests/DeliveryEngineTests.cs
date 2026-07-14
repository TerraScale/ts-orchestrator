using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class DeliveryEngineTests
{
    [Test]
    public async Task BranchMovementAndDuplicateWebhookNeverReplaceImmutableSourceAuthority()
    {
        var proposed = Source();
        var movedRef = Source(reference: "feature-moved");
        var fetched = DeliveryEngine.DecideSource(new(proposed, null, null, 64));
        var movedFetched = DeliveryEngine.DecideSource(new(movedRef, null, null, 64));
        await Assert.That(fetched.Intents.Single()).IsTypeOf<FetchSourceIntent>();
        await Assert.That(((FetchSourceIntent)fetched.Intents.Single()).Commit).IsEqualTo(proposed.Commit);
        await Assert.That(((FetchSourceIntent)movedFetched.Intents.Single()).Commit).IsEqualTo(proposed.Commit);

        var duplicate = DeliveryEngine.DecideSource(new(proposed, proposed, Evidence(), 64));
        await Assert.That(duplicate.Intents).IsEmpty();
        await Assert.That(duplicate.Trace.Single().Code).IsEqualTo(DeliveryTraceCode.Idempotent);
    }

    [Test]
    public async Task SourceVerificationAndPlanBindExactSortedDependencyProofs()
    {
        var source = Source();
        var verify = DeliveryEngine.DecideSource(new(source, null, Evidence(SourceState.Fetched), 64));
        await Assert.That(verify.Intents.Single()).IsTypeOf<VerifySourceIntent>();

        var plan = DeliveryEngine.DecideSource(new(source, null, Evidence(), 64));
        var intent = (PlanApplyIntent)plan.Intents.Single();
        await Assert.That(intent.Commit).IsEqualTo(source.Commit);
        await Assert.That(intent.Tree).IsEqualTo(source.Tree);
        await Assert.That(intent.Dependencies.Select(static value => value.Manifest.Value)
            .SequenceEqual(new[] { "dep-a", "dep-b" }, StringComparer.Ordinal)).IsTrue();
    }

    [Test]
    public async Task LowerAndConflictingDesiredGenerationsHold()
    {
        await AssertHeld(DeliveryEngine.DecideSource(new(Source(generation: 2), Source(generation: 3), null, 64)),
            DeliveryErrorCode.StaleGeneration);
        await AssertHeld(DeliveryEngine.DecideSource(new(Source(), Source(generation: 0), null, 64)),
            DeliveryErrorCode.InvalidInput);
        await AssertHeld(DeliveryEngine.DecideSource(new(Source(tree: "other-tree"), Source(), null, 64)),
            DeliveryErrorCode.ConflictingGeneration);

        foreach (var conflict in new[]
        {
            Source(reference: "other-ref"),
            Source(manifest: "other-manifest"),
            Source(signature: "other-signature"),
            Source(dependencies: [new(new("dep-a"), 9, new("other"))]),
        })
            await AssertHeld(DeliveryEngine.DecideSource(new(conflict, Source(), null, 64)), DeliveryErrorCode.ConflictingGeneration);
    }

    [Test]
    public async Task SourceEvidenceCannotReplayAcrossRevisionOrSubstituteDependencies()
    {
        var source = Source();
        foreach (var replay in new[]
        {
            Evidence(source: "other-source"),
            Evidence(reference: "other-ref"),
            Evidence(generation: 2),
            Evidence(dependencies: [new(new("dep-a"), 1, new("digest-a"))]),
        })
            await AssertHeld(DeliveryEngine.DecideSource(new(source, null, replay, 64)), DeliveryErrorCode.EvidenceInvalidated);

        var duplicate = Evidence(dependencies:
        [
            new(new("dep-a"), 1, new("digest-a")),
            new(new("dep-a"), 1, new("digest-a")),
        ]);
        await AssertHeld(DeliveryEngine.DecideSource(new(source, null, duplicate, 64)), DeliveryErrorCode.EvidenceInvalidated);
    }

    [Test]
    public async Task RunnerSelectionIsDeterministicFreshAndCapabilityBound()
    {
        var job = Job();
        var runners = new[]
        {
            Runner("runner-z", TrustZone.TrustedBuild, 15, RunnerCapability.Compile, RunnerCapability.Test),
            Runner("runner-a", TrustZone.TrustedBuild, 15, RunnerCapability.Test, RunnerCapability.Compile),
        };
        var first = DeliveryEngine.DecideJob(job, runners, 64);
        var second = DeliveryEngine.DecideJob(job, runners.Reverse().ToArray(), 64);
        await Assert.That(((DispatchJobIntent)first.Intents.Single()).Runner.Value).IsEqualTo("runner-a");
        await Assert.That(((DispatchJobIntent)second.Intents.Single()).Runner.Value).IsEqualTo("runner-a");

        await AssertHeld(DeliveryEngine.DecideJob(job, [Runner("stale", TrustZone.TrustedBuild, 9,
            RunnerCapability.Compile, RunnerCapability.Test)], 64), DeliveryErrorCode.RunnerStale);
        await AssertHeld(DeliveryEngine.DecideJob(job, [Runner("missing", TrustZone.TrustedBuild, 15,
            RunnerCapability.Compile)], 64), DeliveryErrorCode.CapabilityMissing);
    }

    [Test]
    public async Task UntrustedProductJobsCannotEscapeTrustZoneOrReceiveAuthority()
    {
        var privileged = Job(kind: JobKind.ProductValidation, zone: TrustZone.ProductionRelease,
            capabilities: [RunnerCapability.ProductionDeploy]);
        await AssertHeld(DeliveryEngine.DecideJob(privileged,
            [Runner("release", TrustZone.ProductionRelease, 15, RunnerCapability.ProductionDeploy)], 64),
            DeliveryErrorCode.TrustZoneDenied);

        var wrongZone = Job();
        await AssertHeld(DeliveryEngine.DecideJob(wrongZone,
            [Runner("untrusted", TrustZone.UntrustedProduct, 15, RunnerCapability.Compile, RunnerCapability.Test)], 64),
            DeliveryErrorCode.TrustZoneDenied);
    }

    [Test]
    public async Task InterruptedJobsRequireExplicitRetryAndAttemptBounds()
    {
        await AssertHeld(DeliveryEngine.DecideJob(Job(attempt: 2, retry: false), [Runner()], 64), DeliveryErrorCode.RetryDenied);
        await AssertHeld(DeliveryEngine.DecideJob(Job(attempt: 4, maximumAttempts: 3, retry: true), [Runner()], 64), DeliveryErrorCode.AttemptsExhausted);
        var retried = DeliveryEngine.DecideJob(Job(attempt: 2, retry: true), [Runner()], 64);
        var intent = (DispatchJobIntent)retried.Intents.Single();
        await Assert.That(intent.Attempt).IsEqualTo(2);
        await Assert.That(intent.Idempotency.Value).IsEqualTo("job-key");
    }

    [Test]
    public async Task EveryPromotionInputChangeInvalidatesEvidence()
    {
        var current = Subject();
        var fields = new EvidenceSubject[]
        {
            current with { Tree = new TreeId("tree-2") },
            current with { DependencyLock = new DigestId("lock-2") },
            current with { GeneratedSchemas = new DigestId("schema-2") },
            current with { Artifact = new ArtifactId("artifact-2") },
            current with { ArtifactDigest = new DigestId("digest-2") },
        };
        foreach (var changed in fields)
            await AssertHeld(DeliveryEngine.DecidePromotion(new(new ReleaseId("release"), 1, changed, Qualification(current), 64)),
                DeliveryErrorCode.EvidenceInvalidated);
    }

    [Test]
    public async Task PromotionRequiresTestsSignatureApprovalAndCompatibility()
    {
        var subject = Subject();
        var accepted = DeliveryEngine.DecidePromotion(new(new ReleaseId("release"), 1, subject, Qualification(subject), 64));
        await Assert.That(accepted.Intents.Single()).IsTypeOf<PromoteArtifactIntent>();

        var compatibility = Qualification(subject).Compatibility;
        var cases = new[]
        {
            (Qualification(subject) with { TestsPassed = false }, DeliveryErrorCode.EvidenceInvalidated),
            (Qualification(subject) with { SignatureValid = false }, DeliveryErrorCode.ArtifactMismatch),
            (Qualification(subject) with { ApprovalValid = false }, DeliveryErrorCode.ApprovalDenied),
            (Qualification(subject) with { Compatibility = compatibility with { CurrentToCurrentCompatible = false } }, DeliveryErrorCode.CompatibilityDenied),
            (Qualification(subject) with { Compatibility = compatibility with { CurrentToPreviousCompatible = false } }, DeliveryErrorCode.CompatibilityDenied),
            (Qualification(subject) with { Compatibility = compatibility with { PreviousToCurrentCompatible = false } }, DeliveryErrorCode.CompatibilityDenied),
        };
        foreach (var (evidence, code) in cases)
            await AssertHeld(DeliveryEngine.DecidePromotion(new(new ReleaseId("release"), 1, subject, evidence, 64)), code);
    }

    [Test]
    public async Task PromotionEvidenceCannotReplayAcrossReleaseOrGeneration()
    {
        var subject = Subject();
        await AssertHeld(DeliveryEngine.DecidePromotion(new(new("other-release"), 1, subject,
            Qualification(subject), 64)), DeliveryErrorCode.EvidenceInvalidated);
        await AssertHeld(DeliveryEngine.DecidePromotion(new(new("release"), 2, subject,
            Qualification(subject), 64)), DeliveryErrorCode.EvidenceInvalidated);
    }

    [Test]
    public async Task RolloutStagesCellsInExactCallerOrderAndLostResponseAdvancesWithoutRestage()
    {
        var release = Release();
        var initial = DeliveryEngine.DecideRollout(Rollout(release));
        var stage = (StageReleaseIntent)initial.Intents.Single();
        await Assert.That(stage.Cell.Value).IsEqualTo("sfo");
        await Assert.That(stage.Operation).IsEqualTo(release.Operation);
        await Assert.That(stage.Signature).IsEqualTo(release.Signature);
        await Assert.That(stage.RollbackSignature).IsEqualTo(release.RollbackSignature);

        var observed = DeliveryEngine.DecideRollout(Rollout(release, stage: Stage("sfo", StageHealth.Healthy)));
        var advance = (AdvanceReleaseIntent)observed.Intents.Single();
        await Assert.That(advance.CompletedCell.Value).IsEqualTo("sfo");
        await Assert.That(advance.NextCell!.Value).IsEqualTo("fra");
        await Assert.That(advance.Operation).IsEqualTo(release.Operation);
        await Assert.That(advance.Signature).IsEqualTo(release.Signature);
        await Assert.That(observed.Intents.Any(static value => value is StageReleaseIntent)).IsFalse();

        var second = DeliveryEngine.DecideRollout(Rollout(release, completed: [Completion("sfo")]));
        await Assert.That(((StageReleaseIntent)second.Intents.Single()).Cell.Value).IsEqualTo("fra");
    }

    [Test]
    public async Task ProcessExitAloneNeverAdvancesAndAvailabilityProofIsMandatory()
    {
        await AssertHeld(DeliveryEngine.DecideRollout(Rollout(Release(), stage: Stage("sfo", StageHealth.Pending))),
            DeliveryErrorCode.HealthDenied);
        await AssertHeld(DeliveryEngine.DecideRollout(Rollout(Release(), stage: Stage("sfo", StageHealth.Healthy) with
        { AvailabilityAuthorized = false })), DeliveryErrorCode.AvailabilityDenied);
        await AssertHeld(DeliveryEngine.DecideRollout(Rollout(Release(), rollbackAvailable: false)), DeliveryErrorCode.RollbackUnavailable);
    }

    [Test]
    public async Task AvailabilityEvidenceCannotReplayAcrossRolloutOrArtifact()
    {
        var release = Release();
        var valid = Availability(release);
        foreach (var replay in new[]
        {
            valid[0] with { Operation = new("other-operation") },
            valid[0] with { Generation = 3 },
            valid[0] with { ForwardDigest = new("other-digest") },
            valid[0] with { RollbackDigest = new("other-rollback") },
            valid[0] with { RollbackSignature = new("other-rollback-signature") },
        })
        {
            var availability = valid.ToArray();
            availability[0] = replay;
            await AssertHeld(DeliveryEngine.DecideRollout(new(release, [], availability, null, 64)),
                DeliveryErrorCode.EvidenceInvalidated);
        }
    }

    [Test]
    public async Task FailedStageRollsBackExactLocalArtifactOrHoldsByPolicy()
    {
        var rollback = DeliveryEngine.DecideRollout(Rollout(Release(), stage: Stage("sfo", StageHealth.Failed)));
        var intent = (RollbackReleaseIntent)rollback.Intents.Single();
        await Assert.That(intent.FailedDigest.Value).IsEqualTo("digest-n");
        await Assert.That(intent.RollbackDigest.Value).IsEqualTo("digest-n-1");
        await Assert.That(intent.FailedSignature.Value).IsEqualTo("signature-n");
        await Assert.That(intent.RollbackSignature.Value).IsEqualTo("signature-n-1");

        await AssertHeld(DeliveryEngine.DecideRollout(Rollout(Release(policy: RollbackPolicy.HoldForApproval),
            stage: Stage("sfo", StageHealth.Failed))), DeliveryErrorCode.HealthDenied);
    }

    [Test]
    public async Task StageAndCompletionEvidenceBindOperationSignatureAndExactArtifact()
    {
        await AssertHeld(DeliveryEngine.DecideRollout(Rollout(Release(),
            stage: Stage("sfo", StageHealth.Healthy) with { Operation = new("other-operation") })),
            DeliveryErrorCode.ArtifactMismatch);
        await AssertHeld(DeliveryEngine.DecideRollout(Rollout(Release(),
            stage: Stage("sfo", StageHealth.Healthy) with { Signature = new("other-signature") })),
            DeliveryErrorCode.ArtifactMismatch);
        await AssertHeld(DeliveryEngine.DecideRollout(Rollout(Release(),
            completed: [Completion("sfo") with { Digest = new("other-digest") }])),
            DeliveryErrorCode.StageOutOfOrder);
    }

    [Test]
    public async Task DeliveryContractsAreCulturePermutationAndSecretSurfaceSafe()
    {
        var original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new("tr-TR");
            var first = DeliveryEngine.DecideJob(Job(), [Runner("runner-z"), Runner("runner-a")], 64);
            CultureInfo.CurrentCulture = new("en-US");
            var second = DeliveryEngine.DecideJob(Job(), [Runner("runner-a"), Runner("runner-z")], 64);
            await Assert.That(((DispatchJobIntent)first.Intents.Single()).Runner)
                .IsEqualTo(((DispatchJobIntent)second.Intents.Single()).Runner);
        }
        finally { CultureInfo.CurrentCulture = original; }

        var forbidden = new[] { "command", "script", "query", "pipelineText", "secret", "credential", "callback", "process", "network" };
        var names = typeof(DeliveryIntent).Assembly.GetTypes()
            .Where(static type => type.Namespace == typeof(DeliveryIntent).Namespace)
            .SelectMany(static type => type.GetProperties()).Select(static property => property.Name).ToArray();
        await Assert.That(names.Any(name => forbidden.Any(value => name.Contains(value, StringComparison.OrdinalIgnoreCase)))).IsFalse();
        await Assert.That(typeof(DeliveryError).GetProperty(nameof(DeliveryError.Requirement))!.PropertyType)
            .IsEqualTo(typeof(DeliveryRequirementCode));
        var held = DeliveryEngine.DecideSource(new(Source(generation: 2), Source(generation: 3), null, 64));
        await Assert.That(held.Errors.Single().Requirement).IsEqualTo(DeliveryRequirementCode.Inv005);

        var closedOutputs = typeof(DeliveryIntent).Assembly.GetTypes()
            .Where(type => type == typeof(DeliveryDecision) || type == typeof(DeliveryError) ||
                type == typeof(DeliveryTrace) || typeof(DeliveryIntent).IsAssignableFrom(type));
        await Assert.That(closedOutputs.All(static type => type.GetConstructors().Length == 0)).IsTrue();
    }

    private static SourceRevision Source(string reference = "develop", string tree = "tree-1", long generation = 3,
        string manifest = "manifest", string signature = "source-signature", DependencyProof[]? dependencies = null) => new(
        new("source"), new(reference), new("commit-1"), new(tree), new(manifest), generation,
        new("desired-digest"), new(signature), dependencies ??
        [new(new("dep-b"), 2, new("digest-b")), new(new("dep-a"), 1, new("digest-a"))]);
    private static SourceEvidence Evidence(SourceState state = SourceState.Verified, string source = "source",
        string reference = "develop", long generation = 3, DependencyProof[]? dependencies = null) => new(
        new("source-observation"), state, new(source), new(reference), generation,
        new("commit-1"), new("tree-1"), new("manifest"), new("desired-digest"), new("source-signature"),
        new("schema-attestation"), new("dependency-attestation"), dependencies ??
        [new(new("dep-b"), 2, new("digest-b")), new(new("dep-a"), 1, new("digest-a"))], true, true);
    private static JobRequest Job(JobKind kind = JobKind.TrustedBuild, TrustZone zone = TrustZone.TrustedBuild,
        int attempt = 1, int maximumAttempts = 3, bool retry = false,
        RunnerCapability[]? capabilities = null) => new(new("pipeline"), new("job"), kind, new("tree-1"),
        1, attempt, maximumAttempts, new("job-key"), [zone], capabilities ?? [RunnerCapability.Compile, RunnerCapability.Test],
        10, 20, retry);
    private static RunnerEvidence Runner(string id = "runner", TrustZone zone = TrustZone.TrustedBuild,
        long sequence = 15, params RunnerCapability[] capabilities) => new(new(id), zone, sequence, true,
        capabilities.Length == 0 ? [RunnerCapability.Compile, RunnerCapability.Test] : capabilities);
    private static EvidenceSubject Subject() => new(new("tree-1"), new("lock-1"), new("schema-1"), new("artifact-1"), new("digest-1"), DeliveryArchitecture.LinuxArm64);
    private static QualificationEvidence Qualification(EvidenceSubject subject) => new(new("release"), 1, subject, new("tests"), new("evidence"),
        new("signer"), new("signature"), new("approval"),
        new(new("compatibility-n-n"), new("compatibility-n-prev"), new("compatibility-prev-n"), true, true, true),
        true, true, true, true);
    private static ReleaseSpec Release(RollbackPolicy policy = RollbackPolicy.AutomaticOnFailedHealth) => new(new("release"), new("operation"),
        4, new("artifact-n"), new("digest-n"), new("signer-n"), new("signature-n"), DeliveryArchitecture.LinuxArm64,
        new("artifact-n-1"), new("digest-n-1"), new("signer-n-1"), new("signature-n-1"), DeliveryArchitecture.LinuxArm64,
        RolloutStrategy.Canary, policy, [new("sfo"), new("fra"), new("gru")]);
    private static StageEvidence Stage(string cell, StageHealth health) => new(new("stage-observation"), new("operation"),
        new(cell), new("release"), 4, new("artifact-n"), new("digest-n"), new("signer-n"), new("signature-n"), DeliveryArchitecture.LinuxArm64,
        health, new("health-proof"), true, true);
    private static CellCompletionEvidence Completion(string cell) => new(new("operation"), new(cell), new("release"),
        4, new("artifact-n"), new("digest-n"), new("signer-n"), new("signature-n"), DeliveryArchitecture.LinuxArm64, new("health-proof"), StageHealth.Healthy);
    private static RolloutRequest Rollout(ReleaseSpec release, IReadOnlyList<CellCompletionEvidence>? completed = null,
        StageEvidence? stage = null, bool rollbackAvailable = true) => new(release, completed ?? [],
        Availability(release, rollbackAvailable), stage, 64);
    private static CellArtifactAvailability[] Availability(ReleaseSpec release, bool rollbackAvailable = true) =>
        release.OrderedCells.Select(cell => new CellArtifactAvailability(release.Release, release.Operation, release.Generation,
            cell, release.Artifact, release.Digest, release.SigningIdentity, release.Signature, release.Architecture,
            release.RollbackArtifact, release.RollbackDigest, release.RollbackSigningIdentity, release.RollbackSignature, release.RollbackArchitecture,
            true, rollbackAvailable)).ToArray();
    private static async Task AssertHeld(DeliveryDecision decision, DeliveryErrorCode code)
    {
        await Assert.That(decision.Errors.Any(error => error.Code == code)).IsTrue();
        await Assert.That(decision.Intents.Single()).IsTypeOf<HoldDeliveryIntent>();
    }
}
