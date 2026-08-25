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

        var evidence = Evidence();
        var plan = DeliveryEngine.DecideSource(new(source, null, evidence, 64));
        var intent = (PlanApplyIntent)plan.Intents.Single();
        await Assert.That(intent.Commit).IsEqualTo(source.Commit);
        await Assert.That(intent.Tree).IsEqualTo(source.Tree);
        await Assert.That(ReferenceEquals(intent.SignatureAttestation, evidence.SignatureAttestation)).IsTrue();
        await Assert.That(intent.Dependencies.Select(static value => value.Manifest.Value)
            .SequenceEqual(new[] { "dep-a", "dep-b" }, StringComparer.Ordinal)).IsTrue();
    }

    [Test]
    public async Task InvalidOrUnattestedSourceSignatureNeverAuthorizesPlanApply()
    {
        var source = Source(signature: "forged-signature");
        var forged = Evidence(signature: "forged-signature", signatureValid: false,
            signatureAttestation: "forged-signature-check");

        var verify = DeliveryEngine.DecideSource(new(source, null, forged, 64));
        await Assert.That(verify.Errors).IsEmpty();
        await Assert.That(verify.Intents.Single()).IsTypeOf<VerifySourceIntent>();
        await Assert.That(verify.Trace.Single().Code).IsEqualTo(DeliveryTraceCode.VerificationRequired);

        foreach (var invalid in new[]
        {
            Evidence(signatureAttestation: null),
            Evidence(signatureAttestation: string.Empty),
            Evidence(signatureAttestation: new string('a', 65)),
        })
            await AssertHeld(DeliveryEngine.DecideSource(new(Source(), null, invalid, 64)),
                DeliveryErrorCode.EvidenceInvalidated);
    }

    [Test]
    public async Task EverySourceVerificationResultMustPassBeforePlanApply()
    {
        foreach (var evidence in new[]
        {
            Evidence(signatureValid: false),
            Evidence(schemaValid: false),
            Evidence(dependenciesValid: false),
        })
        {
            var decision = DeliveryEngine.DecideSource(new(Source(), null, evidence, 64));
            await Assert.That(decision.Intents.Single()).IsTypeOf<VerifySourceIntent>();
            await Assert.That(decision.Trace.Single().Code).IsEqualTo(DeliveryTraceCode.VerificationRequired);
        }
    }

    [Test]
    public async Task PlanApplyPublicShapeRetainsAllVerificationAttestations()
    {
        var properties = typeof(PlanApplyIntent).GetProperties().Select(static property => property.Name)
            .OrderBy(static name => name, StringComparer.Ordinal).ToArray();
        await Assert.That(properties).IsEquivalentTo(new[]
        {
            nameof(DeliveryIntent.Action), nameof(PlanApplyIntent.Commit), nameof(PlanApplyIntent.Dependencies),
            nameof(PlanApplyIntent.DependencyAttestation), nameof(PlanApplyIntent.Digest), nameof(PlanApplyIntent.Generation),
            nameof(PlanApplyIntent.Manifest), nameof(PlanApplyIntent.SchemaAttestation), nameof(PlanApplyIntent.Signature),
            nameof(PlanApplyIntent.SignatureAttestation), nameof(PlanApplyIntent.Source), nameof(PlanApplyIntent.Tree),
        });
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
        string reference = "develop", long generation = 3, DependencyProof[]? dependencies = null,
        string signature = "source-signature",
        string? signatureAttestation = "signature-attestation", bool signatureValid = true,
        bool schemaValid = true, bool dependenciesValid = true) => new(
        new("source-observation"), state, new(source), new(reference), generation,
        new("commit-1"), new("tree-1"), new("manifest"), new("desired-digest"), new(signature),
        new("schema-attestation"), new("dependency-attestation"),
        signatureAttestation is null ? null! : new(signatureAttestation), dependencies ??
        [new(new("dep-b"), 2, new("digest-b")), new(new("dep-a"), 1, new("digest-a"))],
        signatureValid, schemaValid, dependenciesValid);
    private static JobRequest Job(JobKind kind = JobKind.TrustedBuild, TrustZone zone = TrustZone.TrustedBuild,
        int attempt = 1, int maximumAttempts = 3, bool retry = false,
        RunnerCapability[]? capabilities = null) => new(new("pipeline"), new("job"), kind, new("tree-1"),
        1, attempt, maximumAttempts, new("job-key"), [zone], capabilities ?? [RunnerCapability.Compile, RunnerCapability.Test],
        10, 20, retry);
    private static RunnerEvidence Runner(string id = "runner", TrustZone zone = TrustZone.TrustedBuild,
        long sequence = 15, params RunnerCapability[] capabilities) => new(new(id), zone, sequence, true,
        capabilities.Length == 0 ? [RunnerCapability.Compile, RunnerCapability.Test] : capabilities);
    private static async Task AssertHeld(DeliveryDecision decision, DeliveryErrorCode code)
    {
        await Assert.That(decision.Errors.Any(error => error.Code == code)).IsTrue();
        await Assert.That(decision.Intents.Single()).IsTypeOf<HoldDeliveryIntent>();
    }
}
