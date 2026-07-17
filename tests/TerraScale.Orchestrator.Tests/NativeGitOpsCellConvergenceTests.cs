using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsCellConvergenceTests
{
    private const string ApiV1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ApiV2 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string Auth = "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Test]
    public async Task OneDependencyOrderedActionAdvancesFromObservationToLiveConvergence()
    {
        var accepted = Accepted(null, Plan(1,
            Workload("api", "Api", ApiV1, ["auth"]),
            Workload("auth", "Authentication", Auth)));
        var authDigest = DesiredDigest(accepted, "auth");
        var apiDigest = DesiredDigest(accepted, "api");

        await AssertIntent(Decide(accepted, null, []), NativeGitOpsCellConvergenceIntentKind.Observe, "auth");
        await AssertIntent(Decide(accepted, null, [Absent("auth")]), NativeGitOpsCellConvergenceIntentKind.Apply, "auth");
        await AssertIntent(Decide(accepted, null, [Present("auth", 1, authDigest, NativeGitOpsWorkloadState.Applying)]),
            NativeGitOpsCellConvergenceIntentKind.Observe, "auth");
        await AssertIntent(Decide(accepted, null,
                [Healthy("auth", 1, authDigest), Absent("api")]),
            NativeGitOpsCellConvergenceIntentKind.Apply, "api");

        var observations = new[] { Healthy("api", 1, apiDigest), Healthy("auth", 1, authDigest) };
        var first = Decide(accepted, null, observations);
        var reordered = Decide(accepted, null, observations.Reverse());
        await Assert.That(first.IsConverged).IsTrue();
        await Assert.That(first.ConvergenceDigest).IsEqualTo(reordered.ConvergenceDigest);
        await Assert.That(first.ConvergenceDigest!.Length).IsEqualTo(64);
    }

    [Test]
    public async Task StaleDriftForeignAndConflictingObservationsFailOrRepairSafely()
    {
        var acceptedPlan = Plan(1, Workload("api", "Api", ApiV1));
        var acceptedManifest = NativeGitOpsManifest.Parse(acceptedPlan);
        var accepted = Accepted(acceptedPlan, Plan(2, Workload("api", "Api", ApiV2)));
        var baseline = new NativeGitOpsAcceptedCellBaseline("gru", 1, acceptedManifest.Digest);
        var desired = DesiredDigest(accepted, "api");
        var previous = NativeGitOpsCellSpecCompiler.WorkloadDigest(acceptedManifest.Workloads.Single());

        await AssertIntent(Decide(accepted, baseline, [Healthy("api", 1, previous)]),
            NativeGitOpsCellConvergenceIntentKind.Apply, "api");
        await AssertIntent(Decide(accepted, baseline, [Healthy("api", 1, previous, sequence: 4)], minimumSequence: 5),
            NativeGitOpsCellConvergenceIntentKind.Observe, "api");
        await AssertHold(Decide(accepted, baseline,
            [Present("api", 2, ApiV1, NativeGitOpsWorkloadState.Healthy)]),
            NativeGitOpsCellConvergenceHoldReason.SameGenerationConflict);
        await AssertHold(Decide(accepted, baseline,
            [Present("api", 3, desired, NativeGitOpsWorkloadState.Healthy)]),
            NativeGitOpsCellConvergenceHoldReason.FutureGeneration);
        await AssertHold(Decide(accepted, baseline,
            [Present("api", 2, desired, NativeGitOpsWorkloadState.Healthy,
                NativeGitOpsWorkloadOwnership.RegionalJournalChild)]),
            NativeGitOpsCellConvergenceHoldReason.ForeignOwnership);
        await AssertHold(Decide(accepted, baseline, [Healthy("unknown", 2, desired)]),
            NativeGitOpsCellConvergenceHoldReason.ForeignOwnership);
    }

    [Test]
    public async Task FailedHealthRequestsANewQualifiedGenerationInsteadOfLocalRewind()
    {
        var prior = Plan(1, Workload("api", "Api", ApiV1));
        var priorPlan = NativeGitOpsManifest.Parse(prior);
        var accepted = Accepted(prior, Plan(2, Workload("api", "Api", ApiV2)));
        var baseline = new NativeGitOpsAcceptedCellBaseline("gru", 1, priorPlan.Digest);
        var failed = Present(
            "api",
            2,
            DesiredDigest(accepted, "api"),
            NativeGitOpsWorkloadState.Unhealthy);

        await AssertHold(Decide(accepted, baseline, [failed]),
            NativeGitOpsCellConvergenceHoldReason.FailedHealthWithoutRollback);
        var target = new NativeGitOpsRollbackTarget(1, priorPlan.Digest, Hash("qualified-generation-1"));
        var rollback = Decide(accepted, baseline, [failed], rollbackTarget: target);
        await AssertIntent(rollback, NativeGitOpsCellConvergenceIntentKind.RequestRollbackGeneration, "api");
        await Assert.That(rollback.Intent!.RollbackTarget).IsEqualTo(target);
        await Assert.That(rollback.Intent.Generation).IsEqualTo(2);

        await AssertHold(Decide(accepted, baseline, [failed], rollbackTarget: target with
        {
            GlobalPlanDigest = accepted.GlobalPlanDigest,
        }), NativeGitOpsCellConvergenceHoldReason.FailedHealthWithoutRollback);
    }

    [Test]
    public async Task RetirementIsDependentFirstAndRequiresEveryBoundProofBeforeMutation()
    {
        var prior = Plan(1,
            Workload("api", "Api", ApiV1, ["auth"]),
            Workload("auth", "Authentication", Auth));
        var priorPlan = NativeGitOpsManifest.Parse(prior);
        var accepted = Accepted(prior, Plan(2,
            Workload("auth", "Authentication", Auth, suspended: true)));
        var baseline = new NativeGitOpsAcceptedCellBaseline("gru", 1, priorPlan.Digest);
        var parsed = NativeGitOpsCellPayload.Parse(accepted);
        var retirement = parsed.Changes.Single(static value => value.Kind == NativeGitOpsChangeKind.GuardedRetirement);
        var api = Healthy("api", 1, retirement.AcceptedWorkloadSha256!);
        var auth = Healthy(
            "auth",
            1,
            NativeGitOpsCellSpecCompiler.WorkloadDigest(priorPlan.Workloads.Single(static value => value.Id == "auth")));

        await AssertIntent(Decide(accepted, baseline, [auth, api]),
            NativeGitOpsCellConvergenceIntentKind.AuthorizeRetirement, "api");
        var proof = RetirementProof(accepted, parsed, retirement);
        await AssertIntent(Decide(accepted, baseline, [auth, api], [proof]),
            NativeGitOpsCellConvergenceIntentKind.Retire, "api");
        await AssertHold(Decide(accepted, baseline, [auth, api], [proof with { WriterEpoch = 8 }]),
            NativeGitOpsCellConvergenceHoldReason.RetirementProofMismatch);

        var apiAbsent = Absent("api");
        await AssertIntent(Decide(accepted, baseline, [auth, apiAbsent], [proof]),
            NativeGitOpsCellConvergenceIntentKind.Suspend, "auth");
        var suspended = Present(
            "auth",
            2,
            DesiredDigest(accepted, "auth"),
            NativeGitOpsWorkloadState.Suspended);
        var complete = Decide(accepted, baseline, [suspended, apiAbsent], [proof]);
        await Assert.That(complete.IsConverged).IsTrue();
    }

    [Test]
    public async Task AcceptedBaseContinuityIsMandatoryBeforeAnyRegionalAction()
    {
        var prior = Plan(4, Workload("api", "Api", ApiV1));
        var priorPlan = NativeGitOpsManifest.Parse(prior);
        var accepted = Accepted(prior, Plan(5, Workload("api", "Api", ApiV2)));

        await AssertHold(Decide(accepted, null, []),
            NativeGitOpsCellConvergenceHoldReason.AcceptedBaseMismatch);
        await AssertHold(Decide(accepted, new("gru", 4, ApiV1), []),
            NativeGitOpsCellConvergenceHoldReason.AcceptedBaseMismatch);
        await AssertIntent(Decide(accepted, new("gru", 4, priorPlan.Digest), []),
            NativeGitOpsCellConvergenceIntentKind.Observe, "api");
    }

    private static NativeGitOpsCellConvergenceDecision Decide(
        NativeGitOpsAcceptedCellSpec accepted,
        NativeGitOpsAcceptedCellBaseline? baseline,
        IEnumerable<NativeGitOpsWorkloadObservation> observations,
        IEnumerable<NativeGitOpsRetirementEvidence>? retirementEvidence = null,
        NativeGitOpsRollbackTarget? rollbackTarget = null,
        long minimumSequence = 1) => NativeGitOpsCellConvergencePlanner.Decide(
            accepted,
            baseline,
            observations,
            retirementEvidence ?? [],
            rollbackTarget,
            minimumSequence);

    private static NativeGitOpsRetirementEvidence RetirementProof(
        NativeGitOpsAcceptedCellSpec accepted,
        NativeGitOpsParsedCellSpec parsed,
        NativeGitOpsParsedCellChange change) => new(
        parsed.Cell,
        change.WorkloadId,
        parsed.AcceptedGeneration!.Value,
        parsed.AcceptedGlobalPlanDigest!,
        change.AcceptedWorkloadSha256!,
        accepted.WriterEpoch,
        Hash("ownership"),
        Hash("safety"),
        Hash("retention"),
        Hash("dependencies"),
        Hash("domain-authorization"));

    private static NativeGitOpsWorkloadObservation Absent(string workloadId, long sequence = 10) => new(
        workloadId,
        0,
        null,
        NativeGitOpsWorkloadState.Absent,
        NativeGitOpsWorkloadOwnership.Unspecified,
        sequence,
        Hash($"absent-{workloadId}-{sequence}"));

    private static NativeGitOpsWorkloadObservation Healthy(
        string workloadId,
        long generation,
        string digest,
        long sequence = 10) => Present(
        workloadId,
        generation,
        digest,
        NativeGitOpsWorkloadState.Healthy,
        sequence: sequence);

    private static NativeGitOpsWorkloadObservation Present(
        string workloadId,
        long generation,
        string digest,
        NativeGitOpsWorkloadState state,
        NativeGitOpsWorkloadOwnership ownership = NativeGitOpsWorkloadOwnership.NativeGitOpsParent,
        long sequence = 10) => new(
        workloadId,
        generation,
        digest,
        state,
        ownership,
        sequence,
        Hash($"{workloadId}-{generation}-{digest}-{state}-{ownership}-{sequence}"));

    private static string DesiredDigest(NativeGitOpsAcceptedCellSpec accepted, string workloadId) =>
        NativeGitOpsCellSpecCompiler.WorkloadDigest(
            NativeGitOpsCellPayload.Parse(accepted).DesiredWorkloads.Single(value => value.Id == workloadId));

    private static NativeGitOpsAcceptedCellSpec Accepted(byte[]? prior, byte[] proposed)
    {
        var handoff = Handoff(prior, proposed);
        var cell = handoff.Cells.Single();
        return new(
            cell.Cell,
            cell.Generation,
            cell.GlobalPlanDigest,
            handoff.HandoffDigest,
            cell.PayloadSha256,
            cell.Payload.ToArray(),
            7,
            1,
            $"gitops/{handoff.HandoffDigest}/{cell.Cell}",
            $"gitops/{cell.PayloadSha256}",
            1,
            new(2026, 7, 17, 11, 59, 0, TimeSpan.Zero),
            new(2026, 7, 17, 12, 1, 0, TimeSpan.Zero),
            new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero),
            1,
            Hash("signature"),
            1);
    }

    private static NativeGitOpsCellHandoff Handoff(byte[]? prior, byte[] proposedContent)
    {
        const string repository = "TerraScale/TerraScale.Orchestrator";
        const string commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
        const string tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
        const string blob = "217eb74224043ba2feb48d137756c8a9331c44ee";
        var accepted = prior is null ? null : NativeGitOpsManifest.Parse(prior);
        var proposed = NativeGitOpsManifest.Parse(proposedContent);
        return NativeGitOpsCellSpecCompiler.Compile(new(
            new(repository, commit, tree, signatureVerified: true),
            new(
                repository,
                commit,
                NativeGitOpsSourceLoader.ManifestPath,
                blob,
                Convert.ToHexStringLower(SHA256.HashData(proposedContent)),
                proposedContent),
            proposed,
            NativeGitOpsDiff.Compare(accepted, proposed)));
    }

    private static byte[] Plan(long generation, params string[] workloads) => Encoding.UTF8.GetBytes($$"""
        {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":{{generation}},"workloads":[{{string.Join(',', workloads)}}]}
        """);

    private static string Workload(
        string id,
        string role,
        string digest,
        string[]? dependsOn = null,
        bool suspended = false) => $$"""
        {"id":"{{id}}","role":"{{role}}","artifactDigest":"{{digest}}","cells":["gru"],"dependsOn":[{{string.Join(',', (dependsOn ?? []).Select(static dependency => $"\"{dependency}\""))}}],"suspended":{{suspended.ToString().ToLowerInvariant()}}}
        """;

    private static string Hash(string value) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static async Task AssertIntent(
        NativeGitOpsCellConvergenceDecision decision,
        NativeGitOpsCellConvergenceIntentKind kind,
        string workloadId)
    {
        await Assert.That(decision.State).IsEqualTo(NativeGitOpsCellConvergenceState.Pending);
        await Assert.That(decision.Intent).IsNotNull();
        await Assert.That(decision.Intent!.Kind).IsEqualTo(kind);
        await Assert.That(decision.Intent.WorkloadId).IsEqualTo(workloadId);
        await Assert.That(decision.ConvergenceDigest).IsNull();
    }

    private static async Task AssertHold(
        NativeGitOpsCellConvergenceDecision decision,
        NativeGitOpsCellConvergenceHoldReason reason)
    {
        await Assert.That(decision.State).IsEqualTo(NativeGitOpsCellConvergenceState.Held);
        await Assert.That(decision.HoldReason).IsEqualTo(reason);
        await Assert.That(decision.Intent).IsNull();
        await Assert.That(decision.ConvergenceDigest).IsNull();
    }
}
