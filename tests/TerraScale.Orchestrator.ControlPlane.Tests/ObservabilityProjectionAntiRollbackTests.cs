using TerraScale.Orchestrator.ControlPlane.Observability;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class ObservabilityProjectionAntiRollbackTests
{
    [Test]
    public async Task Accepted_projection_checkpoint_rejects_old_whole_envelope_replay()
    {
        var accepted = Request(6, 10, 6, 10, "new-dashboard");
        var acceptedDecision = ObservabilityDecisionEngine.EvaluateGrafanaProjection(accepted);
        await Assert.That(acceptedDecision.Authorized).IsTrue();
        await Assert.That(((ProjectGrafanaIntent)acceptedDecision.Intent).Changes.Single() is CreateGrafanaResource).IsTrue();

        var replay = Request(5, 9, 6, 10, "old-dashboard");
        var replayDecision = ObservabilityDecisionEngine.EvaluateGrafanaProjection(replay);
        await Assert.That(replayDecision.Authorized).IsFalse();
        await Assert.That(replayDecision.Intent is HoldObservabilityIntent).IsTrue();
        await Assert.That(replayDecision.Trace.Select(reason => reason.Code).SequenceEqual(new[]
        {
            ObservabilityDecisionCode.EvidenceComplete,
            ObservabilityDecisionCode.ProjectionGenerationNotRollback,
            ObservabilityDecisionCode.ProjectionSequenceNotRollback,
            ObservabilityDecisionCode.ScopeExact,
            ObservabilityDecisionCode.AccessExact,
            ObservabilityDecisionCode.GenerationCurrent,
            ObservabilityDecisionCode.OwnershipExact,
        })).IsTrue();
        await AssertReason(replayDecision, ObservabilityDecisionCode.ProjectionGenerationNotRollback, ObservabilityDecisionOutcome.Rejected, 5, 6);
        await AssertReason(replayDecision, ObservabilityDecisionCode.ProjectionSequenceNotRollback, ObservabilityDecisionOutcome.Rejected, 9, 10);
    }

    [Test]
    public async Task Generation_and_sequence_high_water_marks_are_independent()
    {
        var staleGeneration = ObservabilityDecisionEngine.EvaluateGrafanaProjection(Request(5, 10, 6, 10, "stale-generation"));
        var staleSequence = ObservabilityDecisionEngine.EvaluateGrafanaProjection(Request(6, 9, 6, 10, "stale-sequence"));
        await AssertReason(staleGeneration, ObservabilityDecisionCode.ProjectionGenerationNotRollback, ObservabilityDecisionOutcome.Rejected, 5, 6);
        await AssertReason(staleGeneration, ObservabilityDecisionCode.ProjectionSequenceNotRollback, ObservabilityDecisionOutcome.Passed, 10, 10);
        await AssertReason(staleSequence, ObservabilityDecisionCode.ProjectionGenerationNotRollback, ObservabilityDecisionOutcome.Passed, 6, 6);
        await AssertReason(staleSequence, ObservabilityDecisionCode.ProjectionSequenceNotRollback, ObservabilityDecisionOutcome.Rejected, 9, 10);
    }

    [Test]
    public async Task Equality_and_forward_checkpoints_authorize_and_retain_exact_request()
    {
        foreach (var request in new[] { Request(6, 10, 6, 10, "equal"), Request(7, 11, 6, 10, "forward") })
        {
            var decision = ObservabilityDecisionEngine.EvaluateGrafanaProjection(request);
            await Assert.That(decision.Authorized).IsTrue();
            await Assert.That(ReferenceEquals(((ProjectGrafanaIntent)decision.Intent).Request, request)).IsTrue();
            await Assert.That(decision.Trace.Select(reason => reason.Code).SequenceEqual(new[]
            {
                ObservabilityDecisionCode.EvidenceComplete,
                ObservabilityDecisionCode.ProjectionGenerationNotRollback,
                ObservabilityDecisionCode.ProjectionSequenceNotRollback,
                ObservabilityDecisionCode.ScopeExact,
                ObservabilityDecisionCode.AccessExact,
                ObservabilityDecisionCode.GenerationCurrent,
                ObservabilityDecisionCode.OwnershipExact,
                ObservabilityDecisionCode.ProjectionExact,
            })).IsTrue();
        }
    }

    [Test]
    public async Task Error_ids_are_append_only_and_exact()
    {
        await Assert.That(Enum.GetValues<ObservabilityDecisionCode>().Select(value => (int)value).SequenceEqual(Enumerable.Range(1, 19))).IsTrue();
        var generationCode = (int)ObservabilityDecisionCode.ProjectionGenerationNotRollback;
        var sequenceCode = (int)ObservabilityDecisionCode.ProjectionSequenceNotRollback;
        await Assert.That(generationCode).IsEqualTo(18);
        await Assert.That(sequenceCode).IsEqualTo(19);
    }

    [Test]
    public async Task Checkpoint_trace_and_output_follow_exact_oracle_for_1000_cases()
    {
        for (var seed = 1UL; seed <= 1000; seed++)
        {
            var candidateGeneration = 1000 + seed;
            var candidateSequence = 2000 + seed;
            var variant = seed % 5;
            var acceptedGeneration = variant is 2 or 4 ? candidateGeneration + 1 : variant == 1 ? candidateGeneration - 1 : candidateGeneration;
            var acceptedSequence = variant is 3 or 4 ? candidateSequence + 1 : variant == 1 ? candidateSequence - 1 : candidateSequence;
            var request = Request(candidateGeneration, candidateSequence, acceptedGeneration, acceptedSequence, $"dashboard-{seed}");
            var decision = ObservabilityDecisionEngine.EvaluateGrafanaProjection(request);
            var authorized = variant is 0 or 1;

            Require(decision.Authorized == authorized, seed, "authorization");
            Require(decision.Trace.Select(reason => reason.Code).SequenceEqual(authorized ? AuthorizedCodes : RejectedCodes), seed, "trace order");
            Require(Reason(decision, ObservabilityDecisionCode.ProjectionGenerationNotRollback).Outcome ==
                (variant is 2 or 4 ? ObservabilityDecisionOutcome.Rejected : ObservabilityDecisionOutcome.Passed), seed, "generation outcome");
            Require(Reason(decision, ObservabilityDecisionCode.ProjectionSequenceNotRollback).Outcome ==
                (variant is 3 or 4 ? ObservabilityDecisionOutcome.Rejected : ObservabilityDecisionOutcome.Passed), seed, "sequence outcome");
            Require(Reason(decision, ObservabilityDecisionCode.ProjectionGenerationNotRollback).Observed == candidateGeneration &&
                Reason(decision, ObservabilityDecisionCode.ProjectionGenerationNotRollback).Required == acceptedGeneration, seed, "generation values");
            Require(Reason(decision, ObservabilityDecisionCode.ProjectionSequenceNotRollback).Observed == candidateSequence &&
                Reason(decision, ObservabilityDecisionCode.ProjectionSequenceNotRollback).Required == acceptedSequence, seed, "sequence values");
            if (authorized)
                Require(ReferenceEquals(((ProjectGrafanaIntent)decision.Intent).Request, request), seed, "request retention");
        }
    }

    private static readonly ObservabilityDecisionCode[] RejectedCodes =
    [
        ObservabilityDecisionCode.EvidenceComplete,
        ObservabilityDecisionCode.ProjectionGenerationNotRollback,
        ObservabilityDecisionCode.ProjectionSequenceNotRollback,
        ObservabilityDecisionCode.ScopeExact,
        ObservabilityDecisionCode.AccessExact,
        ObservabilityDecisionCode.GenerationCurrent,
        ObservabilityDecisionCode.OwnershipExact,
    ];

    private static readonly ObservabilityDecisionCode[] AuthorizedCodes = [.. RejectedCodes, ObservabilityDecisionCode.ProjectionExact];

    private static GrafanaProjectionRequest Request(ulong generation, ulong sequence, ulong acceptedGeneration, ulong acceptedSequence, string resourceId)
    {
        var operation = new ObservabilityOperationId($"operation-{resourceId}");
        var owner = new ObservabilityOwnerId("terrascale");
        var tenant = new ObservabilityTenantId("tenant-a");
        var cell = new ObservabilityCellId("gru");
        var desired = new DesiredGrafanaResource(new(resourceId), owner, tenant, cell, new(generation), new($"release-{generation}"), Digest(), new DashboardSelection(DashboardCatalogEntry.FleetOverview));
        var inventory = new GrafanaInventoryEvidence(operation, owner, tenant, cell, new(generation), new(sequence), EvidenceCompleteness.Complete, new(2), []);
        return new(operation, owner, tenant, cell, GrafanaAccessBoundary.Tenant, new(generation), new(sequence), new(acceptedGeneration), new(acceptedSequence), new(2), [desired], inventory);
    }

    private static ObservabilityDigest Digest() => new(new string('a', 64));
    private static ObservabilityDecisionReason Reason(ObservabilityDecision decision, ObservabilityDecisionCode code) => decision.Trace.Single(reason => reason.Code == code);
    private static async Task AssertReason(ObservabilityDecision decision, ObservabilityDecisionCode code, ObservabilityDecisionOutcome outcome, ulong observed, ulong required)
    {
        var reason = Reason(decision, code);
        await Assert.That(reason.Outcome).IsEqualTo(outcome);
        await Assert.That(reason.Observed).IsEqualTo(observed);
        await Assert.That(reason.Required).IsEqualTo(required);
    }
    private static void Require(bool condition, ulong seed, string property)
    {
        if (!condition) throw new InvalidOperationException($"{property} failed at seed {seed}.");
    }
}
