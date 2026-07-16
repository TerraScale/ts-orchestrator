using TerraScale.Orchestrator.ControlPlane.Authority;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class AuthorityEngineTests
{
    private static readonly DateTimeOffset Start = new(2026, 7, 13, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Duration = TimeSpan.FromMinutes(10);

    [Test]
    public async Task AcquisitionAdvancesEpochAndOnlyExactCasProducesBoundPermit()
    {
        var (history, pending) = BeginAcquisition("candidate-a", "acquire-a");
        await Assert.That(pending.State.Status).IsEqualTo(AuthorityStatus.AcquisitionPending);
        await Assert.That(pending.MutationPermit).IsNull();
        var intent = (CompareAndSetLeaseIntent)pending.Intents.Single();
        await Assert.That(intent.ExpectedEpoch).IsEqualTo(5);
        await Assert.That(intent.ProposedEpoch).IsEqualTo(6);

        var result = ConfirmSet(history, pending, "candidate-a", "acquire-a");
        await Assert.That(result.Errors).IsEmpty();
        await Assert.That(result.State.Status).IsEqualTo(AuthorityStatus.Leader);
        await Assert.That(result.MutationPermit).IsNotNull();
        await Assert.That(result.MutationPermit!.AuthorityId).IsEqualTo("regional-authority");
        await Assert.That(result.MutationPermit.CandidateId).IsEqualTo("candidate-a");
        await Assert.That(result.MutationPermit.LeaseId).IsEqualTo("lease-candidate-a");
        await Assert.That(result.MutationPermit.Epoch).IsEqualTo(6);
        await Assert.That(result.MutationPermit.KvRevision).IsEqualTo(11);
    }

    [Test]
    public async Task MismatchedSuccessfulCasFencesWithoutAuthority()
    {
        var (history, pending) = BeginAcquisition("candidate-a", "acquire-a");
        var proposal = ((CompareAndSetLeaseIntent)pending.Intents.Single()).ProposedLease;
        var mismatch = AuthorityEngine.Decide(history, new ObserveAuthorityCas(
            "regional-authority", "candidate-a", "acquire-a", AuthorityCasOutcome.Succeeded,
            new AuthorityObservation("regional-authority", 12, 6, "wrong-revision", proposal),
            Healthy(Start, TimeSpan.Zero)));

        await Assert.That(mismatch.State.Status).IsEqualTo(AuthorityStatus.Fenced);
        await Assert.That(mismatch.MutationPermit).IsNull();
        await Assert.That(mismatch.Errors.Single().Code).IsEqualTo(AuthorityErrorCode.RevisionMismatch);
    }

    [Test]
    public async Task ThreeCandidatesInterleaveButOnlyCasWinnerObtainsAuthority()
    {
        var candidates = new[] { "candidate-a", "candidate-b", "candidate-c" };
        var attempts = candidates.ToDictionary(candidate => candidate,
            candidate => BeginAcquisition(candidate, $"acquire-{candidate}"));
        var winner = attempts["candidate-b"];
        var winnerIntent = (CompareAndSetLeaseIntent)winner.Pending.Intents.Single();
        var winnerObservation = new AuthorityObservation("regional-authority", 11, 6,
            "winner-observation", winnerIntent.ProposedLease);
        var confirmed = AuthorityEngine.Decide(winner.History, new ObserveAuthorityCas(
            "regional-authority", "candidate-b", "acquire-candidate-b", AuthorityCasOutcome.Succeeded,
            winnerObservation, Healthy(Start, TimeSpan.Zero)));
        await Assert.That(confirmed.MutationPermit).IsNotNull();

        foreach (var candidate in new[] { "candidate-a", "candidate-c" })
        {
            var loser = attempts[candidate];
            var stale = AuthorityEngine.Decide(loser.History, new ObserveAuthorityCas(
                "regional-authority", candidate, $"acquire-{candidate}", AuthorityCasOutcome.Conflict,
                winnerObservation, Healthy(Start, TimeSpan.Zero)));
            await Assert.That(stale.MutationPermit).IsNull();
            await Assert.That(stale.State.Status).IsEqualTo(AuthorityStatus.ReadOnlyHeld);
            await Assert.That(stale.State.HighestEpoch).IsEqualTo(6);
        }
    }

    [Test]
    public async Task CandidateBJumpsEpochAfterAExpiresAndStaleAIsFencedBySharedCasTruth()
    {
        var historyA = BuildLeader();
        var candidateA = AuthorityEngine.Replay(historyA).State.Confirmed!;
        var (historyB, beginB) = BeginAcquisition("candidate-b", "acquire-b", candidateA);
        var confirmedB = ConfirmSet(historyB, beginB, "candidate-b", "acquire-b");
        await Assert.That(confirmedB.MutationPermit!.CandidateId).IsEqualTo("candidate-b");
        await Assert.That(confirmedB.MutationPermit.Epoch).IsEqualTo(7);

        var staleA = AuthorityEngine.Decide(historyA, new EvaluateMutationAuthority(
            "regional-authority", "candidate-a", "observe-b", confirmedB.State.Confirmed!,
            Healthy(Start.Add(Duration), Duration)));
        await Assert.That(staleA.MutationPermit).IsNull();
        await Assert.That(staleA.State.Status).IsEqualTo(AuthorityStatus.Fenced);
        await Assert.That(staleA.Errors.Single().Code).IsEqualTo(AuthorityErrorCode.EpochMismatch);

        historyA.AddRange(staleA.EventsToAppend);
        var cannotReturn = AuthorityEngine.Decide(historyA,
            new RequestAuthorityRead("regional-authority", "candidate-a", "self-unfence"));
        await Assert.That(cannotReturn.Errors.Single().Code).IsEqualTo(AuthorityErrorCode.Fenced);
    }

    [Test]
    public async Task ExplicitGenesisCreatesRevisionAndEpochOne()
    {
        var genesis = new AuthorityObservation("regional-authority", 0, 0, "genesis-absent", null);
        var pending = AuthorityEngine.Decide([], Acquire("candidate-a", "genesis", genesis) with
        {
            Health = Healthy(Start, TimeSpan.Zero),
        });
        var intent = (CompareAndSetLeaseIntent)pending.Intents.Single();
        await Assert.That(intent.ExpectedRevision).IsEqualTo(0);
        await Assert.That(intent.ExpectedEpoch).IsEqualTo(0);
        await Assert.That(intent.ProposedEpoch).IsEqualTo(1);
        var history = pending.EventsToAppend.ToList();
        var confirmed = ConfirmSet(history, pending, "candidate-a", "genesis");
        await Assert.That(confirmed.MutationPermit!.KvRevision).IsEqualTo(1);
        await Assert.That(confirmed.MutationPermit.Epoch).IsEqualTo(1);
    }

    [Test]
    public async Task ObservationsFromAnotherAuthorityNeverSatisfyCommandsOrReplay()
    {
        var wrongBaseline = AuthorityEngine.Decide([], Acquire("candidate-a", "wrong-baseline") with
        {
            Baseline = Baseline() with { AuthorityId = "other-authority" },
        });
        await Assert.That(wrongBaseline.Errors.Single().Code).IsEqualTo(AuthorityErrorCode.IdentityMismatch);

        var (history, pending) = BeginAcquisition("candidate-a", "wrong-result");
        var intent = (CompareAndSetLeaseIntent)pending.Intents.Single();
        var wrongResult = AuthorityEngine.Decide(history, new ObserveAuthorityCas(
            "regional-authority", "candidate-a", "wrong-result", AuthorityCasOutcome.Succeeded,
            new AuthorityObservation("other-authority", 11, 6, "wrong", intent.ProposedLease),
            Healthy(Start, TimeSpan.Zero)));
        await Assert.That(wrongResult.Errors.Single().Code).IsEqualTo(AuthorityErrorCode.IdentityMismatch);
        await Assert.That(wrongResult.MutationPermit).IsNull();
    }

    [Test]
    public async Task RenewalPendingRevokesPermitAndExactCasPreservesEpoch()
    {
        var history = BuildLeader();
        var current = AuthorityEngine.Replay(history).State.Confirmed!;
        var renewal = AuthorityEngine.Decide(history, new RenewAuthority(
            "regional-authority", "candidate-a", "renew-a", current,
            Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1)), Duration));
        history.AddRange(renewal.EventsToAppend);

        await Assert.That(renewal.State.Status).IsEqualTo(AuthorityStatus.RenewalPending);
        await Assert.That(renewal.MutationPermit).IsNull();
        var intent = (CompareAndSetLeaseIntent)renewal.Intents.Single();
        await Assert.That(intent.ProposedEpoch).IsEqualTo(current.Epoch);

        var observation = new AuthorityObservation("regional-authority", current.KvRevision + 1,
            current.Epoch, "renewed", intent.ProposedLease);
        var confirmed = AuthorityEngine.Decide(history, new ObserveAuthorityCas(
            "regional-authority", "candidate-a", "renew-a", AuthorityCasOutcome.Succeeded,
            observation, Healthy(Start.AddMinutes(1), TimeSpan.Zero)));
        await Assert.That(confirmed.State.Status).IsEqualTo(AuthorityStatus.Leader);
        await Assert.That(confirmed.MutationPermit!.Epoch).IsEqualTo(current.Epoch);
        await Assert.That(confirmed.MutationPermit.KvRevision).IsEqualTo(current.KvRevision + 1);
    }

    [Test]
    public async Task RenewalFailureUncertaintyAndConflictFenceImmediately()
    {
        foreach (var outcome in new[] { AuthorityCasOutcome.Failed, AuthorityCasOutcome.Uncertain, AuthorityCasOutcome.Conflict })
        {
            var history = BuildLeader();
            var current = AuthorityEngine.Replay(history).State.Confirmed!;
            var renewal = AuthorityEngine.Decide(history, new RenewAuthority(
                "regional-authority", "candidate-a", $"renew-{outcome}", current,
                Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1)), Duration));
            history.AddRange(renewal.EventsToAppend);
            var result = AuthorityEngine.Decide(history, new ObserveAuthorityCas(
                "regional-authority", "candidate-a", $"renew-{outcome}", outcome, current,
                Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1))));
            await Assert.That(result.State.Status).IsEqualTo(AuthorityStatus.Fenced);
            await Assert.That(result.MutationPermit).IsNull();
        }
    }

    [Test]
    public async Task ExpiryEqualityHigherEpochPartitionAndClockAnomalyRemoveAuthority()
    {
        var leader = BuildLeader();
        var current = AuthorityEngine.Replay(leader).State.Confirmed!;
        var expiry = AuthorityEngine.Decide(leader, new EvaluateMutationAuthority(
            "regional-authority", "candidate-a", "evaluate-expiry", current,
            Healthy(Start.Add(Duration), Duration)));
        await Assert.That(expiry.State.Status).IsEqualTo(AuthorityStatus.Fenced);
        await Assert.That(expiry.Errors.Single().Code).IsEqualTo(AuthorityErrorCode.LeaseExpired);

        var higher = current with { KvRevision = 12, Epoch = 7, ObservationId = "higher" };
        var higherDecision = AuthorityEngine.Decide(leader, new EvaluateMutationAuthority(
            "regional-authority", "candidate-a", "evaluate-higher", higher,
            Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1))));
        await Assert.That(higherDecision.State.Status).IsEqualTo(AuthorityStatus.Fenced);

        foreach (var health in new[]
                 {
                     Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1)) with { PartitionCertain = false },
                     Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1)) with { ClockCertain = false },
                 })
        {
            var held = AuthorityEngine.Decide(leader, new EvaluateMutationAuthority(
                "regional-authority", "candidate-a", $"hold-{health.PartitionCertain}", current, health));
            await Assert.That(held.State.Status).IsEqualTo(AuthorityStatus.ReadOnlyHeld);
            await Assert.That(held.MutationPermit).IsNull();
        }
    }

    [Test]
    public async Task HeldLeaderCanReadAndRecoverButFencedCandidateCannotSelfUnfence()
    {
        var history = BuildLeader();
        var current = AuthorityEngine.Replay(history).State.Confirmed!;
        var held = AuthorityEngine.Decide(history, new EvaluateMutationAuthority(
            "regional-authority", "candidate-a", "partition", current,
            Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1)) with { PartitionCertain = false }));
        history.AddRange(held.EventsToAppend);
        var read = AuthorityEngine.Decide(history,
            new RequestAuthorityRead("regional-authority", "candidate-a", "read-after-partition"));
        history.AddRange(read.EventsToAppend);
        var recovered = AuthorityEngine.Decide(history, new ObserveAuthorityRead(
            "regional-authority", "candidate-a", "read-after-partition", AuthorityCasOutcome.Succeeded,
            current, Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1))));
        await Assert.That(recovered.State.Status).IsEqualTo(AuthorityStatus.Leader);
        await Assert.That(recovered.MutationPermit).IsNotNull();

        var fencedHistory = BuildLeader();
        var higher = current with { KvRevision = 12, Epoch = 7, ObservationId = "higher" };
        var fenced = AuthorityEngine.Decide(fencedHistory, new EvaluateMutationAuthority(
            "regional-authority", "candidate-a", "higher", higher,
            Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1))));
        fencedHistory.AddRange(fenced.EventsToAppend);
        var cannotRead = AuthorityEngine.Decide(fencedHistory,
            new RequestAuthorityRead("regional-authority", "candidate-a", "read-fenced"));
        await Assert.That(cannotRead.Errors.Single().Code).IsEqualTo(AuthorityErrorCode.Fenced);
        await Assert.That(cannotRead.Intents).IsEmpty();
    }

    [Test]
    public async Task ReleasePendingRevokesPermitAndExactDeleteReturnsFollower()
    {
        var history = BuildLeader();
        var current = AuthorityEngine.Replay(history).State.Confirmed!;
        var release = AuthorityEngine.Decide(history, new ReleaseAuthority(
            "regional-authority", "candidate-a", "release-a", current,
            Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1))));
        history.AddRange(release.EventsToAppend);
        await Assert.That(release.State.Status).IsEqualTo(AuthorityStatus.ReleasePending);
        await Assert.That(release.MutationPermit).IsNull();
        await Assert.That(release.Intents.Single()).IsTypeOf<CompareAndDeleteLeaseIntent>();

        var absent = new AuthorityObservation("regional-authority", current.KvRevision + 1,
            current.Epoch, "deleted", null);
        var deleted = AuthorityEngine.Decide(history, new ObserveAuthorityDelete(
            "regional-authority", "candidate-a", "release-a", AuthorityCasOutcome.Succeeded,
            absent, Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1))));
        await Assert.That(deleted.State.Status).IsEqualTo(AuthorityStatus.Follower);
        await Assert.That(deleted.MutationPermit).IsNull();
    }

    [Test]
    public async Task ReleaseFailureOrUncertaintyFencesAndNeverClaimsSuccess()
    {
        foreach (var outcome in new[] { AuthorityCasOutcome.Failed, AuthorityCasOutcome.Conflict, AuthorityCasOutcome.Uncertain })
        {
            var history = BuildLeader();
            var current = AuthorityEngine.Replay(history).State.Confirmed!;
            var request = $"release-{outcome}";
            var release = AuthorityEngine.Decide(history, new ReleaseAuthority(
                "regional-authority", "candidate-a", request, current,
                Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1))));
            history.AddRange(release.EventsToAppend);
            var result = AuthorityEngine.Decide(history, new ObserveAuthorityDelete(
                "regional-authority", "candidate-a", request, outcome, current,
                Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1))));
            await Assert.That(result.State.Status).IsEqualTo(AuthorityStatus.Fenced);
            await Assert.That(result.MutationPermit).IsNull();
            await Assert.That(result.Errors).IsNotEmpty();
        }
    }

    [Test]
    public async Task CrashReplayAtEveryIntentAndResultBoundaryHasEqualDigest()
    {
        var history = new List<AuthorityEvent>();
        var acquisition = AuthorityEngine.Decide(history, Acquire("candidate-a", "acquire-a"));
        await AppendAndReplay(history, acquisition);
        var acquired = ConfirmSet(history, acquisition, "candidate-a", "acquire-a");
        await AppendAndReplay(history, acquired);

        var current = AuthorityEngine.Replay(history).State.Confirmed!;
        var renewal = AuthorityEngine.Decide(history, new RenewAuthority("regional-authority", "candidate-a",
            "renew-a", current, Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1)), Duration));
        await AppendAndReplay(history, renewal);
        var renewIntent = (CompareAndSetLeaseIntent)renewal.Intents.Single();
        var renewedObservation = new AuthorityObservation("regional-authority", current.KvRevision + 1,
            current.Epoch, "renewed", renewIntent.ProposedLease);
        var renewed = AuthorityEngine.Decide(history, new ObserveAuthorityCas("regional-authority", "candidate-a",
            "renew-a", AuthorityCasOutcome.Succeeded, renewedObservation, Healthy(Start.AddMinutes(1), TimeSpan.Zero)));
        await AppendAndReplay(history, renewed);

        var read = AuthorityEngine.Decide(history, new RequestAuthorityRead("regional-authority", "candidate-a", "read-a"));
        await AppendAndReplay(history, read);
        var readResult = AuthorityEngine.Decide(history, new ObserveAuthorityRead("regional-authority", "candidate-a",
            "read-a", AuthorityCasOutcome.Succeeded, renewedObservation, Healthy(Start.AddMinutes(2), TimeSpan.FromMinutes(1))));
        await AppendAndReplay(history, readResult);

        var release = AuthorityEngine.Decide(history, new ReleaseAuthority("regional-authority", "candidate-a",
            "release-a", renewedObservation, Healthy(Start.AddMinutes(2), TimeSpan.FromMinutes(1))));
        await AppendAndReplay(history, release);
        var deleted = AuthorityEngine.Decide(history, new ObserveAuthorityDelete("regional-authority", "candidate-a",
            "release-a", AuthorityCasOutcome.Succeeded,
            new AuthorityObservation("regional-authority", renewedObservation.KvRevision + 1,
                renewedObservation.Epoch, "deleted", null), Healthy(Start.AddMinutes(2), TimeSpan.FromMinutes(1))));
        await AppendAndReplay(history, deleted);
    }

    [Test]
    public async Task DuplicateAndReorderedEventsReplayButStaleResultsNeverGrantAgain()
    {
        var history = BuildLeader();
        var expected = AuthorityEngine.Replay(history);
        var replay = AuthorityEngine.Replay(history.AsEnumerable().Reverse().Concat(history).ToArray());
        await Assert.That(replay.Errors).IsEmpty();
        await Assert.That(AuthorityDigest.State(replay.State)).IsEqualTo(AuthorityDigest.State(expected.State));

        var duplicateResult = AuthorityEngine.Decide(history, new ObserveAuthorityCas(
            "regional-authority", "candidate-a", "acquire-a", AuthorityCasOutcome.Succeeded,
            expected.State.Confirmed, Healthy(Start, TimeSpan.Zero)));
        await Assert.That(duplicateResult.EventsToAppend).IsEmpty();
        await Assert.That(duplicateResult.MutationPermit).IsNull();

        var staleRequest = AuthorityEngine.Decide(history, new ObserveAuthorityCas(
            "regional-authority", "candidate-a", "older-request", AuthorityCasOutcome.Succeeded,
            expected.State.Confirmed, Healthy(Start, TimeSpan.Zero)));
        await Assert.That(staleRequest.Errors.Single().Code).IsEqualTo(AuthorityErrorCode.StaleObservation);
        await Assert.That(staleRequest.MutationPermit).IsNull();
    }

    [Test]
    public async Task IdenticalAuthorityInputHasEqualDigestAndCorruptReplayFailsClosed()
    {
        var command = Acquire("candidate-a", "deterministic");
        var first = AuthorityEngine.Decide([], command);
        var second = AuthorityEngine.Decide(Array.Empty<AuthorityEvent>(), command);
        await Assert.That(first.DecisionDigest).IsEqualTo(second.DecisionDigest);
        await Assert.That(first.EventsToAppend).IsEquivalentTo(second.EventsToAppend);
        await Assert.That(first.Intents).IsEquivalentTo(second.Intents);

        var requested = (AuthoritySetRequested)first.EventsToAppend.Single();
        var corruptBase = requested with { PreviousDigest = "corrupt", EventDigest = string.Empty };
        var corrupt = corruptBase with { EventDigest = AuthorityDigest.Event(corruptBase) };
        var replay = AuthorityEngine.Replay([corrupt]);
        await Assert.That(replay.Errors.Single().Code).IsEqualTo(AuthorityErrorCode.InvalidJournal);
    }

    [Test]
    public async Task RejectedCasObservationsAndReplayErrorCodesMustBeStructurallyExact()
    {
        var (history, pending) = BeginAcquisition("candidate-a", "conflict-a");
        var malformed = AuthorityEngine.Decide(history, new ObserveAuthorityCas(
            "regional-authority", "candidate-a", "conflict-a", AuthorityCasOutcome.Conflict,
            Baseline() with { KvRevision = -1 }, Healthy(Start, TimeSpan.Zero)));
        await Assert.That(malformed.Errors.Single().Code).IsEqualTo(AuthorityErrorCode.InvalidInput);
        await Assert.That(malformed.EventsToAppend).IsEmpty();

        var valid = AuthorityEngine.Decide(history, new ObserveAuthorityCas(
            "regional-authority", "candidate-a", "conflict-a", AuthorityCasOutcome.Conflict,
            Baseline(), Healthy(Start, TimeSpan.Zero)));
        var rejected = (AuthoritySetRejected)valid.EventsToAppend.Single();
        var mismatchedBase = rejected with
        {
            Error = new AuthorityError(AuthorityErrorCode.CasFailed, "INV-004", "wrong mapping"),
            EventDigest = string.Empty,
        };
        var mismatched = mismatchedBase with { EventDigest = AuthorityDigest.Event(mismatchedBase) };
        var replay = AuthorityEngine.Replay(history.Append(mismatched).ToArray());
        await Assert.That(replay.Errors.Single().Code).IsEqualTo(AuthorityErrorCode.InvalidJournal);
        await Assert.That(replay.MutationPermit).IsNull();
    }

    [Test]
    public async Task EpochRevisionAndServerExpiryOverflowProduceTypedHolds()
    {
        var epochOverflow = AuthorityEngine.Decide([], Acquire("candidate-a", "epoch-overflow") with
        {
            Baseline = Baseline() with { Epoch = long.MaxValue },
        });
        await AssertHeld(epochOverflow, AuthorityErrorCode.ArithmeticOverflow);
        var overflowHistory = epochOverflow.EventsToAppend.ToList();
        var cannotRegress = AuthorityEngine.Decide(overflowHistory, Acquire("candidate-a", "regress-after-overflow"));
        await Assert.That(cannotRegress.Errors.Single().Code).IsEqualTo(AuthorityErrorCode.EpochMismatch);
        await Assert.That(cannotRegress.Intents).IsEmpty();

        var revisionOverflow = AuthorityEngine.Decide([], Acquire("candidate-a", "revision-overflow") with
        {
            Baseline = Baseline() with { KvRevision = long.MaxValue },
        });
        await AssertHeld(revisionOverflow, AuthorityErrorCode.ArithmeticOverflow);
        var revisionHistory = revisionOverflow.EventsToAppend.ToList();
        var cannotRegressRevision = AuthorityEngine.Decide(revisionHistory,
            Acquire("candidate-a", "regress-revision"));
        await Assert.That(cannotRegressRevision.Errors.Single().Code).IsEqualTo(AuthorityErrorCode.RevisionMismatch);
        await Assert.That(cannotRegressRevision.Intents).IsEmpty();

        var timeOverflow = AuthorityEngine.Decide([], Acquire("candidate-a", "time-overflow") with
        {
            Health = Healthy(DateTimeOffset.MaxValue.AddTicks(-1), TimeSpan.Zero),
            LeaseDuration = TimeSpan.FromTicks(2),
        });
        await AssertHeld(timeOverflow, AuthorityErrorCode.ArithmeticOverflow);
    }

    private static AcquireAuthority Acquire(string candidate, string request, AuthorityObservation? baseline = null) => new(
        "regional-authority", candidate, request, $"lease-{candidate}", baseline ?? Baseline(),
        Healthy(Start, TimeSpan.FromMinutes(10)), Duration);

    private static AuthorityObservation Baseline() => new(
        "regional-authority", 10, 5, "baseline",
        new AuthorityLease("old-candidate", "old-lease", Start.AddMinutes(-10), TimeSpan.FromMinutes(5)));

    private static AuthorityHealth Healthy(DateTimeOffset time, TimeSpan elapsed) => new(time, elapsed, true, true);

    private static (List<AuthorityEvent> History, AuthorityDecision Pending) BeginAcquisition(
        string candidate, string request, AuthorityObservation? baseline = null)
    {
        var pending = AuthorityEngine.Decide([], Acquire(candidate, request, baseline));
        return (pending.EventsToAppend.ToList(), pending);
    }

    private static AuthorityDecision ConfirmSet(
        IReadOnlyList<AuthorityEvent> history, AuthorityDecision pending, string candidate, string request)
    {
        var intent = (CompareAndSetLeaseIntent)pending.Intents.Single();
        return AuthorityEngine.Decide(history, new ObserveAuthorityCas(
            "regional-authority", candidate, request, AuthorityCasOutcome.Succeeded,
            new AuthorityObservation("regional-authority", intent.ExpectedRevision + 1,
                intent.ProposedEpoch, $"confirmed-{request}", intent.ProposedLease),
            Healthy(intent.ProposedLease.ServerIssuedAt, TimeSpan.Zero)));
    }

    private static List<AuthorityEvent> BuildLeader()
    {
        var (history, pending) = BeginAcquisition("candidate-a", "acquire-a");
        history.AddRange(ConfirmSet(history, pending, "candidate-a", "acquire-a").EventsToAppend);
        return history;
    }

    private static async Task AppendAndReplay(List<AuthorityEvent> history, AuthorityDecision decision)
    {
        await Assert.That(decision.Errors).IsEmpty();
        history.AddRange(decision.EventsToAppend);
        var restored = AuthorityEngine.Replay(history);
        await Assert.That(restored.Errors).IsEmpty();
        await Assert.That(AuthorityDigest.State(restored.State)).IsEqualTo(AuthorityDigest.State(decision.State));
    }

    private static async Task AssertHeld(AuthorityDecision decision, AuthorityErrorCode code)
    {
        await Assert.That(decision.State.Status).IsEqualTo(AuthorityStatus.ReadOnlyHeld);
        await Assert.That(decision.Errors.Single().Code).IsEqualTo(code);
        await Assert.That(decision.Intents).IsEmpty();
        await Assert.That(decision.MutationPermit).IsNull();
    }
}
