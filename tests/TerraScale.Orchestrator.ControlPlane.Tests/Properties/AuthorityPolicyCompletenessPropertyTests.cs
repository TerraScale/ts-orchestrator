using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Authority;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class AuthorityPolicyCompletenessPropertyTests
{
    private const int Cases = 1_000;
    private static readonly DateTimeOffset Start = new(2026, 7, 13, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task ReplayRejectsEveryAuthorityHighWaterRegressionBeforeItCanMintAuthority()
    {
        for (var index = 0; index < Cases; index++)
        {
            var highRevision = 10_000L + index;
            var highEpoch = 20_000L + index;
            var (history, held) = BuildHeld(index, highRevision, highEpoch);
            var expectedRevision = index % 3 is 1 or 2 ? highRevision - 1 : highRevision;
            var expectedEpoch = index % 3 is 0 or 2 ? highEpoch - 1 : highEpoch;
            var proposedEpoch = checked(expectedEpoch + 1);
            var lease = Lease(Candidate(index), $"regressed-{index}", Start.AddMinutes(1));
            var pending = new PendingAuthoritySet(
                $"regressed-{index}", expectedRevision, expectedEpoch, proposedEpoch, lease,
                Observation(expectedRevision, expectedEpoch, $"regressed-{index}"),
                Healthy(Start.AddMinutes(1)), false);
            history.Add(Stamp(history, (sequence, previous, digest) => new AuthoritySetRequested(
                sequence, previous, digest, AuthorityId, Candidate(index), pending.RequestId, pending)));
            var regressed = new AuthorityObservation(
                AuthorityId, checked(expectedRevision + 1), proposedEpoch, $"confirmed-regressed-{index}", lease);
            history.Add(Stamp(history, (sequence, previous, digest) => new AuthoritySetConfirmed(
                sequence, previous, digest, AuthorityId, Candidate(index), pending.RequestId,
                regressed, Healthy(Start.AddMinutes(1)), false)));

            var replay = AuthorityEngine.Replay(history);
            await AssertHighWaterRejection(replay, held);
            var evaluate = AuthorityEngine.Decide(history, new EvaluateMutationAuthority(
                AuthorityId, Candidate(index), $"evaluate-{index}", regressed,
                Healthy(Start.AddMinutes(2), TimeSpan.FromMinutes(1))));
            await AssertHighWaterRejection(evaluate, held);
        }
    }

    [Test]
    public async Task ReplayAcceptsExactEqualityAndIndependentMonotonicAdvancement()
    {
        for (var index = 0; index < Cases; index++)
        {
            var highRevision = 30_000L + index;
            var highEpoch = 40_000L + index;
            var (baseHistory, _) = BuildHeld(index, highRevision, highEpoch);
            var expectedRevision = index % 3 == 1 ? highRevision + 1 : highRevision;
            var expectedEpoch = index % 3 == 2 ? highEpoch + 1 : highEpoch;
            var lease = Lease(Candidate(index), $"monotonic-{index}", Start.AddMinutes(1));
            var pending = new PendingAuthoritySet(
                $"monotonic-{index}", expectedRevision, expectedEpoch, checked(expectedEpoch + 1), lease,
                Observation(expectedRevision, expectedEpoch, $"monotonic-{index}"),
                Healthy(Start.AddMinutes(1)), false);
            var history = baseHistory.ToList();
            history.Add(Stamp(history, (sequence, previous, digest) => new AuthoritySetRequested(
                sequence, previous, digest, AuthorityId, Candidate(index), pending.RequestId, pending)));
            var confirmed = new AuthorityObservation(
                AuthorityId, checked(expectedRevision + 1), pending.ProposedEpoch,
                $"confirmed-monotonic-{index}", lease);
            history.Add(Stamp(history, (sequence, previous, digest) => new AuthoritySetConfirmed(
                sequence, previous, digest, AuthorityId, Candidate(index), pending.RequestId,
                confirmed, Healthy(Start.AddMinutes(1)), false)));

            var replay = AuthorityEngine.Replay(history);
            await Assert.That(replay.Errors).IsEmpty();
            await Assert.That(replay.State.Status).IsEqualTo(AuthorityStatus.Leader);
            await Assert.That(replay.State.Confirmed).IsEqualTo(confirmed);
            var permit = AuthorityEngine.Decide(history, new EvaluateMutationAuthority(
                AuthorityId, Candidate(index), $"evaluate-monotonic-{index}", confirmed,
                Healthy(Start.AddMinutes(2), TimeSpan.FromMinutes(1))));
            await Assert.That(permit.Errors).IsEmpty();
            await Assert.That(permit.MutationPermit).IsNotNull();
            await Assert.That(permit.MutationPermit!.Epoch).IsEqualTo(pending.ProposedEpoch);
            await Assert.That(permit.MutationPermit.KvRevision).IsEqualTo(expectedRevision + 1);
        }
    }

    [Test]
    public async Task ReplayRegressionPreservesStructuralAndLeasePrecedence()
    {
        var (history, held) = BuildHeld(7, 100, 200);
        var malformed = new PendingAuthoritySet(
            "malformed", 99, 199, 0, Lease(Candidate(7), "malformed", Start.AddMinutes(1)),
            Observation(99, 199, "malformed"), Healthy(Start.AddMinutes(1)), false);
        var malformedHistory = history.ToList();
        malformedHistory.Add(Stamp(malformedHistory, (sequence, previous, digest) => new AuthoritySetRequested(
            sequence, previous, digest, AuthorityId, Candidate(7), "malformed", malformed)));
        var malformedReplay = AuthorityEngine.Replay(malformedHistory);
        await AssertReplayError(
            malformedReplay, held, AuthorityErrorCode.InvalidJournal, "INV-005", "Pending CAS set is malformed.");

        var activeLease = Lease("active-candidate", "active", Start.AddMinutes(1));
        var regressed = new PendingAuthoritySet(
            "active-regression", 99, 199, 200, Lease(Candidate(7), "proposal", Start.AddMinutes(1)),
            new AuthorityObservation(AuthorityId, 99, 199, "active-regression", activeLease),
            Healthy(Start.AddMinutes(1)), false);
        var regressedHistory = history.ToList();
        regressedHistory.Add(Stamp(regressedHistory, (sequence, previous, digest) => new AuthoritySetRequested(
            sequence, previous, digest, AuthorityId, Candidate(7), "active-regression", regressed)));
        await AssertHighWaterRejection(AuthorityEngine.Replay(regressedHistory), held);
    }

    [Test]
    public async Task CompletedRequestIdsNeverInitiateAnotherAdmissibleActionButFreshIdsRemainExact()
    {
        for (var index = 0; index < Cases; index++)
        {
            var (leaderHistory, confirmed) = BuildLeader(index);
            var completedId = $"acquire-{index}";
            var renewHealth = Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1));

            await AssertStale(AuthorityEngine.Decide(leaderHistory, new RenewAuthority(
                AuthorityId, Candidate(index), completedId, confirmed, renewHealth, TimeSpan.FromMinutes(10))));
            await AssertStale(AuthorityEngine.Decide(leaderHistory, new ReleaseAuthority(
                AuthorityId, Candidate(index), completedId, confirmed, renewHealth)));
            await AssertStale(AuthorityEngine.Decide(leaderHistory, new RequestAuthorityRead(
                AuthorityId, Candidate(index), completedId)));

            var renew = AuthorityEngine.Decide(leaderHistory, new RenewAuthority(
                AuthorityId, Candidate(index), $"renew-{index}", confirmed, renewHealth, TimeSpan.FromMinutes(10)));
            var renewIntent = (CompareAndSetLeaseIntent)renew.Intents.Single();
            var renewEvent = (AuthoritySetRequested)renew.EventsToAppend.Single();
            var expectedRenewLease = new AuthorityLease(
                Candidate(index), confirmed.Lease!.LeaseId, renewHealth.ServerTime, TimeSpan.FromMinutes(10));
            await Assert.That(renewIntent.AuthorityId).IsEqualTo(AuthorityId);
            await Assert.That(renewIntent.RequestId).IsEqualTo($"renew-{index}");
            await Assert.That(renewIntent.ExpectedRevision).IsEqualTo(confirmed.KvRevision);
            await Assert.That(renewIntent.ExpectedEpoch).IsEqualTo(confirmed.Epoch);
            await Assert.That(renewIntent.ProposedEpoch).IsEqualTo(confirmed.Epoch);
            await Assert.That(renewIntent.ProposedLease).IsEqualTo(expectedRenewLease);
            await Assert.That(renewEvent.AuthorityId).IsEqualTo(AuthorityId);
            await Assert.That(renewEvent.CandidateId).IsEqualTo(Candidate(index));
            await Assert.That(renewEvent.RequestId).IsEqualTo($"renew-{index}");
            await Assert.That(renewEvent.Pending).IsEqualTo(new PendingAuthoritySet(
                $"renew-{index}", confirmed.KvRevision, confirmed.Epoch, confirmed.Epoch,
                expectedRenewLease, confirmed, renewHealth, true));

            var release = AuthorityEngine.Decide(leaderHistory, new ReleaseAuthority(
                AuthorityId, Candidate(index), $"release-{index}", confirmed, renewHealth));
            var deleteIntent = (CompareAndDeleteLeaseIntent)release.Intents.Single();
            await Assert.That(deleteIntent.AuthorityId).IsEqualTo(AuthorityId);
            await Assert.That(deleteIntent.RequestId).IsEqualTo($"release-{index}");
            await Assert.That(deleteIntent.ExpectedRevision).IsEqualTo(confirmed.KvRevision);
            await Assert.That(deleteIntent.ExpectedEpoch).IsEqualTo(confirmed.Epoch);
            await Assert.That(deleteIntent.ExpectedLease).IsEqualTo(confirmed.Lease);
            var releaseEvent = (AuthorityDeleteRequested)release.EventsToAppend.Single();
            await Assert.That(releaseEvent.AuthorityId).IsEqualTo(AuthorityId);
            await Assert.That(releaseEvent.CandidateId).IsEqualTo(Candidate(index));
            await Assert.That(releaseEvent.RequestId).IsEqualTo($"release-{index}");
            await Assert.That(releaseEvent.Pending).IsEqualTo(new PendingAuthorityDelete(
                $"release-{index}", confirmed.KvRevision, confirmed.Epoch, confirmed.Lease!, renewHealth));

            var read = AuthorityEngine.Decide(leaderHistory, new RequestAuthorityRead(
                AuthorityId, Candidate(index), $"read-{index}"));
            var readIntent = (ReadAuthorityIntent)read.Intents.Single();
            await Assert.That(readIntent.AuthorityId).IsEqualTo(AuthorityId);
            await Assert.That(readIntent.RequestId).IsEqualTo($"read-{index}");
            await Assert.That(readIntent.CandidateId).IsEqualTo(Candidate(index));
            await Assert.That(readIntent.ResumeStatus).IsEqualTo(AuthorityStatus.Leader);
            await Assert.That(readIntent.ExpectedHighestEpoch).IsEqualTo(confirmed.Epoch);
            await Assert.That(readIntent.ExpectedHighestKvRevision).IsEqualTo(confirmed.KvRevision);
            await Assert.That(readIntent.ExpectedConfirmedObservation).IsEqualTo(confirmed);
            await Assert.That(ReferenceEquals(readIntent.ExpectedConfirmedObservation, confirmed)).IsTrue();
            var readEvent = (AuthorityReadRequested)read.EventsToAppend.Single();
            await Assert.That(readEvent.AuthorityId).IsEqualTo(AuthorityId);
            await Assert.That(readEvent.CandidateId).IsEqualTo(Candidate(index));
            await Assert.That(readEvent.RequestId).IsEqualTo($"read-{index}");
            await Assert.That(readEvent.ResumeStatus).IsEqualTo(AuthorityStatus.Leader);

            var (heldHistory, held) = BuildHeld(index, 50_000L + index, 60_000L + index);
            var baseline = Observation(held.State.HighestKvRevision, held.State.HighestEpoch, $"fresh-{index}");
            await AssertStale(AuthorityEngine.Decide(heldHistory, new AcquireAuthority(
                AuthorityId, Candidate(index), held.State.LastCompletedRequestId!, $"reused-lease-{index}",
                baseline, Healthy(Start.AddMinutes(2)), TimeSpan.FromMinutes(10))));
            var acquire = AuthorityEngine.Decide(heldHistory, new AcquireAuthority(
                AuthorityId, Candidate(index), $"fresh-acquire-{index}", $"fresh-lease-{index}",
                baseline, Healthy(Start.AddMinutes(2)), TimeSpan.FromMinutes(10)));
            var setIntent = (CompareAndSetLeaseIntent)acquire.Intents.Single();
            await Assert.That(setIntent.AuthorityId).IsEqualTo(AuthorityId);
            await Assert.That(setIntent.RequestId).IsEqualTo($"fresh-acquire-{index}");
            await Assert.That(setIntent.ExpectedRevision).IsEqualTo(baseline.KvRevision);
            await Assert.That(setIntent.ExpectedEpoch).IsEqualTo(baseline.Epoch);
            await Assert.That(setIntent.ProposedEpoch).IsEqualTo(baseline.Epoch + 1);
            await Assert.That(setIntent.ProposedLease.CandidateId).IsEqualTo(Candidate(index));
            await Assert.That(setIntent.ProposedLease.LeaseId).IsEqualTo($"fresh-lease-{index}");
            await Assert.That(setIntent.ProposedLease.ServerIssuedAt).IsEqualTo(Start.AddMinutes(2));
            await Assert.That(setIntent.ProposedLease.Duration).IsEqualTo(TimeSpan.FromMinutes(10));
            var acquireEvent = (AuthoritySetRequested)acquire.EventsToAppend.Single();
            await Assert.That(acquireEvent.AuthorityId).IsEqualTo(AuthorityId);
            await Assert.That(acquireEvent.CandidateId).IsEqualTo(Candidate(index));
            await Assert.That(acquireEvent.RequestId).IsEqualTo($"fresh-acquire-{index}");
            await Assert.That(acquireEvent.Pending).IsEqualTo(new PendingAuthoritySet(
                $"fresh-acquire-{index}", baseline.KvRevision, baseline.Epoch, baseline.Epoch + 1,
                setIntent.ProposedLease, baseline, Healthy(Start.AddMinutes(2)), false));
        }
    }

    [Test]
    public async Task CompletedRequestPrecedenceIsStableAcrossStatusAndMalformedPayloads()
    {
        var (leaderHistory, confirmed) = BuildLeader(91);
        var completed = "acquire-91";
        var acquireFromLeader = AuthorityEngine.Decide(leaderHistory, new AcquireAuthority(
            AuthorityId, Candidate(91), completed, "lease", confirmed, Healthy(Start), TimeSpan.FromMinutes(1)));
        await Assert.That(acquireFromLeader.Errors.Single().Code).IsEqualTo(AuthorityErrorCode.InvalidTransition);
        await Assert.That(acquireFromLeader.Intents).IsEmpty();

        await AssertStale(AuthorityEngine.Decide(leaderHistory, new RenewAuthority(
            AuthorityId, Candidate(91), completed, null!, null!, TimeSpan.Zero)));
        await AssertStale(AuthorityEngine.Decide(leaderHistory, new ReleaseAuthority(
            AuthorityId, Candidate(91), completed, null!, null!)));

        var (heldHistory, held) = BuildHeld(92, 500, 600);
        await AssertStale(AuthorityEngine.Decide(heldHistory, new AcquireAuthority(
            AuthorityId, Candidate(92), held.State.LastCompletedRequestId!, string.Empty,
            null!, null!, TimeSpan.Zero)));
    }

    [Test]
    public async Task AuthorityVocabularyAndNewDecisionsRemainCultureDeterministic()
    {
        await Assert.That(Enum.GetValues<AuthorityStatus>()).IsEquivalentTo(new[]
        {
            AuthorityStatus.Follower, AuthorityStatus.AcquisitionPending, AuthorityStatus.Leader,
            AuthorityStatus.RenewalPending, AuthorityStatus.ReleasePending, AuthorityStatus.ReadOnlyHeld,
            AuthorityStatus.Fenced,
        });
        await Assert.That(Enum.GetValues<AuthorityCasOutcome>()).IsEquivalentTo(new[]
        {
            AuthorityCasOutcome.Succeeded, AuthorityCasOutcome.Conflict,
            AuthorityCasOutcome.Failed, AuthorityCasOutcome.Uncertain,
        });
        await Assert.That(Enum.GetValues<AuthorityErrorCode>()).IsEquivalentTo(new[]
        {
            AuthorityErrorCode.InvalidInput, AuthorityErrorCode.InvalidJournal,
            AuthorityErrorCode.ConflictingJournalEvent, AuthorityErrorCode.InvalidTransition,
            AuthorityErrorCode.IdentityMismatch, AuthorityErrorCode.RevisionMismatch,
            AuthorityErrorCode.EpochMismatch, AuthorityErrorCode.StaleObservation,
            AuthorityErrorCode.LeaseActive, AuthorityErrorCode.LeaseExpired,
            AuthorityErrorCode.PartitionUncertain, AuthorityErrorCode.ClockAnomaly,
            AuthorityErrorCode.CasConflict, AuthorityErrorCode.CasFailed,
            AuthorityErrorCode.CasUncertain, AuthorityErrorCode.ArithmeticOverflow,
            AuthorityErrorCode.Fenced,
        });
        await Assert.That(typeof(AuthorityCommand).Assembly.GetTypes()
            .Where(type => type.BaseType == typeof(AuthorityCommand)).Select(type => type.Name)
            .Order(StringComparer.Ordinal).ToArray()).IsEquivalentTo(new[]
        {
            nameof(AcquireAuthority), nameof(EvaluateMutationAuthority), nameof(ObserveAuthorityCas),
            nameof(ObserveAuthorityDelete), nameof(ObserveAuthorityRead), nameof(ReleaseAuthority),
            nameof(RenewAuthority), nameof(RequestAuthorityRead),
        });
        await Assert.That(typeof(AuthorityEvent).Assembly.GetTypes()
            .Where(type => type.BaseType == typeof(AuthorityEvent)).Select(type => type.Name)
            .Order(StringComparer.Ordinal).ToArray()).IsEquivalentTo(new[]
        {
            nameof(AuthorityDeleteConfirmed), nameof(AuthorityDeleteRequested), nameof(AuthorityFencedEvent),
            nameof(AuthorityHeld), nameof(AuthorityReadConfirmed), nameof(AuthorityReadRequested),
            nameof(AuthoritySetConfirmed), nameof(AuthoritySetRejected), nameof(AuthoritySetRequested),
        });
        await Assert.That(typeof(AuthorityIntent).Assembly.GetTypes()
            .Where(type => type.BaseType == typeof(AuthorityIntent)).Select(type => type.Name)
            .Order(StringComparer.Ordinal).ToArray()).IsEquivalentTo(new[]
        {
            nameof(CompareAndDeleteLeaseIntent), nameof(CompareAndSetLeaseIntent), nameof(ReadAuthorityIntent),
        });

        string? expected = null;
        foreach (var cultureName in new[] { "en-US", "tr-TR", "ar-SA", "ja-JP" })
        {
            var actual = UnderCulture(cultureName, static () =>
            {
                var (history, held) = BuildHeld(404, 900, 800);
                return AuthorityEngine.Decide(history, new AcquireAuthority(
                    AuthorityId, Candidate(404), held.State.LastCompletedRequestId!, "lease",
                    Observation(900, 800, "culture"), Healthy(Start), TimeSpan.FromMinutes(1))).DecisionDigest;
            });
            expected ??= actual;
            await Assert.That(actual).IsEqualTo(expected);
        }
    }

    private static async Task AssertHighWaterRejection(AuthorityDecision actual, AuthorityDecision prior) =>
        await AssertReplayError(actual, prior, AuthorityErrorCode.InvalidJournal, "INV-004",
            "Acquisition baseline regresses persisted authority high-water.");

    private static async Task AssertReplayError(
        AuthorityDecision actual, AuthorityDecision prior, AuthorityErrorCode code, string requirement, string message)
    {
        await Assert.That(actual.Errors).HasSingleItem();
        await Assert.That(actual.Errors.Single()).IsEqualTo(new AuthorityError(code, requirement, message));
        await Assert.That(actual.EventsToAppend).IsEmpty();
        await Assert.That(actual.Intents).IsEmpty();
        await Assert.That(actual.MutationPermit).IsNull();
        await Assert.That(actual.State.LastSequence).IsEqualTo(prior.State.LastSequence);
        await Assert.That(AuthorityDigest.State(actual.State)).IsEqualTo(AuthorityDigest.State(prior.State));
    }

    private static async Task AssertStale(AuthorityDecision actual)
    {
        await Assert.That(actual.Errors).HasSingleItem();
        await Assert.That(actual.Errors.Single()).IsEqualTo(new AuthorityError(
            AuthorityErrorCode.StaleObservation, "INV-005",
            "A completed request identity cannot initiate another authority action."));
        await Assert.That(actual.EventsToAppend).IsEmpty();
        await Assert.That(actual.Intents).IsEmpty();
        await Assert.That(actual.MutationPermit).IsNull();
    }

    private static (List<AuthorityEvent> History, AuthorityDecision Held) BuildHeld(
        int index, long highRevision, long highEpoch)
    {
        var baseline = Observation(highRevision - 2, highEpoch - 2, $"baseline-{index}");
        var acquisition = AuthorityEngine.Decide([], new AcquireAuthority(
            AuthorityId, Candidate(index), $"conflict-{index}", $"lease-{index}", baseline,
            Healthy(Start), TimeSpan.FromMinutes(10)));
        var winner = new AuthorityObservation(
            AuthorityId, highRevision, highEpoch, $"winner-{index}",
            Lease($"winner-{index}", $"winner-{index}", Start));
        var held = AuthorityEngine.Decide(acquisition.EventsToAppend, new ObserveAuthorityCas(
            AuthorityId, Candidate(index), $"conflict-{index}", AuthorityCasOutcome.Conflict,
            winner, Healthy(Start)));
        return (acquisition.EventsToAppend.Concat(held.EventsToAppend).ToList(), held);
    }

    private static (List<AuthorityEvent> History, AuthorityObservation Confirmed) BuildLeader(int index)
    {
        var baseline = Observation(1_000L + index, 2_000L + index, $"baseline-leader-{index}");
        var acquire = AuthorityEngine.Decide([], new AcquireAuthority(
            AuthorityId, Candidate(index), $"acquire-{index}", $"lease-{index}", baseline,
            Healthy(Start), TimeSpan.FromMinutes(10)));
        var intent = (CompareAndSetLeaseIntent)acquire.Intents.Single();
        var confirmed = new AuthorityObservation(
            AuthorityId, baseline.KvRevision + 1, intent.ProposedEpoch, $"confirmed-{index}", intent.ProposedLease);
        var result = AuthorityEngine.Decide(acquire.EventsToAppend, new ObserveAuthorityCas(
            AuthorityId, Candidate(index), $"acquire-{index}", AuthorityCasOutcome.Succeeded,
            confirmed, Healthy(Start)));
        return (acquire.EventsToAppend.Concat(result.EventsToAppend).ToList(), confirmed);
    }

    private static AuthorityObservation Observation(long revision, long epoch, string id) =>
        new(AuthorityId, revision, epoch, id, null);

    private static AuthorityLease Lease(string candidateId, string leaseId, DateTimeOffset issued) =>
        new(candidateId, leaseId, issued, TimeSpan.FromMinutes(10));

    private static AuthorityHealth Healthy(DateTimeOffset time, TimeSpan elapsed = default) =>
        new(time, elapsed, true, true);

    private static string Candidate(int index) => $"candidate-{index}";
    private const string AuthorityId = "regional-authority";

    private static T Stamp<T>(IReadOnlyList<AuthorityEvent> history, Func<long, string, string, T> factory)
        where T : AuthorityEvent
    {
        var previous = history.Count == 0 ? AuthorityDigest.EmptyJournalDigest : history[^1].EventDigest;
        var provisional = factory(history.Count + 1L, previous, string.Empty);
        return factory(provisional.Sequence, provisional.PreviousDigest, AuthorityDigest.Event(provisional));
    }

    private static T UnderCulture<T>(string name, Func<T> action)
    {
        var previous = CultureInfo.CurrentCulture;
        var previousUi = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(name);
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(name);
            return action();
        }
        finally
        {
            CultureInfo.CurrentCulture = previous;
            CultureInfo.CurrentUICulture = previousUi;
        }
    }
}

