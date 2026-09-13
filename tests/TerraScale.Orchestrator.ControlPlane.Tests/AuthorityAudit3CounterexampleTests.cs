using TerraScale.Orchestrator.ControlPlane.Authority;
using System.Globalization;
using System.Reflection;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class AuthorityAudit3CounterexampleTests
{
    private static readonly DateTimeOffset Start = new(2026, 7, 13, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Accepted_read_intent_binds_candidate_resume_authority_and_known_truth()
    {
        var leaderHistory = BuildLeader();
        var leaderRead = AuthorityEngine.Decide(leaderHistory,
            new RequestAuthorityRead("regional-authority", "candidate-a", "shared-read"));
        var followerRead = AuthorityEngine.Decide([],
            new RequestAuthorityRead("regional-authority", "candidate-a", "shared-read"));
        var otherCandidateRead = AuthorityEngine.Decide([],
            new RequestAuthorityRead("regional-authority", "candidate-b", "shared-read"));

        var leaderIntent = (ReadAuthorityIntent)leaderRead.Intents.Single();
        var followerIntent = (ReadAuthorityIntent)followerRead.Intents.Single();
        var otherCandidateIntent = (ReadAuthorityIntent)otherCandidateRead.Intents.Single();

        await Assert.That(leaderIntent).IsNotEqualTo(followerIntent);
        await Assert.That(followerIntent).IsNotEqualTo(otherCandidateIntent);
    }

    [Test]
    public async Task Every_accepted_read_posture_retains_exact_execution_coordinates()
    {
        var follower = AuthorityEngine.Decide([], Read("candidate-a", "follower"));
        await AssertIntent(follower, "candidate-a", AuthorityStatus.Follower, 0, 0, null);

        var leaderHistory = BuildLeader();
        var leaderState = AuthorityEngine.Replay(leaderHistory).State;
        var leader = AuthorityEngine.Decide(leaderHistory, Read("candidate-a", "leader"));
        await AssertIntent(leader, "candidate-a", AuthorityStatus.Leader,
            leaderState.HighestEpoch, leaderState.HighestKvRevision, leaderState.Confirmed);

        var heldFollowerHistory = BuildHeldFollower();
        var heldFollowerState = AuthorityEngine.Replay(heldFollowerHistory).State;
        var heldFollower = AuthorityEngine.Decide(heldFollowerHistory, Read("candidate-a", "held-follower"));
        await AssertIntent(heldFollower, "candidate-a", AuthorityStatus.ReadOnlyHeld,
            heldFollowerState.HighestEpoch, heldFollowerState.HighestKvRevision, null);

        var partition = AuthorityEngine.Decide(leaderHistory, new EvaluateMutationAuthority(
            "regional-authority", "candidate-a", "partition", leaderState.Confirmed!,
            new AuthorityHealth(Start.AddMinutes(1), TimeSpan.FromMinutes(1), false, true)));
        var heldLeaderHistory = leaderHistory.Concat(partition.EventsToAppend).ToList();
        var heldLeaderState = AuthorityEngine.Replay(heldLeaderHistory).State;
        var heldLeader = AuthorityEngine.Decide(heldLeaderHistory, Read("candidate-a", "held-leader"));
        await AssertIntent(heldLeader, "candidate-a", AuthorityStatus.Leader,
            heldLeaderState.HighestEpoch, heldLeaderState.HighestKvRevision, heldLeaderState.Confirmed);

        await Assert.That(follower.MutationPermit).IsNull();
        await Assert.That(leader.MutationPermit).IsNull();
        await Assert.That(heldFollower.MutationPermit).IsNull();
        await Assert.That(heldLeader.MutationPermit).IsNull();
    }

    [Test]
    public async Task Every_provenance_field_independently_changes_value_and_decision_digest()
    {
        var observation = new AuthorityObservation("regional-authority", 11, 6, "confirmed",
            new AuthorityLease("candidate-a", "lease-a", Start, TimeSpan.FromMinutes(10)));
        var state = AuthorityState.Empty with
        {
            AuthorityId = "regional-authority", CandidateId = "candidate-a", Status = AuthorityStatus.Leader,
            HighestEpoch = 6, HighestKvRevision = 11, Confirmed = observation,
        };
        var request = Read("candidate-a", "read");
        var baseline = CreateIntent(request, state, AuthorityStatus.Leader);
        var variants = new[]
        {
            CreateIntent(request with { CandidateId = "candidate-b" }, state, AuthorityStatus.Leader),
            CreateIntent(request, state, AuthorityStatus.Follower),
            CreateIntent(request, state with { HighestEpoch = 7 }, AuthorityStatus.Leader),
            CreateIntent(request, state with { HighestKvRevision = 12 }, AuthorityStatus.Leader),
            CreateIntent(request, state with { Confirmed = observation with { ObservationId = "other" } }, AuthorityStatus.Leader),
        };
        var baselineDigest = IntentDigest(state, baseline);

        foreach (var variant in variants)
        {
            await Assert.That(variant).IsNotEqualTo(baseline);
            await Assert.That(IntentDigest(state, variant)).IsNotEqualTo(baselineDigest);
        }
    }

    [Test]
    public async Task Read_intent_replay_and_digest_are_culture_stable()
    {
        var history = BuildLeader();
        ReadAuthorityIntent? expectedIntent = null;
        string? expectedDigest = null;
        foreach (var culture in new[] { "en-US", "tr-TR", "ar-SA", "ja-JP" })
        {
            var previous = CultureInfo.CurrentCulture;
            var previousUi = CultureInfo.CurrentUICulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
                CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(culture);
                var decision = AuthorityEngine.Decide(history, Read("candidate-a", "culture-read"));
                var intent = (ReadAuthorityIntent)decision.Intents.Single();
                expectedIntent ??= intent;
                expectedDigest ??= decision.DecisionDigest;
                await Assert.That(intent).IsEqualTo(expectedIntent);
                await Assert.That(decision.DecisionDigest).IsEqualTo(expectedDigest);
            }
            finally
            {
                CultureInfo.CurrentCulture = previous;
                CultureInfo.CurrentUICulture = previousUi;
            }
        }
    }

    [Test]
    public async Task Read_intent_construction_is_closed_with_only_immutable_record_copy()
    {
        var decision = AuthorityEngine.Decide([], Read("candidate-a", "closed"));
        var intent = (ReadAuthorityIntent)decision.Intents.Single();
        var type = typeof(ReadAuthorityIntent);
        await Assert.That(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(static property => property.SetMethod?.IsPublic == true)).IsEmpty();
        await Assert.That(type.GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(static method => method.Name == "Deconstruct")).IsEmpty();
        var returning = type.Assembly.GetExportedTypes()
            .SelectMany(static exported => exported.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(method => !method.IsSpecialName && method.ReturnType == type).ToArray();
        await Assert.That(returning.Select(static method => method.Name)).IsEquivalentTo(["<Clone>$"]);
        var clone = (ReadAuthorityIntent)returning.Single().Invoke(intent, null)!;
        await Assert.That(clone).IsEqualTo(intent);
        await Assert.That(ReferenceEquals(clone, intent)).IsFalse();
    }

    private static List<AuthorityEvent> BuildLeader()
    {
        var baseline = new AuthorityObservation("regional-authority", 10, 5, "baseline",
            new AuthorityLease("old-candidate", "old-lease", Start.AddMinutes(-10), TimeSpan.FromMinutes(5)));
        var health = new AuthorityHealth(Start, TimeSpan.FromMinutes(10), true, true);
        var pending = AuthorityEngine.Decide([], new AcquireAuthority(
            "regional-authority", "candidate-a", "acquire-a", "lease-a", baseline, health, TimeSpan.FromMinutes(10)));
        var history = pending.EventsToAppend.ToList();
        var intent = (CompareAndSetLeaseIntent)pending.Intents.Single();
        var confirmed = AuthorityEngine.Decide(history, new ObserveAuthorityCas(
            "regional-authority", "candidate-a", "acquire-a", AuthorityCasOutcome.Succeeded,
            new AuthorityObservation("regional-authority", 11, 6, "confirmed", intent.ProposedLease),
            new AuthorityHealth(Start, TimeSpan.Zero, true, true)));
        history.AddRange(confirmed.EventsToAppend);
        return history;
    }

    private static List<AuthorityEvent> BuildHeldFollower()
    {
        var baseline = new AuthorityObservation("regional-authority", 10, 5, "baseline", null);
        var held = AuthorityEngine.Decide([], new AcquireAuthority(
            "regional-authority", "candidate-a", "held", "lease-a", baseline,
            new AuthorityHealth(Start, TimeSpan.Zero, false, true), TimeSpan.FromMinutes(10)));
        return held.EventsToAppend.ToList();
    }

    private static RequestAuthorityRead Read(string candidate, string request) =>
        new("regional-authority", candidate, request);

    private static async Task AssertIntent(AuthorityDecision decision, string candidate, AuthorityStatus resume,
        long epoch, long revision, AuthorityObservation? confirmed)
    {
        await Assert.That(decision.Errors).IsEmpty();
        var intent = (ReadAuthorityIntent)decision.Intents.Single();
        await Assert.That(intent.AuthorityId).IsEqualTo("regional-authority");
        await Assert.That(intent.CandidateId).IsEqualTo(candidate);
        await Assert.That(intent.ResumeStatus).IsEqualTo(resume);
        await Assert.That(intent.ExpectedHighestEpoch).IsEqualTo(epoch);
        await Assert.That(intent.ExpectedHighestKvRevision).IsEqualTo(revision);
        await Assert.That(intent.ExpectedConfirmedObservation).IsEqualTo(confirmed);
        await Assert.That(ReferenceEquals(intent.ExpectedConfirmedObservation, confirmed)).IsTrue();
    }

    private static ReadAuthorityIntent CreateIntent(
        RequestAuthorityRead request, AuthorityState state, AuthorityStatus resume)
    {
        var constructor = typeof(ReadAuthorityIntent).GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance)
            .Single(static candidate => candidate.GetParameters().Length == 3);
        return (ReadAuthorityIntent)constructor.Invoke([request, state, resume]);
    }

    private static string IntentDigest(AuthorityState state, ReadAuthorityIntent intent) =>
        AuthorityDigest.Decision(state, [], [intent], [], null);
}

