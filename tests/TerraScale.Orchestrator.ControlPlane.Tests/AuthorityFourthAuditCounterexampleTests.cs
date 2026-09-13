using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Authority;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class AuthorityFourthAuditCounterexampleTests
{
    private static readonly DateTimeOffset Start = new(2026, 7, 14, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Mutation_permit_and_decision_digest_must_bind_the_evaluation_request()
    {
        var history = BuildLeader();
        var state = AuthorityEngine.Replay(history).State;
        var health = new AuthorityHealth(Start.AddMinutes(1), TimeSpan.FromMinutes(1), true, true);
        var first = AuthorityEngine.Decide(history, new EvaluateMutationAuthority(
            "regional-authority", "candidate-a", "mutation-request-a", state.Confirmed!, health));
        var second = AuthorityEngine.Decide(history, new EvaluateMutationAuthority(
            "regional-authority", "candidate-a", "mutation-request-b", state.Confirmed!, health));

        await Assert.That(first.Errors).IsEmpty();
        await Assert.That(second.Errors).IsEmpty();
        await Assert.That(first.MutationPermit).IsNotNull();
        await Assert.That(second.MutationPermit).IsNotNull();
        await Assert.That(first.MutationPermit).IsNotEqualTo(second.MutationPermit);
        await Assert.That(first.DecisionDigest).IsNotEqualTo(second.DecisionDigest);
    }

    [Test]
    public async Task Mutation_permit_must_bind_the_semantic_command_that_authorized_it()
    {
        var history = BuildLeader();
        var leader = AuthorityEngine.Replay(history).State;
        var health = new AuthorityHealth(Start.AddMinutes(1), TimeSpan.FromMinutes(1), true, true);
        const string requestId = "shared-mutation-request";
        var evaluated = AuthorityEngine.Decide(history, new EvaluateMutationAuthority(
            "regional-authority", "candidate-a", requestId, leader.Confirmed!, health));

        var readRequested = AuthorityEngine.Decide(history, new RequestAuthorityRead(
            "regional-authority", "candidate-a", requestId));
        history.AddRange(readRequested.EventsToAppend);
        var observed = AuthorityEngine.Decide(history, new ObserveAuthorityRead(
            "regional-authority", "candidate-a", requestId, AuthorityCasOutcome.Succeeded,
            leader.Confirmed, health));

        await Assert.That(evaluated.Errors).IsEmpty();
        await Assert.That(observed.Errors).IsEmpty();
        await Assert.That(evaluated.MutationPermit).IsNotNull();
        await Assert.That(observed.MutationPermit).IsNotNull();
        await Assert.That(evaluated.MutationPermit).IsNotEqualTo(observed.MutationPermit);
    }

    [Test]
    public async Task All_permit_minting_routes_retain_the_exact_accepted_command()
    {
        var (history, casCommand, casDecision) = BuildLeaderDecision();
        await AssertPermit(casDecision, casCommand);

        var leader = AuthorityEngine.Replay(history).State;
        var health = Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1));
        var evaluationCommand = new EvaluateMutationAuthority(
            "regional-authority", "candidate-a", "evaluate", leader.Confirmed!, health);
        await AssertPermit(AuthorityEngine.Decide(history, evaluationCommand), evaluationCommand);

        var readRequest = AuthorityEngine.Decide(history, new RequestAuthorityRead(
            "regional-authority", "candidate-a", "read"));
        history.AddRange(readRequest.EventsToAppend);
        var readCommand = new ObserveAuthorityRead("regional-authority", "candidate-a", "read",
            AuthorityCasOutcome.Succeeded, leader.Confirmed, health);
        await AssertPermit(AuthorityEngine.Decide(history, readCommand), readCommand);
    }

    [Test]
    public async Task Rejected_held_and_invalid_command_shapes_never_mint_a_permit()
    {
        var (history, _, _) = BuildLeaderDecision();
        var leader = AuthorityEngine.Replay(history).State;
        var uncertain = new AuthorityHealth(Start.AddMinutes(1), TimeSpan.FromMinutes(1), false, true);
        var held = AuthorityEngine.Decide(history, new EvaluateMutationAuthority(
            "regional-authority", "candidate-a", "held", leader.Confirmed!, uncertain));
        await Assert.That(held.MutationPermit).IsNull();

        var pending = PendingAcquisition();
        var rejectedCas = AuthorityEngine.Decide(pending.History, new ObserveAuthorityCas(
            "regional-authority", "candidate-a", "acquire-a", AuthorityCasOutcome.Conflict, null,
            Healthy(Start, TimeSpan.Zero)));
        await Assert.That(rejectedCas.MutationPermit).IsNull();

        var readRequest = AuthorityEngine.Decide(history, new RequestAuthorityRead(
            "regional-authority", "candidate-a", "rejected-read"));
        history.AddRange(readRequest.EventsToAppend);
        var rejectedRead = AuthorityEngine.Decide(history, new ObserveAuthorityRead(
            "regional-authority", "candidate-a", "rejected-read", AuthorityCasOutcome.Failed, null,
            Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1))));
        await Assert.That(rejectedRead.MutationPermit).IsNull();

        var observation = leader.Confirmed!;
        var health = Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1));
        await Assert.That(Capture(() => CreatePermit(new AcquireAuthority(
            "regional-authority", "candidate-a", "wrong-type", "lease", observation, health,
            TimeSpan.FromMinutes(1))))).IsTypeOf<ArgumentException>();
        await Assert.That(Capture(() => CreatePermit(new ObserveAuthorityCas(
            "regional-authority", "candidate-a", "bad-outcome", AuthorityCasOutcome.Conflict,
            observation, health)))).IsTypeOf<ArgumentException>();
        await Assert.That(Capture(() => CreatePermit(new ObserveAuthorityCas(
            "regional-authority", "candidate-a", "null-observation", AuthorityCasOutcome.Succeeded,
            null, health)))).IsTypeOf<ArgumentException>();
        await Assert.That(Capture(() => CreatePermit(new EvaluateMutationAuthority(
            "regional-authority", "candidate-a", "null-lease", observation with { Lease = null },
            health)))).IsTypeOf<ArgumentException>();
    }

    [Test]
    public async Task Permit_digest_is_sensitive_to_every_authorizing_command_field_and_type()
    {
        var lease = new AuthorityLease("candidate-a", "lease-a", Start, TimeSpan.FromMinutes(10));
        var observation = new AuthorityObservation("regional-authority", 11, 6, "confirmed", lease);
        var health = Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1));
        var baseline = new EvaluateMutationAuthority(
            "regional-authority", "candidate-a", "request", observation, health);
        var expected = PermitDigest(baseline);
        AuthorityCommand[] mutations =
        [
            baseline with { AuthorityId = "regional-authority-b" },
            baseline with { CandidateId = "candidate-b" },
            baseline with { RequestId = "request-b" },
            baseline with { Observation = observation with { AuthorityId = "observation-authority-b" } },
            baseline with { Observation = observation with { KvRevision = 12 } },
            baseline with { Observation = observation with { Epoch = 7 } },
            baseline with { Observation = observation with { ObservationId = "confirmed-b" } },
            baseline with { Observation = observation with { Lease = lease with { CandidateId = "candidate-b" } } },
            baseline with { Observation = observation with { Lease = lease with { LeaseId = "lease-b" } } },
            baseline with { Observation = observation with { Lease = lease with { ServerIssuedAt = Start.AddTicks(1) } } },
            baseline with { Observation = observation with { Lease = lease with { Duration = lease.Duration.Add(TimeSpan.FromTicks(1)) } } },
            baseline with { Health = health with { ServerTime = health.ServerTime.AddTicks(1) } },
            baseline with { Health = health with { MonotonicElapsed = health.MonotonicElapsed.Add(TimeSpan.FromTicks(1)) } },
            baseline with { Health = health with { PartitionCertain = false } },
            baseline with { Health = health with { ClockCertain = false } },
            new ObserveAuthorityCas(baseline.AuthorityId, baseline.CandidateId, baseline.RequestId,
                AuthorityCasOutcome.Succeeded, observation, health),
            new ObserveAuthorityRead(baseline.AuthorityId, baseline.CandidateId, baseline.RequestId,
                AuthorityCasOutcome.Succeeded, observation, health),
        ];

        await Assert.That(mutations.Select(PermitDigest)).DoesNotContain(expected);
        await Assert.That(mutations.Select(PermitDigest).Distinct(StringComparer.Ordinal).Count())
            .IsEqualTo(mutations.Length);
    }

    [Test]
    public async Task Permit_replay_is_deterministic_for_one_thousand_cases_and_cultures()
    {
        var first = UnderCulture("tr-TR", ReplayPermitCases);
        var second = UnderCulture("ar-SA", ReplayPermitCases);
        await Assert.That(first).IsEquivalentTo(second);
        await Assert.That(first.Count).IsEqualTo(1_000);
        await Assert.That(first.Distinct(StringComparer.Ordinal).Count()).IsEqualTo(1_000);
    }

    [Test]
    public async Task Permit_corpus_is_content_addressed_and_replays_exactly()
    {
        const string corpus = "v1|evaluate:corpus-a|evaluate:corpus-b|cas:corpus-a|read:corpus-a";
        const string corpusDigest = "d04f683acb9e1dce3c566aea27655ef42cfda7a8849aab39a5e5bf541d2d89a7";
        await Assert.That(Sha256(corpus)).IsEqualTo(corpusDigest);

        var observation = Observation();
        var health = Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1));
        AuthorityCommand[] commands =
        [
            new EvaluateMutationAuthority("regional-authority", "candidate-a", "corpus-a", observation, health),
            new EvaluateMutationAuthority("regional-authority", "candidate-a", "corpus-b", observation, health),
            new ObserveAuthorityCas("regional-authority", "candidate-a", "corpus-a",
                AuthorityCasOutcome.Succeeded, observation, health),
            new ObserveAuthorityRead("regional-authority", "candidate-a", "corpus-a",
                AuthorityCasOutcome.Succeeded, observation, health),
        ];
        var first = commands.Select(PermitDigest).ToArray();
        var replay = commands.Select(PermitDigest).ToArray();
        await Assert.That(replay).IsEquivalentTo(first);
        await Assert.That(first.Distinct(StringComparer.Ordinal).Count()).IsEqualTo(commands.Length);
        await Assert.That(Sha256(string.Join('|', first)))
            .IsEqualTo("272469aa813b11f52584be6f5a4d5fedfc8661d49117ec5bc71e6c062815bd24");
    }

    [Test]
    public async Task Permit_construction_accessors_and_clone_route_are_closed()
    {
        var command = new EvaluateMutationAuthority("regional-authority", "candidate-a", "closed",
            Observation(), Healthy(Start.AddMinutes(1), TimeSpan.FromMinutes(1)));
        var permit = CreatePermit(command);
        var type = typeof(MutationAuthorityPermit);
        await Assert.That(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        var constructors = type.GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance);
        await Assert.That(constructors.Select(static value => value.GetParameters()
            .Select(static parameter => parameter.ParameterType).ToArray())).IsEquivalentTo(new[]
        {
            new[] { typeof(AuthorityCommand) }, new[] { typeof(MutationAuthorityPermit) },
        });
        await Assert.That(type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(static property => property.SetMethod?.IsPublic == true)).IsEmpty();
        await Assert.That(type.GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(static method => method.Name == "Deconstruct")).IsEmpty();
        await Assert.That(type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(static property => property.Name)).IsEquivalentTo(new[]
            {
                "AuthorizingCommand", "RequestId", "AuthorityId", "CandidateId", "LeaseId", "Epoch",
                "KvRevision", "ObservationId", "EvaluatedServerTime", "EvaluatedMonotonicElapsed",
            });
        var routes = type.Assembly.GetExportedTypes()
            .SelectMany(static exported => exported.GetMethods(BindingFlags.Public | BindingFlags.Static |
                BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(method => method.ReturnType == type)
            .Select(static method => $"{method.DeclaringType!.Name}.{method.Name}").ToArray();
        await Assert.That(routes).IsEquivalentTo(new[]
        {
            "AuthorityDecision.get_MutationPermit", "MutationAuthorityPermit.<Clone>$",
        });
        var cloneMethod = type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Single(static method => method.Name == "<Clone>$");
        var clone = (MutationAuthorityPermit)cloneMethod.Invoke(permit, null)!;
        await Assert.That(clone).IsEqualTo(permit);
        await Assert.That(ReferenceEquals(clone, permit)).IsFalse();
        await Assert.That(ReferenceEquals(clone.AuthorizingCommand, command)).IsTrue();
    }

    private static List<AuthorityEvent> BuildLeader()
        => BuildLeaderDecision().History;

    private static (List<AuthorityEvent> History, ObserveAuthorityCas Command, AuthorityDecision Decision)
        BuildLeaderDecision()
    {
        var pending = PendingAcquisition();
        var intent = (CompareAndSetLeaseIntent)pending.Decision.Intents.Single();
        var command = new ObserveAuthorityCas(
            "regional-authority", "candidate-a", "acquire-a", AuthorityCasOutcome.Succeeded,
            new AuthorityObservation("regional-authority", 11, 6, "confirmed", intent.ProposedLease),
            Healthy(Start, TimeSpan.Zero));
        var confirmed = AuthorityEngine.Decide(pending.History, command);
        pending.History.AddRange(confirmed.EventsToAppend);
        return (pending.History, command, confirmed);
    }

    private static (List<AuthorityEvent> History, AuthorityDecision Decision) PendingAcquisition()
    {
        var baseline = new AuthorityObservation("regional-authority", 10, 5, "baseline",
            new AuthorityLease("old-candidate", "old-lease", Start.AddMinutes(-10), TimeSpan.FromMinutes(5)));
        var decision = AuthorityEngine.Decide([], new AcquireAuthority(
            "regional-authority", "candidate-a", "acquire-a", "lease-a", baseline,
            new AuthorityHealth(Start, TimeSpan.FromMinutes(10), true, true), TimeSpan.FromMinutes(10)));
        return (decision.EventsToAppend.ToList(), decision);
    }

    private static async Task AssertPermit(AuthorityDecision decision, AuthorityCommand command)
    {
        await Assert.That(decision.Errors).IsEmpty();
        await Assert.That(decision.MutationPermit).IsNotNull();
        var permit = decision.MutationPermit!;
        var (observation, health) = command switch
        {
            ObserveAuthorityCas value => (value.Observation!, value.Health),
            ObserveAuthorityRead value => (value.Observation!, value.Health),
            EvaluateMutationAuthority value => (value.Observation, value.Health),
            _ => throw new InvalidOperationException(),
        };
        await Assert.That(ReferenceEquals(permit.AuthorizingCommand, command)).IsTrue();
        await Assert.That(permit.RequestId).IsEqualTo(command.RequestId);
        await Assert.That(permit.AuthorityId).IsEqualTo(command.AuthorityId);
        await Assert.That(permit.CandidateId).IsEqualTo(command.CandidateId);
        await Assert.That(permit.LeaseId).IsEqualTo(observation.Lease!.LeaseId);
        await Assert.That(permit.Epoch).IsEqualTo(observation.Epoch);
        await Assert.That(permit.KvRevision).IsEqualTo(observation.KvRevision);
        await Assert.That(permit.ObservationId).IsEqualTo(observation.ObservationId);
        await Assert.That(permit.EvaluatedServerTime).IsEqualTo(health.ServerTime);
        await Assert.That(permit.EvaluatedMonotonicElapsed).IsEqualTo(health.MonotonicElapsed);
    }

    private static IReadOnlyList<string> ReplayPermitCases()
    {
        var results = new string[1_000];
        for (var index = 0; index < results.Length; index++)
        {
            var command = new EvaluateMutationAuthority("regional-authority", "candidate-a", $"request-{index}",
                Observation(), Healthy(Start.AddSeconds(index % 300), TimeSpan.FromSeconds(index % 300)));
            results[index] = PermitDigest(command);
        }
        return results;
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

    private static AuthorityObservation Observation() => new("regional-authority", 11, 6, "confirmed",
        new AuthorityLease("candidate-a", "lease-a", Start, TimeSpan.FromMinutes(10)));
    private static AuthorityHealth Healthy(DateTimeOffset serverTime, TimeSpan elapsed) =>
        new(serverTime, elapsed, true, true);
    private static string PermitDigest(AuthorityCommand command) => AuthorityDigest.Decision(
        AuthorityState.Empty, [], [], [], CreatePermit(command));
    private static MutationAuthorityPermit CreatePermit(AuthorityCommand command)
    {
        var constructor = typeof(MutationAuthorityPermit)
            .GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance)
            .Single(static value => value.GetParameters() is [{ ParameterType: var type }]
                && type == typeof(AuthorityCommand));
        try { return (MutationAuthorityPermit)constructor.Invoke([command]); }
        catch (TargetInvocationException error) when (error.InnerException is not null)
        {
            throw error.InnerException;
        }
    }
    private static string Sha256(string value) => Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    private static Exception? Capture(Action action)
    {
        try { action(); return null; }
        catch (Exception error) { return error; }
    }
}

