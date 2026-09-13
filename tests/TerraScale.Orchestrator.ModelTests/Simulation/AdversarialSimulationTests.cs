using System.Globalization;
using System.Reflection;
using System.Text.Json;
using TerraScale.Orchestrator.ModelTests.RegressionCorpus;

namespace TerraScale.Orchestrator.ModelTests.Simulation;

public sealed class AdversarialSimulationTests
{
    [Test]
    public async Task VirtualClockIdentityAndBoundsFailWithTypedCodes()
    {
        await Assert.That(new VirtualClock(long.MaxValue).Advance(1).Code).IsEqualTo(SimulationFailureCode.Overflow);
        await Assert.That(new VirtualClock(4).Advance(-1).Code).IsEqualTo(SimulationFailureCode.InvalidEvent);
        await Assert.That(new DeterministicIdentitySource(long.MaxValue).Next().Code).IsEqualTo(SimulationFailureCode.Overflow);
        await Assert.That(new DeterministicIdentitySource(0).Next().Code).IsEqualTo(SimulationFailureCode.InvalidEvent);
        await Assert.That(DeterministicSimulator.Replay(Events(), [], new(0, 1, 1)).Code)
            .IsEqualTo(SimulationFailureCode.InvalidEvent);
        await Assert.That(DeterministicSimulator.Replay(Events(), [], new(1, 1, 1)).Code)
            .IsEqualTo(SimulationFailureCode.StepBoundExhausted);
        var explored = DeterministicSimulator.Explore(Events(), new(100, 1, 3));
        await Assert.That(explored.Code).IsEqualTo(SimulationFailureCode.ScheduleBoundExhausted);
    }

    [Test]
    public async Task QueueOrderingDigestAndReplayAreCulturePermutationStable()
    {
        var ordered = ModelState.Create(Events()).Queue.Events.Select(static item => item.EventId).ToArray();
        var permuted = ModelState.Create(Events().Reverse()).Queue.Events.Select(static item => item.EventId).ToArray();
        await Assert.That(permuted).IsEquivalentTo(ordered);
        await Assert.That(string.Join(',', permuted)).IsEqualTo(string.Join(',', ordered));

        var schedule = Schedule();
        var original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new("tr-TR");
            var first = DeterministicSimulator.Replay(Events(), schedule, new(128, 16, 8));
            CultureInfo.CurrentCulture = new("ar-SA");
            var second = DeterministicSimulator.Replay(Events().Reverse(), schedule, new(128, 16, 8));
            await Assert.That(first.Code).IsEqualTo(SimulationFailureCode.Completed);
            await Assert.That(first.Digest).IsEqualTo(second.Digest);
            await Assert.That(first.State.Canonical()).IsEqualTo(second.State.Canonical());
        }
        finally { CultureInfo.CurrentCulture = original; }
    }

    [Test]
    public async Task CanonicalEncodingIsCollisionSafeForAdversarialDelimiters()
    {
        var first = Event(1, ModelEventKind.Delivery) with { EventId = "a|node=1:b", Node = "c" };
        var second = Event(1, ModelEventKind.Delivery) with { EventId = "a", Node = "b|node=1:c" };
        await Assert.That(ModelState.EventCanonical(first)).IsNotEqualTo(ModelState.EventCanonical(second));
        await Assert.That(ModelState.EventCanonical(first).Length).IsNotEqualTo(0);
    }

    [Test]
    public async Task EveryFailureKindIsClosedDeterministicAndReplayable()
    {
        await Assert.That(string.Join(',', FailureScheduleCatalog.Ordered)).IsEqualTo(
            "Loss,Duplicate,Reorder,Delay,Crash,Restart,LeaderChange,Partition,Heal");
        foreach (var kind in FailureScheduleCatalog.Ordered)
        {
            var targets = kind is FailureKind.Crash or FailureKind.Restart or FailureKind.LeaderChange or
                FailureKind.Partition or FailureKind.Heal ? new[] { "n1", "n2", "n3" } : ["n1"];
            foreach (var target in targets)
            {
                var directive = new FailureDirective(kind, target, kind == FailureKind.Delay ? 2 : 0);
                var first = DeterministicSimulator.Replay(Events(), [directive], new(128, 16, 4));
                var second = DeterministicSimulator.Replay(Events(), [directive], new(128, 16, 4));
                await Assert.That(first.Code).IsEqualTo(SimulationFailureCode.Completed);
                await Assert.That(first.Digest).IsEqualTo(second.Digest);
            }
        }
    }

    [Test]
    public async Task ReorderChangesDeliveryOrdinalWithoutForgingEventEvidence()
    {
        var original = new ImmutableEventQueue(Events().Take(2));
        var reordered = original.ReorderFirstTwo();
        await Assert.That(reordered.Events[0]).IsEqualTo(original.Events[1]);
        await Assert.That(reordered.Events[1]).IsEqualTo(original.Events[0]);
        await Assert.That(reordered.Events.Select(ModelState.EventCanonical)).IsEquivalentTo(
            original.Events.Select(ModelState.EventCanonical));
    }

    [Test]
    public async Task BoundedThreeNodeExplorationDeduplicatesCanonicalStates()
    {
        var bounds = new SimulationBounds(4096, 2048, 3);
        var first = DeterministicSimulator.Explore(Events(), bounds);
        var second = DeterministicSimulator.Explore(Events(), bounds);
        await Assert.That(first.Code).IsEqualTo(SimulationFailureCode.NonConvergent);
        await Assert.That(first.Schedules).IsGreaterThan(0);
        await Assert.That(first.Schedules).IsLessThanOrEqualTo(bounds.MaximumSchedules);
        await Assert.That(first.Schedules).IsEqualTo(second.Schedules);
        await Assert.That(first.Digest).IsEqualTo(second.Digest);
    }

    [Test]
    public async Task LeaderChangePartitionDuplicateAndLateCompletionPreserveSafety()
    {
        var result = DeterministicSimulator.Replay(Events(), Schedule(), new(128, 16, 8));
        await Assert.That(result.Code).IsEqualTo(SimulationFailureCode.Completed);
        await Assert.That(result.Invariant).IsEqualTo(SafetyInvariant.Unspecified);
        await Assert.That(result.State.Nodes.Count(node => node.AcceptedWriterEpoch == result.State.CurrentEpoch)).IsEqualTo(1);
        await Assert.That(result.State.Operations.All(static operation => operation.CreateCount <= 1)).IsTrue();
        await Assert.That(result.State.Terminations).IsEqualTo(0);
        await Assert.That(result.State.RejectedMutations).IsGreaterThan(0);
    }

    [Test]
    public async Task StaleAndUnauthorizedMutationNeverSucceeds()
    {
        var stale = Event(6, ModelEventKind.MutationSucceeded, node: "n1", epoch: 1);
        var result = DeterministicSimulator.Replay([.. Events().Take(4), stale],
            [new(FailureKind.LeaderChange, "n2", 0)], new(128, 16, 4));
        await Assert.That(result.Code).IsEqualTo(SimulationFailureCode.Completed);
        await Assert.That(result.State.AcceptedMutations).IsEqualTo(0);
        await Assert.That(result.State.RejectedMutations).IsGreaterThan(0);

        var unauthorized = DeterministicSimulator.Replay([Event(1, ModelEventKind.MutationSucceeded)], [], new(16, 4, 1));
        await Assert.That(unauthorized.State.AcceptedMutations).IsEqualTo(0);
        await Assert.That(unauthorized.State.RejectedMutations).IsEqualTo(1);
    }

    [Test]
    public async Task CriticalTerminationAndDuplicateCreateAreNeverAccepted()
    {
        var events = Events().Concat([Event(7, ModelEventKind.RequestCreate),
            Event(8, ModelEventKind.RequestTermination, node: "n1")]).ToArray();
        var result = DeterministicSimulator.Replay(events, [new(FailureKind.Duplicate, "n1", 0)], new(128, 16, 4));
        await Assert.That(result.Code).IsEqualTo(SimulationFailureCode.Completed);
        await Assert.That(result.State.Operations.Single().CreateCount).IsEqualTo(1);
        await Assert.That(result.State.Terminations).IsEqualTo(0);
        await Assert.That(result.State.RejectedMutations).IsGreaterThan(0);
    }

    [Test]
    public async Task ExactOperationMutationCompletionIsTerminalAndIdempotent()
    {
        var events = Events().Concat([Event(7, ModelEventKind.MutationSucceeded)]).ToArray();
        var result = DeterministicSimulator.Replay(events, [], new(128, 16, 4));
        await Assert.That(result.Code).IsEqualTo(SimulationFailureCode.Completed);
        await Assert.That(result.State.AcceptedMutations).IsEqualTo(1);
        await Assert.That(result.State.CompletedMutationOperations).IsEquivalentTo(new[] { "operation-1" });
        await Assert.That(result.State.RejectedMutations).IsGreaterThan(0);
        await Assert.That(DeterministicSimulator.InvariantHolds(result.State,
            SafetyInvariant.TerminalMutationUnique)).IsTrue();
    }

    [Test]
    public async Task EveryAdvertisedInvariantHasSafeAndAdversarialEvaluation()
    {
        var safe = ModelState.Create([]);
        await Assert.That(DeterministicSimulator.InvariantHolds(safe, SafetyInvariant.SingleAcceptedWriter)).IsTrue();
        await Assert.That(DeterministicSimulator.InvariantHolds(safe, SafetyInvariant.NoStaleSuccessfulMutation)).IsTrue();
        await Assert.That(DeterministicSimulator.InvariantHolds(safe, SafetyInvariant.NoUnauthorizedAction)).IsTrue();
        await Assert.That(DeterministicSimulator.InvariantHolds(safe, SafetyInvariant.NoUnsafeTermination)).IsTrue();
        await Assert.That(DeterministicSimulator.InvariantHolds(safe, SafetyInvariant.QuorumFloorPreserved)).IsTrue();
        await Assert.That(DeterministicSimulator.InvariantHolds(safe, SafetyInvariant.NoSecondCreateAfterUnknown)).IsTrue();
        await Assert.That(DeterministicSimulator.InvariantHolds(safe, SafetyInvariant.SnapshotReplayDigestEqual, safe.Digest())).IsTrue();
        await Assert.That(DeterministicSimulator.InvariantHolds(safe, SafetyInvariant.TerminalMutationUnique)).IsTrue();

        var twoWriters = Clone(safe, nodes:
            [new("n1", ModelNodeRole.Critical, false, false, 1), new("n2", ModelNodeRole.Critical, false, false, 1),
             new("n3", ModelNodeRole.Critical, false, false, 0)]);
        await Assert.That(DeterministicSimulator.InvariantHolds(twoWriters, SafetyInvariant.SingleAcceptedWriter)).IsFalse();
        await Assert.That(DeterministicSimulator.InvariantHolds(Clone(safe, actions:
            [Accepted(AcceptedActionKind.Mutation, eventEpoch: 1, authorityEpoch: 2)]),
            SafetyInvariant.NoStaleSuccessfulMutation)).IsFalse();
        await Assert.That(DeterministicSimulator.InvariantHolds(Clone(safe, actions:
            [Accepted(AcceptedActionKind.Mutation, authorized: false)]), SafetyInvariant.NoUnauthorizedAction)).IsFalse();
        await Assert.That(DeterministicSimulator.InvariantHolds(Clone(safe, actions:
            [Accepted(AcceptedActionKind.Termination, role: ModelNodeRole.Critical)]),
            SafetyInvariant.NoUnsafeTermination)).IsFalse();
        await Assert.That(DeterministicSimulator.InvariantHolds(Clone(safe, actions:
            [Accepted(AcceptedActionKind.Termination, role: ModelNodeRole.Critical, criticalNodesAfter: 2)]),
            SafetyInvariant.QuorumFloorPreserved)).IsFalse();
        await Assert.That(DeterministicSimulator.InvariantHolds(Clone(safe, actions:
            [Accepted(AcceptedActionKind.Create), Accepted(AcceptedActionKind.Create, ordinal: 2)]),
            SafetyInvariant.NoSecondCreateAfterUnknown)).IsFalse();
        await Assert.That(DeterministicSimulator.InvariantHolds(safe, SafetyInvariant.SnapshotReplayDigestEqual,
            new string('0', 64))).IsFalse();
        await Assert.That(DeterministicSimulator.InvariantHolds(Clone(safe, actions:
            [Accepted(AcceptedActionKind.Mutation), Accepted(AcceptedActionKind.Mutation)]),
            SafetyInvariant.TerminalMutationUnique)).IsFalse();
    }

    [Test]
    public async Task AuthorityAuditIndependentlyChecksEveryAcceptedFactAndIdentityDimension()
    {
        var state = DeterministicSimulator.Replay([Event(1, ModelEventKind.AuthorizeOperation)], [],
            new(16, 4, 1)).State;
        var exact = state.AcceptedActions.Single();
        await Assert.That(DeterministicSimulator.InvariantHolds(state, SafetyInvariant.NoUnauthorizedAction)).IsTrue();
        var mutations = new[]
        {
            exact with { AcceptedEvent = exact.AcceptedEvent with { Node = "n2" } },
            exact with { LeaderAtAcceptance = "n2" },
            exact with { NodeAcceptedEpoch = 0 }, exact with { NodeCrashed = true },
            exact with { NodePartitioned = true }, exact with { Authorized = false },
            exact with { AcceptedEvent = exact.AcceptedEvent with { Generation = exact.Generation + 1 } },
            exact with { AcceptedEvent = exact.AcceptedEvent with { IdempotencyKey = "other-key" } },
            exact with { AcceptedEvent = exact.AcceptedEvent with { Resource = "other-resource" } },
        };
        foreach (var mutation in mutations)
            await Assert.That(DeterministicSimulator.InvariantHolds(Clone(state, actions: [mutation]),
                SafetyInvariant.NoUnauthorizedAction)).IsFalse();
        await Assert.That(DeterministicSimulator.InvariantHolds(Clone(state, actions:
            [exact with { AcceptedEvent = exact.AcceptedEvent with { Epoch = exact.EventEpoch + 1 } }]),
            SafetyInvariant.NoStaleSuccessfulMutation)).IsFalse();
    }

    [Test]
    public async Task ShrinkingReplaysTheFailureAndRetainsTheCausalDirective()
    {
        var overflowEvent = Event(1, ModelEventKind.Delivery) with { DueTick = long.MaxValue };
        var schedule = new[] { new FailureDirective(FailureKind.Delay, "n1", 1),
            new(FailureKind.Partition, "n1", 0), new(FailureKind.Heal, "n1", 0) };
        var bounds = new SimulationBounds(16, 16, 3);
        var first = DeterministicSimulator.Shrink([overflowEvent], schedule, bounds, SimulationFailureCode.Overflow);
        var second = DeterministicSimulator.Shrink([overflowEvent], schedule, bounds, SimulationFailureCode.Overflow);
        await Assert.That(first.Code).IsEqualTo(SimulationFailureCode.Completed);
        await Assert.That(first.Schedule).IsEquivalentTo(second.Schedule);
        await Assert.That(string.Join(',', first.Schedule.Select(static item => item.Kind))).IsEqualTo("Delay");
        await Assert.That(DeterministicSimulator.Replay([overflowEvent], first.Schedule, bounds).Code)
            .IsEqualTo(SimulationFailureCode.Overflow);
        await Assert.That(DeterministicSimulator.Replay([overflowEvent], [], bounds).Code)
            .IsEqualTo(SimulationFailureCode.Completed);
    }

    [Test]
    public async Task ExistingPureCoresRejectUnknownCreateDuplicateDeliveryAndTrustEscape()
    {
        await Assert.That(CoreSafetyProbe.AuthorityRequiresObservedCasBeforeMutationPermit()).IsTrue();
        await Assert.That(CoreSafetyProbe.OperationCannotDispatchWithoutDurablePreparation()).IsTrue();
        await Assert.That(CoreSafetyProbe.ProviderCannotMutateWithoutRegionalAuthority()).IsTrue();
        await Assert.That(CoreSafetyProbe.ComputeUnknownOutcomeObservesWithoutSecondCreate()).IsTrue();
        await Assert.That(CoreSafetyProbe.DuplicateDeliveryIsIdempotent()).IsTrue();
        await Assert.That(CoreSafetyProbe.UntrustedDeliveryCannotAcquireProductionAuthority()).IsTrue();
    }

    [Test]
    public async Task FakeObservationsAreExactPassiveDataAndCannotForgeAcceptedOutputs()
    {
        var provider = new FakeProviderObservation("operation", 2, 3, "key", "resource", 4, ProviderOutcome.OutcomeUnknown);
        var delivery = new FakeDeliveryObservation("operation", 2, 3, "key", "resource", 4, true);
        await Assert.That(provider.Operation).IsEqualTo(delivery.Operation);
        await Assert.That(provider.Generation).IsEqualTo(delivery.Generation);
        await Assert.That(provider.Epoch).IsEqualTo(delivery.Epoch);
        await Assert.That(provider.IdempotencyKey).IsEqualTo(delivery.IdempotencyKey);
        await Assert.That(provider.Resource).IsEqualTo(delivery.Resource);
        await Assert.That(provider.ObservationSequence).IsEqualTo(delivery.ObservationSequence);
        var types = new[] { typeof(FakeProviderObservation), typeof(FakeDeliveryObservation) };
        await Assert.That(types.SelectMany(static type => type.GetMethods(BindingFlags.Instance | BindingFlags.Public))
            .Any(static method => method.Name.Contains("Authorize", StringComparison.Ordinal) ||
                method.ReturnType.Name.Contains("Intent", StringComparison.Ordinal) ||
                method.ReturnType.Name.Contains("Permit", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task InvalidEventsAndOverflowAreTypedNotExceptions()
    {
        var invalid = Event(1, ModelEventKind.Delivery) with { Epoch = 0 };
        await Assert.That(DeterministicSimulator.Replay([invalid], [], new(8, 4, 1)).Code)
            .IsEqualTo(SimulationFailureCode.InvalidEvent);
        var overflow = Event(1, ModelEventKind.Delivery) with { DueTick = long.MaxValue };
        await Assert.That(DeterministicSimulator.Replay([overflow],
            [new(FailureKind.Delay, "n1", 1)], new(8, 4, 1)).Code).IsEqualTo(SimulationFailureCode.Overflow);
    }

    [Test]
    public async Task MalformedDuplicateAndBoundPlusOneInputsAreRejectedBeforeExecution()
    {
        var malformed = Event(1, ModelEventKind.Delivery) with { Kind = ModelEventKind.Unspecified };
        var negative = Event(1, ModelEventKind.Delivery) with { DueTick = -1 };
        var duplicate = new[] { Event(1, ModelEventKind.Delivery), Event(2, ModelEventKind.Delivery) with { EventId = "event-1" } };
        await Assert.That(DeterministicSimulator.Replay([malformed], [], new(8, 4, 1)).Code)
            .IsEqualTo(SimulationFailureCode.InvalidEvent);
        await Assert.That(DeterministicSimulator.Replay([negative], [], new(8, 4, 1)).Code)
            .IsEqualTo(SimulationFailureCode.InvalidEvent);
        await Assert.That(DeterministicSimulator.Replay(duplicate, [], new(8, 4, 1)).Code)
            .IsEqualTo(SimulationFailureCode.InvalidEvent);
        var tooMany = Enumerable.Range(1, 5).Select(index => Event(index, ModelEventKind.Delivery));
        await Assert.That(DeterministicSimulator.Replay(tooMany, [], new(4, 4, 1)).Code)
            .IsEqualTo(SimulationFailureCode.StepBoundExhausted);
        var fullQueue = Enumerable.Range(1, 2048).Select(index => Event(index, ModelEventKind.Delivery)).ToArray();
        await Assert.That(DeterministicSimulator.Replay(fullQueue,
            [new(FailureKind.Duplicate, "n1", 0)], new(4096, 16, 1)).Code)
            .IsEqualTo(SimulationFailureCode.StepBoundExhausted);
        await Assert.That(DeterministicSimulator.Replay(ThrowingEvents(), [], new(8, 4, 1)).Code)
            .IsEqualTo(SimulationFailureCode.InvalidEvent);
        await Assert.That(DeterministicSimulator.Explore(ThrowingEvents(), new(8, 4, 1)).Code)
            .IsEqualTo(SimulationFailureCode.InvalidEvent);
        await Assert.That(DeterministicSimulator.Shrink(ThrowingEvents(), [], new(8, 4, 1),
            SimulationFailureCode.Completed).Code).IsEqualTo(SimulationFailureCode.InvalidEvent);

        var rejectedFourNodes = false;
        try
        {
            _ = new ModelState(new(0), new(1), 1, "n1",
                [new("n1", ModelNodeRole.Critical, false, false, 1),
                 new("n2", ModelNodeRole.Critical, false, false, 0),
                 new("n3", ModelNodeRole.Critical, false, false, 0),
                 new("n4", ModelNodeRole.Critical, false, false, 0)], [], new([]), [], 0, 0, 0);
        }
        catch (ArgumentException) { rejectedFourNodes = true; }
        await Assert.That(rejectedFourNodes).IsTrue();
    }

    [Test]
    public async Task StateQueueAndResultDefensivelyCopyCallerCollections()
    {
        var callerEvents = Events();
        var state = ModelState.Create(callerEvents);
        var stateDigest = state.Digest();
        callerEvents[0] = callerEvents[0] with { EventId = "mutated" };
        await Assert.That(state.Digest()).IsEqualTo(stateDigest);

        var callerSchedule = Schedule();
        var result = DeterministicSimulator.Replay(Events(), callerSchedule, new(128, 16, 8));
        var retained = result.Schedule[0];
        callerSchedule[0] = new(FailureKind.Loss, "n3", 0);
        await Assert.That(result.Schedule[0]).IsEqualTo(retained);
    }

    [Test]
    public async Task CheckedInCorpusIsCanonicalContentAddressedAndCultureIndependent()
    {
        var original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new("tr-TR");
            var first = RegressionCorpusLoader.LoadCheckedInStaleLeaderLateCompletion();
            CultureInfo.CurrentCulture = new("ar-SA");
            var second = RegressionCorpusLoader.LoadCheckedInStaleLeaderLateCompletion();
            await Assert.That(first.Code).IsEqualTo(CorpusLoadCode.Accepted);
            await Assert.That(RegressionCorpusLoader.Canonical(first.Entries.Single()))
                .IsEqualTo(RegressionCorpusLoader.Canonical(second.Entries.Single()));
            await Assert.That(RegressionCorpusLoader.Digest(first.Entries.Single())).IsEqualTo(first.Entries.Single().Digest);
            var replay = DeterministicSimulator.Replay(Events(), first.Entries.Single().Schedule, SimulationBounds.SmokeShard);
            await Assert.That(replay.Code).IsEqualTo(first.Entries.Single().ExpectedError);
            await Assert.That(DeterministicSimulator.InvariantHolds(replay.State,
                first.Entries.Single().ExpectedInvariant)).IsTrue();
            await Assert.That(replay.State.AcceptedMutations).IsEqualTo(0);
        }
        finally { CultureInfo.CurrentCulture = original; }
    }

    [Test]
    public async Task CorpusRejectsTamperUnknownFieldsVersionsTraversalAndDuplicates()
    {
        var source = RegressionCorpusLoader.ReadCheckedInStaleLeaderLateCompletion();
        await Assert.That(RegressionCorpusLoader.Load(source.Replace("\"seed\":17", "\"seed\":18", StringComparison.Ordinal)).Code)
            .IsEqualTo(CorpusLoadCode.InvalidDigest);
        await Assert.That(RegressionCorpusLoader.Load(source.Replace("\"version\":1", "\"version\":2", StringComparison.Ordinal)).Code)
            .IsEqualTo(CorpusLoadCode.UnsupportedVersion);
        await Assert.That(RegressionCorpusLoader.Load(source.Replace("\"seed\":17", "\"seed\":17,\"extra\":1", StringComparison.Ordinal)).Code)
            .IsEqualTo(CorpusLoadCode.UnknownField);
        await Assert.That(RegressionCorpusLoader.Load(source.Replace("\"seed\":17", "\"seed\":17,\"seed\":17", StringComparison.Ordinal)).Code)
            .IsEqualTo(CorpusLoadCode.UnknownField);
        await Assert.That(RegressionCorpusLoader.Load(source.Replace("stale-leader-late-completion", "../escape", StringComparison.Ordinal)).Code)
            .IsEqualTo(CorpusLoadCode.InvalidId);
        await Assert.That(RegressionCorpusLoader.LoadMany([source, source]).Code).IsEqualTo(CorpusLoadCode.DuplicateId);
        await Assert.That(RegressionCorpusLoader.LoadMany(Enumerable.Repeat(source, 257)).Code)
            .IsEqualTo(CorpusLoadCode.InvalidSchedule);
        await Assert.That(RegressionCorpusLoader.Load(new string('x', 65_537)).Code).IsEqualTo(CorpusLoadCode.InvalidJson);
        var scheduleItem = "{\"kind\":\"Loss\",\"node\":\"n1\",\"delay\":0}";
        var oversizedSchedule = source.Replace(source[source.IndexOf("\"schedule\":[", StringComparison.Ordinal)..source.IndexOf("]", source.IndexOf("\"schedule\":[", StringComparison.Ordinal), StringComparison.Ordinal)],
            $"\"schedule\":[{string.Join(',', Enumerable.Repeat(scheduleItem, 129))}", StringComparison.Ordinal);
        await Assert.That(RegressionCorpusLoader.Load(oversizedSchedule).Code).IsEqualTo(CorpusLoadCode.InvalidSchedule);
        await Assert.That(RegressionCorpusLoader.Load("{").Code).IsEqualTo(CorpusLoadCode.InvalidJson);
    }

    [Test]
    public async Task SimulatorArchitectureHasNoMutationOrAmbientRuntimeCapability()
    {
        var assembly = typeof(DeterministicSimulator).Assembly;
        var simulationTypes = assembly.GetTypes().Where(type => type.Namespace is not null &&
            (type.Namespace.Contains(".Simulation", StringComparison.Ordinal) ||
             type.Namespace.Contains(".RegressionCorpus", StringComparison.Ordinal))).ToArray();
        var forbiddenTypeFragments = new[] { "System.IO.File", "System.IO.Directory", "System.Net", "System.Diagnostics.Process",
            "System.Threading.Thread", "System.Random", "System.Timers", "System.Environment" };
        var exposedTypes = simulationTypes.SelectMany(static type => type.GetProperties().Select(static property => property.PropertyType)
            .Concat(type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)
                .Select(static method => method.ReturnType))).ToArray();
        await Assert.That(exposedTypes.Any(type => forbiddenTypeFragments.Any(fragment =>
            (type.FullName ?? string.Empty).Contains(fragment, StringComparison.Ordinal)))).IsFalse();
        await Assert.That(simulationTypes.SelectMany(static type => type.GetMethods(BindingFlags.Public |
                BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            .Where(static method => !method.IsSpecialName)
            .Any(static method => method.Name.StartsWith("Write", StringComparison.Ordinal) ||
                method.Name.StartsWith("Send", StringComparison.Ordinal) ||
                method.Name.StartsWith("Execute", StringComparison.Ordinal))).IsFalse();
        await Assert.That(typeof(SimulationBounds).GetProperty(nameof(SimulationBounds.SmokeShard))).IsNotNull();
        await Assert.That(SimulationBounds.FeatureMinimum.MaximumSchedules).IsEqualTo(10_000);
        await Assert.That(SimulationBounds.FullMinimum.MaximumSchedules).IsEqualTo(1_000_000);
    }

    private static ModelEvent[] Events() =>
    [
        Event(1, ModelEventKind.AuthorizeOperation),
        Event(2, ModelEventKind.RequestCreate),
        Event(3, ModelEventKind.ProviderOutcomeUnknown),
        Event(4, ModelEventKind.ProviderLateCompletion),
        Event(5, ModelEventKind.Delivery),
        Event(6, ModelEventKind.MutationSucceeded),
    ];
    private static FailureDirective[] Schedule() =>
    [
        new(FailureKind.Duplicate, "n1", 0),
        new(FailureKind.Delay, "n1", 1),
        new(FailureKind.LeaderChange, "n2", 0),
        new(FailureKind.Partition, "n1", 0),
        new(FailureKind.Heal, "n1", 0),
    ];
    private static ModelEvent Event(long sequence, ModelEventKind kind, string node = "n1", long epoch = 1) => new(
        sequence, sequence, $"event-{sequence.ToString(CultureInfo.InvariantCulture)}", kind, node, "operation-1", 2,
        epoch, "create-key", "resource-1", sequence);

    private static ModelState Clone(ModelState state, ModelNode[]? nodes = null, int terminations = 0,
        AcceptedActionEvidence[]? actions = null) => new(
        state.Clock, state.Identities, state.CurrentEpoch, state.Leader, nodes ?? state.Nodes.ToArray(), state.Operations,
        state.Queue, state.DeliveredEventIds, state.AcceptedMutations, state.RejectedMutations, terminations,
        state.CompletedMutationOperations, actions ?? state.AcceptedActions.ToArray());
    private static AcceptedActionEvidence Accepted(AcceptedActionKind kind, long eventEpoch = 1,
        long authorityEpoch = 1, bool authorized = true, ModelNodeRole role = ModelNodeRole.Critical, int ordinal = 1,
        int criticalNodesAfter = 3) =>
        new(Event(1, kind switch
        {
            AcceptedActionKind.Authorization => ModelEventKind.AuthorizeOperation,
            AcceptedActionKind.Create => ModelEventKind.RequestCreate,
            AcceptedActionKind.Mutation => ModelEventKind.MutationSucceeded,
            AcceptedActionKind.Termination => ModelEventKind.RequestTermination,
            _ => ModelEventKind.Delivery,
        }, epoch: eventEpoch), authorityEpoch,
            "n1", authorityEpoch, false, false, authorized, role, ordinal, criticalNodesAfter);
    private static IEnumerable<ModelEvent> ThrowingEvents()
    {
        yield return Event(1, ModelEventKind.Delivery);
        throw new InvalidOperationException("adversarial iterator");
    }
}

