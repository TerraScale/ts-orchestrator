using System.Globalization;

namespace TerraScale.Orchestrator.ModelTests.Simulation;

/// <summary>
/// Local qualification scenarios for the declared three-node topology. The
/// simulator is the deterministic C# harness used before a VM or OCI run; it
/// records only model observations and never stands in for a service binary.
/// </summary>
public sealed class LocalChaosQualificationTests
{
    [Test]
    public async Task RollingUpgradeAndNetworkFaultScheduleConvergesDeterministically()
    {
        var events = SeedEvents();
        FailureDirective[] schedule =
        [
            // The first candidate is upgraded one node at a time. A restart
            // is deliberately interleaved with duplicate/reordered delivery.
            new FailureDirective(FailureKind.Duplicate, "n1", 0),
            new FailureDirective(FailureKind.Reorder, "n1", 0),
            new FailureDirective(FailureKind.Delay, "n1", 3),
            new FailureDirective(FailureKind.Crash, "n1", 0),
            new FailureDirective(FailureKind.Restart, "n1", 0),
            new FailureDirective(FailureKind.LeaderChange, "n2", 0),
            // Isolate and heal the third node while the new leader serves.
            new FailureDirective(FailureKind.Partition, "n3", 0),
            new FailureDirective(FailureKind.Heal, "n3", 0),
            new FailureDirective(FailureKind.Crash, "n2", 0),
            new FailureDirective(FailureKind.Restart, "n2", 0),
            new FailureDirective(FailureKind.LeaderChange, "n3", 0),
        ];

        var bounds = new SimulationBounds(512, 64, 16);
        var first = DeterministicSimulator.Replay(events, schedule, bounds);
        var second = DeterministicSimulator.Replay(events.Reverse(), schedule, bounds);

        await Assert.That(first.Code).IsEqualTo(SimulationFailureCode.Completed);
        await Assert.That(first.Invariant).IsEqualTo(SafetyInvariant.Unspecified);
        await Assert.That(first.Digest).IsEqualTo(second.Digest);
        await Assert.That(first.State.Canonical()).IsEqualTo(second.State.Canonical());
        await Assert.That(first.State.Nodes.Select(static node => node.Id))
            .IsEquivalentTo(new[] { "n1", "n2", "n3" });
        await Assert.That(first.State.Nodes.Count(node => node.AcceptedWriterEpoch == first.State.CurrentEpoch))
            .IsEqualTo(1);
        await Assert.That(first.State.Operations.All(static operation => operation.CreateCount <= 1)).IsTrue();
        await Assert.That(DeterministicSimulator.InvariantHolds(first.State, SafetyInvariant.NoStaleSuccessfulMutation))
            .IsTrue();
        await Assert.That(DeterministicSimulator.InvariantHolds(first.State, SafetyInvariant.NoUnauthorizedAction))
            .IsTrue();
        await Assert.That(DeterministicSimulator.InvariantHolds(first.State, SafetyInvariant.NoSecondCreateAfterUnknown))
            .IsTrue();
        await Assert.That(DeterministicSimulator.InvariantHolds(first.State, SafetyInvariant.TerminalMutationUnique))
            .IsTrue();
        await Assert.That(first.State.Clock.Tick).IsGreaterThanOrEqualTo(15);
    }

    [Test]
    public async Task ClockSkewAndQueuePerturbationsRemainTypedAndCultureStable()
    {
        var originalCulture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR");
            var first = DeterministicSimulator.Replay(
                SeedEvents(),
                [
                    new FailureDirective(FailureKind.Delay, "n1", 4),
                    new FailureDirective(FailureKind.Reorder, "n1", 0),
                    new FailureDirective(FailureKind.Duplicate, "n1", 0),
                ],
                new SimulationBounds(512, 64, 8));

            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA");
            var second = DeterministicSimulator.Replay(
                SeedEvents().Reverse(),
                [
                    new FailureDirective(FailureKind.Delay, "n1", 4),
                    new FailureDirective(FailureKind.Reorder, "n1", 0),
                    new FailureDirective(FailureKind.Duplicate, "n1", 0),
                ],
                new SimulationBounds(512, 64, 8));

            await Assert.That(first.Code).IsEqualTo(SimulationFailureCode.Completed);
            await Assert.That(second.Code).IsEqualTo(SimulationFailureCode.Completed);
            await Assert.That(first.Digest).IsEqualTo(second.Digest);
            await Assert.That(first.State.Clock.Tick).IsGreaterThanOrEqualTo(15);
            await Assert.That(new VirtualClock(0).Advance(-1).Code)
                .IsEqualTo(SimulationFailureCode.InvalidEvent);
            await Assert.That(new VirtualClock(long.MaxValue).Advance(1).Code)
                .IsEqualTo(SimulationFailureCode.Overflow);
            var overflow = ModelEventFor("overflow", ModelEventKind.Delivery, "n1", 1, long.MaxValue);
            await Assert.That(DeterministicSimulator.Replay(
                    [overflow],
                    [new FailureDirective(FailureKind.Delay, "n1", 1)],
                    new SimulationBounds(8, 4, 1)).Code)
                .IsEqualTo(SimulationFailureCode.Overflow);
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
        }
    }

    private static ModelEvent[] SeedEvents() =>
    [
        ModelEventFor("op-1-authorize", ModelEventKind.AuthorizeOperation, "n1", 1, 1, "operation-1"),
        ModelEventFor("op-1-create", ModelEventKind.RequestCreate, "n1", 1, 2, "operation-1"),
        ModelEventFor("op-1-unknown", ModelEventKind.ProviderOutcomeUnknown, "n1", 1, 3, "operation-1"),
        ModelEventFor("op-1-late", ModelEventKind.ProviderLateCompletion, "n1", 1, 4, "operation-1"),
        ModelEventFor("op-1-mutation", ModelEventKind.MutationSucceeded, "n1", 1, 5, "operation-1"),
        ModelEventFor("op-2-authorize", ModelEventKind.AuthorizeOperation, "n2", 2, 6, "operation-2"),
        ModelEventFor("op-2-create", ModelEventKind.RequestCreate, "n2", 2, 7, "operation-2"),
        ModelEventFor("op-2-unknown", ModelEventKind.ProviderOutcomeUnknown, "n2", 2, 8, "operation-2"),
        ModelEventFor("op-2-late", ModelEventKind.ProviderLateCompletion, "n2", 2, 9, "operation-2"),
        ModelEventFor("op-2-mutation", ModelEventKind.MutationSucceeded, "n2", 2, 10, "operation-2"),
        ModelEventFor("op-3-authorize", ModelEventKind.AuthorizeOperation, "n3", 3, 11, "operation-3"),
        ModelEventFor("op-3-create", ModelEventKind.RequestCreate, "n3", 3, 12, "operation-3"),
        ModelEventFor("op-3-unknown", ModelEventKind.ProviderOutcomeUnknown, "n3", 3, 13, "operation-3"),
        ModelEventFor("op-3-late", ModelEventKind.ProviderLateCompletion, "n3", 3, 14, "operation-3"),
        ModelEventFor("op-3-mutation", ModelEventKind.MutationSucceeded, "n3", 3, 15, "operation-3"),
    ];

    private static ModelEvent ModelEventFor(
        string id,
        ModelEventKind kind,
        string node,
        long epoch,
        long dueTick,
        string operation = "operation-1") =>
        new(
            dueTick,
            dueTick,
            id,
            kind,
            node,
            operation,
            2,
            epoch,
            $"key-{operation}",
            $"resource-{operation}",
            dueTick);
}
