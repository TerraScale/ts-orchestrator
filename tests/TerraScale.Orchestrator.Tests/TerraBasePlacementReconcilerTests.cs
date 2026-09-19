using System.Text.Json;
using NATS.Client.KeyValueStore;
using TerraScale.Orchestrator.ControlPlane.DatabasePlacement;
using TerraScale.Orchestrator.ControlPlane.EdgeRouting;
using TerraScale.Orchestrator.ControlPlane.TerraBase;
using TUnit.Core;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Loop-level placement reconciliation: intent to diff to single action, every
/// refusal gate, and the edge projection — against a real NATS KV with the scripted
/// fake fleet.
/// </summary>
[NotInParallel("TerrabasePlacement")]
public sealed class TerraBasePlacementReconcilerTests
{
    [Test]
    public async Task TopologyDerivesExactSeatsAndTheEvaluatorAccepts()
    {
        var intent = PlacementTestHarness.Intent("prod-db", 2, "GRU", "SFO");
        var seats = PlacementTopology.Seats(intent);

        await Assert.That(string.Join(",", seats.Select(static seat => seat.MemberId)))
            .IsEqualTo("permanent-a,elastic-gru,permanent-b,elastic-sfo");
        await Assert.That(seats.All(static seat => seat.Kind != TerraBaseMemberKind.Unknown)).IsTrue();
        await Assert.That(seats.Select(static seat => seat.FailureDomain).Distinct(StringComparer.Ordinal).Count())
            .IsEqualTo(seats.Count);

        var decision = DatabasePlacementEvaluator.Evaluate(PlacementTopology.ToPlacementRequest(intent));
        await Assert.That(decision.Accepted).IsTrue();
        var repeat = DatabasePlacementEvaluator.Evaluate(PlacementTopology.ToPlacementRequest(intent));
        await Assert.That(repeat.Fingerprint).IsEqualTo(decision.Fingerprint);
    }

    [Test]
    public async Task InvalidIntentDocumentIsRejectedWithZeroMutations()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var server = await PlacementNatsServer.StartAsync();
        var fleet = new FakeMemberHostFleet();
        var authority = new PlacementAuthorityHolder();
        var reconciler = PlacementTestHarness.Reconciler(server, fleet, authority);
        // A hand-written duplicate-Region intent can never pass validation or admission.
        await server.Delivery.PutAsync(
            PlacementIntentDocument.Key("prod-db"),
            JsonSerializer.Serialize(
                PlacementTestHarness.Intent("prod-db", 1, "GRU", "GRU"),
                TerraBasePlacementJsonContext.Default.PlacementIntentDocument));

        var result = await reconciler.TickAsync(CancellationToken.None);

        await Assert.That(result.State).IsEqualTo(PlacementTickObservation.StateRejected);
        await Assert.That(result.Database).IsEqualTo("prod-db");
        await Assert.That(fleet.Calls).IsEmpty();
        await Assert.That((await PlacementTestHarness.MemberStatesAsync(server.Delivery, "prod-db"))).IsEmpty();
    }

    [Test]
    public async Task NotLeaderTickMutatesNothing()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var server = await PlacementNatsServer.StartAsync();
        var fleet = new FakeMemberHostFleet();
        var authority = new PlacementAuthorityHolder { IsLeader = false };
        var reconciler = PlacementTestHarness.Reconciler(server, fleet, authority);
        await PlacementTestHarness.ApplyIntentAsync(server.Delivery, "prod-db", 1, "GRU");

        var result = await reconciler.TickAsync(CancellationToken.None);

        await Assert.That(result.State).IsEqualTo(PlacementTickObservation.StateNotLeader);
        await Assert.That(fleet.Calls).IsEmpty();
        var status = await PlacementTestHarness.ReadStatusAsync(server.Runtime);
        await Assert.That(status!.State).IsEqualTo(PlacementTickObservation.StateNotLeader);
    }

    [Test]
    public async Task AuthorityLostMidTickAbortsBeforeTheProvision()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var server = await PlacementNatsServer.StartAsync();
        var fleet = new FakeMemberHostFleet();
        var authority = new PlacementAuthorityHolder();
        var reconciler = PlacementTestHarness.Reconciler(server, fleet, authority);
        await PlacementTestHarness.ApplyIntentAsync(server.Delivery, "prod-db", 1, "GRU");
        // The fleet observation is the last read before the mutation: leadership dies there.
        fleet.OnObserve = () => authority.IsLeader = false;

        var result = await reconciler.TickAsync(CancellationToken.None);

        await Assert.That(result.State).IsEqualTo(PlacementTickObservation.StateAuthorityLost);
        await Assert.That(fleet.Calls).IsEmpty();
        // The durable member record exists but no host was ever created; the next
        // leader tick continues from it with the same idempotent create key.
        var members = await PlacementTestHarness.MemberStatesAsync(server.Delivery, "prod-db");
        await Assert.That(members.Count).IsEqualTo(1);
        await Assert.That(members[0].InstanceId).IsNull();
    }

    [Test]
    public async Task ExactlyOneMemberActionPerTick()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var server = await PlacementNatsServer.StartAsync();
        var fleet = new FakeMemberHostFleet();
        var authority = new PlacementAuthorityHolder();
        var reconciler = PlacementTestHarness.Reconciler(server, fleet, authority);
        await PlacementTestHarness.ApplyIntentAsync(server.Delivery, "prod-db", 1, "GRU", "SFO");

        await reconciler.TickAsync(CancellationToken.None);
        await Assert.That(fleet.Calls.Count).IsEqualTo(1);
        await reconciler.TickAsync(CancellationToken.None);
        await Assert.That(fleet.Calls.Count).IsEqualTo(1);
        await reconciler.TickAsync(CancellationToken.None);
        await Assert.That(fleet.Calls.Count).IsEqualTo(2);
    }

    [Test]
    public async Task ProvisionFailureIsRecordedAndRetriedWithTheSameCreateKey()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var server = await PlacementNatsServer.StartAsync();
        var fleet = new FakeMemberHostFleet();
        var authority = new PlacementAuthorityHolder();
        var reconciler = PlacementTestHarness.Reconciler(server, fleet, authority);
        await PlacementTestHarness.ApplyIntentAsync(server.Delivery, "prod-db", 1, "GRU");

        fleet.ProvisionFailure = new InvalidOperationException("quota exhausted");
        var failed = await reconciler.TickAsync(CancellationToken.None);
        await Assert.That(failed.State).IsEqualTo(PlacementTickObservation.StateError);
        await Assert.That(failed.Error).IsEqualTo(nameof(InvalidOperationException));

        fleet.ProvisionFailure = null;
        var retried = await reconciler.TickAsync(CancellationToken.None);
        await Assert.That(retried.State).IsEqualTo("provision");
        await Assert.That(fleet.Calls.Count).IsEqualTo(2);
        // The retry resolved to the same idempotent create key, never a second identity.
        await Assert.That(fleet.Calls[1]).IsEqualTo(fleet.Calls[0]);
        await Assert.That(fleet.Calls[0].EndsWith(".r1.h1", StringComparison.Ordinal)).IsTrue();
    }

    [Test]
    public async Task RemovalRefusesWhileTheVictimsObservationIsMissing()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var server = await PlacementNatsServer.StartAsync();
        var fleet = new FakeMemberHostFleet();
        var authority = new PlacementAuthorityHolder();
        var reconciler = PlacementTestHarness.Reconciler(server, fleet, authority);
        await PlacementTestHarness.ConvergeAsync(server, fleet, authority, reconciler, "prod-db", 1, "GRU");
        // A recorded extra member whose host is not in the listing — and not yet
        // confirmed dead (first missing tick): the graceful gate must refuse.
        await server.Delivery.PutAsync(
            PlacementMemberStateDocument.Key("prod-db", "elastic-x"),
            JsonSerializer.Serialize(
                new PlacementMemberStateDocument(
                    1, "prod-db", "elastic-x", "GRU", nameof(TerraBaseMemberKind.Elastic),
                    PlacementMemberStateDocument.StageServing,
                    "ocid1.instance.fake.99", null, 1, 1, null, DateTimeOffset.UtcNow),
                TerraBasePlacementJsonContext.Default.PlacementMemberStateDocument));

        var result = await reconciler.TickAsync(CancellationToken.None);

        await Assert.That(result.State).IsEqualTo(PlacementTickObservation.StateHeld);
        await Assert.That(result.Member).IsEqualTo("elastic-x");
        await Assert.That(fleet.Calls.Where(static call =>
            call.StartsWith("cordon:", StringComparison.Ordinal) ||
            call.StartsWith("retire:", StringComparison.Ordinal))).IsEmpty();
    }

    [Test]
    public async Task ComputeFloorRefusesRemovalBelowThreeHealthySurvivors()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var server = await PlacementNatsServer.StartAsync();
        var fleet = new FakeMemberHostFleet();
        var authority = new PlacementAuthorityHolder();
        var reconciler = PlacementTestHarness.Reconciler(server, fleet, authority);
        await PlacementTestHarness.ConvergeAsync(server, fleet, authority, reconciler, "prod-db", 1, "GRU");
        var instance = fleet.AddRunningHost("prod-db", "elastic-x", "GRU");
        await server.Delivery.PutAsync(
            PlacementMemberStateDocument.Key("prod-db", "elastic-x"),
            JsonSerializer.Serialize(
                new PlacementMemberStateDocument(
                    1, "prod-db", "elastic-x", "GRU", nameof(TerraBaseMemberKind.Elastic),
                    PlacementMemberStateDocument.StageServing,
                    instance, null, 1, 1, null, DateTimeOffset.UtcNow),
                TerraBasePlacementJsonContext.Default.PlacementMemberStateDocument));

        var result = await reconciler.TickAsync(CancellationToken.None);

        await Assert.That(result.State).IsEqualTo(PlacementTickObservation.StateHeld);
        await Assert.That(result.Member).IsEqualTo("elastic-x");
        await Assert.That(fleet.Calls.Where(static call => call.StartsWith("cordon:", StringComparison.Ordinal))).IsEmpty();
    }

    [Test]
    public async Task LeaderRemovalWaitsForTwoConsecutiveTicksOfObservedTransfer()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var server = await PlacementNatsServer.StartAsync();
        var fleet = new FakeMemberHostFleet();
        var authority = new PlacementAuthorityHolder();
        var reconciler = PlacementTestHarness.Reconciler(server, fleet, authority);
        await PlacementTestHarness.ConvergeAsync(server, fleet, authority, reconciler, "prod-db", 1, "GRU", "SFO");
        var instance = fleet.AddRunningHost("prod-db", "elastic-x", "GRU", up: true, lag: 0, role: "leader");
        await server.Delivery.PutAsync(
            PlacementMemberStateDocument.Key("prod-db", "elastic-x"),
            JsonSerializer.Serialize(
                new PlacementMemberStateDocument(
                    1, "prod-db", "elastic-x", "GRU", nameof(TerraBaseMemberKind.Elastic),
                    PlacementMemberStateDocument.StageServing,
                    instance, null, 1, 1, null, DateTimeOffset.UtcNow),
                TerraBasePlacementJsonContext.Default.PlacementMemberStateDocument));
        // A different member reports Leader — the transfer this reconciler only observes.
        fleet.SetHealth(fleet.Instances[0], up: true, lag: 0, role: "leader");

        var waiting = await reconciler.TickAsync(CancellationToken.None);
        await Assert.That(waiting.State).IsEqualTo(PlacementTickObservation.StateTransferWait);
        await Assert.That(waiting.Member).IsEqualTo("elastic-x");
        await Assert.That(fleet.Calls.Where(static call =>
            call.StartsWith("cordon:", StringComparison.Ordinal) ||
            call.StartsWith("retire:", StringComparison.Ordinal))).IsEmpty();

        var transferred = await reconciler.TickAsync(CancellationToken.None);
        await Assert.That(transferred.State).IsEqualTo("cordon");
        await Assert.That(transferred.Member).IsEqualTo("elastic-x");
        await Assert.That(fleet.Calls.Count(static call => call.StartsWith("cordon:", StringComparison.Ordinal)))
            .IsEqualTo(1);
    }

    [Test]
    public async Task EdgeProjectionFiltersByHealthAndTheFingerprintTracksIt()
    {
        var intent = PlacementTestHarness.Intent("prod-db", 3, "GRU", "SFO");
        var gruSeat = PlacementTopology.Seats(intent)[0];
        var sfoSeat = PlacementTopology.Seats(intent)[2];
        var gruLeader = Member("prod-db", "permanent-a", "GRU", gruSeat, healthy: true, leader: true);
        var world = new PlacementWorldSnapshot(
            [new(intent, [gruLeader, Member("prod-db", "elastic-gru", "GRU", gruSeat, healthy: false)])],
            []);

        var snapshot = TerraBasePlacementEdgeSource.Project(world);
        var branch = snapshot.Databases["prod-db"].Branches["main"];
        await Assert.That(branch.Count).IsEqualTo(2);
        await Assert.That(branch[0].Region).IsEqualTo(RegionCode.Gru);
        await Assert.That(branch[0].Read).IsTrue();
        await Assert.That(branch[0].Write).IsTrue();
        await Assert.That(branch[1].Region).IsEqualTo(RegionCode.Sfo);
        await Assert.That(branch[1].Read).IsFalse();
        await Assert.That(branch[1].Write).IsFalse();
        var healthy = TerraBasePlacementEdgeSource.Fingerprint(snapshot);

        var recovered = TerraBasePlacementEdgeSource.Project(new(
            [new(intent, [gruLeader, Member("prod-db", "elastic-sfo", "SFO", sfoSeat, healthy: true)])],
            []));
        await Assert.That(recovered.Databases["prod-db"].Branches["main"][1].Read).IsTrue();
        await Assert.That(TerraBasePlacementEdgeSource.Fingerprint(recovered)).IsNotEqualTo(healthy);
    }

    private static PlacementMemberSnapshot Member(
        string database,
        string member,
        string region,
        PlacementTopology.DesiredSeat? seat,
        bool healthy,
        bool leader = false) => new(
        new PlacementMemberStateDocument(
            1, database, member, region, nameof(TerraBaseMemberKind.Elastic),
            PlacementMemberStateDocument.StageServing,
            $"ocid1.instance.fake.{member}", null, 1, 1, null, DateTimeOffset.UtcNow),
        Revision: 1,
        Observation: null,
        seat,
        healthy,
        leader);
}
