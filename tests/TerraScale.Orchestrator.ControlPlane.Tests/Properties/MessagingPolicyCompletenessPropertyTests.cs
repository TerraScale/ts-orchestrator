using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class MessagingPolicyCompletenessPropertyTests
{
    private const int Cases = 1_000;

    [Test]
    public async Task ReplacementResourceSafetyRejectsEveryCriticalAndInvalidPolicyMutationFor1000Cases()
    {
        var first = RunSafetyMatrix("tr-TR");
        var replay = RunSafetyMatrix("ar-SA");

        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Coverage).IsEqualTo(16);
    }

    [Test]
    public async Task ReplacementResourceSafetyPreservesExplicitBoundedAndCriticalPoliciesFor1000Cases()
    {
        var first = RunAcceptedMatrix("tr-TR");
        var replay = RunAcceptedMatrix("ja-JP");

        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Coverage).IsEqualTo(3);
    }

    [Test]
    public async Task ReplacementHardeningPreservesTopologySingletonErrorSets()
    {
        var product = TopologyPlane(MessagingPlane.Product, "product", membershipFloor: 3, serverCount: 3,
            resourceReplicas: 3);
        var malformedFloor = MessagingPolicyEngine.DecideTopology(new(
            TopologyPlane(MessagingPlane.Control, "control", membershipFloor: 1, serverCount: 1,
                resourceReplicas: 1),
            product, 96, 160, 100, Features()));
        var validTwoServerFloor = MessagingPolicyEngine.DecideTopology(new(
            TopologyPlane(MessagingPlane.Control, "control", membershipFloor: 2, serverCount: 2,
                resourceReplicas: 1),
            product, 96, 160, 100, Features()));

        await Assert.That(malformedFloor.Errors.Select(static error => error.Code))
            .IsEquivalentTo([MessagingErrorCode.InvalidInput]);
        await Assert.That(validTwoServerFloor.Errors.Select(static error => error.Code))
            .IsEquivalentTo([MessagingErrorCode.DurabilityViolation]);
        await Assert.That(malformedFloor.Intents.Single()).IsTypeOf<HoldMessagingIntent>();
        await Assert.That(validTwoServerFloor.Intents.Single()).IsTypeOf<HoldMessagingIntent>();
        await Assert.That(malformedFloor.Trace.Single())
            .IsEqualTo(new MessagingTrace(1, MessagingTraceCode.Held, MessagingAction.Hold));
        await Assert.That(validTwoServerFloor.Trace.Single())
            .IsEqualTo(new MessagingTrace(1, MessagingTraceCode.Held, MessagingAction.Hold));
    }

    private static Summary RunSafetyMatrix(string culture)
    {
        var previous = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
            var coverage = new HashSet<int>();
            ulong digest = 0;
            for (var index = 0; index < Cases; index++)
            {
                var mode = index % 16;
                var request = mode switch
                {
                    0 => Scenario(index, stream => stream with { Replicas = 2 }),
                    1 => Scenario(index, mutateBucket: bucket => bucket with { Replicas = 2 }),
                    2 => Scenario(index, stream => stream with { Acknowledgement = MessagingAcknowledgement.Leader }),
                    3 => Scenario(index, mutateBucket: bucket => bucket with { Acknowledgement = MessagingAcknowledgement.Leader }),
                    4 => Scenario(index, stream => stream with { Acknowledgement = MessagingAcknowledgement.NoAck }),
                    5 => Scenario(index, mutateBucket: bucket => bucket with { Acknowledgement = MessagingAcknowledgement.NoAck }),
                    6 => Scenario(index, stream => stream with { DiskSyncClass = MessagingDiskSyncClass.BoundedLoss }),
                    7 => Scenario(index, mutateBucket: bucket => bucket with { DiskSyncClass = MessagingDiskSyncClass.BoundedLoss }),
                    8 => Scenario(index, stream => stream with { Durability = MessagingDurability.Unspecified }),
                    9 => Scenario(index, mutateBucket: bucket => bucket with { Durability = (MessagingDurability)999 }),
                    10 => Scenario(index, stream => stream with { Acknowledgement = MessagingAcknowledgement.Unspecified }),
                    11 => Scenario(index, mutateBucket: bucket => bucket with { Acknowledgement = (MessagingAcknowledgement)999 }),
                    12 => Scenario(index, stream => stream with { DiskSyncClass = MessagingDiskSyncClass.Unspecified }),
                    13 => Scenario(index, mutateBucket: bucket => bucket with { DiskSyncClass = (MessagingDiskSyncClass)999 }),
                    14 => Scenario(index, stream => stream with { Replicas = 4 }),
                    _ => Scenario(index, mutateBucket: bucket => bucket with { Replicas = 4 }),
                };
                var expected = mode < 8 ? MessagingErrorCode.DurabilityViolation : MessagingErrorCode.InvalidInput;
                VerifyHeld(MessagingPolicyEngine.DecideReplacement(request), request, expected, index);
                VerifyHeld(MessagingPolicyEngine.DecideReplacement(Reverse(request)), request, expected, index);
                coverage.Add(mode);
                digest = Mix(digest, expected, request.Proposed.AuthorityEpoch);
            }
            return new(Cases, coverage.Count, digest);
        }
        finally
        {
            CultureInfo.CurrentCulture = previous;
        }
    }

    private static Summary RunAcceptedMatrix(string culture)
    {
        var previous = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
            var coverage = new HashSet<int>();
            ulong digest = 0;
            for (var index = 0; index < Cases; index++)
            {
                var mode = index % 3;
                var request = mode switch
                {
                    0 => Scenario(index, stream => stream with
                    {
                        Replicas = 1,
                        Durability = MessagingDurability.Bounded,
                        Acknowledgement = MessagingAcknowledgement.NoAck,
                        DiskSyncClass = MessagingDiskSyncClass.BoundedLoss,
                    }),
                    1 => Scenario(index, mutateBucket: bucket => bucket with
                    {
                        Replicas = 1,
                        Durability = MessagingDurability.Bounded,
                        Acknowledgement = MessagingAcknowledgement.NoAck,
                        DiskSyncClass = MessagingDiskSyncClass.BoundedLoss,
                    }),
                    _ => Scenario(index),
                };
                VerifyRemove(MessagingPolicyEngine.DecideReplacement(request), request, index);
                VerifyRemove(MessagingPolicyEngine.DecideReplacement(Reverse(request)), request, index);
                coverage.Add(mode);
                digest = Mix(digest, MessagingErrorCode.Unspecified, request.Proposed.AuthorityEpoch);
            }
            return new(Cases, coverage.Count, digest);
        }
        finally
        {
            CultureInfo.CurrentCulture = previous;
        }
    }

    private static ReplacementRequest Scenario(
        int index,
        Func<StreamPolicy, StreamPolicy>? mutateStream = null,
        Func<BucketPolicy, BucketPolicy>? mutateBucket = null)
    {
        var suffix = index.ToString(CultureInfo.InvariantCulture);
        var servers = Enumerable.Range(1, 3).Select(number => new ServerPolicy(
            new ServerId($"control-server-{suffix}-{number}"),
            new PeerId($"control-peer-{suffix}-{number}"),
            new PlacementId($"control-host-{suffix}-{number}"))).ToArray();
        var account = new AccountId($"control-account-{suffix}");
        var stream = new StreamPolicy(new StreamId($"control-stream-{suffix}"), account,
            $"ts.control{suffix}.stream.>", 3, MessagingDurability.Critical, MessagingRetention.Limits,
            100, 1_000_000, MessagingDiscard.Old, new PlacementId("regional"), 10,
            MessagingAcknowledgement.Replicated, MessagingDiskSyncClass.AcknowledgedWriteStrict);
        var bucket = new BucketPolicy(new BucketId($"control-bucket-{suffix}"), account,
            $"ts.control{suffix}.kv.>", 3, MessagingDurability.Critical, 100, 1_000_000,
            new PlacementId("regional"), MessagingAcknowledgement.Replicated,
            MessagingDiskSyncClass.AcknowledgedWriteStrict);
        stream = mutateStream?.Invoke(stream) ?? stream;
        bucket = mutateBucket?.Invoke(bucket) ?? bucket;
        var policy = new PlanePolicy(MessagingPlane.Control, new CellId($"cell-{suffix}"),
            new ClusterId($"control-cluster-{suffix}"), generation: 7, membershipFloor: 3, servers,
            servers.SelectMany(from => servers.Where(to => to.Server != from.Server)
                .Select(to => new RouteLink(from.Server, to.Server))),
            [new ClusterId($"fra-control-{suffix}")],
            [new AccountPolicy(account, [$"ts.control{suffix}.>"])], [stream], [bucket]);
        var operation = new ReplacementOperation(new MessagingOperationId($"replace-{suffix}"),
            MessagingPlane.Control, policy.Cell, policy.Cluster, index + 1L, index + 11L, policy.Generation,
            100, 200, servers[2].Server, servers[2].Peer, new ServerId($"replacement-server-{suffix}"),
            new PeerId($"replacement-peer-{suffix}"), new PlacementId($"replacement-host-{suffix}"));
        var peers = new PeerObservation[]
        {
            new(operation.FailedServer, operation.FailedPeer, PeerHealth.Failed, StoreClassification.Lost,
                ProcessFenced: true, OwnershipProven: false, CaughtUp: false),
            new(servers[0].Server, servers[0].Peer, PeerHealth.Current, StoreClassification.Surviving,
                ProcessFenced: false, OwnershipProven: true, CaughtUp: true),
            new(servers[1].Server, servers[1].Peer, PeerHealth.Current, StoreClassification.Surviving,
                ProcessFenced: false, OwnershipProven: true, CaughtUp: true),
            new(operation.ReplacementServer, operation.ReplacementPeer, PeerHealth.Current, StoreClassification.Surviving,
                ProcessFenced: false, OwnershipProven: true, CaughtUp: true),
        };
        var observation = new ClusterObservation(new MessagingObservationId($"observation-{suffix}"),
            policy.Cluster, policy.Generation, 150, peers,
            [new ReplicaObservation(stream.Id.Value, stream.Replicas, stream.Replicas, 50)],
            [new ReplicaObservation(bucket.Id.Value, bucket.Replicas, bucket.Replicas, 50)]);
        return new(policy, operation, operation, observation, 96);
    }

    private static ReplacementRequest Reverse(ReplacementRequest request)
    {
        var policy = request.Policy;
        var reversedPolicy = new PlanePolicy(policy.Plane, policy.Cell, policy.Cluster, policy.Generation,
            policy.MembershipFloor, policy.Servers.Reverse(), policy.Routes.Reverse(), policy.Gateways.Reverse(),
            policy.Accounts.Reverse(), policy.Streams.Reverse(), policy.Buckets.Reverse());
        var observation = request.Observation!;
        var reversedObservation = new ClusterObservation(observation.ObservationId, observation.Cluster,
            observation.ConfigurationGeneration, observation.MembershipSequence, observation.Peers.Reverse(),
            observation.StreamReplicas.Reverse(), observation.BucketReplicas.Reverse());
        return request with { Policy = reversedPolicy, Observation = reversedObservation };
    }

    private static PlanePolicy TopologyPlane(MessagingPlane plane, string prefix,
        int membershipFloor, int serverCount, int resourceReplicas)
    {
        var servers = Enumerable.Range(1, serverCount).Select(index => new ServerPolicy(
            new ServerId($"{prefix}-topology-server-{index}"),
            new PeerId($"{prefix}-topology-peer-{index}"),
            new PlacementId($"{prefix}-topology-host-{index}"))).ToArray();
        var account = new AccountId($"{prefix}-topology-account");
        return new PlanePolicy(plane, new CellId("topology-cell"), new ClusterId($"{prefix}-topology-cluster"),
            generation: 1, membershipFloor, servers,
            servers.SelectMany(from => servers.Where(to => to.Server != from.Server)
                .Select(to => new RouteLink(from.Server, to.Server))),
            plane == MessagingPlane.Control ? [new ClusterId("remote-control-cluster")] : [],
            [new AccountPolicy(account, [$"ts.{prefix}.>"])],
            [new StreamPolicy(new StreamId($"{prefix}-topology-stream"), account, $"ts.{prefix}.stream.>",
                resourceReplicas, MessagingDurability.Critical, MessagingRetention.Limits, 100, 1_000,
                MessagingDiscard.Old, new PlacementId("regional"), 10, MessagingAcknowledgement.Replicated,
                MessagingDiskSyncClass.AcknowledgedWriteStrict)],
            [new BucketPolicy(new BucketId($"{prefix}-topology-bucket"), account, $"ts.{prefix}.kv.>",
                resourceReplicas, MessagingDurability.Critical, 100, 1_000, new PlacementId("regional"),
                MessagingAcknowledgement.Replicated, MessagingDiskSyncClass.AcknowledgedWriteStrict)]);
    }

    private static CompatibilityFeature[] Features() => Enum.GetValues<CompatibilityFeature>()
        .Where(static feature => feature != CompatibilityFeature.Unspecified).ToArray();

    private static void VerifyHeld(MessagingDecision decision, ReplacementRequest request,
        MessagingErrorCode expected, int index)
    {
        Require(decision.Errors.Count == 1, "error-count", index);
        var error = decision.Errors[0];
        Require(error.Code == expected && error.Requirement == "INV-005" && error.Operation == request.Proposed.OperationId &&
            error.Server == request.Proposed.FailedServer && error.Peer == request.Proposed.FailedPeer, "error-subject", index);
        Require(decision.Intents.Count == 1 && decision.Intents[0] is HoldMessagingIntent hold &&
            hold.Reason == expected && hold.Operation == request.Proposed.OperationId &&
            hold.Server == request.Proposed.FailedServer && hold.Peer == request.Proposed.FailedPeer,
            "hold-subject", index);
        Require(decision.Intents.All(static intent => intent is not RemovePeerIntent), "no-remove", index);
        Require(decision.Trace.Count == 1 && decision.Trace[0] ==
            new MessagingTrace(1, MessagingTraceCode.Held, MessagingAction.Hold), "hold-trace", index);
    }

    private static void VerifyRemove(MessagingDecision decision, ReplacementRequest request, int index)
    {
        Require(decision.Errors.Count == 0 && decision.Intents.Count == 1 &&
            decision.Intents[0] is RemovePeerIntent, "remove-count", index);
        var remove = (RemovePeerIntent)decision.Intents[0];
        var operation = request.Proposed;
        Require(remove.Operation == operation.OperationId && remove.Cluster == operation.Cluster &&
            remove.FailedServer == operation.FailedServer && remove.FailedPeer == operation.FailedPeer &&
            remove.ReplacementPeer == operation.ReplacementPeer &&
            remove.VerifiedMembershipSequence == request.Observation!.MembershipSequence &&
            remove.AuthorityEpoch == operation.AuthorityEpoch, "remove-subject", index);
        Require(decision.Trace.Count == 1 && decision.Trace[0] ==
            new MessagingTrace(1, MessagingTraceCode.FailedPeerRemovalAllowed, MessagingAction.RemovePeer),
            "remove-trace", index);
    }

    private static void Require(bool condition, string family, int index)
    {
        if (!condition) throw new InvalidOperationException($"{family} failed at {index}.");
    }

    private static ulong Mix(ulong digest, MessagingErrorCode code, long value) =>
        unchecked((digest ^ (uint)code ^ (ulong)value) * 1099511628211UL);

    private sealed record Summary(int Cases, int Coverage, ulong Digest);
}
