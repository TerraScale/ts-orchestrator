using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class MessagingPolicyEngineTests
{
    [Test]
    public async Task DualPlaneTopologyIsDeterministicAcrossPermutationAndCulture()
    {
        var originalCulture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("tr-TR");
            var first = MessagingPolicyEngine.DecideTopology(Topology());
            CultureInfo.CurrentCulture = new CultureInfo("en-US");
            var second = MessagingPolicyEngine.DecideTopology(Topology(reverse: true));

            await Assert.That(first.Errors).IsEmpty();
            await Assert.That(second.Errors).IsEmpty();
            await Assert.That(Signature(first)).IsEqualTo(Signature(second));
            await Assert.That(first.Intents.Count).IsEqualTo(2);
            await Assert.That(((ConfigurePlaneIntent)first.Intents[0]).Policy.Streams).HasSingleItem();
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
        }
    }

    [Test]
    public async Task ControlAndProductIsolationRejectsEverySharedAuthoritySurface()
    {
        var baseline = Topology();
        var cases = new MessagingTopologyPolicy[]
        {
            Topology(product: Product(cluster: baseline.Control.Cluster)),
            Topology(product: Product(servers: Servers("control"), routes: Routes("control"))),
            Topology(product: Product(accounts:
            [
                Account("product-account", "ts.product.>"),
                Account("control-account", "aux.control.>"),
            ])),
            Topology(product: Product(streams: [Stream("control-stream", "product-account", "ts.product.stream.>")])),
            Topology(product: Product(buckets: [Bucket("control-bucket", "product-account", "ts.product.kv.>")])),
            Topology(product: Product(accounts: [Account("product-account", "ts.control.child.>")])),
            Topology(product: Product(gateways: [new ClusterId("remote-product")])),
        };

        foreach (var policy in cases)
            await AssertHeld(MessagingPolicyEngine.DecideTopology(policy), MessagingErrorCode.IsolationViolation);
    }

    [Test]
    public async Task CriticalDurabilityRequiresFullFloorReplicatedAckAndStrictSync()
    {
        var cases = new[]
        {
            Stream("control-stream", "control-account", "ts.control.stream.>") with { Replicas = 1 },
            Stream("control-stream", "control-account", "ts.control.stream.>") with { Acknowledgement = MessagingAcknowledgement.Leader },
            Stream("control-stream", "control-account", "ts.control.stream.>") with { DiskSyncClass = MessagingDiskSyncClass.BoundedLoss },
        };
        foreach (var stream in cases)
        {
            var control = Control(streams: [stream]);
            await AssertHeld(MessagingPolicyEngine.DecideTopology(Topology(control: control)), MessagingErrorCode.DurabilityViolation);
        }

        var cycleRoutes = Control(routes:
        [
            new(new ServerId("control-server-1"), new ServerId("control-server-2")),
            new(new ServerId("control-server-2"), new ServerId("control-server-3")),
            new(new ServerId("control-server-3"), new ServerId("control-server-1")),
        ]);
        await Assert.That(MessagingPolicyEngine.DecideTopology(Topology(control: cycleRoutes)).Errors).IsEmpty();

        var incompleteRoutes = Control(routes:
        [
            new(new ServerId("control-server-1"), new ServerId("control-server-2")),
            new(new ServerId("control-server-2"), new ServerId("control-server-1")),
            new(new ServerId("control-server-2"), new ServerId("control-server-3")),
        ]);
        await AssertHeld(MessagingPolicyEngine.DecideTopology(Topology(control: incompleteRoutes)), MessagingErrorCode.IncompleteObservation);
    }

    [Test]
    public async Task UnknownCatalogValuesAndUnsafeScalarsFailClosed()
    {
        var unknown = new MessagingTopologyPolicy(Control(), Product(), 64, 128, 100,
            [(CompatibilityFeature)999]);
        await AssertHeld(MessagingPolicyEngine.DecideTopology(unknown), MessagingErrorCode.InvalidCatalog);

        var unsafeAccount = Product(accounts: [Account("bad\naccount", "ts.product.>")]);
        await AssertHeld(MessagingPolicyEngine.DecideTopology(Topology(product: unsafeAccount)), MessagingErrorCode.InvalidInput);

        var crossAccount = Product(accounts:
        [
            Account("product-account", "ts.product.>"),
            Account("product-audit", "ts.product.audit.>"),
        ]);
        await AssertHeld(MessagingPolicyEngine.DecideTopology(Topology(product: crossAccount)), MessagingErrorCode.IsolationViolation);

        var outsideAccount = Product(streams: [Stream("product-stream", "product-account", "ts.other.>")]);
        await AssertHeld(MessagingPolicyEngine.DecideTopology(Topology(product: outsideAccount)), MessagingErrorCode.IsolationViolation);

        foreach (var malformed in new[] { "ts..product", ".ts.product", "ts.product.", "ts.*.product", "ts.>.product", "TS.product", "ts.product.>>" })
        {
            var malformedSubject = Product(accounts: [Account("product-account", malformed)]);
            await AssertHeld(MessagingPolicyEngine.DecideTopology(Topology(product: malformedSubject)), MessagingErrorCode.InvalidInput);
        }

        await Assert.That(Throws<ArgumentException>(() => Account("product-account", null!))).IsTrue();
    }

    [Test]
    public async Task LostPeerReplacementFollowsPersistAddCatchupVerifyRemoveOrder()
    {
        var operation = Operation();
        var policy = Control();

        var observe = MessagingPolicyEngine.DecideReplacement(new(policy, operation, null, null, 64));
        await Assert.That(observe.Intents.Single()).IsTypeOf<ObserveClusterIntent>();

        var failed = Observation(operation, includeReplacement: false, caughtUp: false, replicas: 2);
        var persist = MessagingPolicyEngine.DecideReplacement(new(policy, operation, null, failed, 64));
        await Assert.That(persist.Intents.Single()).IsTypeOf<ConfigureReplacementIntent>();

        var add = MessagingPolicyEngine.DecideReplacement(new(policy, operation, operation, failed, 64));
        await Assert.That(add.Intents.Single()).IsTypeOf<AddPeerIntent>();

        var added = Observation(operation, includeReplacement: true, caughtUp: false, replicas: 2);
        var wait = MessagingPolicyEngine.DecideReplacement(new(policy, operation, operation, added, 64));
        await Assert.That(wait.Intents.Single()).IsTypeOf<WaitCatchupIntent>();

        var caughtButUnverified = Observation(operation, includeReplacement: true, caughtUp: true, replicas: 2);
        var verify = MessagingPolicyEngine.DecideReplacement(new(policy, operation, operation, caughtButUnverified, 64));
        await Assert.That(verify.Intents.Single()).IsTypeOf<WaitCatchupIntent>();
        await Assert.That(verify.Trace.Single().Code).IsEqualTo(MessagingTraceCode.ReplicaVerificationRequired);

        var verified = Observation(operation, includeReplacement: true, caughtUp: true, replicas: 3);
        var remove = MessagingPolicyEngine.DecideReplacement(new(policy, operation, operation, verified, 64));
        var removeIntent = (RemovePeerIntent)remove.Intents.Single();
        await Assert.That(removeIntent.FailedPeer).IsEqualTo(operation.FailedPeer);
        await Assert.That(removeIntent.ReplacementPeer).IsEqualTo(operation.ReplacementPeer);

        var complete = MessagingPolicyEngine.DecideReplacement(new(policy, operation, operation,
            Observation(operation, true, true, 3, includeFailed: false), 64));
        await Assert.That(complete.Errors).IsEmpty();
        await Assert.That(complete.Intents).IsEmpty();
        await Assert.That(complete.Trace.Single().Code).IsEqualTo(MessagingTraceCode.ReplacementComplete);
    }

    [Test]
    public async Task LostAddResponseReplaysFromMembershipAndNeverAddsTwice()
    {
        var operation = Operation();
        var decision = MessagingPolicyEngine.DecideReplacement(new(
            Control(), operation, operation, Observation(operation, true, false, 2), 64));

        await Assert.That(decision.Intents.Single()).IsTypeOf<WaitCatchupIntent>();
        await Assert.That(decision.Intents.Any(static intent => intent is AddPeerIntent)).IsFalse();
    }

    [Test]
    public async Task SurvivingStoreReattachBindsExactProofAndLostResponseDoesNotReattachTwice()
    {
        var operation = Operation();
        var initial = SurvivingObservation(operation, activeAttachment: null);
        var decision = MessagingPolicyEngine.DecideReplacement(new(Control(), operation, operation, initial, 64));
        var intent = (ReattachSurvivingStoreIntent)decision.Intents.Single();
        await Assert.That(decision.Intents.Any(static value => value is AddPeerIntent or RemovePeerIntent)).IsFalse();

        await Assert.That(intent.Operation).IsEqualTo(operation.OperationId);
        await Assert.That(intent.Plane).IsEqualTo(operation.Plane);
        await Assert.That(intent.Cell).IsEqualTo(operation.Cell);
        await Assert.That(intent.Cluster).IsEqualTo(operation.Cluster);
        await Assert.That(intent.RecordedServer).IsEqualTo(operation.FailedServer);
        await Assert.That(intent.RecordedPeer).IsEqualTo(operation.FailedPeer);
        await Assert.That(intent.ReplacementPlacement).IsEqualTo(operation.ReplacementPlacement);
        await Assert.That(intent.Store).IsEqualTo(new StoreId("control-store-3"));
        await Assert.That(intent.StoreGeneration).IsEqualTo(4);
        await Assert.That(intent.OwnershipEpoch).IsEqualTo(operation.AuthorityEpoch);

        var replay = MessagingPolicyEngine.DecideReplacement(new(Control(), operation, operation,
            SurvivingObservation(operation, operation.FailedServer), 64));
        await Assert.That(replay.Errors).IsEmpty();
        await Assert.That(replay.Intents).IsEmpty();
        await Assert.That(replay.Trace.Single().Code).IsEqualTo(MessagingTraceCode.ReplacementComplete);

        var swapped = MessagingPolicyEngine.DecideReplacement(new(Control(), operation, operation,
            SurvivingObservation(operation, operation.FailedServer, includeReplacement: true), 64));
        await AssertHeld(swapped, MessagingErrorCode.ConflictingEvidence);
    }

    [Test]
    public async Task SurvivingStoreRejectsConflictingAttachmentWrongPlaneAndStaleProof()
    {
        var operation = Operation();
        var policy = Control();
        await AssertHeld(MessagingPolicyEngine.DecideReplacement(new(policy, operation, operation,
            SurvivingObservation(operation, new ServerId("other-server")), 64)), MessagingErrorCode.ConflictingEvidence);

        await AssertHeld(MessagingPolicyEngine.DecideReplacement(new(policy, operation, operation,
            SurvivingObservation(operation, null, plane: MessagingPlane.Product), 64)), MessagingErrorCode.IsolationViolation);

        await AssertHeld(MessagingPolicyEngine.DecideReplacement(new(policy, operation, operation,
            SurvivingObservation(operation, null, proofSequence: 149), 64)), MessagingErrorCode.StaleEvidence);

        await AssertHeld(MessagingPolicyEngine.DecideReplacement(new(policy, operation, operation,
            SurvivingObservation(operation, null, ownershipEpoch: 8), 64)), MessagingErrorCode.StaleEvidence);

        await AssertHeld(MessagingPolicyEngine.DecideReplacement(new(policy, operation, operation,
            SurvivingObservation(operation, null, compatible: false), 64)), MessagingErrorCode.ConflictingEvidence);
    }

    [Test]
    public async Task RemovalBeforeCatchupFloorOrReplicaProofIsDenied()
    {
        var operation = Operation();
        var policy = Control();
        var beforeCatchup = MessagingPolicyEngine.DecideReplacement(new(
            policy, operation, operation, Observation(operation, true, false, 3), 64));
        await Assert.That(beforeCatchup.Intents.Single()).IsTypeOf<WaitCatchupIntent>();

        var tooFew = Observation(operation, false, false, 1, currentOriginalPeers: 1);
        await AssertHeld(MessagingPolicyEngine.DecideReplacement(new(policy, operation, operation, tooFew, 64)),
            MessagingErrorCode.MembershipFloorViolation);

        var ambiguous = Observation(operation, false, false, 2, failedStore: StoreClassification.Ambiguous);
        await AssertHeld(MessagingPolicyEngine.DecideReplacement(new(policy, operation, operation, ambiguous, 64)),
            MessagingErrorCode.StoreAmbiguous);
    }

    [Test]
    public async Task ReplacementRejectsConflictDuplicateStaleAndFutureEvidence()
    {
        var operation = Operation();
        var policy = Control();
        var conflictingOperation = operation with { ReplacementPeer = new PeerId("other-peer") };
        await AssertHeld(MessagingPolicyEngine.DecideReplacement(new(policy, operation, conflictingOperation,
            Observation(operation, false, false, 2), 64)), MessagingErrorCode.ReplacementConflict);

        var duplicate = Observation(operation, false, false, 2, duplicatePeer: true);
        await AssertHeld(MessagingPolicyEngine.DecideReplacement(new(policy, operation, operation, duplicate, 64)),
            MessagingErrorCode.DuplicateEvidence);

        var stale = Observation(operation, false, false, 2);
        var staleSnapshot = Clone(stale, membershipSequence: operation.MinimumObservationSequence - 1);
        await AssertHeld(MessagingPolicyEngine.DecideReplacement(new(policy, operation, operation, staleSnapshot, 64)),
            MessagingErrorCode.StaleEvidence);

        var future = Clone(stale, membershipSequence: operation.MaximumObservationSequence + 1);
        await AssertHeld(MessagingPolicyEngine.DecideReplacement(new(policy, operation, operation, future, 64)),
            MessagingErrorCode.FutureEvidence);

        var baseObservation = Observation(operation, false, false, 2);
        var unknownPeers = baseObservation.Peers.Append(new PeerObservation(
            new ServerId("unknown-server"), new PeerId("unknown-peer"), PeerHealth.Current,
            StoreClassification.Surviving, ProcessFenced: false, OwnershipProven: true, CaughtUp: true));
        var unknown = new ClusterObservation(baseObservation.ObservationId, baseObservation.Cluster,
            baseObservation.ConfigurationGeneration, baseObservation.MembershipSequence,
            unknownPeers, baseObservation.StreamReplicas, baseObservation.BucketReplicas);
        await AssertHeld(MessagingPolicyEngine.DecideReplacement(new(policy, operation, operation, unknown, 64)),
            MessagingErrorCode.ConflictingEvidence);
    }

    [Test]
    public async Task PartitionPreservesCurrentRegionalAuthorityButNeverCreatesGlobalAuthority()
    {
        var local = Partition(ConnectivityState.GlobalDisconnected, AuthorityScope.Regional);
        var allowed = MessagingPolicyEngine.DecidePartition(local);
        await Assert.That(allowed.Intents.Single()).IsTypeOf<ContinueRegionalIntent>();

        await AssertHeld(MessagingPolicyEngine.DecidePartition(
            Partition(ConnectivityState.GlobalDisconnected, AuthorityScope.Global) with { HoldsCurrentGlobalAuthority = true }),
            MessagingErrorCode.PartitionDenied);
        await AssertHeld(MessagingPolicyEngine.DecidePartition(
            Partition(ConnectivityState.RegionalQuorumLost, AuthorityScope.Regional)), MessagingErrorCode.PartitionDenied);
        await AssertHeld(MessagingPolicyEngine.DecidePartition(
            local with { CommandRegionalEpoch = 6 }), MessagingErrorCode.StaleAuthority);
        await AssertHeld(MessagingPolicyEngine.DecidePartition(
            local with { CommandGlobalGeneration = 8 }), MessagingErrorCode.StaleEvidence);
        await AssertHeld(MessagingPolicyEngine.DecidePartition(
            local with { CommandGlobalGeneration = 10 }), MessagingErrorCode.FutureEvidence);

        var global = Partition(ConnectivityState.Connected, AuthorityScope.Global) with { HoldsCurrentGlobalAuthority = true };
        await Assert.That(MessagingPolicyEngine.DecidePartition(global).Intents.Single()).IsTypeOf<ContinueGlobalIntent>();
        await AssertHeld(MessagingPolicyEngine.DecidePartition(global with { CommandGlobalEpoch = 10 }),
            MessagingErrorCode.StaleAuthority);
    }

    [Test]
    public async Task CompatibilityRequiresExplicitNNAndBothNMinusOneDirectionsPerFeature()
    {
        var features = Features();
        var complete = Compatibility(features, available: true);
        var accepted = MessagingPolicyEngine.DecideCompatibility(features, complete);
        await Assert.That(accepted.Errors).IsEmpty();
        await Assert.That(accepted.Trace.Single().Code).IsEqualTo(MessagingTraceCode.CompatibilityAccepted);

        var unavailable = new CompatibilityPolicy(2, 1,
            complete.Outcomes.Select((outcome, index) => index == 0 ? outcome with { Available = false } : outcome));
        await AssertHeld(MessagingPolicyEngine.DecideCompatibility(features, unavailable),
            MessagingErrorCode.CompatibilityUnavailable);

        var incomplete = new CompatibilityPolicy(2, 1, complete.Outcomes.Skip(1));
        await AssertHeld(MessagingPolicyEngine.DecideCompatibility(features, incomplete),
            MessagingErrorCode.IncompleteObservation);

        var duplicate = new CompatibilityPolicy(2, 1, complete.Outcomes.Append(complete.Outcomes[0]));
        await AssertHeld(MessagingPolicyEngine.DecideCompatibility(features, duplicate),
            MessagingErrorCode.DuplicateEvidence);

        await AssertHeld(MessagingPolicyEngine.DecideCompatibility(features.Skip(1).ToArray(), complete),
            MessagingErrorCode.InvalidCatalog);
    }

    [Test]
    public async Task PolicyAndObservationCollectionsAreDefensivelyCopied()
    {
        var servers = Servers("control").ToList();
        var routes = Routes("control").ToList();
        var accounts = new List<AccountPolicy> { Account("control-account", "ts.control.>") };
        var streams = new List<StreamPolicy> { Stream("control-stream", "control-account", "ts.control.stream.>") };
        var buckets = new List<BucketPolicy> { Bucket("control-bucket", "control-account", "ts.control.kv.>") };
        var policy = new PlanePolicy(MessagingPlane.Control, new CellId("gru"), new ClusterId("control-cluster"),
            7, 3, servers, routes, [new ClusterId("fra-control")], accounts, streams, buckets);
        servers.Clear();
        routes.Clear();
        accounts.Clear();
        streams.Clear();
        buckets.Clear();

        await Assert.That(policy.Servers).Count().IsEqualTo(3);
        await Assert.That(policy.Routes).Count().IsEqualTo(6);
        await Assert.That(policy.Accounts).HasSingleItem();
        await Assert.That(policy.Streams).HasSingleItem();
        await Assert.That(policy.Buckets).HasSingleItem();

        var operation = Operation();
        var observation = Observation(operation, false, false, 2);
        var reversed = new ClusterObservation(observation.ObservationId, observation.Cluster,
            observation.ConfigurationGeneration, observation.MembershipSequence,
            observation.Peers.Reverse(), observation.StreamReplicas.Reverse(), observation.BucketReplicas.Reverse());
        var first = MessagingPolicyEngine.DecideReplacement(new(policy, operation, operation, observation, 64));
        var second = MessagingPolicyEngine.DecideReplacement(new(policy, operation, operation, reversed, 64));
        await Assert.That(Signature(first)).IsEqualTo(Signature(second));
    }

    [Test]
    public async Task MaximumValuesDoNotOverflowAndIntentsExposeNoSecretOrExecutableSurface()
    {
        var topology = new MessagingTopologyPolicy(Control(), Product(), 64, 128, int.MaxValue,
            Features());
        await Assert.That(MessagingPolicyEngine.DecideTopology(topology).Errors).IsEmpty();

        var operation = Operation() with
        {
            OperationGeneration = long.MaxValue,
            AuthorityEpoch = long.MaxValue,
            MaximumObservationSequence = long.MaxValue,
        };
        var decision = MessagingPolicyEngine.DecideReplacement(new(
            Control(), operation, operation, Observation(operation, false, false, 2), 64));
        await Assert.That(decision.Intents.Single()).IsTypeOf<AddPeerIntent>();

        var forbidden = new[] { "credential", "secret", "password", "payload", "callback", "configtext", "executable" };
        var propertyNames = typeof(MessagingIntent).Assembly.GetTypes()
            .Where(static type => type.Namespace == typeof(MessagingIntent).Namespace && type.IsAssignableTo(typeof(MessagingIntent)))
            .SelectMany(static type => type.GetProperties())
            .Select(static property => property.Name.ToLowerInvariant())
            .ToArray();
        await Assert.That(propertyNames.Any(name => forbidden.Any(name.Contains))).IsFalse();
    }

    [Test]
    public async Task DefaultEnumValuesAreRejectedAcrossEveryInputDecision()
    {
        await AssertHeld(MessagingPolicyEngine.DecideTopology(Topology(control: Plane(
            MessagingPlane.Unspecified, "control"))), MessagingErrorCode.InvalidInput);

        var unspecifiedStream = Stream("control-stream", "control-account", "ts.control.stream.>") with
        {
            Durability = MessagingDurability.Unspecified,
            Retention = MessagingRetention.Unspecified,
            Discard = MessagingDiscard.Unspecified,
            Acknowledgement = MessagingAcknowledgement.Unspecified,
            DiskSyncClass = MessagingDiskSyncClass.Unspecified,
        };
        await AssertHeld(MessagingPolicyEngine.DecideTopology(Topology(control: Control(streams: [unspecifiedStream]))),
            MessagingErrorCode.InvalidInput);

        await AssertHeld(MessagingPolicyEngine.DecidePartition(
            Partition(ConnectivityState.Unspecified, AuthorityScope.Regional)), MessagingErrorCode.InvalidInput);
        await AssertHeld(MessagingPolicyEngine.DecidePartition(
            Partition(ConnectivityState.Connected, AuthorityScope.Unspecified)), MessagingErrorCode.InvalidInput);

        await AssertHeld(MessagingPolicyEngine.DecideCompatibility(
            [CompatibilityFeature.Unspecified], new CompatibilityPolicy(2, 1, [])), MessagingErrorCode.InvalidCatalog);

        var operation = Operation();
        var defaultPeer = Observation(operation, false, false, 2).Peers
            .Select((peer, index) => index == 0 ? peer with { Health = PeerHealth.Unspecified } : peer);
        var baseline = Observation(operation, false, false, 2);
        var observation = new ClusterObservation(baseline.ObservationId, baseline.Cluster,
            baseline.ConfigurationGeneration, baseline.MembershipSequence,
            defaultPeer, baseline.StreamReplicas, baseline.BucketReplicas);
        await AssertHeld(MessagingPolicyEngine.DecideReplacement(new(Control(), operation, operation, observation, 64)),
            MessagingErrorCode.IncompleteObservation);

        await AssertHeld(MessagingPolicyEngine.DecideReplacement(new(Control(),
            operation with { Plane = MessagingPlane.Unspecified }, null, null, 64)), MessagingErrorCode.InvalidInput);

        var boundedNoAck = Stream("control-stream", "control-account", "ts.control.stream.>") with
        {
            Replicas = 1,
            Durability = MessagingDurability.Bounded,
            Acknowledgement = MessagingAcknowledgement.NoAck,
            DiskSyncClass = MessagingDiskSyncClass.BoundedLoss,
        };
        await Assert.That(MessagingPolicyEngine.DecideTopology(Topology(control: Control(streams: [boundedNoAck]))).Errors).IsEmpty();

        await Assert.That(Throws<ArgumentNullException>(() => new CellId(null!))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new PlanePolicy(
            MessagingPlane.Control, new CellId("gru"), new ClusterId("control-cluster"), 1, 3,
            [null!], [], [], [], [], []))).IsTrue();
    }

    private static MessagingTopologyPolicy Topology(PlanePolicy? control = null, PlanePolicy? product = null, bool reverse = false) => new(
        control ?? Control(reverse: reverse), product ?? Product(reverse: reverse), 64, 128, 100,
        reverse ? Features().Reverse() : Features());

    private static PlanePolicy Control(IEnumerable<RouteLink>? routes = null, IEnumerable<StreamPolicy>? streams = null, bool reverse = false) =>
        Plane(MessagingPlane.Control, "control", routes, streams, null, null, null, reverse);

    private static PlanePolicy Product(
        ClusterId? cluster = null,
        IEnumerable<ServerPolicy>? servers = null,
        IEnumerable<RouteLink>? routes = null,
        IEnumerable<ClusterId>? gateways = null,
        IEnumerable<AccountPolicy>? accounts = null,
        IEnumerable<StreamPolicy>? streams = null,
        IEnumerable<BucketPolicy>? buckets = null,
        bool reverse = false) => Plane(MessagingPlane.Product, "product", routes, streams, cluster, servers, gateways, reverse, accounts, buckets);

    private static PlanePolicy Plane(
        MessagingPlane plane,
        string prefix,
        IEnumerable<RouteLink>? routes = null,
        IEnumerable<StreamPolicy>? streams = null,
        ClusterId? cluster = null,
        IEnumerable<ServerPolicy>? servers = null,
        IEnumerable<ClusterId>? gateways = null,
        bool reverse = false,
        IEnumerable<AccountPolicy>? accounts = null,
        IEnumerable<BucketPolicy>? buckets = null)
    {
        var serverValues = (servers ?? Servers(prefix)).ToArray();
        var accountValues = (accounts ?? [Account($"{prefix}-account", $"ts.{prefix}.>")]).ToArray();
        var streamValues = (streams ?? [Stream($"{prefix}-stream", $"{prefix}-account", $"ts.{prefix}.stream.>")]).ToArray();
        var bucketValues = (buckets ?? [Bucket($"{prefix}-bucket", $"{prefix}-account", $"ts.{prefix}.kv.>")]).ToArray();
        return new(plane, new CellId("gru"), cluster ?? new ClusterId($"{prefix}-cluster"), 7, 3,
            reverse ? serverValues.Reverse() : serverValues,
            reverse ? (routes ?? Routes(prefix)).Reverse() : routes ?? Routes(prefix),
            reverse ? (gateways ?? (plane == MessagingPlane.Control ? [new ClusterId("fra-control")] : [])).Reverse() :
                gateways ?? (plane == MessagingPlane.Control ? [new ClusterId("fra-control")] : []),
            reverse ? accountValues.Reverse() : accountValues,
            reverse ? streamValues.Reverse() : streamValues,
            reverse ? bucketValues.Reverse() : bucketValues);
    }

    private static ServerPolicy[] Servers(string prefix) => Enumerable.Range(1, 3)
        .Select(index => new ServerPolicy(new ServerId($"{prefix}-server-{index}"),
            new PeerId($"{prefix}-peer-{index}"), new PlacementId($"host-{index}"))).ToArray();

    private static RouteLink[] Routes(string prefix) => Servers(prefix)
        .SelectMany(from => Servers(prefix).Where(to => to.Server != from.Server)
            .Select(to => new RouteLink(from.Server, to.Server))).ToArray();

    private static AccountPolicy Account(string id, string subject) => new(new AccountId(id), [subject]);
    private static StreamPolicy Stream(string id, string account, string subject) => new(
        new StreamId(id), new AccountId(account), subject, 3, MessagingDurability.Critical,
        MessagingRetention.Limits, 1000, 1_000_000, MessagingDiscard.Old,
        new PlacementId("regional"), 100, MessagingAcknowledgement.Replicated,
        MessagingDiskSyncClass.AcknowledgedWriteStrict);
    private static BucketPolicy Bucket(string id, string account, string subject) => new(
        new BucketId(id), new AccountId(account), subject, 3, MessagingDurability.Critical,
        1000, 1_000_000, new PlacementId("regional"), MessagingAcknowledgement.Replicated,
        MessagingDiskSyncClass.AcknowledgedWriteStrict);

    private static ReplacementOperation Operation() => new(
        new MessagingOperationId("replace-1"), MessagingPlane.Control, new CellId("gru"), new ClusterId("control-cluster"),
        3, 9, 7, 100, 200, new ServerId("control-server-3"), new PeerId("control-peer-3"),
        new ServerId("control-server-4"), new PeerId("control-peer-4"), new PlacementId("host-4"));

    private static ClusterObservation Observation(
        ReplacementOperation operation,
        bool includeReplacement,
        bool caughtUp,
        int replicas,
        bool includeFailed = true,
        int currentOriginalPeers = 2,
        StoreClassification failedStore = StoreClassification.Lost,
        bool duplicatePeer = false)
    {
        var peers = new List<PeerObservation>();
        if (includeFailed)
            peers.Add(new(operation.FailedServer, operation.FailedPeer, PeerHealth.Failed, failedStore,
                ProcessFenced: true, OwnershipProven: false, CaughtUp: false));
        for (var index = 1; index <= currentOriginalPeers; index++)
            peers.Add(new(new ServerId($"control-server-{index}"), new PeerId($"control-peer-{index}"),
                PeerHealth.Current, StoreClassification.Surviving,
                ProcessFenced: false, OwnershipProven: true, CaughtUp: true));
        if (includeReplacement)
            peers.Add(new(operation.ReplacementServer, operation.ReplacementPeer, PeerHealth.Current,
                StoreClassification.Surviving,
                ProcessFenced: false, OwnershipProven: true, CaughtUp: caughtUp));
        if (duplicatePeer) peers.Add(peers[0]);
        return new(new MessagingObservationId("observation-1"), operation.Cluster, operation.ConfigurationGeneration, 150,
            peers, [new("control-stream", replicas, replicas, 50)], [new("control-bucket", replicas, replicas, 50)]);
    }

    private static ClusterObservation Clone(ClusterObservation value, long membershipSequence) => new(
        value.ObservationId, value.Cluster, value.ConfigurationGeneration, membershipSequence,
        value.Peers, value.StreamReplicas, value.BucketReplicas);

    private static ClusterObservation SurvivingObservation(
        ReplacementOperation operation,
        ServerId? activeAttachment,
        bool includeReplacement = false,
        MessagingPlane plane = MessagingPlane.Control,
        long proofSequence = 150,
        long ownershipEpoch = 9,
        bool compatible = true)
    {
        var proof = new SurvivingStoreProof(new StoreId("control-store-3"), 4, proofSequence,
            plane, operation.Cell, operation.Cluster, operation.FailedServer, activeAttachment, ownershipEpoch, compatible);
        var peers = new List<PeerObservation>
        {
            new(operation.FailedServer, operation.FailedPeer,
                activeAttachment == operation.FailedServer ? PeerHealth.Current : PeerHealth.Failed,
                StoreClassification.Surviving,
                ProcessFenced: activeAttachment != operation.FailedServer,
                OwnershipProven: activeAttachment == operation.FailedServer,
                CaughtUp: activeAttachment == operation.FailedServer,
                SurvivingStoreProof: proof),
            new(new ServerId("control-server-1"), new PeerId("control-peer-1"), PeerHealth.Current,
                StoreClassification.Surviving, ProcessFenced: false, OwnershipProven: true, CaughtUp: true),
            new(new ServerId("control-server-2"), new PeerId("control-peer-2"), PeerHealth.Current,
                StoreClassification.Surviving, ProcessFenced: false, OwnershipProven: true, CaughtUp: true),
        };
        if (includeReplacement)
            peers.Add(new(operation.ReplacementServer, operation.ReplacementPeer, PeerHealth.Current,
                StoreClassification.Surviving, ProcessFenced: false, OwnershipProven: true, CaughtUp: true));
        return new(new MessagingObservationId("surviving-observation"), operation.Cluster,
            operation.ConfigurationGeneration, 150, peers,
            [new("control-stream", 3, 3, 50)], [new("control-bucket", 3, 3, 50)]);
    }

    private static PartitionRequest Partition(ConnectivityState connectivity, AuthorityScope scope) => new(
        new CellId("gru"), 64, connectivity, scope, 7, 7, 9, 9, 11, 11, true, false);

    private static CompatibilityPolicy Compatibility(IEnumerable<CompatibilityFeature> features, bool available) => new(
        2, 1, features.SelectMany(feature => Pairs()
            .Select(pair => new CompatibilityOutcome(feature, pair, available))));

    private static CompatibilityFeature[] Features() => Enum.GetValues<CompatibilityFeature>()
        .Where(static value => value != CompatibilityFeature.Unspecified).ToArray();
    private static CompatibilityPair[] Pairs() => Enum.GetValues<CompatibilityPair>()
        .Where(static value => value != CompatibilityPair.Unspecified).ToArray();

    private static string Signature(MessagingDecision decision) => string.Join('|',
        decision.Intents.Select(static intent => $"{intent.Action}:{intent.GetType().Name}")
            .Concat(decision.Trace.Select(static trace => $"{trace.Sequence}:{trace.Code}:{trace.Action}")));

    private static async Task AssertHeld(MessagingDecision decision, MessagingErrorCode code)
    {
        await Assert.That(decision.Errors.Any(error => error.Code == code)).IsTrue();
        await Assert.That(decision.Intents.Single()).IsTypeOf<HoldMessagingIntent>();
    }

    private static bool Throws<TException>(Action action) where TException : Exception
    {
        try { action(); return false; }
        catch (TException) { return true; }
    }
}
