using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class MessagingPolicyAudit4ReviewTests
{
    [Test]
    public async Task Every_accepted_request_semantic_leaf_or_collection_family_changes_the_fingerprint_independently()
    {
        var request = MessagingPolicyAudit4CounterexampleTests.FingerprintBaseline();
        var policy = request.Policy;
        var operation = request.Proposed;
        var observation = request.Observation!;
        var peer = observation.Peers[0];
        var proof = peer.SurvivingStoreProof!;
        var streamReplica = observation.StreamReplicas[0];
        var bucketReplica = observation.BucketReplicas[0];
        var mutations = new List<Mutation>();
        void Add(string name, ReplacementRequest value) => mutations.Add(new(name, value));

        Add("policy-plane", request with { Policy = Rebuild(policy, plane: MessagingPlane.Product) });
        Add("policy-cell", request with { Policy = Rebuild(policy, cell: new("cell-other")) });
        Add("policy-cluster", request with { Policy = Rebuild(policy, cluster: new("cluster-other")) });
        Add("policy-generation", request with { Policy = Rebuild(policy, generation: policy.Generation + 1) });
        Add("policy-floor", request with { Policy = Rebuild(policy, floor: policy.MembershipFloor + 1) });

        Add("servers-count", request with { Policy = Rebuild(policy, servers: policy.Servers.Skip(1)) });
        Add("server-id", request with { Policy = Rebuild(policy, servers: Replace(policy.Servers, policy.Servers[0] with { Server = new("server-other") })) });
        Add("server-peer", request with { Policy = Rebuild(policy, servers: Replace(policy.Servers, policy.Servers[0] with { Peer = new("peer-other") })) });
        Add("server-placement", request with { Policy = Rebuild(policy, servers: Replace(policy.Servers, policy.Servers[0] with { Placement = new("placement-other") })) });
        Add("routes-count", request with { Policy = Rebuild(policy, routes: policy.Routes.Skip(1)) });
        Add("route-from", request with { Policy = Rebuild(policy, routes: Replace(policy.Routes, policy.Routes[0] with { From = new("from-other") })) });
        Add("route-to", request with { Policy = Rebuild(policy, routes: Replace(policy.Routes, policy.Routes[0] with { To = new("to-other") })) });
        Add("gateways-count", request with { Policy = Rebuild(policy, gateways: []) });
        Add("gateway-item", request with { Policy = Rebuild(policy, gateways: [new ClusterId("gateway-other")]) });
        Add("accounts-count", request with { Policy = Rebuild(policy, accounts: []) });
        Add("account-id", request with { Policy = Rebuild(policy, accounts: [new AccountPolicy(new("account-other"), policy.Accounts[0].SubjectRoots)]) });
        Add("account-roots-count", request with { Policy = Rebuild(policy, accounts: [new AccountPolicy(policy.Accounts[0].Id, policy.Accounts[0].SubjectRoots.Append("ts.other.>"))]) });
        Add("account-root-item", request with { Policy = Rebuild(policy, accounts: [new AccountPolicy(policy.Accounts[0].Id, ["ts.changed.>"])]) });

        Add("streams-count", request with { Policy = Rebuild(policy, streams: []) });
        foreach (var mutation in StreamMutations(policy.Streams[0])) Add(mutation.Name, request with { Policy = Rebuild(policy, streams: [mutation.Value]) });
        Add("buckets-count", request with { Policy = Rebuild(policy, buckets: []) });
        foreach (var mutation in BucketMutations(policy.Buckets[0])) Add(mutation.Name, request with { Policy = Rebuild(policy, buckets: [mutation.Value]) });

        foreach (var mutation in OperationMutations("proposed", operation)) Add(mutation.Name, request with { Proposed = mutation.Value });
        Add("persisted-null", request with { Persisted = null });
        Add("persisted-value", request with { Persisted = operation with { AuthorityEpoch = operation.AuthorityEpoch + 1 } });
        Add("request-maximum-identity", request with { MaximumIdentityLength = request.MaximumIdentityLength + 1 });

        Add("observation-id", request with { Observation = Rebuild(observation, id: new("observation-other")) });
        Add("observation-cluster", request with { Observation = Rebuild(observation, cluster: new("observation-cluster-other")) });
        Add("observation-generation", request with { Observation = Rebuild(observation, generation: observation.ConfigurationGeneration + 1) });
        Add("observation-sequence", request with { Observation = Rebuild(observation, sequence: observation.MembershipSequence + 1) });
        Add("peers-count", request with { Observation = Rebuild(observation, peers: observation.Peers.Skip(1)) });
        foreach (var mutation in PeerMutations(peer)) Add(mutation.Name, request with { Observation = Rebuild(observation, peers: Replace(observation.Peers, mutation.Value)) });
        Add("proof-null", request with { Observation = Rebuild(observation, peers: Replace(observation.Peers, peer with { SurvivingStoreProof = null })) });
        foreach (var mutation in ProofMutations(proof)) Add(mutation.Name, request with
        {
            Observation = Rebuild(observation, peers: Replace(observation.Peers, peer with { SurvivingStoreProof = mutation.Value }))
        });
        Add("stream-replicas-count", request with { Observation = Rebuild(observation, streams: []) });
        foreach (var mutation in ReplicaMutations("stream-replica", streamReplica)) Add(mutation.Name, request with
        {
            Observation = Rebuild(observation, streams: [mutation.Value])
        });
        Add("bucket-replicas-count", request with { Observation = Rebuild(observation, buckets: []) });
        foreach (var mutation in ReplicaMutations("bucket-replica", bucketReplica)) Add(mutation.Name, request with
        {
            Observation = Rebuild(observation, buckets: [mutation.Value])
        });

        var baseline = MessagingAcceptedReplacementFingerprint.Hash(request);
        await Assert.That(mutations.Select(value => value.Name).Distinct(StringComparer.Ordinal).Count()).IsEqualTo(mutations.Count);
        await Assert.That(mutations.All(value => MessagingAcceptedReplacementFingerprint.Hash(value.Request) != baseline)).IsTrue();
        await Assert.That(mutations.Select(value => MessagingAcceptedReplacementFingerprint.Hash(value.Request))
            .Distinct(StringComparer.Ordinal).Count()).IsEqualTo(mutations.Count);
    }

    [Test]
    public async Task Every_public_decision_intent_collection_request_accessor_clone_and_origin_is_exactly_inventoried()
    {
        var assembly = typeof(MessagingDecision).Assembly;
        var methods = assembly.ExportedTypes.SelectMany(type => type.GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly)).ToArray();
        var intentEnumerable = typeof(IEnumerable<MessagingIntent>);
        var relevant = methods.Where(method => method.ReturnType == typeof(MessagingDecision) ||
            typeof(MessagingIntent).IsAssignableFrom(method.ReturnType) ||
            intentEnumerable.IsAssignableFrom(method.ReturnType) ||
            method.ReturnType == typeof(ReplacementRequest)).ToArray();
        var intentTypes = assembly.ExportedTypes.Where(type => typeof(MessagingIntent).IsAssignableFrom(type)).ToArray();
        var cloneTypes = intentTypes.Append(typeof(MessagingDecision)).Append(typeof(ReplacementRequest)).ToArray();
        var expected = cloneTypes.Select(Clone).Concat(new[]
        {
            typeof(MessagingPolicyEngine).GetMethod(nameof(MessagingPolicyEngine.DecideTopology))!,
            typeof(MessagingPolicyEngine).GetMethod(nameof(MessagingPolicyEngine.DecideReplacement))!,
            typeof(MessagingPolicyEngine).GetMethod(nameof(MessagingPolicyEngine.DecidePartition))!,
            typeof(MessagingPolicyEngine).GetMethod(nameof(MessagingPolicyEngine.DecideCompatibility))!,
            typeof(MessagingDecision).GetProperty(nameof(MessagingDecision.Intents))!.GetMethod!,
            typeof(MessagingDecision).GetProperty(nameof(MessagingDecision.AcceptedReplacementRequest))!.GetMethod!,
        }).ToArray();
        await Assert.That(Signatures(relevant).SequenceEqual(Signatures(expected))).IsTrue();

        var origins = relevant.Where(method => method.IsStatic && method.DeclaringType == typeof(MessagingPolicyEngine)).ToArray();
        await Assert.That(origins.Length).IsEqualTo(4);
        await Assert.That(cloneTypes.Select(Clone).All(method => method.Name == "<Clone>$" && !method.IsStatic &&
            method.GetParameters().Length == 0 && method.ReturnType == method.DeclaringType)).IsTrue();

        var request = MessagingPolicyAudit4CounterexampleTests.FingerprintBaseline();
        var decision = MessagingPolicyEngine.DecideReplacement(request);
        var clone = (MessagingDecision)Clone(typeof(MessagingDecision)).Invoke(decision, null)!;
        await Assert.That(ReferenceEquals(decision.AcceptedReplacementRequest, request)).IsTrue();
        await Assert.That(ReferenceEquals(clone.AcceptedReplacementRequest, request)).IsTrue();
        await Assert.That(ReferenceEquals(clone.Intents, decision.Intents)).IsTrue();
        await Assert.That(ReferenceEquals(clone.Errors, decision.Errors)).IsTrue();
        await Assert.That(ReferenceEquals(clone.Trace, decision.Trace)).IsTrue();
        await Assert.That(typeof(MessagingDecision).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .All(property => property.GetMethod is not null && property.SetMethod is null)).IsTrue();
    }

    private static IEnumerable<(string Name, StreamPolicy Value)> StreamMutations(StreamPolicy value)
    {
        yield return ("stream-id", value with { Id = new("stream-other") });
        yield return ("stream-account", value with { Account = new("stream-account-other") });
        yield return ("stream-subject", value with { SubjectRoot = "ts.stream.changed.>" });
        yield return ("stream-replicas", value with { Replicas = value.Replicas + 1 });
        yield return ("stream-durability", value with { Durability = MessagingDurability.Bounded });
        yield return ("stream-retention", value with { Retention = MessagingRetention.Interest });
        yield return ("stream-age", value with { MaximumAgeTicks = value.MaximumAgeTicks + 1 });
        yield return ("stream-bytes", value with { MaximumBytes = value.MaximumBytes + 1 });
        yield return ("stream-discard", value with { Discard = MessagingDiscard.New });
        yield return ("stream-placement", value with { Placement = new("stream-placement-other") });
        yield return ("stream-duplicate-window", value with { DuplicateWindowTicks = value.DuplicateWindowTicks + 1 });
        yield return ("stream-ack", value with { Acknowledgement = MessagingAcknowledgement.Leader });
        yield return ("stream-sync", value with { DiskSyncClass = MessagingDiskSyncClass.BoundedLoss });
    }

    private static IEnumerable<(string Name, BucketPolicy Value)> BucketMutations(BucketPolicy value)
    {
        yield return ("bucket-id", value with { Id = new("bucket-other") });
        yield return ("bucket-account", value with { Account = new("bucket-account-other") });
        yield return ("bucket-subject", value with { SubjectRoot = "ts.bucket.changed.>" });
        yield return ("bucket-replicas", value with { Replicas = value.Replicas + 1 });
        yield return ("bucket-durability", value with { Durability = MessagingDurability.Bounded });
        yield return ("bucket-age", value with { MaximumAgeTicks = value.MaximumAgeTicks + 1 });
        yield return ("bucket-bytes", value with { MaximumBytes = value.MaximumBytes + 1 });
        yield return ("bucket-placement", value with { Placement = new("bucket-placement-other") });
        yield return ("bucket-ack", value with { Acknowledgement = MessagingAcknowledgement.Leader });
        yield return ("bucket-sync", value with { DiskSyncClass = MessagingDiskSyncClass.BoundedLoss });
    }

    private static IEnumerable<(string Name, ReplacementOperation Value)> OperationMutations(string prefix, ReplacementOperation value)
    {
        yield return ($"{prefix}-id", value with { OperationId = new("operation-other") });
        yield return ($"{prefix}-plane", value with { Plane = MessagingPlane.Product });
        yield return ($"{prefix}-cell", value with { Cell = new("operation-cell-other") });
        yield return ($"{prefix}-cluster", value with { Cluster = new("operation-cluster-other") });
        yield return ($"{prefix}-generation", value with { OperationGeneration = value.OperationGeneration + 1 });
        yield return ($"{prefix}-epoch", value with { AuthorityEpoch = value.AuthorityEpoch + 1 });
        yield return ($"{prefix}-configuration", value with { ConfigurationGeneration = value.ConfigurationGeneration + 1 });
        yield return ($"{prefix}-minimum", value with { MinimumObservationSequence = value.MinimumObservationSequence + 1 });
        yield return ($"{prefix}-maximum", value with { MaximumObservationSequence = value.MaximumObservationSequence + 1 });
        yield return ($"{prefix}-store", value with { FailedStore = new("store-other") });
        yield return ($"{prefix}-store-generation", value with { CurrentStoreGeneration = value.CurrentStoreGeneration + 1 });
        yield return ($"{prefix}-failed-server", value with { FailedServer = new("failed-server-other") });
        yield return ($"{prefix}-failed-peer", value with { FailedPeer = new("failed-peer-other") });
        yield return ($"{prefix}-replacement-server", value with { ReplacementServer = new("replacement-server-other") });
        yield return ($"{prefix}-replacement-peer", value with { ReplacementPeer = new("replacement-peer-other") });
        yield return ($"{prefix}-replacement-placement", value with { ReplacementPlacement = new("replacement-placement-other") });
    }

    private static IEnumerable<(string Name, PeerObservation Value)> PeerMutations(PeerObservation value)
    {
        yield return ("peer-server", value with { Server = new("peer-server-other") });
        yield return ("peer-id", value with { Peer = new("peer-id-other") });
        yield return ("peer-health", value with { Health = PeerHealth.Failed });
        yield return ("peer-store", value with { Store = StoreClassification.Lost });
        yield return ("peer-fenced", value with { ProcessFenced = !value.ProcessFenced });
        yield return ("peer-owned", value with { OwnershipProven = !value.OwnershipProven });
        yield return ("peer-caught-up", value with { CaughtUp = !value.CaughtUp });
    }

    private static IEnumerable<(string Name, SurvivingStoreProof Value)> ProofMutations(SurvivingStoreProof value)
    {
        yield return ("proof-store", value with { Store = new("proof-store-other") });
        yield return ("proof-store-generation", value with { StoreGeneration = value.StoreGeneration + 1 });
        yield return ("proof-sequence", value with { ObservedMembershipSequence = value.ObservedMembershipSequence + 1 });
        yield return ("proof-plane", value with { Plane = MessagingPlane.Product });
        yield return ("proof-cell", value with { Cell = new("proof-cell-other") });
        yield return ("proof-cluster", value with { Cluster = new("proof-cluster-other") });
        yield return ("proof-owner", value with { RecordedOwner = new("proof-owner-other") });
        yield return ("proof-attachment", value with { ActiveAttachment = new("proof-attachment-other") });
        yield return ("proof-epoch", value with { OwnershipEpoch = value.OwnershipEpoch + 1 });
        yield return ("proof-compatible", value with { Compatible = !value.Compatible });
    }

    private static IEnumerable<(string Name, ReplicaObservation Value)> ReplicaMutations(string prefix, ReplicaObservation value)
    {
        yield return ($"{prefix}-identity", value with { ResourceIdentity = $"{prefix}-other" });
        yield return ($"{prefix}-current", value with { CurrentReplicas = value.CurrentReplicas + 1 });
        yield return ($"{prefix}-healthy", value with { HealthyReplicas = value.HealthyReplicas + 1 });
        yield return ($"{prefix}-sequence", value with { LastSequence = value.LastSequence + 1 });
    }

    private static PlanePolicy Rebuild(PlanePolicy value, MessagingPlane? plane = null, CellId? cell = null,
        ClusterId? cluster = null, long? generation = null, int? floor = null, IEnumerable<ServerPolicy>? servers = null,
        IEnumerable<RouteLink>? routes = null, IEnumerable<ClusterId>? gateways = null, IEnumerable<AccountPolicy>? accounts = null,
        IEnumerable<StreamPolicy>? streams = null, IEnumerable<BucketPolicy>? buckets = null) =>
        new(plane ?? value.Plane, cell ?? value.Cell, cluster ?? value.Cluster, generation ?? value.Generation,
            floor ?? value.MembershipFloor, servers ?? value.Servers, routes ?? value.Routes, gateways ?? value.Gateways,
            accounts ?? value.Accounts, streams ?? value.Streams, buckets ?? value.Buckets);

    private static ClusterObservation Rebuild(ClusterObservation value, MessagingObservationId? id = null,
        ClusterId? cluster = null, long? generation = null, long? sequence = null, IEnumerable<PeerObservation>? peers = null,
        IEnumerable<ReplicaObservation>? streams = null, IEnumerable<ReplicaObservation>? buckets = null) =>
        new(id ?? value.ObservationId, cluster ?? value.Cluster, generation ?? value.ConfigurationGeneration,
            sequence ?? value.MembershipSequence, peers ?? value.Peers, streams ?? value.StreamReplicas,
            buckets ?? value.BucketReplicas);

    private static IReadOnlyList<T> Replace<T>(IReadOnlyList<T> source, T first) => [first, .. source.Skip(1)];
    private static MethodInfo Clone(Type type) => type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
        .Single(method => method.Name == "<Clone>$");
    private static IEnumerable<string> Signatures(IEnumerable<MethodInfo> methods) => methods.Select(method =>
        $"{method.DeclaringType!.FullName}|{method.Name}|{method.IsStatic}|{method.ReturnType.FullName}|{string.Join(',', method.GetParameters().Select(parameter => parameter.ParameterType.FullName))}")
        .Order(StringComparer.Ordinal);

    private sealed record Mutation(string Name, ReplacementRequest Request);
}
