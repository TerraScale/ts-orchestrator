using TerraScale.Orchestrator.ControlPlane.Messaging;
using TerraScale.Orchestrator.ControlPlane.Tests.Properties;
using Cysharp.Text;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class MessagingPolicyAudit4CounterexampleTests
{
    [Test]
    public async Task Distinct_completed_replacements_must_not_collapse_to_the_same_accepted_output()
    {
        var firstRequest = Completed("a", 11);
        var secondRequest = Completed("b", 12);
        var first = MessagingPolicyEngine.DecideReplacement(firstRequest);
        var second = MessagingPolicyEngine.DecideReplacement(secondRequest);

        await Assert.That(first.Errors).IsEmpty();
        await Assert.That(second.Errors).IsEmpty();
        await Assert.That(ReferenceEquals(first.AcceptedReplacementRequest, firstRequest)).IsTrue();
        await Assert.That(ReferenceEquals(second.AcceptedReplacementRequest, secondRequest)).IsTrue();
        await Assert.That(PublicFingerprint(first)).IsNotEqualTo(PublicFingerprint(second));
    }

    [Test]
    public async Task Every_successful_replacement_branch_retains_its_exact_request_and_every_hold_is_null()
    {
        var requests = AcceptedCases().ToArray();
        foreach (var request in requests)
        {
            var decision = MessagingPolicyEngine.DecideReplacement(request);
            await Assert.That(decision.Errors).IsEmpty();
            await Assert.That(ReferenceEquals(decision.AcceptedReplacementRequest, request)).IsTrue();
        }
        await Assert.That(requests.Select(MessagingAcceptedReplacementFingerprint.Hash).Distinct(StringComparer.Ordinal).Count())
            .IsEqualTo(requests.Length);

        var invalid = requests[0] with { Proposed = requests[0].Proposed with { OperationGeneration = 0 } };
        var held = MessagingPolicyEngine.DecideReplacement(invalid);
        await Assert.That(held.Errors).IsNotEmpty();
        await Assert.That(held.AcceptedReplacementRequest).IsNull();

        var partition = MessagingPolicyEngine.DecidePartition(new(new("gru"), 96,
            ConnectivityState.GlobalDisconnected, AuthorityScope.Regional, 2, 2, 3, 3, 4, 4, true, false));
        var features = Enum.GetValues<CompatibilityFeature>().Where(value => value != CompatibilityFeature.Unspecified).ToArray();
        var pairs = Enum.GetValues<CompatibilityPair>().Where(value => value != CompatibilityPair.Unspecified).ToArray();
        var compatibility = MessagingPolicyEngine.DecideCompatibility(features,
            new(2, 1, features.SelectMany(feature => pairs.Select(pair => new CompatibilityOutcome(feature, pair, true)))));
        var heldTopology = MessagingPolicyEngine.DecideTopology(new(requests[0].Policy, requests[0].Policy,
            96, 160, 100, features));
        var heldPartition = MessagingPolicyEngine.DecidePartition(new(new("gru"), 96,
            ConnectivityState.RegionalQuorumLost, AuthorityScope.Regional, 2, 2, 3, 3, 4, 4, true, false));
        var heldCompatibility = MessagingPolicyEngine.DecideCompatibility(features,
            new(2, 1, features.SelectMany(feature => pairs.Select(pair => new CompatibilityOutcome(feature, pair, false)))));
        await Assert.That(partition.AcceptedReplacementRequest).IsNull();
        await Assert.That(compatibility.AcceptedReplacementRequest).IsNull();
        await Assert.That(heldTopology.Errors).IsNotEmpty();
        await Assert.That(heldTopology.AcceptedReplacementRequest).IsNull();
        await Assert.That(heldPartition.Errors).IsNotEmpty();
        await Assert.That(heldPartition.AcceptedReplacementRequest).IsNull();
        await Assert.That(heldCompatibility.Errors).IsNotEmpty();
        await Assert.That(heldCompatibility.AcceptedReplacementRequest).IsNull();
    }

    [Test]
    public async Task Complete_request_fingerprint_is_replayable_culture_permutation_and_schema_complete()
    {
        var request = AcceptedCases().Last();
        string? baseline = null;
        foreach (var culture in new[] { "en-US", "tr-TR", "ar-SA" })
            foreach (var reverse in new[] { false, true })
            {
                var previous = System.Globalization.CultureInfo.CurrentCulture;
                try
                {
                    System.Globalization.CultureInfo.CurrentCulture = System.Globalization.CultureInfo.GetCultureInfo(culture);
                    var candidate = reverse ? Reverse(request) : request;
                    var decision = MessagingPolicyEngine.DecideReplacement(candidate);
                    var actual = MessagingAcceptedReplacementFingerprint.Hash(decision.AcceptedReplacementRequest!);
                    baseline ??= actual;
                    await Assert.That(actual).IsEqualTo(baseline);
                    await Assert.That(MessagingAcceptedReplacementFingerprint.Hash(
                        MessagingPolicyEngine.DecideReplacement(candidate).AcceptedReplacementRequest!)).IsEqualTo(actual);
                }
                finally { System.Globalization.CultureInfo.CurrentCulture = previous; }
            }

        var canonical = MessagingAcceptedReplacementFingerprint.Canonical(request);
        AssertProperties<ReplacementRequest>(canonical, nameof(ReplacementRequest.Policy), nameof(ReplacementRequest.Proposed),
            nameof(ReplacementRequest.Persisted), nameof(ReplacementRequest.Observation), nameof(ReplacementRequest.MaximumIdentityLength));
        AssertProperties<PlanePolicy>(canonical, nameof(PlanePolicy.Plane), nameof(PlanePolicy.Cell), nameof(PlanePolicy.Cluster), nameof(PlanePolicy.Generation),
            nameof(PlanePolicy.MembershipFloor), nameof(PlanePolicy.Servers), nameof(PlanePolicy.Routes), nameof(PlanePolicy.Gateways),
            nameof(PlanePolicy.Accounts), nameof(PlanePolicy.Streams), nameof(PlanePolicy.Buckets));
        AssertProperties<ServerPolicy>(canonical, nameof(ServerPolicy.Server), nameof(ServerPolicy.Peer), nameof(ServerPolicy.Placement));
        AssertProperties<RouteLink>(canonical, nameof(RouteLink.From), nameof(RouteLink.To));
        AssertProperties<AccountPolicy>(canonical, nameof(AccountPolicy.Id), nameof(AccountPolicy.SubjectRoots));
        AssertProperties<StreamPolicy>(canonical, nameof(StreamPolicy.Id), nameof(StreamPolicy.Account), nameof(StreamPolicy.SubjectRoot),
            nameof(StreamPolicy.Replicas), nameof(StreamPolicy.Durability), nameof(StreamPolicy.Retention), nameof(StreamPolicy.MaximumAgeTicks),
            nameof(StreamPolicy.MaximumBytes), nameof(StreamPolicy.Discard), nameof(StreamPolicy.Placement), nameof(StreamPolicy.DuplicateWindowTicks),
            nameof(StreamPolicy.Acknowledgement), nameof(StreamPolicy.DiskSyncClass));
        AssertProperties<BucketPolicy>(canonical, nameof(BucketPolicy.Id), nameof(BucketPolicy.Account), nameof(BucketPolicy.SubjectRoot),
            nameof(BucketPolicy.Replicas), nameof(BucketPolicy.Durability), nameof(BucketPolicy.MaximumAgeTicks), nameof(BucketPolicy.MaximumBytes),
            nameof(BucketPolicy.Placement), nameof(BucketPolicy.Acknowledgement), nameof(BucketPolicy.DiskSyncClass));
        AssertProperties<ReplacementOperation>(canonical, nameof(ReplacementOperation.OperationId), nameof(ReplacementOperation.Plane), nameof(ReplacementOperation.Cell),
            nameof(ReplacementOperation.Cluster), nameof(ReplacementOperation.OperationGeneration), nameof(ReplacementOperation.AuthorityEpoch),
            nameof(ReplacementOperation.ConfigurationGeneration), nameof(ReplacementOperation.MinimumObservationSequence),
            nameof(ReplacementOperation.MaximumObservationSequence), nameof(ReplacementOperation.FailedStore), nameof(ReplacementOperation.CurrentStoreGeneration),
            nameof(ReplacementOperation.FailedServer), nameof(ReplacementOperation.FailedPeer), nameof(ReplacementOperation.ReplacementServer),
            nameof(ReplacementOperation.ReplacementPeer), nameof(ReplacementOperation.ReplacementPlacement));
        AssertProperties<ClusterObservation>(canonical, nameof(ClusterObservation.ObservationId), nameof(ClusterObservation.Cluster),
            nameof(ClusterObservation.ConfigurationGeneration), nameof(ClusterObservation.MembershipSequence), nameof(ClusterObservation.Peers),
            nameof(ClusterObservation.StreamReplicas), nameof(ClusterObservation.BucketReplicas));
        AssertProperties<PeerObservation>(canonical, nameof(PeerObservation.Server), nameof(PeerObservation.Peer), nameof(PeerObservation.Health),
            nameof(PeerObservation.Store), nameof(PeerObservation.ProcessFenced), nameof(PeerObservation.OwnershipProven),
            nameof(PeerObservation.CaughtUp), nameof(PeerObservation.SurvivingStoreProof));
        AssertProperties<SurvivingStoreProof>(canonical, nameof(SurvivingStoreProof.Store), nameof(SurvivingStoreProof.StoreGeneration),
            nameof(SurvivingStoreProof.ObservedMembershipSequence), nameof(SurvivingStoreProof.Plane), nameof(SurvivingStoreProof.Cell),
            nameof(SurvivingStoreProof.Cluster), nameof(SurvivingStoreProof.RecordedOwner), nameof(SurvivingStoreProof.ActiveAttachment),
            nameof(SurvivingStoreProof.OwnershipEpoch), nameof(SurvivingStoreProof.Compatible));
        AssertProperties<ReplicaObservation>(canonical, nameof(ReplicaObservation.ResourceIdentity), nameof(ReplicaObservation.CurrentReplicas),
            nameof(ReplicaObservation.HealthyReplicas), nameof(ReplicaObservation.LastSequence));
        await Assert.That(MessagingAcceptedReplacementFingerprint.Canonical(request)).Contains(nameof(SurvivingStoreProof.ActiveAttachment));
    }

    private static ReplacementRequest Completed(string suffix, long authorityEpoch)
    {
        var servers = Enumerable.Range(1, 3).Select(index => new ServerPolicy(
            new($"server-{index}"), new($"peer-{index}"), new($"host-{index}"))).ToArray();
        var account = new AccountId("control-account");
        var stream = new StreamPolicy(new("control-stream"), account, "ts.control.stream.>", 3,
            MessagingDurability.Critical, MessagingRetention.Limits, 100, 1_000,
            MessagingDiscard.Old, new("regional"), 10, MessagingAcknowledgement.Replicated,
            MessagingDiskSyncClass.AcknowledgedWriteStrict);
        var bucket = new BucketPolicy(new("control-bucket"), account, "ts.control.kv.>", 3,
            MessagingDurability.Critical, 100, 1_000, new("regional"),
            MessagingAcknowledgement.Replicated, MessagingDiskSyncClass.AcknowledgedWriteStrict);
        var policy = new PlanePolicy(MessagingPlane.Control, new("gru"), new("control-cluster"), 7, 3,
            servers,
            servers.SelectMany(from => servers.Where(to => to.Server != from.Server).Select(to => new RouteLink(from.Server, to.Server))),
            [new ClusterId("fra-control")], [new AccountPolicy(account, ["ts.control.>"])], [stream], [bucket]);
        var operation = new ReplacementOperation(new($"replace-{suffix}"), MessagingPlane.Control, policy.Cell,
            policy.Cluster, 5, authorityEpoch, policy.Generation, 100, 200, new($"store-{suffix}"), 4,
            servers[2].Server, servers[2].Peer, new($"replacement-server-{suffix}"),
            new($"replacement-peer-{suffix}"), new($"replacement-host-{suffix}"));
        var peers = new PeerObservation[]
        {
            new(servers[0].Server, servers[0].Peer, PeerHealth.Current, StoreClassification.Surviving, false, true, true),
            new(servers[1].Server, servers[1].Peer, PeerHealth.Current, StoreClassification.Surviving, false, true, true),
            new(operation.ReplacementServer, operation.ReplacementPeer, PeerHealth.Current, StoreClassification.Surviving, false, true, true),
        };
        var observation = new ClusterObservation(new($"observation-{suffix}"), policy.Cluster, policy.Generation, 150,
            peers, [new ReplicaObservation(stream.Id.Value, 3, 3, 150)],
            [new ReplicaObservation(bucket.Id.Value, 3, 3, 150)]);
        return new(policy, operation, operation, observation, 96);
    }

    private static IEnumerable<ReplacementRequest> AcceptedCases()
    {
        var complete = Completed("accepted", 11);
        var operation = complete.Proposed;
        yield return complete with { Persisted = null, Observation = null };
        yield return complete with { Persisted = null, Observation = LostObservation(complete, false, false, 3, true) };
        yield return complete with { Observation = LostObservation(complete, false, false, 3, true) };
        yield return complete with { Observation = LostObservation(complete, true, false, 3, true) };
        yield return complete with { Observation = LostObservation(complete, true, true, 2, true) };
        yield return complete with { Observation = LostObservation(complete, true, true, 3, true) };
        yield return complete;
        yield return complete with { Observation = SurvivingObservation(complete, null, PeerHealth.Failed, false, false) };
        yield return complete with { Observation = SurvivingObservation(complete, operation.FailedServer, PeerHealth.Current, false, true) };
        yield return complete with { Observation = SurvivingObservation(complete, operation.FailedServer, PeerHealth.Current, true, true) };
    }

    internal static ReplacementRequest FingerprintBaseline() => AcceptedCases().Last();

    private static ClusterObservation LostObservation(ReplacementRequest request, bool replacement, bool caughtUp, int replicas, bool includeFailed)
    {
        var operation = request.Proposed;
        var peers = new List<PeerObservation>();
        if (includeFailed) peers.Add(new(operation.FailedServer, operation.FailedPeer, PeerHealth.Failed,
            StoreClassification.Lost, true, false, false));
        foreach (var server in request.Policy.Servers.Take(2))
            peers.Add(new(server.Server, server.Peer, PeerHealth.Current, StoreClassification.Surviving, false, true, true));
        if (replacement) peers.Add(new(operation.ReplacementServer, operation.ReplacementPeer, PeerHealth.Current,
            StoreClassification.Surviving, false, true, caughtUp));
        return Observation(request, peers, replicas, "lost");
    }

    private static ClusterObservation SurvivingObservation(ReplacementRequest request, ServerId? activeAttachment,
        PeerHealth health, bool caughtUp, bool ownershipProven)
    {
        var operation = request.Proposed;
        var proof = new SurvivingStoreProof(operation.FailedStore, operation.CurrentStoreGeneration, 150,
            operation.Plane, operation.Cell, operation.Cluster, operation.FailedServer, activeAttachment,
            operation.AuthorityEpoch, true);
        var peers = new List<PeerObservation>
        {
            new(operation.FailedServer, operation.FailedPeer, health, StoreClassification.Surviving,
                health == PeerHealth.Failed, ownershipProven, caughtUp, proof),
        };
        foreach (var server in request.Policy.Servers.Take(2))
            peers.Add(new(server.Server, server.Peer, PeerHealth.Current, StoreClassification.Surviving, false, true, true));
        return Observation(request, peers, 3, "surviving");
    }

    private static ClusterObservation Observation(ReplacementRequest request, IEnumerable<PeerObservation> peers, int replicas, string prefix) =>
        new(new($"{prefix}-observation"), request.Proposed.Cluster, request.Proposed.ConfigurationGeneration, 150, peers,
            request.Policy.Streams.Select(stream => new ReplicaObservation(stream.Id.Value, replicas, replicas, 150)),
            request.Policy.Buckets.Select(bucket => new ReplicaObservation(bucket.Id.Value, replicas, replicas, 150)));

    private static ReplacementRequest Reverse(ReplacementRequest request)
    {
        var policy = request.Policy;
        var reversedPolicy = new PlanePolicy(policy.Plane, policy.Cell, policy.Cluster, policy.Generation, policy.MembershipFloor,
            policy.Servers.Reverse(), policy.Routes.Reverse(), policy.Gateways.Reverse(), policy.Accounts.Reverse(),
            policy.Streams.Reverse(), policy.Buckets.Reverse());
        var observation = request.Observation!;
        var reversedObservation = new ClusterObservation(observation.ObservationId, observation.Cluster,
            observation.ConfigurationGeneration, observation.MembershipSequence, observation.Peers.Reverse(),
            observation.StreamReplicas.Reverse(), observation.BucketReplicas.Reverse());
        return request with { Policy = reversedPolicy, Observation = reversedObservation };
    }

    private static void AssertProperties<T>(string canonical, params string[] expected)
    {
        var actual = typeof(T).GetProperties(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance)
            .Select(property => property.Name).Order(StringComparer.Ordinal);
        if (!actual.SequenceEqual(expected.Order(StringComparer.Ordinal)))
            throw new InvalidOperationException($"Public fingerprint inventory drifted for {typeof(T).Name}.");
        if (!canonical.Contains($"{(typeof(T).FullName ?? typeof(T).Name).Length}:{typeof(T).FullName ?? typeof(T).Name}", StringComparison.Ordinal) ||
            expected.Any(name => !canonical.Contains($"{name.Length}:{name}", StringComparison.Ordinal)))
            throw new InvalidOperationException($"Canonical fingerprint omitted {typeof(T).Name} material.");
    }

    private static string PublicFingerprint(MessagingDecision decision) =>
        $"{string.Join(',', decision.Intents.Select(intent => intent.GetType().Name))}|" +
        $"{string.Join(',', decision.Errors.Select(error => error.Code))}|" +
        $"{string.Join(',', decision.Trace.Select(trace => $"{trace.Sequence}:{trace.Code}:{trace.Action}"))}|" +
        $"{decision.Compatibility?.CurrentVersion}:{decision.Compatibility?.PreviousVersion}|" +
        (decision.AcceptedReplacementRequest is null ? "none" : MessagingAcceptedReplacementFingerprint.Hash(decision.AcceptedReplacementRequest));
}

internal static class MessagingAcceptedReplacementFingerprint
{
    internal static string Hash(ReplacementRequest request) =>
        Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(Canonical(request))));

    internal static string Canonical(ReplacementRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        using var builder = new ZStringWriter();
        Append(builder, request);
        return builder.ToString();
    }

    private static void Append(ZStringWriter builder, object? value)
    {
        if (value is null)
        {
            Field(builder, "null");
            return;
        }

        var type = value.GetType();
        Field(builder, type.FullName ?? type.Name);
        if (value is string text)
        {
            Field(builder, text);
            return;
        }
        if (type.IsEnum)
        {
            Field(builder, Convert.ToInt64(value, System.Globalization.CultureInfo.InvariantCulture)
                .ToString(System.Globalization.CultureInfo.InvariantCulture));
            return;
        }
        if (value is bool boolean)
        {
            Field(builder, boolean ? "1" : "0");
            return;
        }
        if (value is byte or sbyte or short or ushort or int or uint or long or ulong)
        {
            Field(builder, Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture)!);
            return;
        }
        if (value is System.Collections.IEnumerable enumerable)
        {
            var items = enumerable.Cast<object?>().Select(Item).Order(StringComparer.Ordinal).ToArray();
            Field(builder, items.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
            foreach (var item in items) Field(builder, item);
            return;
        }

        var properties = type.GetProperties(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance)
            .Where(property => property.GetIndexParameters().Length == 0 && property.GetMethod is not null)
            .OrderBy(property => property.Name, StringComparer.Ordinal).ToArray();
        Field(builder, properties.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
        foreach (var property in properties)
        {
            Field(builder, property.Name);
            Append(builder, property.GetValue(value));
        }
    }

    private static string Item(object? value)
    {
        using var builder = new ZStringWriter();
        Append(builder, value);
        return builder.ToString();
    }

    private static void Field(ZStringWriter builder, string value)
    {
        builder.Write(value.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
        builder.Write(':');
        builder.Write(value);
    }
}
