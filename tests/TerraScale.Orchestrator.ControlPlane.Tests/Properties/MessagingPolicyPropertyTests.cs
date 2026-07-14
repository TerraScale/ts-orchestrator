using System.Collections;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class MessagingPolicyPropertyTests
{
    private const int Cases = 1_000;

    [Test]
    public async Task ReplacementPropertiesFollowIndependentPersistAddCatchupVerifyRemoveOracleFor1000Cases()
    {
        var first = UnderCulture("tr-TR", () => RunReplacement(0xA471_1001));
        var replay = UnderCulture("ar-SA", () => RunReplacement(0xA471_1001));
        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Coverage).IsEqualTo(8);
    }

    [Test]
    public async Task SurvivingStoreProofPropertiesBindExactIdentityAndGenerationFor1000Cases()
    {
        var first = UnderCulture("tr-TR", () => RunSurvivingStoreProofs(0xA471_1004));
        var replay = UnderCulture("ja-JP", () => RunSurvivingStoreProofs(0xA471_1004));
        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Coverage).IsEqualTo(5);
    }

    [Test]
    public async Task PartitionPropertiesFollowExactIndependentAuthorityAndGenerationPrecedenceFor1000Cases()
    {
        var first = UnderCulture("tr-TR", () => RunPartition(0xA471_1002));
        var replay = UnderCulture("ja-JP", () => RunPartition(0xA471_1002));
        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Coverage).IsEqualTo(14);
    }

    [Test]
    public async Task DualPlaneIsolationPropertiesRejectEverySharedAuthoritySurfaceFor1000Cases()
    {
        var first = UnderCulture("tr-TR", () => RunIsolation(0xA471_1003));
        var replay = UnderCulture("ar-SA", () => RunIsolation(0xA471_1003));
        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Coverage).IsEqualTo(10);
    }

    [Test]
    public async Task MessagingSnapshotsAreBoundedDefensiveSecretSafeAndFatalAware()
    {
        var exact = Enumerable.Range(0, MessagingTechnicalInputLimits.MaximumCapturedItems).Select(i => $"root{i}").ToArray();
        var account = new AccountPolicy(new("account"), exact);
        exact[0] = "mutated";
        await Assert.That(account.SubjectRoots[0]).IsEqualTo("root0");

        var extra = new ExtraCurrentEnumerable<string>("root", MessagingTechnicalInputLimits.MaximumCapturedItems);
        await Assert.That(Capture(() => new AccountPolicy(new("account"), extra))).IsTypeOf<ArgumentException>();
        await Assert.That(extra.ExtraCurrentRead).IsFalse();
        await Assert.That(Capture(() => new AccountPolicy(new("account"), new EndlessEnumerable<string>("root"))))
            .IsTypeOf<ArgumentException>();

        var source = new List<string> { "root" };
        var disposed = new AccountPolicy(new("account"), new DisposeMutatingEnumerable<string>(source));
        await Assert.That(source).IsEmpty();
        await Assert.That(disposed.SubjectRoots.Single()).IsEqualTo("root");

        foreach (var phase in Enum.GetValues<IteratorPhase>())
        {
            var ordinary = Capture(() => new AccountPolicy(new("account"),
                new ThrowingEnumerable<string>(["root"], phase, new InvalidOperationException("secret-marker"))));
            await Assert.That(ordinary).IsTypeOf<ArgumentException>();
            await Assert.That(ordinary!.Message).DoesNotContain("secret-marker");
            await Assert.That(ordinary.InnerException).IsNull();
            foreach (var fatal in new Exception[] { new OutOfMemoryException("fatal"), new StackOverflowException("fatal"),
                         new AccessViolationException("fatal") })
                await Assert.That(Capture(() => new AccountPolicy(new("account"),
                    new ThrowingEnumerable<string>(["root"], phase, fatal)))!.GetType()).IsEqualTo(fatal.GetType());
        }

        var oversized = new HostileReadOnlyList<CompatibilityFeature>(MessagingTechnicalInputLimits.MaximumCapturedItems + 1);
        await Assert.That(HeldCode(MessagingPolicyEngine.DecideCompatibility(oversized, Compatibility())))
            .IsEqualTo(MessagingErrorCode.InvalidCatalog);
        await Assert.That(oversized.EnumeratorRequested).IsFalse();
        var lying = new EnumerableReadOnlyList<CompatibilityFeature>(1,
            new EndlessEnumerable<CompatibilityFeature>(CompatibilityFeature.Commands));
        await Assert.That(HeldCode(MessagingPolicyEngine.DecideCompatibility(lying, Compatibility())))
            .IsEqualTo(MessagingErrorCode.InvalidCatalog);
        var countOrdinary = new CountThrowingReadOnlyList<CompatibilityFeature>(new InvalidOperationException("count-secret"));
        await Assert.That(HeldCode(MessagingPolicyEngine.DecideCompatibility(countOrdinary, Compatibility())))
            .IsEqualTo(MessagingErrorCode.InvalidCatalog);
        var countFatal = new CountThrowingReadOnlyList<CompatibilityFeature>(new OutOfMemoryException("fatal"));
        await Assert.That(Capture(() => MessagingPolicyEngine.DecideCompatibility(countFatal, Compatibility())))
            .IsTypeOf<OutOfMemoryException>();
    }

    [Test]
    public async Task AuthorizingMessagingOutputsAreConstructionClosed()
    {
        var assembly = typeof(MessagingPolicyEngine).Assembly;
        var intentTypes = assembly.GetExportedTypes().Where(type => typeof(MessagingIntent).IsAssignableFrom(type)).ToArray();
        var outputTypes = intentTypes.Append(typeof(MessagingDecision)).ToArray();
        foreach (var type in outputTypes)
        {
            await Assert.That(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
            await Assert.That(type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Any(property => property.SetMethod is { IsPublic: true })).IsFalse();
            await Assert.That(type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Any(method => method.Name == "Deconstruct")).IsFalse();
        }
        var returningOutputs = assembly.GetExportedTypes().SelectMany(type => type.GetMethods(
            BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(method => (Type: type, Method: method))).Where(candidate =>
                candidate.Method.ReturnType == typeof(MessagingDecision) ||
                typeof(MessagingIntent).IsAssignableFrom(candidate.Method.ReturnType)).ToArray();
        var recordClones = returningOutputs.Where(candidate => outputTypes.Contains(candidate.Type) &&
            !candidate.Method.IsStatic && candidate.Method.GetParameters().Length == 0 &&
            candidate.Method.ReturnType == candidate.Type && candidate.Method.Name == "<Clone>$").ToArray();
        await Assert.That(recordClones.Length).IsEqualTo(outputTypes.Length);
        var callableFactories = returningOutputs.Except(recordClones).ToArray();
        await Assert.That(callableFactories.Length).IsEqualTo(4);
        await Assert.That(callableFactories.All(candidate => candidate.Type == typeof(MessagingPolicyEngine) &&
            candidate.Method.IsStatic && candidate.Method.Name is nameof(MessagingPolicyEngine.DecideTopology) or
                nameof(MessagingPolicyEngine.DecideReplacement) or nameof(MessagingPolicyEngine.DecidePartition) or
                nameof(MessagingPolicyEngine.DecideCompatibility))).IsTrue();
        await Assert.That(callableFactories.Any(candidate => candidate.Method.IsSpecialName)).IsFalse();
    }

    [Test]
    public async Task EmbeddedMessagingCorpusIsStrictPinnedBoundedAndInputSensitive()
    {
        var loaded = MessagingPolicyCorpus.LoadEmbedded();
        await Assert.That(loaded.Code).IsEqualTo(MessagingCorpusCode.Accepted);
        await Assert.That(loaded.Entries.Count).IsEqualTo(12);
        foreach (var entry in loaded.Entries)
        {
            var actual = Replay(entry);
            await Assert.That(actual.Outcome).IsEqualTo(entry.Expected);
            await Assert.That(Replay(entry with { Seed = entry.Seed + 1000 }).Fingerprint).IsNotEqualTo(actual.Fingerprint);
        }
        await Assert.That(MessagingPolicyCorpus.Parse("{}").Code).IsEqualTo(MessagingCorpusCode.InvalidSchema);
        await Assert.That(MessagingPolicyCorpus.Parse("{\"version\":1,\"entries\":[]}").Code).IsEqualTo(MessagingCorpusCode.InvalidSchema);
        await Assert.That(MessagingPolicyCorpus.Parse("{\"version\":1,\"version\":1,\"entries\":[]}").Code).IsEqualTo(MessagingCorpusCode.InvalidSchema);
        await Assert.That(MessagingPolicyCorpus.Parse("{/*x*/\"version\":1,\"entries\":[]}").Code).IsEqualTo(MessagingCorpusCode.InvalidJson);
        await Assert.That(MessagingPolicyCorpus.Parse("{\"version\":1,\"entries\":[],}").Code).IsEqualTo(MessagingCorpusCode.InvalidJson);
        await Assert.That(MessagingPolicyCorpus.Parse("{\"version\":1,\"entries\":[]} trailing").Code).IsEqualTo(MessagingCorpusCode.InvalidJson);
        await Assert.That(MessagingPolicyCorpus.Parse(new string('\u00e9', 16_384)).Code).IsEqualTo(MessagingCorpusCode.InvalidJson);
        await Assert.That(MessagingPolicyCorpus.Parse(new string('\u00e9', 16_385)).Code).IsEqualTo(MessagingCorpusCode.TooLarge);
        var first = loaded.Entries[0];
        foreach (var changed in new[] { first with { Id = "bad/id" }, first with { Family = "nats" },
                     first with { Mode = 99 }, first with { Expected = "Configure" }, first with { Seed = 0 } })
            await Assert.That(MessagingPolicyCorpus.Parse(MessagingPolicyCorpus.Json(changed)).Code).IsEqualTo(MessagingCorpusCode.InvalidSchema);
        await Assert.That(MessagingPolicyCorpus.Parse("{\"version\":\"1\",\"entries\":[]}").Code).IsEqualTo(MessagingCorpusCode.InvalidSchema);
        await Assert.That(MessagingPolicyCorpus.Parse("{\"version\":1,\"entries\":[],\"extra\":true}").Code).IsEqualTo(MessagingCorpusCode.InvalidSchema);
        var duplicate = $"{{\"version\":1,\"entries\":[{MessagingPolicyCorpus.Json(first)[24..^2]},{MessagingPolicyCorpus.Json(first)[24..^2]}]}}";
        await Assert.That(MessagingPolicyCorpus.Parse(duplicate).Code).IsEqualTo(MessagingCorpusCode.InvalidSchema);
    }

    private static Summary RunReplacement(ulong seed)
    {
        var generator = new Generator(seed); var coverage = new HashSet<int>(); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var mode = index % 8; var salt = generator.Next(1_000_000); var operation = Operation(index, salt); var policy = Control(index);
            var (request, expected) = ReplacementCase(index, mode, salt);
            var first = MessagingPolicyEngine.DecideReplacement(request);
            var reversed = request.Observation is null ? first : MessagingPolicyEngine.DecideReplacement(request with
            { Observation = Reverse(request.Observation) });
            Require(first.Compatibility is null && reversed.Compatibility is null, "replacement-compatibility", index);
            var actual = Outcome(first); Require(actual == expected && Outcome(reversed) == expected, "replacement", index);
            VerifyReplacementSubject(first, request, mode, index);
            coverage.Add(mode); digest = Mix(digest, actual, operation.AuthorityEpoch);
        }
        return new(Cases, coverage.Count, digest);
    }

    private static Summary RunPartition(ulong seed)
    {
        var generator = new Generator(seed); var coverage = new HashSet<int>(); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var mode = index % 14; var salt = generator.Next(1_000_000); var (request, expected) = PartitionCase(index, mode, salt);
            var decision = MessagingPolicyEngine.DecidePartition(request); var actual = Outcome(decision);
            Require(decision.Compatibility is null, "partition-compatibility", index);
            Require(actual == expected, "partition", index);
            if (mode == 8) { var intent = (ContinueRegionalIntent)decision.Intents.Single(); Require(intent.Cell == request.Cell && intent.RegionalEpoch == request.CurrentRegionalEpoch && intent.AcceptedGlobalGeneration == request.AcceptedGlobalGeneration, "regional-subject", index); }
            if (mode == 9) { var intent = (ContinueGlobalIntent)decision.Intents.Single(); Require(intent.Cell == request.Cell && intent.GlobalEpoch == request.CurrentGlobalEpoch && intent.AcceptedGlobalGeneration == request.AcceptedGlobalGeneration, "global-subject", index); }
            coverage.Add(mode); digest = Mix(digest, actual, salt);
        }
        return new(Cases, coverage.Count, digest);
    }

    private static Summary RunSurvivingStoreProofs(ulong seed)
    {
        var generator = new Generator(seed); var coverage = new HashSet<int>(); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var mode = index % 5; var salt = generator.Next(1_000_000); var operation = Operation(index, salt);
            var original = SurvivingObservation(index, operation);
            var proof = original.Peers.Single(peer => peer.Server == operation.FailedServer).SurvivingStoreProof!;
            proof = mode switch
            {
                1 => proof with { Store = new StoreId($"unrelated-store-{index}") },
                2 => proof with { StoreGeneration = operation.CurrentStoreGeneration - 1 },
                3 => proof with { StoreGeneration = operation.CurrentStoreGeneration + 1 },
                4 => proof with
                {
                    StoreGeneration = operation.CurrentStoreGeneration - 1,
                    OwnershipEpoch = operation.AuthorityEpoch + 1,
                },
                _ => proof,
            };
            var peers = original.Peers.Select(peer => peer.Server == operation.FailedServer
                ? peer with { SurvivingStoreProof = proof }
                : peer);
            var observation = new ClusterObservation(original.ObservationId, original.Cluster,
                original.ConfigurationGeneration, original.MembershipSequence, peers,
                original.StreamReplicas, original.BucketReplicas);
            var decision = MessagingPolicyEngine.DecideReplacement(new(Control(index), operation, operation, observation, 96));
            var reversed = MessagingPolicyEngine.DecideReplacement(new(Control(index), operation, operation, Reverse(observation), 96));
            var expected = mode switch
            {
                0 => "ReattachStore",
                1 => nameof(MessagingErrorCode.ConflictingEvidence),
                3 => nameof(MessagingErrorCode.FutureEvidence),
                _ => nameof(MessagingErrorCode.StaleEvidence),
            };
            Require(Outcome(decision) == expected && Outcome(reversed) == expected, "store-proof", index);
            if (mode == 0) VerifyReplacementSubject(decision,
                new(Control(index), operation, operation, observation, 96), 7, index);
            coverage.Add(mode); digest = Mix(digest, expected, proof.StoreGeneration);
        }
        return new(Cases, coverage.Count, digest);
    }

    private static Summary RunIsolation(ulong seed)
    {
        var generator = new Generator(seed); var coverage = new HashSet<int>(); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var mode = index % 10; var salt = generator.Next(1_000_000); var (topology, expected) = IsolationCase(index, mode);
            var decision = MessagingPolicyEngine.DecideTopology(topology);
            var reversed = MessagingPolicyEngine.DecideTopology(Reverse(topology));
            Require(decision.Compatibility is null && reversed.Compatibility is null, "topology-compatibility", index);
            var actual = Outcome(decision); Require(actual == expected && Outcome(reversed) == expected, "isolation", index);
            if (mode == 0)
            {
                var configured = decision.Intents.Cast<ConfigurePlaneIntent>().ToArray();
                Require(configured.Length == 2 && configured.Select(x => x.Policy.Plane)
                    .SequenceEqual([MessagingPlane.Control, MessagingPlane.Product]) &&
                    ReferenceEquals(configured[0].Policy, topology.Control) && ReferenceEquals(configured[1].Policy, topology.Product),
                    "plane-subjects", index);
            }
            coverage.Add(mode); digest = Mix(digest, actual, salt);
        }
        return new(Cases, coverage.Count, digest);
    }

    private static (ReplacementRequest Request, string Expected) ReplacementCase(int index, int mode, int salt)
    {
        var operation = Operation(index, salt); var policy = Control(index);
        return mode switch
        {
            0 => (new(policy, operation, null, null, 96), "Observe"),
            1 => (new(policy, operation, null, Observation(index, operation), 96), "Configure"),
            2 => (new(policy, operation, operation, Observation(index, operation), 96), "AddPeer"),
            3 => (new(policy, operation, operation, Observation(index, operation, replacement: true), 96), "WaitCatchup"),
            4 => (new(policy, operation, operation, Observation(index, operation, replacement: true, caught: true, replicas: 2), 96), "WaitCatchup"),
            5 => (new(policy, operation, operation, Observation(index, operation, replacement: true, caught: true), 96), "RemovePeer"),
            6 => (new(policy, operation, operation, Observation(index, operation, replacement: true, caught: true, includeFailed: false), 96), "ReplacementComplete"),
            7 => (new(policy, operation, operation, SurvivingObservation(index, operation), 96), "ReattachStore"),
            _ => throw new ArgumentOutOfRangeException(nameof(mode)),
        };
    }

    private static (PartitionRequest Request, string Expected) PartitionCase(int index, int mode, int salt)
    {
        var request = Partition(index, salt);
        request = mode switch
        {
            0 => request with { CommandRegionalEpoch = request.CurrentRegionalEpoch - 1 },
            1 => request with { Connectivity = ConnectivityState.RegionalQuorumLost },
            2 => request with { CommandGlobalGeneration = request.AcceptedGlobalGeneration - 1 },
            3 => request with { CommandGlobalGeneration = request.AcceptedGlobalGeneration + 1 },
            4 => request with { Scope = AuthorityScope.Global, Connectivity = ConnectivityState.GlobalDisconnected, HoldsCurrentGlobalAuthority = true },
            5 => request with { Scope = AuthorityScope.Global, Connectivity = ConnectivityState.Connected, HoldsCurrentGlobalAuthority = false },
            6 => request with { Scope = AuthorityScope.Global, Connectivity = ConnectivityState.Connected, HoldsCurrentGlobalAuthority = true, CommandGlobalEpoch = request.CurrentGlobalEpoch - 1 },
            7 => request with { CallerAuthorizesLocalOperation = false },
            8 => request,
            9 => request with { Scope = AuthorityScope.Global, Connectivity = ConnectivityState.Connected, HoldsCurrentGlobalAuthority = true },
            10 => request with { CommandRegionalEpoch = request.CurrentRegionalEpoch - 1, Connectivity = ConnectivityState.RegionalQuorumLost,
                CommandGlobalGeneration = request.AcceptedGlobalGeneration + 1 },
            11 => request with { Connectivity = ConnectivityState.RegionalQuorumLost,
                CommandGlobalGeneration = request.AcceptedGlobalGeneration + 1 },
            12 => request with { Scope = AuthorityScope.Global, Connectivity = ConnectivityState.GlobalDisconnected,
                HoldsCurrentGlobalAuthority = false, CommandGlobalGeneration = request.AcceptedGlobalGeneration + 1 },
            13 => request with { Scope = AuthorityScope.Global, Connectivity = ConnectivityState.GlobalDisconnected,
                HoldsCurrentGlobalAuthority = false, CommandGlobalEpoch = request.CurrentGlobalEpoch - 1 },
            _ => throw new ArgumentOutOfRangeException(nameof(mode)),
        };
        var expected = mode switch { 0 or 6 or 10 => "StaleAuthority", 1 or 4 or 5 or 7 or 11 or 13 => "PartitionDenied",
            2 => "StaleEvidence", 3 or 12 => "FutureEvidence", 8 => "ContinueRegional", _ => "ContinueGlobal" };
        return (request, expected);
    }

    private static (MessagingTopologyPolicy Policy, string Expected) IsolationCase(int index, int mode)
    {
        var control = Control(index); var product = Product(index);
        product = mode switch
        {
            1 => Product(index, cluster: control.Cluster),
            2 => Product(index, servers: ReplaceServer(ProductServers(index), 0, new(control.Servers[0].Server, new($"product-peer-x-{index}"), new($"product-host-x-{index}")))),
            3 => Product(index, servers: ReplaceServer(ProductServers(index), 0, new(new($"product-server-x-{index}"), control.Servers[0].Peer, new($"product-host-x-{index}")))),
            4 => Product(index, accounts: [Account($"control-account-{index}", $"ts.product{index}.>")],
                streams: [Stream($"product-stream-{index}", $"control-account-{index}", $"ts.product{index}.stream.>")],
                buckets: [Bucket($"product-bucket-{index}", $"control-account-{index}", $"ts.product{index}.kv.>")]),
            5 => Product(index, streams: [Stream($"control-stream-{index}", $"product-account-{index}", $"ts.product{index}.stream.>")]),
            6 => Product(index, buckets: [Bucket($"control-bucket-{index}", $"product-account-{index}", $"ts.product{index}.kv.>")]),
            7 => Product(index, accounts: [Account($"product-account-{index}", $"ts.control{index}.>")],
                streams: [Stream($"product-stream-{index}", $"product-account-{index}", $"ts.control{index}.stream.>")],
                buckets: [Bucket($"product-bucket-{index}", $"product-account-{index}", $"ts.control{index}.kv.>")]),
            8 => Product(index, gateways: [new($"forbidden-gateway-{index}")]),
            _ => product,
        };
        if (mode == 9) control = Control(index, gateways: [product.Cluster]);
        return (new(control, product, 96, 160, 100, Features()), mode == 0 ? "Configure" : "IsolationViolation");
    }

    private static ReplayResult Replay(MessagingCorpusEntry entry)
    {
        var index = checked((int)entry.Seed); var salt = checked(index * 17 + 3); MessagingDecision decision;
        decision = entry.Family switch
        {
            "replacement" => MessagingPolicyEngine.DecideReplacement(ReplacementCase(index, entry.Mode, salt).Request),
            "partition" => MessagingPolicyEngine.DecidePartition(PartitionCase(index, entry.Mode, salt).Request),
            "isolation" => MessagingPolicyEngine.DecideTopology(IsolationCase(index, entry.Mode).Policy),
            _ => throw new InvalidOperationException(),
        };
        var identity = $"{entry.Family}|{entry.Seed}|{entry.Mode}|" + string.Join('|', decision.Errors.Select(x => x.Code.ToString()).Concat(decision.Intents.Select(IntentIdentity))
            .Concat(decision.Trace.Select(x => $"{x.Sequence}:{x.Code}:{x.Action}")));
        return new(Outcome(decision), Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(identity))));
    }
    private static string IntentIdentity(MessagingIntent intent) => intent switch
    {
        ObserveClusterIntent x => $"observe:{x.Operation.Value}:{x.Cluster.Value}:{x.MinimumSequence}:{x.MaximumSequence}",
        ConfigureReplacementIntent x => $"persist:{x.Operation.OperationId.Value}:{x.Operation.AuthorityEpoch}",
        AddPeerIntent x => $"add:{x.Operation.Value}:{x.Server.Value}:{x.Peer.Value}:{x.AuthorityEpoch}",
        WaitCatchupIntent x => $"wait:{x.Operation.Value}:{x.Peer.Value}:{x.RequiredSequence}",
        RemovePeerIntent x => $"remove:{x.Operation.Value}:{x.FailedServer.Value}:{x.FailedPeer.Value}:{x.ReplacementPeer.Value}:{x.AuthorityEpoch}",
        ReattachSurvivingStoreIntent x =>
            $"reattach:{x.Operation.Value}:{x.Plane}:{x.Cell.Value}:{x.Cluster.Value}:{x.RecordedServer.Value}:{x.RecordedPeer.Value}:" +
            $"{x.ReplacementPlacement.Value}:{x.Store.Value}:{x.StoreGeneration}:{x.ObservedMembershipSequence}:{x.OwnershipEpoch}",
        ContinueRegionalIntent x => $"regional:{x.Cell.Value}:{x.RegionalEpoch}:{x.AcceptedGlobalGeneration}",
        ContinueGlobalIntent x => $"global:{x.Cell.Value}:{x.GlobalEpoch}:{x.AcceptedGlobalGeneration}",
        ConfigurePlaneIntent x => $"plane:{x.Policy.Plane}:{x.Policy.Cell.Value}:{x.Policy.Cluster.Value}:{x.Policy.Generation}",
        HoldMessagingIntent x => $"hold:{x.Reason}:{x.Operation?.Value}:{x.Server?.Value}:{x.Peer?.Value}",
        _ => intent.GetType().Name,
    };

    private static void VerifyReplacementSubject(MessagingDecision decision, ReplacementRequest request, int mode, int index)
    {
        var operation = request.Proposed;
        switch (mode)
        {
            case 0: { var x = (ObserveClusterIntent)decision.Intents.Single(); Require(x.Operation == operation.OperationId && x.Cluster == operation.Cluster && x.MinimumSequence == operation.MinimumObservationSequence && x.MaximumSequence == operation.MaximumObservationSequence, "observe-subject", index); break; }
            case 1: Require(((ConfigureReplacementIntent)decision.Intents.Single()).Operation == operation, "persist-subject", index); break;
            case 2: { var x = (AddPeerIntent)decision.Intents.Single(); Require(x.Operation == operation.OperationId && x.Cluster == operation.Cluster && x.Server == operation.ReplacementServer && x.Peer == operation.ReplacementPeer && x.Placement == operation.ReplacementPlacement && x.AuthorityEpoch == operation.AuthorityEpoch, "add-subject", index); break; }
            case 3 or 4: { var x = (WaitCatchupIntent)decision.Intents.Single(); Require(x.Operation == operation.OperationId && x.Cluster == operation.Cluster && x.Peer == operation.ReplacementPeer && x.RequiredSequence == request.Observation!.MembershipSequence, "wait-subject", index); break; }
            case 5: { var x = (RemovePeerIntent)decision.Intents.Single(); Require(x.Operation == operation.OperationId && x.Cluster == operation.Cluster && x.FailedServer == operation.FailedServer && x.FailedPeer == operation.FailedPeer && x.ReplacementPeer == operation.ReplacementPeer && x.VerifiedMembershipSequence == request.Observation!.MembershipSequence && x.AuthorityEpoch == operation.AuthorityEpoch, "remove-subject", index); break; }
            case 7:
            {
                var x = (ReattachSurvivingStoreIntent)decision.Intents.Single();
                var proof = request.Observation!.Peers.Single(peer => peer.Server == operation.FailedServer && peer.Peer == operation.FailedPeer).SurvivingStoreProof!;
                Require(x.Operation == operation.OperationId && x.Plane == operation.Plane && x.Cell == operation.Cell &&
                    x.Cluster == operation.Cluster && x.RecordedServer == operation.FailedServer && x.RecordedPeer == operation.FailedPeer &&
                    x.ReplacementPlacement == operation.ReplacementPlacement && x.Store == proof.Store &&
                    x.StoreGeneration == proof.StoreGeneration && x.ObservedMembershipSequence == proof.ObservedMembershipSequence &&
                    x.OwnershipEpoch == proof.OwnershipEpoch, "reattach-subject", index);
                break;
            }
        }
    }

    private static PlanePolicy Control(int index, IEnumerable<ClusterId>? gateways = null) => Plane(MessagingPlane.Control, "control", index, gateways: gateways ?? [new($"fra-control-{index}")]);
    private static PlanePolicy Product(int index, ClusterId? cluster = null, ServerPolicy[]? servers = null,
        IEnumerable<ClusterId>? gateways = null, IEnumerable<AccountPolicy>? accounts = null,
        IEnumerable<StreamPolicy>? streams = null, IEnumerable<BucketPolicy>? buckets = null) =>
        Plane(MessagingPlane.Product, "product", index, cluster, servers, gateways ?? [], accounts, streams, buckets);
    private static PlanePolicy Plane(MessagingPlane plane, string prefix, int index, ClusterId? cluster = null,
        ServerPolicy[]? servers = null, IEnumerable<ClusterId>? gateways = null, IEnumerable<AccountPolicy>? accounts = null,
        IEnumerable<StreamPolicy>? streams = null, IEnumerable<BucketPolicy>? buckets = null)
    {
        var serverValues = servers ?? Servers(prefix, index); var accountId = $"{prefix}-account-{index}";
        return new(plane, new($"cell-{index}"), cluster ?? new($"{prefix}-cluster-{index}"), 7, 3,
            serverValues, Routes(serverValues), gateways ?? [], accounts ?? [Account(accountId, $"ts.{prefix}{index}.>")],
            streams ?? [Stream($"{prefix}-stream-{index}", accountId, $"ts.{prefix}{index}.stream.>")],
            buckets ?? [Bucket($"{prefix}-bucket-{index}", accountId, $"ts.{prefix}{index}.kv.>")]);
    }
    private static ServerPolicy[] Servers(string prefix, int index) => Enumerable.Range(1, 3).Select(i =>
        new ServerPolicy(new($"{prefix}-server-{index}-{i}"), new($"{prefix}-peer-{index}-{i}"), new($"{prefix}-host-{index}-{i}"))).ToArray();
    private static ServerPolicy[] ProductServers(int index) => Servers("product", index);
    private static RouteLink[] Routes(ServerPolicy[] servers) => servers.SelectMany(from => servers.Where(to => to.Server != from.Server)
        .Select(to => new RouteLink(from.Server, to.Server))).ToArray();
    private static ServerPolicy[] ReplaceServer(ServerPolicy[] values, int index, ServerPolicy replacement) { var copy = values.ToArray(); copy[index] = replacement; return copy; }
    private static AccountPolicy Account(string id, string root) => new(new(id), [root]);
    private static StreamPolicy Stream(string id, string account, string root) => new(new(id), new(account), root, 3,
        MessagingDurability.Critical, MessagingRetention.Limits, 100, 1_000_000, MessagingDiscard.Old,
        new("regional"), 10, MessagingAcknowledgement.Replicated, MessagingDiskSyncClass.AcknowledgedWriteStrict);
    private static BucketPolicy Bucket(string id, string account, string root) => new(new(id), new(account), root, 3,
        MessagingDurability.Critical, 100, 1_000_000, new("regional"), MessagingAcknowledgement.Replicated,
        MessagingDiskSyncClass.AcknowledgedWriteStrict);
    private static ReplacementOperation Operation(int index, int salt) => new(new($"replace-{index}-{salt}"), MessagingPlane.Control,
        new($"cell-{index}"), new($"control-cluster-{index}"), index + 1L, index + 11L, 7, 100, 200,
        new($"store-{index}"), 4,
        new($"control-server-{index}-3"), new($"control-peer-{index}-3"), new($"replacement-server-{index}"),
        new($"replacement-peer-{index}"), new($"replacement-host-{index}"));
    private static ClusterObservation Observation(int index, ReplacementOperation operation, bool replacement = false,
        bool caught = false, int replicas = 3, bool includeFailed = true)
    {
        var peers = new List<PeerObservation>();
        if (includeFailed) peers.Add(new(operation.FailedServer, operation.FailedPeer, PeerHealth.Failed, StoreClassification.Lost, true, false, false));
        for (var i = 1; i <= 2; i++) peers.Add(new(new($"control-server-{index}-{i}"), new($"control-peer-{index}-{i}"), PeerHealth.Current, StoreClassification.Surviving, false, true, true));
        if (replacement) peers.Add(new(operation.ReplacementServer, operation.ReplacementPeer, PeerHealth.Current, StoreClassification.Surviving, false, true, caught));
        return new(new($"observation-{index}"), operation.Cluster, 7, 150, peers,
            [new($"control-stream-{index}", replicas, replicas, 50)], [new($"control-bucket-{index}", replicas, replicas, 50)]);
    }
    private static ClusterObservation SurvivingObservation(int index, ReplacementOperation operation)
    {
        var proof = new SurvivingStoreProof(new($"store-{index}"), 4, 150, MessagingPlane.Control, operation.Cell,
            operation.Cluster, operation.FailedServer, null, operation.AuthorityEpoch, true);
        var peers = new List<PeerObservation> { new(operation.FailedServer, operation.FailedPeer, PeerHealth.Failed,
            StoreClassification.Surviving, true, false, false, proof) };
        for (var i = 1; i <= 2; i++) peers.Add(new(new($"control-server-{index}-{i}"), new($"control-peer-{index}-{i}"), PeerHealth.Current, StoreClassification.Surviving, false, true, true));
        return new(new($"surviving-{index}"), operation.Cluster, 7, 150, peers,
            [new($"control-stream-{index}", 3, 3, 50)], [new($"control-bucket-{index}", 3, 3, 50)]);
    }
    private static ClusterObservation Reverse(ClusterObservation value) => new(value.ObservationId, value.Cluster,
        value.ConfigurationGeneration, value.MembershipSequence, value.Peers.Reverse(), value.StreamReplicas.Reverse(), value.BucketReplicas.Reverse());
    private static MessagingTopologyPolicy Reverse(MessagingTopologyPolicy value) => new(Reverse(value.Control), Reverse(value.Product),
        value.MaximumIdentityLength, value.MaximumSubjectLength, value.MaximumResources, value.KnownFeatures.Reverse());
    private static PlanePolicy Reverse(PlanePolicy value) => new(value.Plane, value.Cell, value.Cluster, value.Generation,
        value.MembershipFloor, value.Servers.Reverse(), value.Routes.Reverse(), value.Gateways.Reverse(),
        value.Accounts.Reverse(), value.Streams.Reverse(), value.Buckets.Reverse());
    private static PartitionRequest Partition(int index, int salt) => new(new($"cell-{index}-{salt}"), 96,
        ConnectivityState.GlobalDisconnected, AuthorityScope.Regional, index + 10L, index + 10L,
        index + 20L, index + 20L, index + 30L, index + 30L, true, false);
    private static CompatibilityFeature[] Features() => Enum.GetValues<CompatibilityFeature>().Where(x => x != CompatibilityFeature.Unspecified).ToArray();
    private static CompatibilityPair[] Pairs() => Enum.GetValues<CompatibilityPair>().Where(x => x != CompatibilityPair.Unspecified).ToArray();
    private static CompatibilityPolicy Compatibility() => new(2, 1, Features().SelectMany(feature => Pairs().Select(pair => new CompatibilityOutcome(feature, pair, true))));
    private static string Outcome(MessagingDecision decision) => decision.Errors.Count > 0 ? decision.Errors[0].Code.ToString() :
        decision.Intents.Count > 0 ? decision.Intents[0] switch
        { ContinueRegionalIntent => "ContinueRegional", ContinueGlobalIntent => "ContinueGlobal", _ => decision.Intents[0].Action.ToString() }
        : decision.Trace[0].Code.ToString();
    private static MessagingErrorCode HeldCode(MessagingDecision decision) => decision.Errors.Single().Code;
    private static T UnderCulture<T>(string culture, Func<T> action) { var before = CultureInfo.CurrentCulture; try { CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture); return action(); } finally { CultureInfo.CurrentCulture = before; } }
    private static void Require(bool condition, string family, int index) { if (!condition) throw new InvalidOperationException($"{family} failed at {index}."); }
    private static ulong Mix(ulong digest, string value, long number) { unchecked { foreach (var c in value) digest = (digest ^ c) * 1099511628211UL; return (digest ^ (ulong)number) * 1099511628211UL; } }
    private static Exception? Capture(Action action) { try { action(); return null; } catch (Exception error) { return error; } }
    private sealed record Summary(int Cases, int Coverage, ulong Digest);
    private sealed record ReplayResult(string Outcome, string Fingerprint);
    private sealed class Generator(ulong seed) { private ulong _state = seed; public int Next(int max) { _state ^= _state << 13; _state ^= _state >> 7; _state ^= _state << 17; return (int)(_state % (uint)max); } }

    private enum IteratorPhase { GetEnumerator, MoveNext, Current, Dispose }
    private sealed class ThrowingEnumerable<T>(T[] values, IteratorPhase phase, Exception failure) : IEnumerable<T>
    {
        public IEnumerator<T> GetEnumerator() => phase == IteratorPhase.GetEnumerator ? throw failure : new Iterator(values, phase, failure);
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        private sealed class Iterator(T[] values, IteratorPhase phase, Exception failure) : IEnumerator<T>
        { private int _index = -1; public T Current => phase == IteratorPhase.Current ? throw failure : values[_index]; object? IEnumerator.Current => Current;
          public bool MoveNext() { if (phase == IteratorPhase.MoveNext) throw failure; return ++_index < values.Length; }
          public void Reset() => throw new NotSupportedException(); public void Dispose() { if (phase == IteratorPhase.Dispose) throw failure; } }
    }
    private sealed class ExtraCurrentEnumerable<T>(T value, int maximum) : IEnumerable<T>
    { public bool ExtraCurrentRead { get; private set; } public IEnumerator<T> GetEnumerator() => new Iterator(this, value, maximum); IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
      private sealed class Iterator(ExtraCurrentEnumerable<T> owner, T value, int maximum) : IEnumerator<T>
      { private int _index = -1; public T Current { get { if (_index == maximum) owner.ExtraCurrentRead = true; return value; } } object? IEnumerator.Current => Current;
        public bool MoveNext() => ++_index <= maximum; public void Reset() => throw new NotSupportedException(); public void Dispose() { } } }
    private sealed class EndlessEnumerable<T>(T value) : IEnumerable<T>
    { public IEnumerator<T> GetEnumerator() => new Iterator(value); IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
      private sealed class Iterator(T value) : IEnumerator<T> { public T Current => value; object? IEnumerator.Current => Current; public bool MoveNext() => true; public void Reset() { } public void Dispose() { } } }
    private sealed class DisposeMutatingEnumerable<T>(List<T> source) : IEnumerable<T>
    { public IEnumerator<T> GetEnumerator() => new Iterator(source); IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
      private sealed class Iterator(List<T> source) : IEnumerator<T> { private int _index = -1; public T Current => source[_index]; object? IEnumerator.Current => Current; public bool MoveNext() => ++_index < source.Count; public void Reset() { } public void Dispose() => source.Clear(); } }
    private sealed class HostileReadOnlyList<T>(int count) : IReadOnlyList<T>
    { public bool EnumeratorRequested { get; private set; } public int Count => count; public T this[int index] => throw new NotSupportedException();
      public IEnumerator<T> GetEnumerator() { EnumeratorRequested = true; throw new InvalidOperationException(); } IEnumerator IEnumerable.GetEnumerator() => GetEnumerator(); }
    private sealed class EnumerableReadOnlyList<T>(int count, IEnumerable<T> source) : IReadOnlyList<T>
    { public int Count => count; public T this[int index] => throw new NotSupportedException(); public IEnumerator<T> GetEnumerator() => source.GetEnumerator(); IEnumerator IEnumerable.GetEnumerator() => GetEnumerator(); }
    private sealed class CountThrowingReadOnlyList<T>(Exception failure) : IReadOnlyList<T>
    { public int Count => throw failure; public T this[int index] => throw new NotSupportedException(); public IEnumerator<T> GetEnumerator() => throw new InvalidOperationException(); IEnumerator IEnumerable.GetEnumerator() => GetEnumerator(); }
}
