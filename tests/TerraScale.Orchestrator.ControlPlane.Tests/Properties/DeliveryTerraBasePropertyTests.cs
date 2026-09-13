using System.Collections;
using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.ControlPlane.TerraBase;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class DeliveryTerraBasePropertyTests
{
    private const int Cases = 1_000;

    [Test]
    public async Task DeliverySourcePropertiesBindIdentityGenerationDigestSignaturePermutationAndReplay()
    {
        var first = UnderCulture("tr-TR", () => RunSources(0xD311_0001));
        var replay = UnderCulture("ar-SA", () => RunSources(0xD311_0001));
        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Kinds).IsEqualTo(7);
    }

    [Test]
    public async Task TerraBaseTopologyPropertiesProtectMembershipQuorumReplayAndWriterFences()
    {
        var first = UnderCulture("tr-TR", () => RunTopology(0x7E22_0001));
        var replay = UnderCulture("ar-SA", () => RunTopology(0x7E22_0001));
        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Kinds).IsEqualTo(9);
    }

    [Test]
    public async Task TerraBaseRecoveryPropertiesBindChainDigestTerminalGenerationRollbackAndPermutation()
    {
        var first = UnderCulture("tr-TR", () => RunRecovery(0x7E22_0002));
        var replay = UnderCulture("ar-SA", () => RunRecovery(0x7E22_0002));
        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Kinds).IsEqualTo(6);
    }

    [Test]
    public async Task TechnicalSnapshotsAreBoundedDefensiveSecretSafeAndPropagateFatalFailures()
    {
        var dependency = new DependencyProof(new("dep"), 1, new("digest"));
        var exact = Enumerable.Repeat(dependency, DeliveryTechnicalInputLimits.MaximumDependencyCount)
            .Select((value, index) => value with { Manifest = new($"dep-{index}") }).ToArray();
        var revision = Source(dependencies: exact);
        exact[0] = dependency with { Manifest = new("mutated") };
        await Assert.That(revision.Dependencies[0].Manifest.Value).IsEqualTo("dep-0");
        await Assert.That(Capture(() => Source(dependencies: Enumerable.Repeat(dependency,
            DeliveryTechnicalInputLimits.MaximumDependencyCount + 1)))).IsTypeOf<ArgumentException>();

        var extraCurrent = new ExtraCurrentEnumerable<DependencyProof>(dependency,
            DeliveryTechnicalInputLimits.MaximumDependencyCount);
        await Assert.That(Capture(() => Source(dependencies: extraCurrent))).IsTypeOf<ArgumentException>();
        await Assert.That(extraCurrent.ExtraCurrentRead).IsFalse();
        await Assert.That(Capture(() => Source(dependencies: new InfiniteEnumerable<DependencyProof>(dependency))))
            .IsTypeOf<ArgumentException>();
        await Assert.That(Capture(() => Source(dependencies: new DependencyProof[] { null! }))).IsTypeOf<ArgumentException>();
        var mutableDependencies = new[] { dependency };
        var disposedRevision = Source(dependencies: new DisposeMutatingEnumerable<DependencyProof>(mutableDependencies,
            () => mutableDependencies[0] = dependency with { Manifest = new("changed-on-dispose") }));
        await Assert.That(disposedRevision.Dependencies[0].Manifest.Value).IsEqualTo("dep");

        var scope = TerraBaseTestData.Scope();
        var writers = Enumerable.Range(0, 4).Select(index => TerraBaseTestData.Member($"m-{index}")).ToArray();
        var evidence = new TerraBaseWriterEvidence(scope, new DisposeMutatingEnumerable<TerraBaseMemberId>(writers,
            () => writers[0] = TerraBaseTestData.Member("changed")), TerraBaseProof.Proven, TerraBaseProof.Proven,
            TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseTestData.O(9), 4);
        await Assert.That(evidence.Writers[0].Value).IsEqualTo("m-0");
        var exactWriters = Enumerable.Range(0, TerraBaseTechnicalInputLimits.MaximumWriterEvidenceCount)
            .Select(index => TerraBaseTestData.Member($"writer-{index}")).ToArray();
        var exactWriterEvidence = new TerraBaseWriterEvidence(scope, exactWriters, TerraBaseProof.Proven,
            TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseTestData.O(9),
            TerraBaseTechnicalInputLimits.MaximumWriterEvidenceCount);
        await Assert.That(exactWriterEvidence.Writers.Count).IsEqualTo(TerraBaseTechnicalInputLimits.MaximumWriterEvidenceCount);
        await Assert.That(Capture(() => new TerraBaseWriterEvidence(scope,
            Enumerable.Repeat(TerraBaseTestData.Member(), 5), TerraBaseProof.Proven, TerraBaseProof.Proven,
            TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseTestData.O(9), 4))).IsTypeOf<ArgumentException>();
        var extraWriterCurrent = new ExtraCurrentEnumerable<TerraBaseMemberId>(TerraBaseTestData.Member(), 4);
        await Assert.That(Capture(() => new TerraBaseWriterEvidence(scope, extraWriterCurrent, TerraBaseProof.Proven,
            TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseTestData.O(9), 4)))
            .IsTypeOf<ArgumentException>();
        await Assert.That(extraWriterCurrent.ExtraCurrentRead).IsFalse();
        await Assert.That(Capture(() => new TerraBaseWriterEvidence(scope,
            new InfiniteEnumerable<TerraBaseMemberId>(TerraBaseTestData.Member()), TerraBaseProof.Proven,
            TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseTestData.O(9), 4)))
            .IsTypeOf<ArgumentException>();
        await Assert.That(Capture(() => new TerraBaseWriterEvidence(scope, new TerraBaseMemberId?[] { null },
            TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven,
            TerraBaseTestData.O(9), 4))).IsTypeOf<ArgumentException>();

        foreach (var mode in Enum.GetValues<ThrowMode>())
        {
            var ordinary = Capture(() => Source(dependencies: new ThrowingEnumerable<DependencyProof>([dependency], mode,
                new InvalidOperationException("secret-marker"))));
            await Assert.That(ordinary).IsTypeOf<ArgumentException>();
            await Assert.That(ordinary!.Message).DoesNotContain("secret-marker");
            var deliveryFatal = Capture(() => Source(dependencies: new ThrowingEnumerable<DependencyProof>([dependency], mode,
                new OutOfMemoryException("fatal"))));
            await Assert.That(deliveryFatal).IsTypeOf<OutOfMemoryException>();
            var terraOrdinary = Capture(() => new TerraBaseBackupEvidence(scope,
                new ThrowingEnumerable<TerraBaseBackupSegment?>([TerraBaseTestData.Segment(1, true)], mode,
                    new InvalidOperationException("terra-secret-marker")), TerraBaseProof.Proven, TerraBaseProof.Proven,
                TerraBaseProof.Proven, 8));
            await Assert.That(terraOrdinary).IsTypeOf<ArgumentException>();
            await Assert.That(terraOrdinary!.Message).DoesNotContain("terra-secret-marker");
            var fatal = Capture(() => new TerraBaseBackupEvidence(scope,
                new ThrowingEnumerable<TerraBaseBackupSegment?>([TerraBaseTestData.Segment(1, true)], mode,
                    new OutOfMemoryException("fatal")), TerraBaseProof.Proven, TerraBaseProof.Proven,
                TerraBaseProof.Proven, 8));
            await Assert.That(fatal).IsTypeOf<OutOfMemoryException>();
        }

        var tooManyRunners = new OversizedReadOnlyList<RunnerEvidence>(
            DeliveryTechnicalInputLimits.MaximumRunnerEvidenceCount + 1);
        var held = DeliveryEngine.DecideJob(Job(), tooManyRunners, 64);
        await Assert.That(held.Errors.Single().Code).IsEqualTo(DeliveryErrorCode.InvalidInput);
        await Assert.That(tooManyRunners.EnumeratorRequested).IsFalse();
        var lyingInfinite = new EnumerableReadOnlyList<RunnerEvidence>(1,
            new InfiniteEnumerable<RunnerEvidence>(new(new("runner"), TrustZone.TrustedBuild, 1, true,
                [RunnerCapability.Compile])));
        await Assert.That(DeliveryEngine.DecideJob(Job(), lyingInfinite, 64).Errors.Single().Code)
            .IsEqualTo(DeliveryErrorCode.InvalidInput);
        var ordinaryList = new EnumerableReadOnlyList<RunnerEvidence>(1,
            new ThrowingEnumerable<RunnerEvidence>([], ThrowMode.GetEnumerator, new InvalidOperationException("list-secret")));
        await Assert.That(DeliveryEngine.DecideJob(Job(), ordinaryList, 64).Errors.Single().Code)
            .IsEqualTo(DeliveryErrorCode.InvalidInput);
        var fatalList = new EnumerableReadOnlyList<RunnerEvidence>(1,
            new ThrowingEnumerable<RunnerEvidence>([], ThrowMode.GetEnumerator, new OutOfMemoryException("fatal")));
        await Assert.That(Capture(() => DeliveryEngine.DecideJob(Job(), fatalList, 64))).IsTypeOf<OutOfMemoryException>();
        var ordinaryCount = new CountThrowingReadOnlyList<RunnerEvidence>(new InvalidOperationException("count-secret"));
        var ordinaryCountDecision = DeliveryEngine.DecideJob(Job(), ordinaryCount, 64);
        await Assert.That(ordinaryCountDecision.Errors.Single().Code).IsEqualTo(DeliveryErrorCode.InvalidInput);
        await Assert.That(ordinaryCountDecision.ToString()).DoesNotContain("count-secret");
        var fatalCount = new CountThrowingReadOnlyList<RunnerEvidence>(new OutOfMemoryException("fatal"));
        await Assert.That(Capture(() => DeliveryEngine.DecideJob(Job(), fatalCount, 64))).IsTypeOf<OutOfMemoryException>();

        foreach (var fatalType in new Exception[] { new StackOverflowException("fatal"), new AccessViolationException("fatal") })
        {
            await Assert.That(Capture(() => Source(dependencies: new ThrowingEnumerable<DependencyProof>([dependency],
                ThrowMode.GetEnumerator, fatalType)))!.GetType()).IsEqualTo(fatalType.GetType());
            await Assert.That(Capture(() => new TerraBaseBackupEvidence(scope,
                new ThrowingEnumerable<TerraBaseBackupSegment?>([TerraBaseTestData.Segment(1, true)],
                    ThrowMode.GetEnumerator, fatalType), TerraBaseProof.Proven, TerraBaseProof.Proven,
                TerraBaseProof.Proven, 8))!.GetType()).IsEqualTo(fatalType.GetType());
        }
    }

    [Test]
    public async Task AuthorizingOutputsAreConstructionClosedAndObservedEnumsAreDefined()
    {
        var authorizingTypes = typeof(DeliveryDecision).Assembly.GetExportedTypes().Where(type =>
            type == typeof(DeliveryDecision) || typeof(DeliveryIntent).IsAssignableFrom(type) ||
            type == typeof(TerraBaseDecision) || typeof(TerraBaseIntentSubject).IsAssignableFrom(type));
        foreach (var type in authorizingTypes)
            await Assert.That(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();

        var deliveryEnums = typeof(DeliveryAction).Assembly.GetExportedTypes().Where(type => type.IsEnum &&
            type.Namespace == "TerraScale.Orchestrator.ControlPlane.Delivery");
        var terraBaseEnums = typeof(TerraBaseAction).Assembly.GetExportedTypes().Where(type => type.IsEnum &&
            type.Namespace == "TerraScale.Orchestrator.ControlPlane.TerraBase");
        foreach (var type in deliveryEnums.Concat(terraBaseEnums))
            await Assert.That(Enum.GetNames(type).Any(name => name is "Unknown" or "Unspecified" or "Uninitialized" or "None")).IsTrue();

        var invalidJob = Job();
        var undefinedJob = new JobRequest(invalidJob.Pipeline, invalidJob.Job, (JobKind)int.MaxValue, invalidJob.Tree,
            invalidJob.Generation, invalidJob.Attempt, invalidJob.MaximumAttempts, invalidJob.Idempotency,
            invalidJob.AllowedZones, invalidJob.RequiredCapabilities, invalidJob.MinimumRunnerSequence,
            invalidJob.MaximumRunnerSequence, invalidJob.RetryAuthorized);
        await Assert.That(DeliveryEngine.DecideJob(undefinedJob, [], 64).Intents.Single()).IsTypeOf<HoldDeliveryIntent>();
        var scope = TerraBaseTestData.Scope();
        await Assert.That(TerraBaseTopologyPlanner.PlanAdd(scope,
            TerraBaseTestData.Topology(scope: scope) with { MemberKind = (TerraBaseMemberKind)int.MaxValue }).IsMutationAuthorized).IsFalse();
    }

    [Test]
    public async Task EmbeddedReplayCorpusIsStrictWholeFilePinnedBoundedAndInputSensitive()
    {
        var loaded = DeliveryTerraBaseCorpus.LoadEmbedded();
        await Assert.That(loaded.Code).IsEqualTo(DeliveryTerraBaseCorpusCode.Accepted);
        await Assert.That(loaded.Entries.Count).IsEqualTo(4);
        foreach (var entry in loaded.Entries)
        {
            await Assert.That(DeliveryTerraBaseCorpus.Digest(entry)).IsEqualTo(entry.Digest);
            await Assert.That(Replay(entry)).IsEqualTo(entry.Expected);
            var changed = DeliveryTerraBaseCorpus.WithDigest(entry with { Delta = entry.Delta + 1 });
            var result = DeliveryTerraBaseCorpus.Load(DeliveryTerraBaseCorpus.Json(changed));
            await Assert.That(result.Code).IsEqualTo(DeliveryTerraBaseCorpusCode.Accepted);
            await Assert.That(Replay(result.Entries.Single())).IsNotEqualTo(entry.Expected);
        }
        await Assert.That(DeliveryTerraBaseCorpus.Load("{\"version\":2,\"entries\":[]}").Code)
            .IsEqualTo(DeliveryTerraBaseCorpusCode.InvalidSchema);
        await Assert.That(DeliveryTerraBaseCorpus.Load("{\"version\":1,\"entries\":[]}").Code)
            .IsEqualTo(DeliveryTerraBaseCorpusCode.InvalidSchema);
        await Assert.That(DeliveryTerraBaseCorpus.Load("{\"version\":1,\"version\":1,\"entries\":[]}").Code)
            .IsEqualTo(DeliveryTerraBaseCorpusCode.InvalidSchema);
        await Assert.That(DeliveryTerraBaseCorpus.Load("{\"version\":1,\"unknown\":[]}").Code)
            .IsEqualTo(DeliveryTerraBaseCorpusCode.InvalidSchema);
        var validJson = DeliveryTerraBaseCorpus.Json(loaded.Entries[0]);
        await Assert.That(DeliveryTerraBaseCorpus.Load(validJson.Replace(loaded.Entries[0].Digest,
            new string('0', 64), StringComparison.Ordinal)).Code).IsEqualTo(DeliveryTerraBaseCorpusCode.InvalidDigest);
        await Assert.That(DeliveryTerraBaseCorpus.Load(new string('x', 32_769)).Code)
            .IsEqualTo(DeliveryTerraBaseCorpusCode.TooLarge);
        await Assert.That(DeliveryTerraBaseCorpus.Load("{").Code).IsEqualTo(DeliveryTerraBaseCorpusCode.InvalidJson);
    }

    private static Summary RunSources(ulong seed)
    {
        var random = new Generator(seed); var kinds = new HashSet<string>(); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var generation = random.Next(900_000) + 1L; var mode = index % 9;
            var dependencies = new[] { new DependencyProof(new($"z-{index}"), generation, new($"d-z-{index}")),
                new DependencyProof(new($"a-{index}"), generation, new($"d-a-{index}")) };
            var proposed = Source(index, generation, dependencies); SourceDecisionRequest request; string expected;
            switch (mode)
            {
                case 0: request = new(proposed, Source(index, generation, dependencies.Reverse()), null, 96); expected = "Idempotent"; break;
                case 1: request = new(proposed, Source(index, generation + 1, dependencies), null, 96); expected = "StaleGeneration"; break;
                case 2: request = new(proposed, Source(index, generation, dependencies, signature: $"other-{index}"), null, 96); expected = "ConflictingGeneration"; break;
                case 3: request = new(proposed, null, Evidence(proposed, SourceState.Verified, dependencies), 96); expected = "Plan"; break;
                case 4: request = new(proposed, null, Evidence(proposed, SourceState.Verified, dependencies.Reverse()), 96); expected = "Plan"; break;
                case 5: request = new(proposed, null, Evidence(proposed, SourceState.Verified, dependencies, digest: $"wrong-{index}"), 96); expected = "EvidenceInvalidated"; break;
                case 6: request = new(proposed, null, Evidence(proposed, SourceState.Fetched, dependencies), 96); expected = "Verify"; break;
                case 7: request = new(proposed, null, Evidence(proposed, SourceState.Verified, dependencies, signatureValid: false), 96); expected = "Verify"; break;
                default: request = new(proposed, null, null, 96); expected = "Fetch"; break;
            }
            var actual = DeliveryOutcome(DeliveryEngine.DecideSource(request));
            Require(actual == expected, "source", index); kinds.Add(actual); digest = Mix(digest, actual, generation);
        }
        return new(Cases, kinds.Count, digest);
    }

    private static Summary RunTopology(ulong seed)
    {
        var random = new Generator(seed); var kinds = new HashSet<string>(); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var mode = index % 10; var scope = Scope(index, (ulong)random.Next(800_000) + 1); TerraBaseDecision decision; string expected;
            var topology = TerraBaseTestData.Topology(scope: scope);
            switch (mode)
            {
                case 0: decision = TerraBaseTopologyPlanner.PlanRemove(scope, topology with { MemberKind = TerraBaseMemberKind.PermanentA }); expected = "PermanentMember"; break;
                case 1: decision = TerraBaseTopologyPlanner.PlanRemove(scope, topology with { MemberKind = TerraBaseMemberKind.PermanentB }); expected = "PermanentMember"; break;
                case 2: decision = TerraBaseTopologyPlanner.PlanRemove(scope, topology with { LossCount = TerraBaseLossCount.TwoOrMore }); expected = "ReplicationUnsafe"; break;
                case 3: decision = TerraBaseTopologyPlanner.PlanRemove(scope, topology with { QuorumFloor = TerraBaseProof.Unknown }); expected = "ProofMissing"; break;
                case 4: decision = TerraBaseTopologyPlanner.PlanAdd(scope, topology with { Replication = TerraBaseReplication.Lagging, PostChangeReplication = TerraBaseProof.Unknown }); expected = "CatchUp"; break;
                case 5: decision = TerraBaseTopologyPlanner.PlanAdd(scope, topology with { TopologyApplied = TerraBaseProof.Unknown, Replication = TerraBaseReplication.Unknown, PostChangeReplication = TerraBaseProof.Unknown }); expected = "Add"; break;
                case 6: decision = TerraBaseTopologyPlanner.PlanRemove(scope, topology with { MemberRole = TerraBaseRole.Leader, LeadershipTransferred = TerraBaseProof.Unknown, TopologyApplied = TerraBaseProof.Unknown, NoDatabaseReference = TerraBaseProof.Unknown, PostChangeReplication = TerraBaseProof.Unknown }); expected = "Transfer"; break;
                case 7: decision = TerraBaseTopologyPlanner.PlanRemove(scope, topology with { Scope = scope with { Operation = TerraBaseTestData.Op($"wrong-{index}") } }); expected = "WrongEvidenceScope"; break;
                case 8: decision = TerraBaseRetainedVolumePlanner.Plan(scope, new(scope, [], TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseTestData.O(scope.AuthorityEpoch.Value + 1), 8)); expected = "StartWithRetainedVolume"; break;
                default: decision = TerraBaseRetainedVolumePlanner.Plan(scope, new(scope, [scope.Member], TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseTestData.O(scope.AuthorityEpoch.Value + 1), 8)); expected = "SplitWriter"; break;
            }
            var actual = TerraOutcome(decision); Require(actual == expected, "topology", index); kinds.Add(actual); digest = Mix(digest, actual, (long)scope.TopologyGeneration.Value);
        }
        return new(Cases, kinds.Count, digest);
    }

    private static Summary RunRecovery(ulong seed)
    {
        var random = new Generator(seed); var kinds = new HashSet<string>(); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var scope = Scope(index, (ulong)random.Next(800_000) + 1); var mode = index % 10;
            var segments = new[] { Segment(scope, 1, true), Segment(scope, 2, false, 1) }; TerraBaseDecision decision; string expected;
            if (mode < 6)
            {
                IEnumerable<TerraBaseBackupSegment?> input = mode switch
                {
                    1 => segments.Reverse(),
                    2 => [segments[0], segments[1] with { ParentSequence = TerraBaseTestData.O(9) }],
                    3 => [segments[0], segments[1] with { Backup = segments[0].Backup }],
                    4 => [segments[0] with { Digest = TerraBaseTestData.Digest($"changed-{index}") }, segments[1]],
                    _ => segments
                };
                var evidence = new TerraBaseBackupEvidence(scope, input, mode == 5 ? TerraBaseProof.Unknown : TerraBaseProof.Proven,
                    TerraBaseProof.Proven, TerraBaseProof.Proven, 8);
                decision = TerraBaseBackupPlanner.Accept(scope, evidence);
                expected = mode switch { 0 or 1 or 4 => "Completed", 2 or 3 => "ChainGap", _ => "ApplicationConsistencyRequired" };
            }
            else
            {
                var chain = new TerraBaseBackupEvidence(scope, segments, TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven, 8);
                var restoreApplied = mode == 6 ? TerraBaseProof.Unknown : TerraBaseProof.Proven;
                var restore = new TerraBaseRestoreEvidence(scope, TerraBaseTestData.Restore($"r-{index}"), scope.DatabaseGeneration,
                    TerraBaseTestData.O(scope.DatabaseGeneration.Value + 1), chain, TerraBaseProof.Proven,
                    restoreApplied, restoreApplied == TerraBaseProof.Proven ? TerraBaseProof.Proven : TerraBaseProof.Unknown,
                    restoreApplied == TerraBaseProof.Proven ? TerraBaseProof.Proven : TerraBaseProof.Unknown,
                    mode == 9 || restoreApplied != TerraBaseProof.Proven ? TerraBaseProof.Unknown : TerraBaseProof.Proven);
                if (mode == 8) restore = restore with { TargetGeneration = scope.DatabaseGeneration };
                decision = TerraBaseRestorePlanner.Plan(scope, restore.Restore, segments[^1].Backup,
                    TerraBaseTestData.O(scope.DatabaseGeneration.Value + 1), restore);
                expected = mode switch { 6 => "Restore", 7 => "Completed", 8 => "WrongEvidenceScope", _ => "PromotionProofMissing" };
            }
            var actual = TerraOutcome(decision); Require(actual == expected, "recovery", index); kinds.Add(actual); digest = Mix(digest, actual, (long)scope.DatabaseGeneration.Value);
        }
        return new(Cases, kinds.Count, digest);
    }

    private static string Replay(DeliveryTerraBaseCorpusEntry entry)
    {
        if (entry.Family == "delivery-source")
        {
            var proposed = Source((int)entry.Seed, entry.Seed);
            var accepted = Source((int)entry.Seed, entry.Seed + (entry.Delta % 2));
            return DeliveryOutcome(DeliveryEngine.DecideSource(new(proposed, accepted, null, 96)));
        }
        var scope = Scope((int)entry.Seed, (ulong)entry.Seed); var first = Segment(scope, 1, true);
        var second = Segment(scope, (ulong)(1 + (entry.Delta % 2)), false, 1);
        return TerraOutcome(TerraBaseBackupPlanner.Accept(scope, new(scope, [first, second], TerraBaseProof.Proven,
            TerraBaseProof.Proven, TerraBaseProof.Proven, 8)));
    }

    private static SourceRevision Source(int index = 0, long generation = 1, IEnumerable<DependencyProof>? dependencies = null, string? signature = null) =>
        new(new($"source-{index}"), new($"ref-{index}"), new($"commit-{index}"), new($"tree-{index}"), new($"manifest-{index}"),
            generation, new($"desired-{index}"), new(signature ?? $"signature-{index}"), dependencies ?? []);
    private static SourceEvidence Evidence(SourceRevision source, SourceState state, IEnumerable<DependencyProof> dependencies,
        string? digest = null, bool signatureValid = true) =>
        new(new($"obs-{source.Generation}"), state, source.Source, source.Reference, source.Generation, source.Commit, source.Tree,
            source.Manifest, new(digest ?? source.DesiredDigest.Value), source.Signature, new("schema"), new("dependencies"),
            new($"signature-verification-{source.Generation}"), dependencies, signatureValid, true, true);
    private static JobRequest Job() => new(new("pipeline"), new("job"), JobKind.TrustedBuild, new("tree"), 1, 1, 3,
        new("key"), [TrustZone.TrustedBuild], [RunnerCapability.Compile], 1, 10, false);
    private static TerraBaseEvidenceScope Scope(int index, ulong generation) => new(TerraBaseTestData.Region(),
        TerraBaseTestData.Db($"db-{index}"), TerraBaseTestData.Member($"member-{index}"), TerraBaseTestData.Node($"node-{index}"),
        TerraBaseTestData.Volume($"volume-{index}"), TerraBaseTestData.Fence($"fence-{index}"), TerraBaseTestData.O(generation),
        TerraBaseTestData.O(generation + 1), TerraBaseTestData.O(generation + 2), TerraBaseTestData.Op($"op-{index}"));
    private static TerraBaseBackupSegment Segment(TerraBaseEvidenceScope scope, ulong sequence, bool full, ulong? parent = null) =>
        new(new(scope.Region, scope.Database, scope.DatabaseGeneration, scope.TopologyGeneration), TerraBaseTestData.Backup($"b-{sequence}"),
            TerraBaseTestData.O(sequence), parent is null ? null : TerraBaseTestData.O(parent.Value), full,
            TerraBaseTestData.Digest($"digest-{sequence}"), TerraBaseTestData.Object($"object-{sequence}"), TerraBaseTestData.Key($"key-{sequence}"));
    private static string DeliveryOutcome(DeliveryDecision decision) => decision.Errors.Count > 0 ? decision.Errors[0].Code.ToString() :
        decision.Intents.Count > 0 ? decision.Intents[0].Action.ToString() : decision.Trace[0].Code.ToString();
    private static string TerraOutcome(TerraBaseDecision decision) => decision.Action == TerraBaseAction.Hold ? decision.Code.ToString() :
        decision.Code is TerraBaseCode.Completed or TerraBaseCode.RolledBack ? decision.Code.ToString() : decision.Action.ToString();
    private static T UnderCulture<T>(string culture, Func<T> action) { var before = CultureInfo.CurrentCulture; try { CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture); return action(); } finally { CultureInfo.CurrentCulture = before; } }
    private static void Require(bool condition, string family, int index) { if (!condition) throw new InvalidOperationException($"{family} property failed at {index}."); }
    private static ulong Mix(ulong digest, string value, long number) { unchecked { foreach (var c in value) digest = (digest ^ c) * 1099511628211UL; return (digest ^ (ulong)number) * 1099511628211UL; } }
    private static Exception? Capture(Action action) { try { action(); return null; } catch (Exception error) { return error; } }

    private sealed record Summary(int Cases, int Kinds, ulong Digest);
    private sealed class Generator(ulong state) { private ulong _state = state; public int Next(int max) { _state ^= _state << 13; _state ^= _state >> 7; _state ^= _state << 17; return (int)(_state % (uint)max); } }
    private enum ThrowMode { GetEnumerator, MoveNext, Current, Dispose }
    private sealed class ThrowingEnumerable<T>(T[] values, ThrowMode mode, Exception failure) : IEnumerable<T>
    {
        public IEnumerator<T> GetEnumerator() => mode == ThrowMode.GetEnumerator ? throw failure : new Enumerator(values, mode, failure);
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        private sealed class Enumerator(T[] values, ThrowMode mode, Exception failure) : IEnumerator<T>
        {
            private int _index = -1; public T Current => mode == ThrowMode.Current ? throw failure : values[_index]; object? IEnumerator.Current => Current;
            public bool MoveNext() { if (mode == ThrowMode.MoveNext) throw failure; return ++_index < values.Length; }
            public void Reset() => throw new NotSupportedException(); public void Dispose() { if (mode == ThrowMode.Dispose) throw failure; }
        }
    }
    private sealed class ExtraCurrentEnumerable<T>(T value, int maximum) : IEnumerable<T>
    {
        public bool ExtraCurrentRead { get; private set; }
        public IEnumerator<T> GetEnumerator() => new Enumerator(this, value, maximum);
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        private sealed class Enumerator(ExtraCurrentEnumerable<T> owner, T value, int maximum) : IEnumerator<T>
        {
            private int _index = -1; public T Current { get { if (_index == maximum) owner.ExtraCurrentRead = true; return value; } }
            object? IEnumerator.Current => Current;
            public bool MoveNext() => ++_index <= maximum; public void Reset() => throw new NotSupportedException(); public void Dispose() { }
        }
    }
    private sealed class DisposeMutatingEnumerable<T>(T[] values, Action mutate) : IEnumerable<T>
    {
        public IEnumerator<T> GetEnumerator() => new Enumerator(values, mutate); IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        private sealed class Enumerator(T[] values, Action mutate) : IEnumerator<T>
        { private int _index = -1; public T Current => values[_index]; object? IEnumerator.Current => Current; public bool MoveNext() => ++_index < values.Length; public void Reset() => throw new NotSupportedException(); public void Dispose() => mutate(); }
    }
    private sealed class InfiniteEnumerable<T>(T value) : IEnumerable<T>
    {
        public IEnumerator<T> GetEnumerator() => new Enumerator(value); IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        private sealed class Enumerator(T value) : IEnumerator<T>
        { public T Current => value; object? IEnumerator.Current => Current; public bool MoveNext() => true; public void Reset() { } public void Dispose() { } }
    }
    private sealed class OversizedReadOnlyList<T>(int count) : IReadOnlyList<T>
    {
        public bool EnumeratorRequested { get; private set; }
        public int Count => count; public T this[int index] => throw new InvalidOperationException();
        public IEnumerator<T> GetEnumerator() { EnumeratorRequested = true; throw new InvalidOperationException(); }
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
    private sealed class EnumerableReadOnlyList<T>(int count, IEnumerable<T> source) : IReadOnlyList<T>
    {
        public int Count => count; public T this[int index] => throw new NotSupportedException();
        public IEnumerator<T> GetEnumerator() => source.GetEnumerator(); IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
    private sealed class CountThrowingReadOnlyList<T>(Exception failure) : IReadOnlyList<T>
    {
        public int Count => throw failure; public T this[int index] => throw new NotSupportedException();
        public IEnumerator<T> GetEnumerator() => throw new InvalidOperationException("Enumeration must not occur.");
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}

