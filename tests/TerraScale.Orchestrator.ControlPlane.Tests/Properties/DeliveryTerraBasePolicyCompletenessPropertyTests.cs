using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.TerraBase;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class DeliveryTerraBasePolicyCompletenessPropertyTests
{
    private const int Cases = 1_000;
    private const int Undefined = int.MaxValue;

    [Test]
    public async Task UndefinedCheckpointValuesAreRejectedInsteadOfEmittingMutations()
    {
        var scope = Scope(1_999, 7); var topology = Topology(scope);
        var decisions = new[]
        {
            TerraBaseTopologyPlanner.PlanAdd(scope, topology with
                { LossCount = (TerraBaseLossCount)Undefined, TopologyApplied = TerraBaseProof.Unknown }),
            TerraBaseTopologyPlanner.PlanAdd(scope, topology with { TopologyApplied = (TerraBaseProof)Undefined }),
            TerraBaseTopologyPlanner.PlanAdd(scope, topology with { Replication = (TerraBaseReplication)Undefined }),
            TerraBaseTopologyPlanner.PlanRemove(scope, topology with
                { MemberRole = (TerraBaseRole)Undefined, TopologyApplied = TerraBaseProof.Unknown }),
            Upgrade(scope, upgradeApplied: (TerraBaseProof)Undefined),
            Restore(scope, restoreApplied: (TerraBaseProof)Undefined),
        };
        foreach (var decision in decisions)
        {
            await Assert.That(decision.Action).IsEqualTo(TerraBaseAction.Hold);
            await Assert.That(decision.Target).IsEqualTo(TerraBaseTarget.None);
            await Assert.That(decision.Code).IsEqualTo(TerraBaseCode.InvalidInput);
            await Assert.That(decision.IsMutationAuthorized).IsFalse();
            await Assert.That(decision.Subject).IsNull();
        }
    }

    [Test]
    public async Task UndefinedObservedEnumsNeverAuthorizeTerraBaseMutations()
    {
        var en = UnderCulture("en-US", () => RunUndefinedEnums(0x7E22_1001));
        var tr = UnderCulture("tr-TR", () => RunUndefinedEnums(0x7E22_1001));
        await Assert.That(en).IsEqualTo(tr);
        await Assert.That(en.Cases).IsEqualTo(Cases);
        await Assert.That(en.Kinds).IsEqualTo(1);

        var scope = Scope(2_000, 9);
        await Assert.That(TerraBaseTopologyPlanner.PlanAdd(scope,
            Topology(scope) with
            {
                TopologyApplied = TerraBaseProof.Unknown,
                Replication = TerraBaseReplication.Unknown,
                PostChangeReplication = TerraBaseProof.Unknown
            }).Action).IsEqualTo(TerraBaseAction.Add);
        await Assert.That(TerraBaseTopologyPlanner.PlanAdd(scope,
            Topology(scope) with
            {
                TopologyApplied = TerraBaseProof.Contradicted,
                Replication = TerraBaseReplication.Unknown,
                PostChangeReplication = TerraBaseProof.Unknown
            }).Action).IsEqualTo(TerraBaseAction.Add);
        await Assert.That(Upgrade(scope, upgradeApplied: TerraBaseProof.Unknown).Action).IsEqualTo(TerraBaseAction.Upgrade);
        await Assert.That(Upgrade(scope, upgradeApplied: TerraBaseProof.Contradicted).Action).IsEqualTo(TerraBaseAction.Upgrade);
    }

    [Test]
    public async Task EveryScopeDimensionAndAuthorizingIntentFieldAreExactAndCultureStable()
    {
        var en = UnderCulture("en-US", () => RunExactContracts(0x7E22_1002));
        var ar = UnderCulture("ar-SA", () => RunExactContracts(0x7E22_1002));
        await Assert.That(en).IsEqualTo(ar);
        await Assert.That(en.Cases).IsEqualTo(Cases);
        await Assert.That(en.Kinds).IsEqualTo(65);
    }

    private static Summary RunUndefinedEnums(ulong seed)
    {
        var random = new Generator(seed); var kinds = new HashSet<string>(); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var scope = Scope(index, (ulong)random.Next(800_000) + 1);
            var decision = UndefinedDecision(scope, index % 44);
            Require(decision.Action == TerraBaseAction.Hold && decision.Target == TerraBaseTarget.None
                && decision.Code == TerraBaseCode.InvalidInput && !decision.IsMutationAuthorized
                && decision.Subject is null && DecisionText(decision) == UndefinedDecisionText(scope, index % 44),
                "undefined-enum", index);
            var actual = decision.Code.ToString(); kinds.Add(actual); digest = Mix(digest, actual, scope.DatabaseGeneration.Value);
        }
        return new(Cases, kinds.Count, digest);
    }

    private static Summary RunExactContracts(ulong seed)
    {
        var random = new Generator(seed); var kinds = new HashSet<string>(); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var scope = Scope(index, (ulong)random.Next(700_000) + 1); var mode = index % 65;
            TerraBaseDecision decision; string expected;
            if (mode < 60)
            {
                var wrong = WrongScope(scope, mode % 10, index); var planner = mode / 10;
                decision = WrongScopeDecision(scope, wrong, planner);
                expected = $"Hold|None|WrongEvidenceScope|{Trace(scope, planner == 0 ? O(100) : default, scope.TopologyGeneration)}|none";
            }
            else if (mode == 60)
            {
                decision = TerraBaseTopologyPlanner.PlanAdd(scope, Topology(scope) with
                {
                    TopologyApplied = TerraBaseProof.Unknown,
                    Replication = TerraBaseReplication.Unknown,
                    PostChangeReplication = TerraBaseProof.Unknown
                });
                expected = $"Add|Topology|NextStep|{Trace(scope, O(100), scope.TopologyGeneration)}|topology:{ScopeText(scope)}:Elastic:100";
            }
            else if (mode == 61)
            {
                var epoch = O(scope.AuthorityEpoch.Value + 1);
                decision = TerraBaseRetainedVolumePlanner.Plan(scope, new(scope, [], TerraBaseProof.Proven,
                    TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven, epoch, 8));
                expected = $"StartWithRetainedVolume|Volume|NextStep|{Trace(scope, epoch, scope.TopologyGeneration)}|volume:{ScopeText(scope)}:{epoch}";
            }
            else if (mode == 62)
            {
                var current = Release($"current-{index}"); var target = Release($"target-{index}");
                decision = Upgrade(scope, current, target, TerraBaseProof.Unknown);
                expected = $"Upgrade|Release|NextStep|{Trace(scope, default, scope.TopologyGeneration)}|upgrade:{ScopeText(scope)}:{current.Value}:{target.Value}";
            }
            else if (mode == 63)
            {
                var backup = BackupId($"backup-{index}"); var destination = Object($"destination-{index}"); var key = Key($"key-{index}");
                var request = new TerraBaseBackupRequestEvidence(scope, backup, O(1), null, null, null, true,
                    destination, key, TerraBaseProof.Proven, TerraBaseProof.Proven);
                decision = TerraBaseBackupPlanner.Authorize(scope, request);
                expected = $"Backup|BackupChain|NextStep|{Trace(scope, default, scope.TopologyGeneration)}|backup:{ScopeText(scope)}:{backup.Value}:1:null:null:{destination.Value}:{key.Value}";
            }
            else
            {
                var restore = RestoreId($"restore-{index}"); var terminal = BackupId("b-2"); var target = O(scope.DatabaseGeneration.Value + 1);
                var chain = Chain(scope);
                var evidence = new TerraBaseRestoreEvidence(scope, restore, scope.DatabaseGeneration, target, chain,
                    TerraBaseProof.Proven, TerraBaseProof.Unknown, TerraBaseProof.Unknown, TerraBaseProof.Unknown,
                    TerraBaseProof.Unknown);
                decision = TerraBaseRestorePlanner.Plan(scope, restore, terminal, target, evidence);
                expected = $"Restore|RestoreCandidate|NextStep|{Trace(scope, default, scope.TopologyGeneration)}|restore:{ScopeText(scope)}:{restore.Value}:{scope.DatabaseGeneration}:{target}:chain={ScopeText(scope)}["
                    + $"{BackupSubjectText(scope)}:b-1:1:null:True:digest-1:object-1:key-1,"
                    + $"{BackupSubjectText(scope)}:b-2:2:1:False:digest-2:object-2:key-2]";
            }
            var actual = DecisionText(decision);
            Require(actual == expected, "exact-contract", index); kinds.Add(mode.ToString(CultureInfo.InvariantCulture));
            digest = Mix(digest, actual, scope.DatabaseGeneration.Value);
        }
        return new(Cases, kinds.Count, digest);
    }

    private static TerraBaseDecision WrongScopeDecision(TerraBaseEvidenceScope expected,
        TerraBaseEvidenceScope actual, int planner) => planner switch
        {
            0 => TerraBaseTopologyPlanner.PlanAdd(expected, Topology(actual)),
            1 => TerraBaseRetainedVolumePlanner.Plan(expected, new(actual, [], TerraBaseProof.Proven,
                TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven,
                O(expected.AuthorityEpoch.Value + 1), 8)),
            2 => TerraBaseUpgradePlanner.Plan(expected, Release("current"), Release("target"),
                UpgradeEvidence(actual, Release("current"), Release("target"))),
            3 => TerraBaseBackupPlanner.Authorize(expected, new(actual, BackupId("backup"), O(1), null, null,
                null, true, Object("destination"), Key("key"), TerraBaseProof.Proven, TerraBaseProof.Proven)),
            4 => TerraBaseBackupPlanner.Accept(expected, Chain(actual)),
            _ => TerraBaseRestorePlanner.Plan(expected, RestoreId("restore"), BackupId("b-2"),
                O(expected.DatabaseGeneration.Value + 1), new(actual, RestoreId("restore"),
                    expected.DatabaseGeneration, O(expected.DatabaseGeneration.Value + 1), Chain(expected),
                    TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven,
                    TerraBaseProof.Proven)),
        };

    private static string UndefinedDecisionText(TerraBaseEvidenceScope scope, int mode) =>
        $"Hold|None|InvalidInput|{Trace(scope, mode < 19 ? O(100) : default, scope.TopologyGeneration)}|none";

    private static TerraBaseDecision UndefinedDecision(TerraBaseEvidenceScope scope, int mode)
    {
        if (mode < 19)
            return TerraBaseTopologyPlanner.PlanAdd(scope, UndefinedTopology(Topology(scope), mode));
        if (mode < 30)
        {
            var current = Release("current"); var target = Release("target");
            var value = UpgradeEvidence(scope, current, target); var field = mode - 19;
            value = field switch
            {
                0 => value with { Compatibility = (TerraBaseUpgradeCompatibility)Undefined },
                1 => value with { NoTopologyMutation = (TerraBaseProof)Undefined },
                2 => value with { OneFailureDomain = (TerraBaseProof)Undefined },
                3 => value with { RollbackMaterial = (TerraBaseProof)Undefined },
                4 => value with { LeadershipTransferred = (TerraBaseProof)Undefined },
                5 => value with { UpgradeApplied = (TerraBaseProof)Undefined },
                6 => value with { ProcessHealthy = (TerraBaseProof)Undefined },
                7 => value with { Ready = (TerraBaseProof)Undefined },
                8 => value with { CaughtUp = (TerraBaseProof)Undefined },
                9 => value with { RollbackApplied = (TerraBaseProof)Undefined },
                _ => value with { PostRollbackHealthy = (TerraBaseProof)Undefined },
            };
            return TerraBaseUpgradePlanner.Plan(scope, current, target, value);
        }
        if (mode < 34)
        {
            var proofs = new[] { TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven };
            proofs[mode - 30] = (TerraBaseProof)Undefined;
            return TerraBaseRetainedVolumePlanner.Plan(scope, new(scope, [], proofs[0], proofs[1], proofs[2],
                proofs[3], O(scope.AuthorityEpoch.Value + 1), 8));
        }
        if (mode < 36)
        {
            var request = new TerraBaseBackupRequestEvidence(scope, BackupId("backup"), O(1), null, null, null,
                true, Object("destination"), Key("key"), TerraBaseProof.Proven, TerraBaseProof.Proven);
            request = mode == 34 ? request with { ApplicationConsistencyReady = (TerraBaseProof)Undefined }
                : request with { NoConflictingOperation = (TerraBaseProof)Undefined };
            return TerraBaseBackupPlanner.Authorize(scope, request);
        }
        if (mode < 39)
        {
            var proofs = new[] { TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven };
            proofs[mode - 36] = (TerraBaseProof)Undefined;
            return TerraBaseBackupPlanner.Accept(scope, new(scope, [Segment(scope, 1, true)], proofs[0],
                proofs[1], proofs[2], 8));
        }
        var restore = RestoreId("restore"); var targetGeneration = O(scope.DatabaseGeneration.Value + 1);
        var restoreProofs = new[] { TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven,
            TerraBaseProof.Proven, TerraBaseProof.Proven };
        restoreProofs[mode - 39] = (TerraBaseProof)Undefined;
        var evidence = new TerraBaseRestoreEvidence(scope, restore, scope.DatabaseGeneration, targetGeneration,
            Chain(scope), restoreProofs[0], restoreProofs[1], restoreProofs[2], restoreProofs[3], restoreProofs[4]);
        return TerraBaseRestorePlanner.Plan(scope, restore, BackupId("b-2"), targetGeneration, evidence);
    }

    private static TerraBaseTopologyEvidence UndefinedTopology(TerraBaseTopologyEvidence value, int field) => field switch
    {
        0 => value with { MemberKind = (TerraBaseMemberKind)Undefined },
        1 => value with { MemberRole = (TerraBaseRole)Undefined },
        2 => value with { LossCount = (TerraBaseLossCount)Undefined },
        3 => value with { LeadershipTransferred = (TerraBaseProof)Undefined },
        4 => value with { NoTopologyMutation = (TerraBaseProof)Undefined },
        5 => value with { QuorumFloor = (TerraBaseProof)Undefined },
        6 => value with { ReplicationFloor = (TerraBaseProof)Undefined },
        7 => value with { SustainedSignal = (TerraBaseProof)Undefined },
        8 => value with { Placement = (TerraBaseProof)Undefined },
        9 => value with { Storage = (TerraBaseProof)Undefined },
        10 => value with { Budget = (TerraBaseProof)Undefined },
        11 => value with { UniqueMember = (TerraBaseProof)Undefined },
        12 => value with { TopologyApplied = (TerraBaseProof)Undefined },
        13 => value with { NoDatabaseReference = (TerraBaseProof)Undefined },
        14 => value with { RecoveryPoint = (TerraBaseProof)Undefined },
        15 => value with { Retention = (TerraBaseProof)Undefined },
        16 => value with { VolumeDisposition = (TerraBaseProof)Undefined },
        17 => value with { PostChangeReplication = (TerraBaseProof)Undefined },
        _ => value with { Replication = (TerraBaseReplication)Undefined },
    };

    private static TerraBaseDecision Upgrade(TerraBaseEvidenceScope scope, TerraBaseReleaseId? current = null,
        TerraBaseReleaseId? target = null, TerraBaseProof upgradeApplied = TerraBaseProof.Proven)
    {
        current ??= Release("current"); target ??= Release("target");
        var evidence = UpgradeEvidence(scope, current, target) with { UpgradeApplied = upgradeApplied };
        if (upgradeApplied != TerraBaseProof.Proven)
            evidence = evidence with
            {
                ProcessHealthy = TerraBaseProof.Unknown,
                Ready = TerraBaseProof.Unknown,
                CaughtUp = TerraBaseProof.Unknown,
                RollbackApplied = TerraBaseProof.Unknown,
                PostRollbackHealthy = TerraBaseProof.Unknown
            };
        return TerraBaseUpgradePlanner.Plan(scope, current, target, evidence);
    }

    private static TerraBaseUpgradeEvidence UpgradeEvidence(TerraBaseEvidenceScope scope,
        TerraBaseReleaseId current, TerraBaseReleaseId target) => new(scope, current, target,
        TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne, TerraBaseProof.Proven, TerraBaseProof.Proven,
        TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven,
        TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Unknown, TerraBaseProof.Unknown);

    private static TerraBaseDecision Backup(TerraBaseEvidenceScope scope, TerraBaseProof consistency)
    {
        var request = new TerraBaseBackupRequestEvidence(scope, BackupId("backup"), O(1), null, null, null, true,
            Object("destination"), Key("key"), consistency, TerraBaseProof.Proven);
        return TerraBaseBackupPlanner.Authorize(scope, request);
    }

    private static TerraBaseDecision Restore(TerraBaseEvidenceScope scope, TerraBaseProof restoreApplied)
    {
        var restore = RestoreId("restore"); var target = O(scope.DatabaseGeneration.Value + 1);
        var evidence = new TerraBaseRestoreEvidence(scope, restore, scope.DatabaseGeneration, target, Chain(scope),
            TerraBaseProof.Proven, restoreApplied,
            restoreApplied == TerraBaseProof.Proven ? TerraBaseProof.Proven : TerraBaseProof.Unknown,
            restoreApplied == TerraBaseProof.Proven ? TerraBaseProof.Proven : TerraBaseProof.Unknown,
            restoreApplied == TerraBaseProof.Proven ? TerraBaseProof.Proven : TerraBaseProof.Unknown);
        return TerraBaseRestorePlanner.Plan(scope, restore, BackupId("b-2"), target, evidence);
    }

    private static TerraBaseEvidenceScope WrongScope(TerraBaseEvidenceScope value, int dimension, int index) => dimension switch
    {
        0 => value with { Region = Region("SFO") },
        1 => value with { Database = Database($"wrong-db-{index}") },
        2 => value with { Member = Member($"wrong-member-{index}") },
        3 => value with { Node = Node($"wrong-node-{index}") },
        4 => value with { RetainedVolume = Volume($"wrong-volume-{index}") },
        5 => value with { Fence = Fence($"wrong-fence-{index}") },
        6 => value with { DatabaseGeneration = O(value.DatabaseGeneration.Value + 20) },
        7 => value with { TopologyGeneration = O(value.TopologyGeneration.Value + 20) },
        8 => value with { AuthorityEpoch = O(value.AuthorityEpoch.Value + 20) },
        _ => value with { Operation = Operation($"wrong-operation-{index}") },
    };

    private static TerraBaseTopologyEvidence Topology(TerraBaseEvidenceScope scope) => new(scope,
        TerraBaseMemberKind.Elastic, TerraBaseRole.Follower, TerraBaseLossCount.None, TerraBaseProof.Proven,
        TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven,
        TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven,
        TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven,
        TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseReplication.CaughtUp, O(100));

    private static TerraBaseBackupEvidence Chain(TerraBaseEvidenceScope scope,
        TerraBaseProof digest = TerraBaseProof.Proven) => new(scope,
        [Segment(scope, 1, true), Segment(scope, 2, false, 1)], TerraBaseProof.Proven, digest,
        TerraBaseProof.Proven, 8);

    private static TerraBaseBackupSegment Segment(TerraBaseEvidenceScope scope, ulong sequence, bool full,
        ulong? parent = null) => new(new(scope.Region, scope.Database, scope.DatabaseGeneration, scope.TopologyGeneration),
        BackupId($"b-{sequence}"), O(sequence), parent is null ? null : O(parent.Value), full,
        Digest($"digest-{sequence}"), Object($"object-{sequence}"), Key($"key-{sequence}"));

    private static string DecisionText(TerraBaseDecision decision)
    {
        var subject = decision.Subject switch
        {
            null => "none",
            TerraBaseTopologyIntentSubject value => $"topology:{ScopeText(value.Scope)}:{value.MemberKind}:{value.ReplicationPosition}",
            TerraBaseRetainedVolumeIntentSubject value => $"volume:{ScopeText(value.Scope)}:{value.NewAuthorityEpoch}",
            TerraBaseUpgradeIntentSubject value => $"upgrade:{ScopeText(value.Scope)}:{value.Current.Value}:{value.Target.Value}",
            TerraBaseBackupRequestIntentSubject value => $"backup:{ScopeText(value.Scope)}:{value.Backup.Value}:{value.Sequence}:{Nullable(value.ParentSequence)}:{value.ParentBackup?.Value ?? "null"}:{value.Destination.Value}:{value.EncryptionKey.Value}",
            TerraBaseRestoreIntentSubject value => $"restore:{ScopeText(value.Scope)}:{value.Restore.Value}:{value.SourceGeneration}:{value.TargetGeneration}:chain={ScopeText(value.Chain.Scope)}[{string.Join(',', value.Chain.Segments.Select(SegmentText))}]",
            _ => "unexpected",
        };
        return $"{decision.Action}|{decision.Target}|{decision.Code}|{(decision.Trace is null ? "null" : Trace(decision.Trace.Scope, decision.Trace.Position, decision.Trace.Generation))}|{subject}";
    }

    private static string SegmentText(TerraBaseBackupSegment value) =>
        $"{BackupSubjectText(value.Subject)}:{value.Backup.Value}:{value.Sequence}:{Nullable(value.ParentSequence)}:{value.IsFull}:{value.Digest.Value}:{value.Object.Value}:{value.EncryptionKey.Value}";
    private static string BackupSubjectText(TerraBaseBackupSegment value) => BackupSubjectText(value.Subject);
    private static string BackupSubjectText(TerraBaseEvidenceScope value) =>
        $"{value.Region.Value}/{value.Database.Value}/{value.DatabaseGeneration}/{value.TopologyGeneration}";
    private static string BackupSubjectText(TerraBaseBackupSubject value) =>
        $"{value.Region.Value}/{value.Database.Value}/{value.DatabaseGeneration}/{value.TopologyGeneration}";
    private static string Nullable(TerraBaseOrdinal? value) => value?.ToString() ?? "null";
    private static string Trace(TerraBaseEvidenceScope scope, TerraBaseOrdinal position, TerraBaseOrdinal generation) =>
        $"trace:{ScopeText(scope)}:{position}:{generation}";
    private static string ScopeText(TerraBaseEvidenceScope value) =>
        $"{value.Region.Value}/{value.Database.Value}/{value.Member.Value}/{value.Node.Value}/{value.RetainedVolume.Value}/{value.Fence.Value}/{value.DatabaseGeneration}/{value.TopologyGeneration}/{value.AuthorityEpoch}/{value.Operation.Value}";

    private static TerraBaseEvidenceScope Scope(int index, ulong generation) => new(Region(),
        Database($"db-{index}"), Member($"member-{index}"), Node($"node-{index}"), Volume($"volume-{index}"),
        Fence($"fence-{index}"), O(generation), O(generation + 1), O(generation + 2), Operation($"op-{index}"));
    private static TerraBaseRegionCode Region(string value = "GRU") { TerraBaseRegionCode.TryCreate(value, out var result); return result!; }
    private static TerraBaseDatabaseId Database(string value) { TerraBaseDatabaseId.TryCreate(value, 96, out var result); return result!; }
    private static TerraBaseMemberId Member(string value) { TerraBaseMemberId.TryCreate(value, 96, out var result); return result!; }
    private static TerraBaseNodeId Node(string value) { TerraBaseNodeId.TryCreate(value, 96, out var result); return result!; }
    private static TerraBaseVolumeId Volume(string value) { TerraBaseVolumeId.TryCreate(value, 96, out var result); return result!; }
    private static TerraBaseFenceId Fence(string value) { TerraBaseFenceId.TryCreate(value, 96, out var result); return result!; }
    private static TerraBaseOperationId Operation(string value) { TerraBaseOperationId.TryCreate(value, 96, out var result); return result!; }
    private static TerraBaseReleaseId Release(string value) { TerraBaseReleaseId.TryCreate(value, 96, out var result); return result!; }
    private static TerraBaseBackupId BackupId(string value) { TerraBaseBackupId.TryCreate(value, 96, out var result); return result!; }
    private static TerraBaseRestoreId RestoreId(string value) { TerraBaseRestoreId.TryCreate(value, 96, out var result); return result!; }
    private static TerraBaseDigestRef Digest(string value) { TerraBaseDigestRef.TryCreate(value, 96, out var result); return result!; }
    private static TerraBaseObjectRef Object(string value) { TerraBaseObjectRef.TryCreate(value, 96, out var result); return result!; }
    private static TerraBaseKeyRef Key(string value) { TerraBaseKeyRef.TryCreate(value, 96, out var result); return result!; }
    private static TerraBaseOrdinal O(ulong value) { TerraBaseOrdinal.TryCreate(value, out var result); return result; }
    private static T UnderCulture<T>(string name, Func<T> action)
    {
        var culture = CultureInfo.CurrentCulture; var ui = CultureInfo.CurrentUICulture;
        try { CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(name); CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(name); return action(); }
        finally { CultureInfo.CurrentCulture = culture; CultureInfo.CurrentUICulture = ui; }
    }
    private static void Require(bool condition, string family, int index)
    { if (!condition) throw new InvalidOperationException($"{family} property failed at {index}."); }
    private static ulong Mix(ulong digest, string value, ulong number)
    { unchecked { foreach (var character in value) digest = (digest ^ character) * 1099511628211UL; return (digest ^ number) * 1099511628211UL; } }
    private sealed record Summary(int Cases, int Kinds, ulong Digest);
    private sealed class Generator(ulong state)
    { private ulong _state = state; public int Next(int maximum) { _state ^= _state << 13; _state ^= _state >> 7; _state ^= _state << 17; return (int)(_state % (uint)maximum); } }
}

