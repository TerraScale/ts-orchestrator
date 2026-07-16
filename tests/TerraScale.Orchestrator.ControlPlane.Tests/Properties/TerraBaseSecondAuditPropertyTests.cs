using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.TerraBase;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class TerraBaseSecondAuditPropertyTests
{
    private const int Cases = 1_000;

    [Test]
    public async Task ScopeValidityAndMismatchPrecedenceIsCompleteAndCultureStable()
    {
        var en = UnderCulture("en-US", RunScopes);
        var tr = UnderCulture("tr-TR", RunScopes);
        await Assert.That(en).IsEqualTo(tr);
        await Assert.That(en.Cases).IsEqualTo(Cases);
        await Assert.That(en.Kinds).IsEqualTo(21);
    }

    [Test]
    public async Task TopologyTransitionsReplicationAndOutputsAreCompleteAndCultureStable()
    {
        var en = UnderCulture("en-US", RunTopology);
        var ar = UnderCulture("ar-SA", RunTopology);
        await Assert.That(en).IsEqualTo(ar);
        await Assert.That(en.Cases).IsEqualTo(Cases);
        await Assert.That(en.Kinds).IsEqualTo(20);
    }

    [Test]
    public async Task UpgradeRollbackAndRestoreCheckpointsAreCompleteAndCultureStable()
    {
        var en = UnderCulture("en-US", RunRecovery);
        var tr = UnderCulture("tr-TR", RunRecovery);
        await Assert.That(en).IsEqualTo(tr);
        await Assert.That(en.Cases).IsEqualTo(Cases);
        await Assert.That(en.Kinds).IsEqualTo(21);
    }

    private static Summary RunScopes()
    {
        ulong digest = 0; var kinds = new HashSet<int>();
        for (var index = 0; index < Cases; index++)
        {
            var valid = Scope(index); var mode = index % 21;
            kinds.Add(mode);
            TerraBaseEvidenceScope? expected;
            TerraBaseEvidenceScope actual;
            TerraBaseCode code;
            if (mode < 11)
            {
                expected = mode == 0 ? null : Changed(valid, mode - 1, true, index);
                actual = valid;
                code = TerraBaseCode.InvalidInput;
            }
            else
            {
                expected = valid;
                actual = Changed(valid, mode - 11, false, index);
                code = TerraBaseCode.WrongEvidenceScope;
            }

            foreach (var decision in Decisions(expected, actual))
            {
                Require(decision.Action == TerraBaseAction.Hold && decision.Target == TerraBaseTarget.None
                    && decision.Code == code && !decision.IsMutationAuthorized && decision.Subject is null,
                    "scope", index);
                if (expected is null || code == TerraBaseCode.InvalidInput)
                    Require(decision.Trace is null, "invalid-trace", index);
                else
                    Require(decision.Trace?.Scope == expected, "mismatch-trace", index);
                digest = Mix(digest, decision);
            }
        }
        return new(Cases, kinds.Count, digest);
    }

    private static Summary RunTopology()
    {
        ulong digest = 0; var kinds = new HashSet<int>();
        for (var index = 0; index < Cases; index++)
        {
            var scope = Scope(index); var mode = index % 20;
            kinds.Add(mode);
            var completed = TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Topology(scope: scope);
            var addPending = completed with { TopologyApplied = TerraBaseProof.Unknown,
                Replication = TerraBaseReplication.Unknown, PostChangeReplication = TerraBaseProof.Unknown };
            var removePending = completed with { TopologyApplied = TerraBaseProof.Unknown,
                NoDatabaseReference = TerraBaseProof.Unknown, PostChangeReplication = TerraBaseProof.Unknown };
            TerraBaseDecision decision;
            TerraBaseAction action; TerraBaseTarget target; TerraBaseCode code;
            switch (mode)
            {
                case 0: decision = TerraBaseTopologyPlanner.PlanAdd(scope, addPending); action = TerraBaseAction.Add; target = TerraBaseTarget.Topology; code = TerraBaseCode.NextStep; break;
                case 1: decision = TerraBaseTopologyPlanner.PlanAdd(scope, addPending with { TopologyApplied = TerraBaseProof.Contradicted }); action = TerraBaseAction.Add; target = TerraBaseTarget.Topology; code = TerraBaseCode.NextStep; break;
                case 2: decision = TerraBaseTopologyPlanner.PlanAdd(scope, addPending with { Replication = TerraBaseReplication.CaughtUp }); action = TerraBaseAction.Hold; target = TerraBaseTarget.None; code = TerraBaseCode.InvalidInput; break;
                case 3: decision = TerraBaseTopologyPlanner.PlanAdd(scope, completed with { Replication = TerraBaseReplication.Unknown, PostChangeReplication = TerraBaseProof.Unknown }); action = TerraBaseAction.Observe; target = TerraBaseTarget.Application; code = TerraBaseCode.NextStep; break;
                case 4: decision = TerraBaseTopologyPlanner.PlanAdd(scope, completed with { Replication = TerraBaseReplication.Unknown }); action = TerraBaseAction.Hold; target = TerraBaseTarget.None; code = TerraBaseCode.InvalidInput; break;
                case 5: decision = TerraBaseTopologyPlanner.PlanAdd(scope, completed with { Replication = TerraBaseReplication.Lagging, PostChangeReplication = TerraBaseProof.Unknown }); action = TerraBaseAction.CatchUp; target = TerraBaseTarget.Member; code = TerraBaseCode.NextStep; break;
                case 6: decision = TerraBaseTopologyPlanner.PlanAdd(scope, completed with { Replication = TerraBaseReplication.Lagging }); action = TerraBaseAction.Hold; target = TerraBaseTarget.None; code = TerraBaseCode.InvalidInput; break;
                case 7: decision = TerraBaseTopologyPlanner.PlanAdd(scope, completed with { Replication = TerraBaseReplication.Conflicting, PostChangeReplication = TerraBaseProof.Contradicted }); action = TerraBaseAction.Hold; target = TerraBaseTarget.None; code = TerraBaseCode.ReplicationUnsafe; break;
                case 8: decision = TerraBaseTopologyPlanner.PlanRemove(scope, removePending); action = TerraBaseAction.Remove; target = TerraBaseTarget.Topology; code = TerraBaseCode.NextStep; break;
                case 9: decision = TerraBaseTopologyPlanner.PlanRemove(scope, removePending with { MemberRole = TerraBaseRole.Leader, LeadershipTransferred = TerraBaseProof.Unknown }); action = TerraBaseAction.Transfer; target = TerraBaseTarget.Topology; code = TerraBaseCode.NextStep; break;
                case 10: decision = TerraBaseTopologyPlanner.PlanRemove(scope, removePending with { Replication = TerraBaseReplication.Unknown }); action = TerraBaseAction.Hold; target = TerraBaseTarget.None; code = TerraBaseCode.ReplicationUnsafe; break;
                case 11: decision = TerraBaseTopologyPlanner.PlanRemove(scope, removePending with { Replication = TerraBaseReplication.Lagging }); action = TerraBaseAction.Hold; target = TerraBaseTarget.None; code = TerraBaseCode.ReplicationUnsafe; break;
                case 12: decision = TerraBaseTopologyPlanner.PlanRemove(scope, removePending with { Replication = TerraBaseReplication.Conflicting }); action = TerraBaseAction.Hold; target = TerraBaseTarget.None; code = TerraBaseCode.ReplicationUnsafe; break;
                case 13: decision = TerraBaseTopologyPlanner.PlanRemove(scope, removePending with { Replication = TerraBaseReplication.Future }); action = TerraBaseAction.Hold; target = TerraBaseTarget.None; code = TerraBaseCode.ReplicationUnsafe; break;
                case 14: decision = TerraBaseTopologyPlanner.PlanRemove(scope, removePending with { ReplicationPosition = default }); action = TerraBaseAction.Hold; target = TerraBaseTarget.None; code = TerraBaseCode.InvalidInput; break;
                case 15: decision = TerraBaseTopologyPlanner.PlanRemove(scope, removePending with { NoDatabaseReference = TerraBaseProof.Proven }); action = TerraBaseAction.Hold; target = TerraBaseTarget.None; code = TerraBaseCode.InvalidInput; break;
                case 16: decision = TerraBaseTopologyPlanner.PlanRemove(scope, completed with { MemberRole = TerraBaseRole.Leader, LeadershipTransferred = TerraBaseProof.Unknown }); action = TerraBaseAction.Hold; target = TerraBaseTarget.None; code = TerraBaseCode.InvalidInput; break;
                case 17: decision = TerraBaseTopologyPlanner.PlanRemove(scope, completed with { NoDatabaseReference = TerraBaseProof.Unknown }); action = TerraBaseAction.Observe; target = TerraBaseTarget.Application; code = TerraBaseCode.NextStep; break;
                case 18: decision = TerraBaseTopologyPlanner.PlanRemove(scope, completed with { PostChangeReplication = TerraBaseProof.Contradicted }); action = TerraBaseAction.Hold; target = TerraBaseTarget.None; code = TerraBaseCode.ReplicationUnsafe; break;
                default: decision = TerraBaseTopologyPlanner.PlanRemove(scope, completed); action = TerraBaseAction.Verify; target = TerraBaseTarget.Topology; code = TerraBaseCode.Completed; break;
            }
            Exact(decision, scope, action, target, code, index);
            digest = Mix(digest, decision);
        }
        return new(Cases, kinds.Count, digest);
    }

    private static Summary RunRecovery()
    {
        ulong digest = 0; var kinds = new HashSet<int>();
        for (var index = 0; index < Cases; index++)
        {
            var scope = Scope(index); var mode = index % 21;
            kinds.Add(mode);
            var current = TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Release($"current-{index}");
            var targetRelease = TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Release($"target-{index}");
            TerraBaseDecision decision; TerraBaseAction action; TerraBaseTarget target; TerraBaseCode code;
            if (mode < 12)
            {
                var evidence = Upgrade(scope, current, targetRelease);
                evidence = mode switch
                {
                    0 => evidence with { UpgradeApplied = TerraBaseProof.Unknown },
                    1 => evidence with { UpgradeApplied = TerraBaseProof.Contradicted },
                    2 => evidence with { UpgradeApplied = TerraBaseProof.Unknown, ProcessHealthy = TerraBaseProof.Proven },
                    3 => evidence with { UpgradeApplied = TerraBaseProof.Proven, ProcessHealthy = TerraBaseProof.Unknown },
                    4 => evidence with { UpgradeApplied = TerraBaseProof.Proven, ProcessHealthy = TerraBaseProof.Proven, Ready = TerraBaseProof.Proven, CaughtUp = TerraBaseProof.Proven },
                    5 => evidence with { UpgradeApplied = TerraBaseProof.Proven, ProcessHealthy = TerraBaseProof.Contradicted },
                    6 => evidence with { UpgradeApplied = TerraBaseProof.Proven, ProcessHealthy = TerraBaseProof.Contradicted, RollbackApplied = TerraBaseProof.Contradicted },
                    7 => evidence with { UpgradeApplied = TerraBaseProof.Proven, ProcessHealthy = TerraBaseProof.Contradicted, PostRollbackHealthy = TerraBaseProof.Proven },
                    8 => evidence with { UpgradeApplied = TerraBaseProof.Proven, ProcessHealthy = TerraBaseProof.Contradicted, RollbackApplied = TerraBaseProof.Proven },
                    9 => evidence with { UpgradeApplied = TerraBaseProof.Proven, ProcessHealthy = TerraBaseProof.Contradicted, RollbackApplied = TerraBaseProof.Proven, PostRollbackHealthy = TerraBaseProof.Contradicted },
                    10 => evidence with { UpgradeApplied = TerraBaseProof.Proven, ProcessHealthy = TerraBaseProof.Contradicted, RollbackApplied = TerraBaseProof.Proven, PostRollbackHealthy = TerraBaseProof.Proven },
                    _ => evidence with { UpgradeApplied = TerraBaseProof.Proven, ProcessHealthy = TerraBaseProof.Proven, Ready = TerraBaseProof.Proven, CaughtUp = TerraBaseProof.Proven, RollbackApplied = TerraBaseProof.Contradicted },
                };
                decision = TerraBaseUpgradePlanner.Plan(scope, current, targetRelease, evidence);
                (action, target, code) = mode switch
                {
                    0 or 1 => (TerraBaseAction.Upgrade, TerraBaseTarget.Release, TerraBaseCode.NextStep),
                    2 or 7 or 11 => (TerraBaseAction.Hold, TerraBaseTarget.None, TerraBaseCode.InvalidInput),
                    3 => (TerraBaseAction.Observe, TerraBaseTarget.Application, TerraBaseCode.NextStep),
                    4 => (TerraBaseAction.Verify, TerraBaseTarget.Release, TerraBaseCode.Completed),
                    5 or 6 => (TerraBaseAction.Rollback, TerraBaseTarget.Release, TerraBaseCode.NextStep),
                    8 or 9 => (TerraBaseAction.Observe, TerraBaseTarget.Application, TerraBaseCode.NextStep),
                    _ => (TerraBaseAction.Verify, TerraBaseTarget.Release, TerraBaseCode.RolledBack),
                };
            }
            else
            {
                var restore = TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Restore($"restore-{index}");
                var targetGeneration = TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.O(scope.DatabaseGeneration.Value + 1);
                var evidence = Restore(scope, restore, targetGeneration);
                evidence = mode switch
                {
                    12 => evidence with { RestoreApplied = TerraBaseProof.Unknown },
                    13 => evidence with { RestoreApplied = TerraBaseProof.Contradicted },
                    14 => evidence with { RestoreApplied = TerraBaseProof.Unknown, TopologyVerified = TerraBaseProof.Proven },
                    15 => evidence with { RestoreApplied = TerraBaseProof.Proven },
                    16 => evidence with { RestoreApplied = TerraBaseProof.Proven, TopologyVerified = TerraBaseProof.Contradicted },
                    17 => evidence with { RestoreApplied = TerraBaseProof.Proven, PromotionAuthorized = TerraBaseProof.Proven },
                    18 => evidence with { RestoreApplied = TerraBaseProof.Proven, TopologyVerified = TerraBaseProof.Proven, QueryVerified = TerraBaseProof.Proven },
                    19 => evidence with { RestoreApplied = TerraBaseProof.Proven, TopologyVerified = TerraBaseProof.Proven, QueryVerified = TerraBaseProof.Proven, PromotionAuthorized = TerraBaseProof.Contradicted },
                    _ => evidence with { RestoreApplied = TerraBaseProof.Proven, TopologyVerified = TerraBaseProof.Proven, QueryVerified = TerraBaseProof.Proven, PromotionAuthorized = TerraBaseProof.Proven },
                };
                decision = TerraBaseRestorePlanner.Plan(scope, restore,
                    TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Backup("b2"), targetGeneration, evidence);
                (action, target, code) = mode switch
                {
                    12 or 13 => (TerraBaseAction.Restore, TerraBaseTarget.RestoreCandidate, TerraBaseCode.NextStep),
                    14 or 17 => (TerraBaseAction.Hold, TerraBaseTarget.None, TerraBaseCode.InvalidInput),
                    15 or 16 => (TerraBaseAction.Observe, TerraBaseTarget.RestoreCandidate, TerraBaseCode.NextStep),
                    18 or 19 => (TerraBaseAction.Hold, TerraBaseTarget.None, TerraBaseCode.PromotionProofMissing),
                    _ => (TerraBaseAction.Verify, TerraBaseTarget.RestoreCandidate, TerraBaseCode.Completed),
                };
            }
            Exact(decision, scope, action, target, code, index);
            digest = Mix(digest, decision);
        }
        return new(Cases, kinds.Count, digest);
    }

    private static TerraBaseUpgradeEvidence Upgrade(TerraBaseEvidenceScope scope, TerraBaseReleaseId current,
        TerraBaseReleaseId target) => new(scope, current, target,
        TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne, TerraBaseProof.Proven,
        TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven,
        TerraBaseProof.Unknown, TerraBaseProof.Unknown, TerraBaseProof.Unknown,
        TerraBaseProof.Unknown, TerraBaseProof.Unknown, TerraBaseProof.Unknown);

    private static TerraBaseRestoreEvidence Restore(TerraBaseEvidenceScope scope, TerraBaseRestoreId restore,
        TerraBaseOrdinal target) => new(scope, restore, scope.DatabaseGeneration, target,
        Chain(scope), TerraBaseProof.Proven,
        TerraBaseProof.Unknown, TerraBaseProof.Unknown, TerraBaseProof.Unknown, TerraBaseProof.Unknown);

    private static TerraBaseDecision[] Decisions(TerraBaseEvidenceScope? expected, TerraBaseEvidenceScope actual)
    {
        var current = TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Release("current");
        var target = TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Release("target");
        var chain = Chain(actual);
        var restore = TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Restore();
        var targetGeneration = TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.O(5);
        return
        [
            TerraBaseTopologyPlanner.PlanAdd(expected, TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Topology(scope: actual)),
            TerraBaseTopologyPlanner.PlanRemove(expected, TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Topology(scope: actual)),
            TerraBaseRetainedVolumePlanner.Plan(expected, new(actual, [], TerraBaseProof.Proven,
                TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven,
                TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.O(4), 8)),
            TerraBaseUpgradePlanner.Plan(expected, current, target, Upgrade(actual, current, target)),
            TerraBaseBackupPlanner.Authorize(expected, new(actual,
                TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Backup(),
                TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.O(1), null, null, null, true,
                TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Object(),
                TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Key(), TerraBaseProof.Proven,
                TerraBaseProof.Proven)),
            TerraBaseBackupPlanner.Accept(expected, chain),
            TerraBaseRestorePlanner.Plan(expected, restore,
                TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Backup("b2"), targetGeneration,
                Restore(actual, restore, targetGeneration)),
        ];
    }

    private static TerraBaseEvidenceScope Scope(int index) => new(
        TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Cell($"cell-{index}"),
        TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Db($"db-{index}"),
        TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Member($"member-{index}"),
        TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Node($"node-{index}"),
        TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Volume($"volume-{index}"),
        TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Fence($"fence-{index}"),
        TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.O(4),
        TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.O(8),
        TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.O(3),
        TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Op($"operation-{index}"));

    private static TerraBaseBackupEvidence Chain(TerraBaseEvidenceScope scope)
    {
        var subject = new TerraBaseBackupSubject(scope.Cell, scope.Database, scope.DatabaseGeneration,
            scope.TopologyGeneration);
        TerraBaseBackupSegment Segment(ulong sequence, bool full, ulong? parent = null) => new(subject,
            TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Backup($"b{sequence}"),
            TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.O(sequence),
            parent is null ? null : TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.O(parent.Value),
            full, TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Digest($"digest-{sequence}"),
            TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Object($"object-{sequence}"),
            TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Key($"key-{sequence}"));
        return new(scope, [Segment(1, true), Segment(2, false, 1)], TerraBaseProof.Proven,
            TerraBaseProof.Proven, TerraBaseProof.Proven, 8);
    }

    private static TerraBaseEvidenceScope Changed(TerraBaseEvidenceScope value, int dimension,
        bool malformed, int index) => dimension switch
    {
        0 => value with { Cell = malformed ? null! : TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Cell($"other-cell-{index}") },
        1 => value with { Database = malformed ? null! : TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Db($"other-db-{index}") },
        2 => value with { Member = malformed ? null! : TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Member($"other-member-{index}") },
        3 => value with { Node = malformed ? null! : TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Node($"other-node-{index}") },
        4 => value with { RetainedVolume = malformed ? null! : TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Volume($"other-volume-{index}") },
        5 => value with { Fence = malformed ? null! : TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Fence($"other-fence-{index}") },
        6 => value with { Operation = malformed ? null! : TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Op($"other-operation-{index}") },
        7 => value with { DatabaseGeneration = malformed ? default : TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.O(40) },
        8 => value with { TopologyGeneration = malformed ? default : TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.O(80) },
        _ => value with { AuthorityEpoch = malformed ? default : TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.O(30) },
    };

    private static void Exact(TerraBaseDecision decision, TerraBaseEvidenceScope scope,
        TerraBaseAction action, TerraBaseTarget target, TerraBaseCode code, int index)
    {
        Require(decision.Action == action && decision.Target == target && decision.Code == code
            && decision.Trace is { } trace && trace.Scope == scope && trace.Generation == scope.TopologyGeneration,
            "exact-decision", index);
        if (decision.IsMutationAuthorized)
        {
            Require(decision.Subject?.Scope == scope, "mutation-scope", index);
            if (decision.Subject is TerraBaseTopologyIntentSubject topology)
                Require(topology.MemberKind == TerraBaseMemberKind.Elastic
                    && topology.ReplicationPosition == TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.O(100),
                    "topology-subject", index);
            else if (decision.Subject is TerraBaseUpgradeIntentSubject upgrade)
                Require(upgrade.Current == TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Release($"current-{index}")
                    && upgrade.Target == TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Release($"target-{index}"),
                    "upgrade-subject", index);
            else if (decision.Subject is TerraBaseRestoreIntentSubject restore)
                Require(restore.Restore == TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Restore($"restore-{index}")
                    && restore.SourceGeneration == scope.DatabaseGeneration
                    && restore.TargetGeneration == TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.O(scope.DatabaseGeneration.Value + 1)
                    && restore.Chain.Scope == scope && restore.Chain.Segments.Count == 2
                    && restore.Chain.TerminalBackup == TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Backup("b2"),
                    "restore-subject", index);
            else Require(false, "subject-shape", index);
        }
        else if (action == TerraBaseAction.Hold)
            Require(decision.Subject is null, "hold-subject", index);
        else
        {
            Require(decision.Subject?.Scope == scope, "observation-subject", index);
            if (decision.Subject is TerraBaseUpgradeIntentSubject upgrade)
                Require(upgrade.Current == TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Release($"current-{index}")
                    && upgrade.Target == TerraScale.Orchestrator.ControlPlane.Tests.TerraBaseTestData.Release($"target-{index}"),
                    "upgrade-observation-subject", index);
        }
    }

    private static Summary UnderCulture(string name, Func<Summary> action)
    {
        var before = CultureInfo.CurrentCulture; var beforeUi = CultureInfo.CurrentUICulture;
        try { var culture = CultureInfo.GetCultureInfo(name); CultureInfo.CurrentCulture = culture; CultureInfo.CurrentUICulture = culture; return action(); }
        finally { CultureInfo.CurrentCulture = before; CultureInfo.CurrentUICulture = beforeUi; }
    }

    private static ulong Mix(ulong value, TerraBaseDecision decision)
    {
        value=unchecked((value ^ (uint)decision.Action ^ ((ulong)(uint)decision.Target << 8) ^ ((ulong)(uint)decision.Code << 16))
            * 1099511628211UL);
        if(decision.Subject is TerraBaseUpgradeIntentSubject upgrade)
        {
            value=MixText(value,upgrade.Current.Value);
            value=MixText(value,upgrade.Target.Value);
        }
        return value;
    }
    private static ulong MixText(ulong value,string text)
    {
        foreach(var character in text)value=unchecked((value^character)*1099511628211UL);
        return unchecked((value^0xffUL)*1099511628211UL);
    }
    private static void Require(bool condition, string family, int index)
    { if (!condition) throw new InvalidOperationException($"{family} property failed at {index}."); }
    private sealed record Summary(int Cases, int Kinds, ulong Digest);
}
