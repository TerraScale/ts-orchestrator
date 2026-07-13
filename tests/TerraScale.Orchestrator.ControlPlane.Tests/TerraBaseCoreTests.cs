using TerraScale.Orchestrator.ControlPlane.TerraBase;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class TerraBaseCoreTests
{
    [Test]
    public async Task Permanent_members_and_overlapping_topology_mutation_are_held()
    {
        foreach(var kind in new[]{TerraBaseMemberKind.PermanentA,TerraBaseMemberKind.PermanentB,TerraBaseMemberKind.PermanentC})
            await Assert.That(TerraBaseTopologyPlanner.PlanRemove(TerraBaseTestData.Scope(),TerraBaseTestData.Topology(kind)).Code).IsEqualTo(TerraBaseCode.PermanentMember);
        var overlap=TerraBaseTopologyPlanner.PlanAdd(TerraBaseTestData.Scope(),TerraBaseTestData.Topology(noMutation:TerraBaseProof.Unknown));
        await Assert.That(overlap.Code).IsEqualTo(TerraBaseCode.ConflictingTopologyMutation);
    }

    [Test]
    public async Task Add_and_remove_resume_after_topology_mutation_without_duplicate_mutation()
    {
        var s=TerraBaseTestData.Scope();
        var add=TerraBaseTopologyPlanner.PlanAdd(s,TerraBaseTestData.Topology(topologyApplied:TerraBaseProof.Unknown));
        var addReplay=TerraBaseTopologyPlanner.PlanAdd(s,TerraBaseTestData.Topology());
        var remove=TerraBaseTopologyPlanner.PlanRemove(s,TerraBaseTestData.Topology(topologyApplied:TerraBaseProof.Unknown));
        var removeReplay=TerraBaseTopologyPlanner.PlanRemove(s,TerraBaseTestData.Topology());
        await Assert.That(add.Action).IsEqualTo(TerraBaseAction.Add);
        await Assert.That(addReplay.Action).IsNotEqualTo(TerraBaseAction.Add);
        await Assert.That(remove.Action).IsEqualTo(TerraBaseAction.Remove);
        await Assert.That(removeReplay.Action).IsNotEqualTo(TerraBaseAction.Remove);
        await Assert.That(TerraBaseTopologyPlanner.PlanRemove(s,TerraBaseTestData.Topology() with{QuorumFloor=TerraBaseProof.Unknown}).IsMutationAuthorized).IsFalse();
        await Assert.That(TerraBaseTopologyPlanner.PlanAdd(s,TerraBaseTestData.Topology(replication:TerraBaseReplication.Conflicting)).Code).IsEqualTo(TerraBaseCode.ReplicationUnsafe);
    }

    [Test]
    public async Task Topology_evidence_cannot_replay_across_any_subject_dimension()
    {
        var expected=TerraBaseTestData.Scope();
        var variants=new[]{expected with{Database=TerraBaseTestData.Db("other")},expected with{Member=TerraBaseTestData.Member("e")},
            expected with{Node=TerraBaseTestData.Node("other")},expected with{RetainedVolume=TerraBaseTestData.Volume("other")},
            expected with{Fence=TerraBaseTestData.Fence("other")},expected with{DatabaseGeneration=TerraBaseTestData.O(5)},
            expected with{Operation=TerraBaseTestData.Op("other")}};
        foreach(var scope in variants)
        {
            var d=TerraBaseTopologyPlanner.PlanAdd(expected,TerraBaseTestData.Topology(scope:scope));
            await Assert.That(d.Code).IsEqualTo(TerraBaseCode.WrongEvidenceScope);
            await Assert.That(d.IsMutationAuthorized).IsFalse();
        }
    }

    [Test]
    public async Task Retained_volume_rejects_split_writer_and_stale_epoch()
    {
        var s=TerraBaseTestData.Scope();
        TerraBaseWriterEvidence E(IEnumerable<TerraBaseMemberId> w,ulong epoch)=>new(s,w,TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseTestData.O(epoch),4);
        await Assert.That(TerraBaseRetainedVolumePlanner.Plan(s,E([TerraBaseTestData.Member("a"),TerraBaseTestData.Member("b")],4)).Code).IsEqualTo(TerraBaseCode.SplitWriter);
        await Assert.That(TerraBaseRetainedVolumePlanner.Plan(s,E([],3)).IsMutationAuthorized).IsFalse();
        await Assert.That(TerraBaseRetainedVolumePlanner.Plan(s,E([],4)).Action).IsEqualTo(TerraBaseAction.StartWithRetainedVolume);
    }

    [Test]
    public async Task Upgrade_requires_n_n_minus_one_rollback_and_distinct_readiness_proofs()
    {
        var s=TerraBaseTestData.Scope();
        TerraBaseUpgradeEvidence E(TerraBaseUpgradeCompatibility c,TerraBaseProof rollback,TerraBaseProof ready)=>new(s,TerraBaseTestData.Release("n-1"),TerraBaseTestData.Release("n"),c,
            TerraBaseProof.Proven,TerraBaseProof.Proven,rollback,TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,ready,TerraBaseProof.Proven);
        await Assert.That(TerraBaseUpgradePlanner.Plan(s,E(TerraBaseUpgradeCompatibility.Incompatible,TerraBaseProof.Proven,TerraBaseProof.Proven)).Code).IsEqualTo(TerraBaseCode.CompatibilityRequired);
        await Assert.That(TerraBaseUpgradePlanner.Plan(s,E(TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne,TerraBaseProof.Unknown,TerraBaseProof.Proven)).Code).IsEqualTo(TerraBaseCode.RollbackMaterialRequired);
        await Assert.That(TerraBaseUpgradePlanner.Plan(s,E(TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne,TerraBaseProof.Proven,TerraBaseProof.Unknown)).Code).IsNotEqualTo(TerraBaseCode.Completed);
        var first=TerraBaseUpgradePlanner.Plan(s,E(TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne,TerraBaseProof.Proven,TerraBaseProof.Proven) with{UpgradeApplied=TerraBaseProof.Unknown});
        var replay=TerraBaseUpgradePlanner.Plan(s,E(TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne,TerraBaseProof.Proven,TerraBaseProof.Proven));
        await Assert.That(first.Action).IsEqualTo(TerraBaseAction.Upgrade);
        await Assert.That(replay.Action).IsNotEqualTo(TerraBaseAction.Upgrade);
    }

    [Test]
    public async Task Backup_chain_requires_exact_subject_contiguity_digest_and_application_consistency()
    {
        var s=TerraBaseTestData.Scope();
        TerraBaseBackupEvidence E(IEnumerable<TerraBaseBackupSegment> segments,TerraBaseProof app=TerraBaseProof.Proven,TerraBaseEvidenceScope? scope=null)=>new(scope??s,segments,app,TerraBaseProof.Proven,TerraBaseProof.Proven,8);
        await Assert.That(TerraBaseBackupPlanner.Accept(s,E([TerraBaseTestData.Segment(1,true),TerraBaseTestData.Segment(3,parent:1)])).Code).IsEqualTo(TerraBaseCode.ChainGap);
        await Assert.That(TerraBaseBackupPlanner.Accept(s,E([TerraBaseTestData.Segment(1,true)],TerraBaseProof.Unknown)).Code).IsEqualTo(TerraBaseCode.ApplicationConsistencyRequired);
        await Assert.That(TerraBaseBackupPlanner.Accept(s,E([TerraBaseTestData.Segment(1,true),TerraBaseTestData.Segment(2,parent:1)])).Code).IsEqualTo(TerraBaseCode.Completed);
        var wrongSubject=new TerraBaseBackupSubject(s.Cell,s.Database,TerraBaseTestData.O(5),s.TopologyGeneration);
        await Assert.That(TerraBaseBackupPlanner.Accept(s,E([TerraBaseTestData.Segment(1,true,subject:wrongSubject)])).Code).IsEqualTo(TerraBaseCode.WrongEvidenceScope);
        await Assert.That(TerraBaseBackupPlanner.Accept(s,E([TerraBaseTestData.Segment(1,true)],scope:s with{Operation=TerraBaseTestData.Op("other")})).Code).IsEqualTo(TerraBaseCode.WrongEvidenceScope);
    }

    [Test]
    public async Task Restore_is_side_by_side_and_anti_rollback_before_promotion()
    {
        var s=TerraBaseTestData.Scope();
        TerraBaseRestoreEvidence E(ulong source,ulong target,TerraBaseProof side,TerraBaseProof promote=TerraBaseProof.Proven)=>new(s,TerraBaseTestData.Restore(),TerraBaseTestData.O(source),TerraBaseTestData.O(target),side,
            TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,promote);
        await Assert.That(TerraBaseRestorePlanner.Plan(s,E(4,5,TerraBaseProof.Unknown)).Code).IsEqualTo(TerraBaseCode.SideBySideRequired);
        await Assert.That(TerraBaseRestorePlanner.Plan(s,E(3,5,TerraBaseProof.Proven)).Code).IsEqualTo(TerraBaseCode.AntiRollback);
        await Assert.That(TerraBaseRestorePlanner.Plan(s,E(4,5,TerraBaseProof.Proven,TerraBaseProof.Unknown)).Code).IsEqualTo(TerraBaseCode.PromotionProofMissing);
        await Assert.That(TerraBaseRestorePlanner.Plan(s,E(4,5,TerraBaseProof.Proven)).Code).IsEqualTo(TerraBaseCode.Completed);
        var first=TerraBaseRestorePlanner.Plan(s,E(4,5,TerraBaseProof.Proven) with{RestoreApplied=TerraBaseProof.Unknown});
        var replay=TerraBaseRestorePlanner.Plan(s,E(4,5,TerraBaseProof.Proven));
        await Assert.That(first.Action).IsEqualTo(TerraBaseAction.Restore);
        await Assert.That(replay.Action).IsNotEqualTo(TerraBaseAction.Restore);
    }
}
