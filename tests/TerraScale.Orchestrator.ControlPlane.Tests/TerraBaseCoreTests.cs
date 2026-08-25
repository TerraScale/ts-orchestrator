using TerraScale.Orchestrator.ControlPlane.TerraBase;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class TerraBaseCoreTests
{
    private static T RequireSubject<T>(TerraBaseDecision decision) where T : TerraBaseIntentSubject
    {
        if (decision.Subject is T subject) return subject;
        throw new InvalidOperationException($"Expected a {typeof(T).Name} decision subject.");
    }

    [Test]
    public async Task Permanent_members_and_overlapping_topology_mutation_are_held()
    {
        foreach(var kind in new[]{TerraBaseMemberKind.PermanentA,TerraBaseMemberKind.PermanentB,TerraBaseMemberKind.PermanentC})
            await Assert.That(TerraBaseTopologyPlanner.PlanRemove(TerraBaseTestData.Scope(),TerraBaseTestData.Topology(kind)).Code).IsEqualTo(TerraBaseCode.PermanentMember);
        var overlap=TerraBaseTopologyPlanner.PlanAdd(TerraBaseTestData.Scope(),TerraBaseTestData.Topology(noMutation:TerraBaseProof.Unknown));
        await Assert.That(overlap.Code).IsEqualTo(TerraBaseCode.ConflictingTopologyMutation);
        await Assert.That(TerraBaseTopologyPlanner.PlanAdd(TerraBaseTestData.Scope(),TerraBaseTestData.Topology(TerraBaseMemberKind.Unknown)).IsMutationAuthorized).IsFalse();
        await Assert.That(TerraBaseTopologyPlanner.PlanAdd(TerraBaseTestData.Scope(),TerraBaseTestData.Topology(TerraBaseMemberKind.PermanentA)).IsMutationAuthorized).IsFalse();
    }

    [Test]
    public async Task Add_and_remove_resume_after_topology_mutation_without_duplicate_mutation()
    {
        var s=TerraBaseTestData.Scope();
        var add=TerraBaseTopologyPlanner.PlanAdd(s,TerraBaseTestData.Topology(topologyApplied:TerraBaseProof.Unknown,
            replication:TerraBaseReplication.Unknown) with{PostChangeReplication=TerraBaseProof.Unknown});
        var addReplay=TerraBaseTopologyPlanner.PlanAdd(s,TerraBaseTestData.Topology());
        var remove=TerraBaseTopologyPlanner.PlanRemove(s,TerraBaseTestData.Topology(topologyApplied:TerraBaseProof.Unknown) with
            {NoDatabaseReference=TerraBaseProof.Unknown,PostChangeReplication=TerraBaseProof.Unknown});
        var removeReplay=TerraBaseTopologyPlanner.PlanRemove(s,TerraBaseTestData.Topology());
        await Assert.That(add.Action).IsEqualTo(TerraBaseAction.Add);
        await Assert.That(addReplay.Action).IsNotEqualTo(TerraBaseAction.Add);
        await Assert.That(remove.Action).IsEqualTo(TerraBaseAction.Remove);
        await Assert.That(removeReplay.Action).IsNotEqualTo(TerraBaseAction.Remove);
        await Assert.That(TerraBaseTopologyPlanner.PlanRemove(s,TerraBaseTestData.Topology() with{QuorumFloor=TerraBaseProof.Unknown}).IsMutationAuthorized).IsFalse();
        await Assert.That(TerraBaseTopologyPlanner.PlanAdd(s,TerraBaseTestData.Topology(replication:TerraBaseReplication.Conflicting)).Code).IsEqualTo(TerraBaseCode.ReplicationUnsafe);
        var transfer=TerraBaseTopologyPlanner.PlanRemove(s,TerraBaseTestData.Topology(topologyApplied:TerraBaseProof.Unknown,
            role:TerraBaseRole.Leader,leadership:TerraBaseProof.Unknown) with
            {NoDatabaseReference=TerraBaseProof.Unknown,PostChangeReplication=TerraBaseProof.Unknown});
        await Assert.That(transfer.Action).IsEqualTo(TerraBaseAction.Transfer);
        await Assert.That(TerraBaseTopologyPlanner.PlanRemove(s,TerraBaseTestData.Topology(loss:TerraBaseLossCount.One)).Code).IsEqualTo(TerraBaseCode.Completed);
        await Assert.That(TerraBaseTopologyPlanner.PlanRemove(s,TerraBaseTestData.Topology(loss:TerraBaseLossCount.TwoOrMore)).Code).IsEqualTo(TerraBaseCode.ReplicationUnsafe);
        var missingFloor=TerraBaseTopologyPlanner.PlanAdd(s,TerraBaseTestData.Topology(loss:TerraBaseLossCount.One) with{QuorumFloor=TerraBaseProof.Unknown});
        await Assert.That(missingFloor.Code).IsEqualTo(TerraBaseCode.ReplicationUnsafe);
        var catchUp=TerraBaseTopologyPlanner.PlanAdd(s,TerraBaseTestData.Topology(replication:TerraBaseReplication.Lagging) with
            {PostChangeReplication=TerraBaseProof.Unknown});
        await Assert.That(catchUp.Action).IsEqualTo(TerraBaseAction.CatchUp);
        await Assert.That(catchUp.IsMutationAuthorized).IsTrue();
        await Assert.That(RequireSubject<TerraBaseTopologyIntentSubject>(catchUp).ReplicationPosition).IsEqualTo(TerraBaseTestData.O(100));
        await Assert.That(transfer.IsMutationAuthorized).IsTrue();
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
        await Assert.That(TerraBaseRetainedVolumePlanner.Plan(s,E([TerraBaseTestData.Member()],4)).Code).IsEqualTo(TerraBaseCode.SplitWriter);
        await Assert.That(TerraBaseRetainedVolumePlanner.Plan(s,E([],3)).IsMutationAuthorized).IsFalse();
        await Assert.That(TerraBaseRetainedVolumePlanner.Plan(s,E([],4)).Action).IsEqualTo(TerraBaseAction.StartWithRetainedVolume);
        var exact=TerraBaseRetainedVolumePlanner.Plan(s,E([],4));
        await Assert.That(RequireSubject<TerraBaseRetainedVolumeIntentSubject>(exact).NewAuthorityEpoch).IsEqualTo(TerraBaseTestData.O(4));
    }

    [Test]
    public async Task Upgrade_requires_n_n_minus_one_rollback_and_distinct_readiness_proofs()
    {
        var s=TerraBaseTestData.Scope();
        var current=TerraBaseTestData.Release("n-1"); var target=TerraBaseTestData.Release("n");
        TerraBaseUpgradeEvidence E(TerraBaseUpgradeCompatibility c,TerraBaseProof rollback,TerraBaseProof ready)=>new(s,current,target,c,
            TerraBaseProof.Proven,TerraBaseProof.Proven,rollback,TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,ready,TerraBaseProof.Proven,
            TerraBaseProof.Unknown,TerraBaseProof.Unknown);
        await Assert.That(TerraBaseUpgradePlanner.Plan(s,current,target,E(TerraBaseUpgradeCompatibility.Incompatible,TerraBaseProof.Proven,TerraBaseProof.Proven)).Code).IsEqualTo(TerraBaseCode.CompatibilityRequired);
        await Assert.That(TerraBaseUpgradePlanner.Plan(s,current,target,E(TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne,TerraBaseProof.Unknown,TerraBaseProof.Proven)).Code).IsEqualTo(TerraBaseCode.RollbackMaterialRequired);
        await Assert.That(TerraBaseUpgradePlanner.Plan(s,current,target,E(TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne,TerraBaseProof.Proven,TerraBaseProof.Unknown)).Code).IsNotEqualTo(TerraBaseCode.Completed);
        var first=TerraBaseUpgradePlanner.Plan(s,current,target,E(TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne,TerraBaseProof.Proven,TerraBaseProof.Proven) with
            {UpgradeApplied=TerraBaseProof.Unknown,ProcessHealthy=TerraBaseProof.Unknown,Ready=TerraBaseProof.Unknown,CaughtUp=TerraBaseProof.Unknown});
        var replay=TerraBaseUpgradePlanner.Plan(s,current,target,E(TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne,TerraBaseProof.Proven,TerraBaseProof.Proven));
        await Assert.That(first.Action).IsEqualTo(TerraBaseAction.Upgrade);
        await Assert.That(replay.Action).IsNotEqualTo(TerraBaseAction.Upgrade);
        var upgradeSubject=RequireSubject<TerraBaseUpgradeIntentSubject>(first);
        await Assert.That(upgradeSubject.Current).IsEqualTo(current);
        await Assert.That(upgradeSubject.Target).IsEqualTo(target);
        await Assert.That(TerraBaseUpgradePlanner.Plan(s,current,TerraBaseTestData.Release("other"),E(TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne,TerraBaseProof.Proven,TerraBaseProof.Proven)).Code).IsEqualTo(TerraBaseCode.WrongEvidenceScope);
        var failed=E(TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne,TerraBaseProof.Proven,TerraBaseProof.Proven) with{ProcessHealthy=TerraBaseProof.Contradicted};
        var rollbackDecision=TerraBaseUpgradePlanner.Plan(s,current,target,failed);
        var rollbackApplied=TerraBaseUpgradePlanner.Plan(s,current,target,failed with{RollbackApplied=TerraBaseProof.Proven});
        var rollbackHealthy=TerraBaseUpgradePlanner.Plan(s,current,target,failed with{RollbackApplied=TerraBaseProof.Proven,PostRollbackHealthy=TerraBaseProof.Proven});
        await Assert.That(rollbackDecision.Action).IsEqualTo(TerraBaseAction.Rollback);
        await Assert.That(rollbackApplied.Action).IsEqualTo(TerraBaseAction.Observe);
        await Assert.That(rollbackHealthy.Code).IsEqualTo(TerraBaseCode.RolledBack);
    }

    [Test]
    public async Task Backup_chain_requires_exact_subject_contiguity_digest_and_application_consistency()
    {
        var s=TerraBaseTestData.Scope();
        TerraBaseBackupEvidence E(IEnumerable<TerraBaseBackupSegment> segments,TerraBaseProof app=TerraBaseProof.Proven,TerraBaseEvidenceScope? scope=null)=>new(scope??s,segments,app,TerraBaseProof.Proven,TerraBaseProof.Proven,8);
        await Assert.That(TerraBaseBackupPlanner.Accept(s,E([TerraBaseTestData.Segment(1,true),TerraBaseTestData.Segment(3,parent:1)])).Code).IsEqualTo(TerraBaseCode.ChainGap);
        await Assert.That(TerraBaseBackupPlanner.Accept(s,E([TerraBaseTestData.Segment(1,true)],TerraBaseProof.Unknown)).Code).IsEqualTo(TerraBaseCode.ApplicationConsistencyRequired);
        var accepted=TerraBaseBackupPlanner.Accept(s,E([TerraBaseTestData.Segment(1,true),TerraBaseTestData.Segment(2,parent:1)]));
        await Assert.That(accepted.Code).IsEqualTo(TerraBaseCode.Completed);
        await Assert.That(accepted.Action).IsEqualTo(TerraBaseAction.Verify);
        await Assert.That(accepted.IsMutationAuthorized).IsFalse();
        await Assert.That(RequireSubject<TerraBaseBackupChainIntentSubject>(accepted).Segments.Count).IsEqualTo(2);
        var wrongSubject=new TerraBaseBackupSubject(s.Cell,s.Database,TerraBaseTestData.O(5),s.TopologyGeneration);
        await Assert.That(TerraBaseBackupPlanner.Accept(s,E([TerraBaseTestData.Segment(1,true,subject:wrongSubject)])).Code).IsEqualTo(TerraBaseCode.WrongEvidenceScope);
        await Assert.That(TerraBaseBackupPlanner.Accept(s,E([TerraBaseTestData.Segment(1,true)],scope:s with{Operation=TerraBaseTestData.Op("other")})).Code).IsEqualTo(TerraBaseCode.WrongEvidenceScope);
        await Assert.That(TerraBaseBackupPlanner.Accept(s,E([TerraBaseTestData.Segment(1,true) with{Backup=null!}])).Code).IsEqualTo(TerraBaseCode.WrongEvidenceScope);
        await Assert.That(TerraBaseBackupPlanner.Accept(s,E([TerraBaseTestData.Segment(1,true) with{Sequence=default}])).Code).IsEqualTo(TerraBaseCode.WrongEvidenceScope);
        await Assert.That(TerraBaseBackupPlanner.Accept(s,E([TerraBaseTestData.Segment(1,true),TerraBaseTestData.Segment(2,parent:1) with{Backup=TerraBaseTestData.Backup("b1")}])).Code).IsEqualTo(TerraBaseCode.ChainGap);
        var replay=TerraBaseBackupPlanner.Accept(s,E([TerraBaseTestData.Segment(2,parent:1),TerraBaseTestData.Segment(1,true)]));
        await Assert.That(replay).IsEqualTo(accepted);
    }

    [Test]
    public async Task Backup_authorization_is_exact_and_incremental_parent_chain_is_mandatory()
    {
        var s=TerraBaseTestData.Scope(); var parent=TerraBaseTestData.Chain();
        var full=new TerraBaseBackupRequestEvidence(s,TerraBaseTestData.Backup("new"),TerraBaseTestData.O(1),null,null,null,true,
            TerraBaseTestData.Object("destination"),TerraBaseTestData.Key("key-ref"),TerraBaseProof.Proven,TerraBaseProof.Proven);
        var fullDecision=TerraBaseBackupPlanner.Authorize(s,full);
        await Assert.That(fullDecision.Action).IsEqualTo(TerraBaseAction.Backup);
        var fullSubject=RequireSubject<TerraBaseBackupRequestIntentSubject>(fullDecision);
        await Assert.That(fullSubject.Destination).IsEqualTo(TerraBaseTestData.Object("destination"));
        await Assert.That(fullSubject.EncryptionKey).IsEqualTo(TerraBaseTestData.Key("key-ref"));
        await Assert.That(fullDecision.ToString()).DoesNotContain("destination");
        await Assert.That(fullDecision.ToString()).DoesNotContain("key-ref");
        var incremental=new TerraBaseBackupRequestEvidence(s,TerraBaseTestData.Backup("b3"),TerraBaseTestData.O(3),TerraBaseTestData.O(2),
            TerraBaseTestData.Backup("b2"),parent,false,TerraBaseTestData.Object(),TerraBaseTestData.Key(),TerraBaseProof.Proven,TerraBaseProof.Proven);
        await Assert.That(TerraBaseBackupPlanner.Authorize(s,incremental).Action).IsEqualTo(TerraBaseAction.Backup);
        await Assert.That(TerraBaseBackupPlanner.Authorize(s,incremental with{ParentBackup=TerraBaseTestData.Backup("wrong")}).Code).IsEqualTo(TerraBaseCode.ChainGap);
        await Assert.That(TerraBaseBackupPlanner.Authorize(s,incremental with{ParentChain=null}).IsMutationAuthorized).IsFalse();
    }

    [Test]
    public async Task Restore_is_side_by_side_and_anti_rollback_before_promotion()
    {
        var s=TerraBaseTestData.Scope();
        var restore=TerraBaseTestData.Restore(); var terminal=TerraBaseTestData.Backup("b2"); var targetGeneration=TerraBaseTestData.O(5);
        TerraBaseRestoreEvidence E(ulong source,ulong target,TerraBaseProof side,TerraBaseProof promote=TerraBaseProof.Proven,
            TerraBaseBackupEvidence? chain=null)=>new(s,restore,TerraBaseTestData.O(source),TerraBaseTestData.O(target),chain??TerraBaseTestData.Chain(),side,
            TerraBaseProof.Proven,TerraBaseProof.Proven,TerraBaseProof.Proven,promote);
        TerraBaseDecision Plan(TerraBaseRestoreEvidence e)=>TerraBaseRestorePlanner.Plan(s,restore,terminal,targetGeneration,e);
        await Assert.That(Plan(E(4,5,TerraBaseProof.Unknown)).Code).IsEqualTo(TerraBaseCode.SideBySideRequired);
        await Assert.That(Plan(E(3,5,TerraBaseProof.Proven)).Code).IsEqualTo(TerraBaseCode.AntiRollback);
        await Assert.That(Plan(E(4,5,TerraBaseProof.Proven,TerraBaseProof.Unknown)).Code).IsEqualTo(TerraBaseCode.PromotionProofMissing);
        var completed=Plan(E(4,5,TerraBaseProof.Proven));
        await Assert.That(completed.Code).IsEqualTo(TerraBaseCode.Completed);
        var first=Plan(E(4,5,TerraBaseProof.Proven) with
            {RestoreApplied=TerraBaseProof.Unknown,TopologyVerified=TerraBaseProof.Unknown,
                QueryVerified=TerraBaseProof.Unknown,PromotionAuthorized=TerraBaseProof.Unknown});
        var replay=Plan(E(4,5,TerraBaseProof.Proven));
        await Assert.That(first.Action).IsEqualTo(TerraBaseAction.Restore);
        await Assert.That(replay.Action).IsNotEqualTo(TerraBaseAction.Restore);
        var otherChain=TerraBaseTestData.Chain(segments:[TerraBaseTestData.Segment(1,true),TerraBaseTestData.Segment(2,parent:1) with{Backup=TerraBaseTestData.Backup("other")}]);
        await Assert.That(Plan(E(4,5,TerraBaseProof.Proven,chain:otherChain)).Code).IsEqualTo(TerraBaseCode.WrongEvidenceScope);
        var unverifiedChain=TerraBaseTestData.Chain(digest:TerraBaseProof.Unknown);
        await Assert.That(Plan(E(4,5,TerraBaseProof.Proven,chain:unverifiedChain)).Code).IsEqualTo(TerraBaseCode.DigestProofMissing);
        var subject=RequireSubject<TerraBaseRestoreIntentSubject>(completed);
        await Assert.That(subject.Restore).IsEqualTo(restore);
        await Assert.That(subject.Chain.TerminalBackup).IsEqualTo(terminal);
    }
}
