using TerraScale.Orchestrator.ControlPlane.Storage;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class StorageExpansionTests
{
    [Test]
    public async Task Filesystem_growth_intent_distinguishes_exact_filesystem_and_layout()
    {
        var xfsEvidence=StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,
            StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,
            scope:StorageTestData.Scope(providerBytes:200,block:200,filesystemType:StorageFilesystemType.Xfs,layout:StorageLayout.Lvm));
        var ext4Evidence=StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,
            StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,
            scope:StorageTestData.Scope(providerBytes:200,block:200,filesystemType:StorageFilesystemType.Ext4,layout:StorageLayout.Partition));
        var xfs=StorageExpansionPlanner.Plan(StorageTestData.Volume(provider:200,block:200,
            filesystemType:StorageFilesystemType.Xfs,layout:StorageLayout.Lvm),StorageTestData.Context(),xfsEvidence);
        var ext4=StorageExpansionPlanner.Plan(StorageTestData.Volume(provider:200,block:200,
            filesystemType:StorageFilesystemType.Ext4,layout:StorageLayout.Partition),StorageTestData.Context(),ext4Evidence);
        var xfsScope = StorageTestData.Require(xfs.Scope);
        var ext4Scope = StorageTestData.Require(ext4.Scope);

        await Assert.That(xfs.Action).IsEqualTo(StorageAction.Grow);
        await Assert.That(ext4.Action).IsEqualTo(StorageAction.Grow);
        await Assert.That(xfs).IsNotEqualTo(ext4);
        await Assert.That(xfsScope.FilesystemType).IsEqualTo(StorageFilesystemType.Xfs);
        await Assert.That(xfsScope.Layout).IsEqualTo(StorageLayout.Lvm);
        await Assert.That(ext4Scope.FilesystemType).IsEqualTo(StorageFilesystemType.Ext4);
        await Assert.That(ext4Scope.Layout).IsEqualTo(StorageLayout.Partition);
    }

    [Test]
    public async Task Expansion_evidence_scope_distinguishes_exact_observed_capacity()
    {
        var beforeVolume=StorageTestData.Volume(provider:100,block:100,filesystem:100);
        var afterVolume=StorageTestData.Volume(provider:200,block:100,filesystem:100);
        var beforeProviderGrowth=beforeVolume.EvidenceScope;
        var afterProviderGrowth=afterVolume.EvidenceScope;
        var afterGuestRescan=StorageTestData.Volume(provider:200,block:200,filesystem:100).EvidenceScope;
        var afterFilesystemGrowth=StorageTestData.Volume(provider:200,block:200,filesystem:200,used:100,free:100).EvidenceScope;

        await Assert.That(beforeProviderGrowth).IsNotEqualTo(afterProviderGrowth);
        await Assert.That(afterProviderGrowth).IsNotEqualTo(afterGuestRescan);
        await Assert.That(afterGuestRescan).IsNotEqualTo(afterFilesystemGrowth);

        var replay=StorageExpansionPlanner.Plan(afterVolume,StorageTestData.Context(),
            StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,
                StorageProof.Proven,scope:beforeProviderGrowth));
        await Assert.That(replay.Code).IsEqualTo(StorageDecisionCode.WrongEvidenceScope);
        await Assert.That(replay.IsMutationAuthorized).IsFalse();
    }

    [Test]
    public async Task Expansion_evidence_scope_binds_every_capacity_and_performance_component()
    {
        var baselinePerformance=new StoragePerformance(StoragePerformanceTier.Balanced,StorageTestData.B(10),StorageTestData.B(1000),
            StorageTestData.B(200),StorageTestData.B(5),StorageTestData.B(900),StorageTestData.B(180),StorageTestData.B(10));
        var baseline=StorageTestData.Volume(performance:baselinePerformance).EvidenceScope;
        var byteVariants=new[]
        {
            StorageTestData.Volume(observed:101).EvidenceScope,
            StorageTestData.Volume(provider:101).EvidenceScope,
            StorageTestData.Volume(block:101).EvidenceScope,
            StorageTestData.Volume(filesystem:101).EvidenceScope,
            StorageTestData.Volume(used:61).EvidenceScope,
            StorageTestData.Volume(free:41).EvidenceScope,
            StorageTestData.Volume(forecast:3601).EvidenceScope,
        };
        var performanceVariants=new[]
        {
            Performance(StoragePerformanceTier.HighPerformance,10,1000,200,5,900,180,10),
            Performance(StoragePerformanceTier.Balanced,11,1000,200,5,900,180,10),
            Performance(StoragePerformanceTier.Balanced,10,1001,200,5,900,180,10),
            Performance(StoragePerformanceTier.Balanced,10,1000,201,5,900,180,10),
            Performance(StoragePerformanceTier.Balanced,10,1000,200,6,900,180,10),
            Performance(StoragePerformanceTier.Balanced,10,1000,200,5,901,180,10),
            Performance(StoragePerformanceTier.Balanced,10,1000,200,5,900,181,10),
            Performance(StoragePerformanceTier.Balanced,10,1000,200,5,900,180,11),
        }.Select(performance=>StorageTestData.Volume(performance:performance).EvidenceScope);

        foreach(var variant in byteVariants.Concat(performanceVariants))
            await Assert.That(variant).IsNotEqualTo(baseline);

        static StoragePerformance Performance(StoragePerformanceTier tier,long setting,long iops,long throughput,long latency,
            long minimumIops,long minimumThroughput,long maximumLatency) =>
            new(tier,StorageTestData.B(setting),StorageTestData.B(iops),StorageTestData.B(throughput),StorageTestData.B(latency),
                StorageTestData.B(minimumIops),StorageTestData.B(minimumThroughput),StorageTestData.B(maximumLatency));
    }

    [Test]
    public async Task Evidence_scope_rejects_every_undefined_closed_enum_before_proof_evaluation()
    {
        var volume=StorageTestData.Volume();
        var baseline=volume.EvidenceScope;
        var invalidPerformance=new StoragePerformance((StoragePerformanceTier)99,StorageTestData.B(10),StorageTestData.B(1000),
            StorageTestData.B(200),StorageTestData.B(5),StorageTestData.B(900),StorageTestData.B(180),StorageTestData.B(10));
        var invalidScopes=new[]
        {
            baseline with { FilesystemType=(StorageFilesystemType)99 },
            baseline with { Layout=(StorageLayout)99 },
            baseline with { Retention=(StorageRetention)99 },
            baseline with { Performance=invalidPerformance },
        };

        foreach(var scope in invalidScopes)
        {
            var decision=StorageExpansionPlanner.Plan(volume,StorageTestData.Context(),
                StorageTestData.Expansion(intent:StorageProof.Contradicted,scope:scope));
            await Assert.That(decision.Code).IsEqualTo(StorageDecisionCode.WrongEvidenceScope);
            await Assert.That(decision.IsMutationAuthorized).IsFalse();
        }
    }

    [Test]
    public async Task Evidence_from_other_owner_or_requested_size_is_rejected()
    {
        var otherOwner=StorageTestData.Scope() with { Member=StorageTestData.Member("other") };
        var oldRequest=StorageTestData.Scope(requested:200);
        var ownerReplay=StorageExpansionPlanner.Plan(StorageTestData.Volume(),StorageTestData.Context(),StorageTestData.Expansion(scope:otherOwner));
        var sizeReplay=StorageExpansionPlanner.Plan(StorageTestData.Volume(requested:400),StorageTestData.Context(),StorageTestData.Expansion(scope:oldRequest));
        await Assert.That(ownerReplay.Code).IsEqualTo(StorageDecisionCode.WrongEvidenceScope);
        await Assert.That(sizeReplay.Code).IsEqualTo(StorageDecisionCode.WrongEvidenceScope);
        await Assert.That(new[]{ownerReplay,sizeReplay}.Any(static x=>x.IsMutationAuthorized)).IsFalse();
    }
    [Test]
    public async Task Crash_at_every_checkpoint_resumes_at_first_unproven_step()
    {
        var cases=new (StorageVolumeRecord Volume,StorageExpansionEvidence Evidence,StorageAction Action,StorageIntentTarget Target)[]
        {
            (StorageTestData.Volume(),StorageTestData.Expansion(),StorageAction.Observe,StorageIntentTarget.None),
            (StorageTestData.Volume(),StorageTestData.Expansion(intent:StorageProof.Proven),StorageAction.Verify,StorageIntentTarget.Application),
            (StorageTestData.Volume(),StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven),StorageAction.Extend,StorageIntentTarget.ProviderVolume),
            (StorageTestData.Volume(),StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven),StorageAction.Observe,StorageIntentTarget.ProviderVolume),
            ExpansionCase(StorageTestData.Volume(provider:200),[StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven],StorageAction.Rescan,StorageIntentTarget.DeviceIdentity),
            ExpansionCase(StorageTestData.Volume(provider:200,block:200),[StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven],StorageAction.Extend,StorageIntentTarget.StorageLayout),
            ExpansionCase(StorageTestData.Volume(provider:200,block:200),[StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven],StorageAction.Grow,StorageIntentTarget.Filesystem),
            ExpansionCase(StorageTestData.Volume(provider:200,block:200,filesystem:200,used:100,free:100),[StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven],StorageAction.Verify,StorageIntentTarget.Filesystem),
            ExpansionCase(StorageTestData.Volume(provider:200,block:200,filesystem:200,used:100,free:100),[StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven],StorageAction.Verify,StorageIntentTarget.Application),
            ExpansionCase(StorageTestData.Volume(provider:200,block:200,filesystem:200,used:100,free:100),[StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven],StorageAction.Observe,StorageIntentTarget.MetricsAndCost),
            ExpansionCase(StorageTestData.Volume(provider:200,block:200,filesystem:200,used:100,free:100),[StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven],StorageAction.Verify,StorageIntentTarget.Application),
        };

        static (StorageVolumeRecord,StorageExpansionEvidence,StorageAction,StorageIntentTarget) ExpansionCase(
            StorageVolumeRecord volume,StorageProof[] proofs,StorageAction action,StorageIntentTarget target)
        {
            var values=proofs.Concat(Enumerable.Repeat(StorageProof.Unknown,11-proofs.Length)).ToArray();
            return (volume,new StorageExpansionEvidence(volume.EvidenceScope,values[0],values[1],values[2],values[3],values[4],
                values[5],values[6],values[7],values[8],values[9],values[10],StorageConflictClass.None),action,target);
        }
        foreach(var item in cases)
        {
            var first=StorageExpansionPlanner.Plan(item.Volume,StorageTestData.Context(),item.Evidence);
            var replay=StorageExpansionPlanner.Plan(item.Volume,StorageTestData.Context(),item.Evidence);
            await Assert.That(first.Action).IsEqualTo(item.Action);
            await Assert.That(first.Target).IsEqualTo(item.Target);
            await Assert.That(replay).IsEqualTo(first);
        }
        await Assert.That(cases[^1].Evidence.MetricsAndCostUpdated).IsEqualTo(StorageProof.Proven);
    }

    [Test]
    public async Task Provider_growth_observed_before_request_record_never_issues_duplicate_growth()
    {
        var volume=StorageTestData.Volume(provider:200);
        var decision=StorageExpansionPlanner.Plan(volume,StorageTestData.Context(),
            StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,volume:volume));
        await Assert.That(decision.Action).IsEqualTo(StorageAction.Verify);
        await Assert.That(decision.Target).IsEqualTo(StorageIntentTarget.ProviderVolume);
        await Assert.That(decision.Action).IsNotEqualTo(StorageAction.Extend);
    }

    [Test]
    public async Task Provider_size_alone_is_never_completion()
    {
        var volume=StorageTestData.Volume(provider:200);
        var evidence=StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,
            StorageProof.Proven,StorageProof.Proven,volume:volume);
        var decision=StorageExpansionPlanner.Plan(volume,StorageTestData.Context(),evidence);
        await Assert.That(decision.Action).IsEqualTo(StorageAction.Rescan);
        await Assert.That(decision.Code).IsNotEqualTo(StorageDecisionCode.Completed);
    }

    [Test]
    public async Task Proven_irreversible_steps_with_lagging_sizes_are_verified_not_reissued()
    {
        var rescanVolume=StorageTestData.Volume(provider:200);
        var growVolume=StorageTestData.Volume(provider:200,block:200);
        var afterRescan=StorageExpansionPlanner.Plan(rescanVolume,StorageTestData.Context(),
            StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,volume:rescanVolume));
        var afterGrow=StorageExpansionPlanner.Plan(growVolume,StorageTestData.Context(),
            StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,
                StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,volume:growVolume));
        await Assert.That(afterRescan.Action).IsEqualTo(StorageAction.Verify);
        await Assert.That(afterRescan.Action).IsNotEqualTo(StorageAction.Rescan);
        await Assert.That(afterGrow.Action).IsEqualTo(StorageAction.Verify);
        await Assert.That(afterGrow.Action).IsNotEqualTo(StorageAction.Grow);
    }

    [Test]
    public async Task Later_proof_after_unknown_checkpoint_is_conflicting_observation()
    {
        var evidence=StorageTestData.Expansion(StorageProof.Unknown,StorageProof.Proven);
        var decision=StorageExpansionPlanner.Plan(StorageTestData.Volume(),StorageTestData.Context(),evidence);
        await Assert.That(decision.Action).IsEqualTo(StorageAction.Hold);
        await Assert.That(decision.Code).IsEqualTo(StorageDecisionCode.ConflictingObservation);
    }

    [Test]
    public async Task Shrink_no_growth_size_disagreement_and_overflow_fail_closed()
    {
        var shrink=StorageExpansionPlanner.Plan(StorageTestData.Volume(requested:99),StorageTestData.Context(),StorageTestData.Expansion(scope:StorageTestData.Scope(requested:99)));
        var equal=StorageExpansionPlanner.Plan(StorageTestData.Volume(requested:100),StorageTestData.Context(),StorageTestData.Expansion(scope:StorageTestData.Scope(requested:100)));
        var disagreementVolume=StorageTestData.Volume(used:60,free:39);
        var overflowVolume=StorageTestData.Volume(filesystem:long.MaxValue-1,used:long.MaxValue,free:1,requested:long.MaxValue);
        var disagreement=StorageExpansionPlanner.Plan(disagreementVolume,StorageTestData.Context(),StorageTestData.Expansion(volume:disagreementVolume));
        var overflow=StorageExpansionPlanner.Plan(overflowVolume,StorageTestData.Context(),StorageTestData.Expansion(volume:overflowVolume));
        await Assert.That(shrink.Code).IsEqualTo(StorageDecisionCode.ShrinkForbidden);
        await Assert.That(equal.Code).IsEqualTo(StorageDecisionCode.NoGrowthRequested);
        await Assert.That(disagreement.Code).IsEqualTo(StorageDecisionCode.SizeDisagreement);
        await Assert.That(overflow.Code).IsEqualTo(StorageDecisionCode.ArithmeticOverflow);
    }

    [Test]
    public async Task Every_conflict_class_serializes_expansion()
    {
        foreach(var conflict in new[]{StorageConflictClass.BackupRestore,StorageConflictClass.Topology,
            StorageConflictClass.MemberScaling,StorageConflictClass.Upgrade,StorageConflictClass.CertificateReplacement,
            StorageConflictClass.DetachReattach,StorageConflictClass.StorageOperation})
        {
            var decision=StorageExpansionPlanner.Plan(StorageTestData.Volume(),StorageTestData.Context(),StorageTestData.Expansion(conflicts:conflict));
            await Assert.That(decision.Action).IsEqualTo(StorageAction.Hold);
            await Assert.That(decision.Code).IsEqualTo(StorageDecisionCode.ConflictingOperation);
            await Assert.That(StorageTestData.Require(decision.Trace).Conflicts).IsEqualTo(conflict);
        }
    }

    [Test]
    public async Task Contradicted_step_and_wrong_owner_fence_never_mutate()
    {
        var contradicted=StorageExpansionPlanner.Plan(StorageTestData.Volume(),StorageTestData.Context(),StorageTestData.Expansion(intent:StorageProof.Contradicted));
        var wrongOwner=StorageExpansionPlanner.Plan(StorageTestData.Volume(),StorageTestData.Context(member:StorageTestData.Member("other")),StorageTestData.Expansion());
        var staleEpoch=StorageExpansionPlanner.Plan(StorageTestData.Volume(),StorageTestData.Context(epoch:StorageTestData.Epoch(6)),StorageTestData.Expansion());
        await Assert.That(contradicted.Code).IsEqualTo(StorageDecisionCode.StepContradicted);
        await Assert.That(wrongOwner.Code).IsEqualTo(StorageDecisionCode.WrongOwner);
        await Assert.That(staleEpoch.Code).IsEqualTo(StorageDecisionCode.StaleWriterEpoch);
        await Assert.That(new[]{contradicted,wrongOwner,staleEpoch}.Any(static decision=>decision.IsMutationAuthorized)).IsFalse();
    }
}

