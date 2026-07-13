using TerraScale.Orchestrator.ControlPlane.Storage;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class StorageExpansionTests
{
    [Test]
    public async Task Crash_at_every_checkpoint_resumes_at_first_unproven_step()
    {
        var cases=new (StorageVolumeRecord Volume,StorageExpansionEvidence Evidence,StorageAction Action,StorageIntentTarget Target)[]
        {
            (StorageTestData.Volume(),StorageTestData.Expansion(),StorageAction.Observe,StorageIntentTarget.None),
            (StorageTestData.Volume(),StorageTestData.Expansion(intent:StorageProof.Proven),StorageAction.Verify,StorageIntentTarget.Application),
            (StorageTestData.Volume(),StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven),StorageAction.Extend,StorageIntentTarget.ProviderVolume),
            (StorageTestData.Volume(),StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven),StorageAction.Observe,StorageIntentTarget.ProviderVolume),
            (StorageTestData.Volume(provider:200),StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven),StorageAction.Rescan,StorageIntentTarget.DeviceIdentity),
            (StorageTestData.Volume(provider:200,block:200),StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven),StorageAction.Extend,StorageIntentTarget.StorageLayout),
            (StorageTestData.Volume(provider:200,block:200),StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven),StorageAction.Grow,StorageIntentTarget.Filesystem),
            (StorageTestData.Volume(provider:200,block:200,filesystem:200,used:100,free:100),StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven),StorageAction.Verify,StorageIntentTarget.Filesystem),
            (StorageTestData.Volume(provider:200,block:200,filesystem:200,used:100,free:100),StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven),StorageAction.Verify,StorageIntentTarget.Application),
            (StorageTestData.Volume(provider:200,block:200,filesystem:200,used:100,free:100),StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven),StorageAction.Observe,StorageIntentTarget.MetricsAndCost),
            (StorageTestData.Volume(provider:200,block:200,filesystem:200,used:100,free:100),StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven),StorageAction.Verify,StorageIntentTarget.Application),
        };
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
        var decision=StorageExpansionPlanner.Plan(StorageTestData.Volume(provider:200),StorageTestData.Context(),
            StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven));
        await Assert.That(decision.Action).IsEqualTo(StorageAction.Verify);
        await Assert.That(decision.Target).IsEqualTo(StorageIntentTarget.ProviderVolume);
        await Assert.That(decision.Action).IsNotEqualTo(StorageAction.Extend);
    }

    [Test]
    public async Task Provider_size_alone_is_never_completion()
    {
        var evidence=StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,
            StorageProof.Proven,StorageProof.Proven);
        var decision=StorageExpansionPlanner.Plan(StorageTestData.Volume(provider:200),StorageTestData.Context(),evidence);
        await Assert.That(decision.Action).IsEqualTo(StorageAction.Rescan);
        await Assert.That(decision.Code).IsNotEqualTo(StorageDecisionCode.Completed);
    }

    [Test]
    public async Task Proven_irreversible_steps_with_lagging_sizes_are_verified_not_reissued()
    {
        var afterRescan=StorageExpansionPlanner.Plan(StorageTestData.Volume(provider:200),StorageTestData.Context(),
            StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven));
        var afterGrow=StorageExpansionPlanner.Plan(StorageTestData.Volume(provider:200,block:200),StorageTestData.Context(),
            StorageTestData.Expansion(StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,StorageProof.Proven,
                StorageProof.Proven,StorageProof.Proven,StorageProof.Proven));
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
        var shrink=StorageExpansionPlanner.Plan(StorageTestData.Volume(requested:99),StorageTestData.Context(),StorageTestData.Expansion());
        var equal=StorageExpansionPlanner.Plan(StorageTestData.Volume(requested:100),StorageTestData.Context(),StorageTestData.Expansion());
        var disagreement=StorageExpansionPlanner.Plan(StorageTestData.Volume(used:60,free:39),StorageTestData.Context(),StorageTestData.Expansion());
        var overflow=StorageExpansionPlanner.Plan(StorageTestData.Volume(filesystem:long.MaxValue-1,used:long.MaxValue,free:1,requested:long.MaxValue),StorageTestData.Context(),StorageTestData.Expansion());
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
            await Assert.That(decision.Trace!.Conflicts).IsEqualTo(conflict);
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
