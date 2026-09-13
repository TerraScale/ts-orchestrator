using TerraScale.Orchestrator.ControlPlane.Storage;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class StorageDeletionTests
{
    [Test]
    public async Task Delete_intent_distinguishes_retention_policy_and_verified_backup()
    {
        var elasticVolume=StorageTestData.Volume(retention:StorageRetention.ElasticQuarantine);
        var disposableVolume=StorageTestData.Volume(retention:StorageRetention.ExplicitDisposable);
        var elastic=StorageDeletionPlanner.Plan(elasticVolume,StorageTestData.Context(),
            StorageTestData.Deletion(scope:elasticVolume.EvidenceScope));
        var disposable=StorageDeletionPlanner.Plan(disposableVolume,StorageTestData.Context(),
            StorageTestData.Deletion(scope:disposableVolume.EvidenceScope));

        await Assert.That(elastic.Action).IsEqualTo(StorageAction.Delete);
        await Assert.That(disposable.Action).IsEqualTo(StorageAction.Delete);
        await Assert.That(elastic).IsNotEqualTo(disposable);
        await Assert.That(StorageTestData.Require(elastic.Scope).Retention).IsEqualTo(StorageRetention.ElasticQuarantine);
        await Assert.That(StorageTestData.Require(disposable.Scope).Retention).IsEqualTo(StorageRetention.ExplicitDisposable);

        var backupA=StorageTestData.Backup("verified-backup-a");
        var backupB=StorageTestData.Backup("verified-backup-b");
        var volumeA=StorageTestData.Volume(backup:backupA);
        var volumeB=StorageTestData.Volume(backup:backupB);
        var decisionA=StorageDeletionPlanner.Plan(volumeA,StorageTestData.Context(),
            StorageTestData.Deletion(scope:volumeA.EvidenceScope));
        var decisionB=StorageDeletionPlanner.Plan(volumeB,StorageTestData.Context(),
            StorageTestData.Deletion(scope:volumeB.EvidenceScope));

        await Assert.That(decisionA).IsNotEqualTo(decisionB);
        await Assert.That(ReferenceEquals(StorageTestData.Require(decisionA.Scope).Backup,backupA)).IsTrue();
        await Assert.That(ReferenceEquals(StorageTestData.Require(decisionB.Scope).Backup,backupB)).IsTrue();
        await Assert.That(decisionA.ToString()).DoesNotContain(backupA.Value);
        await Assert.That(decisionB.ToString()).DoesNotContain(backupB.Value);
    }

    [Test]
    public async Task Permanent_volume_deletion_is_never_representable()
    {
        var decision=StorageDeletionPlanner.Plan(StorageTestData.Volume(retention:StorageRetention.Permanent),
            StorageTestData.Context(),StorageTestData.Deletion());
        await Assert.That(decision.Action).IsEqualTo(StorageAction.Hold);
        await Assert.That(decision.Code).IsEqualTo(StorageDecisionCode.PermanentRetention);
        await Assert.That(decision.IsMutationAuthorized).IsFalse();
    }

    [Test]
    public async Task Every_common_deletion_proof_is_mandatory()
    {
        var cases=new[]
        {
            StorageTestData.Deletion(leadership:StorageProof.Unknown),
            StorageTestData.Deletion(topology:StorageProof.Unknown),
            StorageTestData.Deletion(quorum:StorageProof.Unknown),
            StorageTestData.Deletion(noReference:StorageProof.Unknown),
            StorageTestData.Deletion(backup:StorageProof.Unknown),
            StorageTestData.Deletion(retention:StorageProof.Unknown),
            StorageTestData.Deletion(ownerFence:StorageProof.Unknown),
            StorageTestData.Deletion(auditReady:StorageProof.Unknown),
        };
        foreach(var evidence in cases)
        {
            var decision=StorageDeletionPlanner.Plan(StorageTestData.Volume(),StorageTestData.Context(),evidence);
            await Assert.That(decision.Action).IsEqualTo(StorageAction.Hold);
            await Assert.That(decision.Code).IsEqualTo(StorageDecisionCode.DeletionProofMissing);
        }
    }

    [Test]
    public async Task Elastic_requires_quarantine_and_disposable_requires_explicit_policy()
    {
        var elastic=StorageDeletionPlanner.Plan(StorageTestData.Volume(retention:StorageRetention.ElasticQuarantine),
            StorageTestData.Context(),StorageTestData.Deletion(quarantine:StorageProof.Unknown));
        var disposable=StorageDeletionPlanner.Plan(StorageTestData.Volume(retention:StorageRetention.ExplicitDisposable),
            StorageTestData.Context(),StorageTestData.Deletion(disposable:StorageProof.Unknown,scopeRetention:StorageRetention.ExplicitDisposable));
        await Assert.That(elastic.Code).IsEqualTo(StorageDecisionCode.QuarantineProofMissing);
        await Assert.That(disposable.Code).IsEqualTo(StorageDecisionCode.DisposableProofMissing);
    }

    [Test]
    public async Task Complete_preconditions_emit_exact_delete_intent_and_replay_is_deterministic()
    {
        var evidence=StorageTestData.Deletion();
        var first=StorageDeletionPlanner.Plan(StorageTestData.Volume(),StorageTestData.Context(),evidence);
        var replay=StorageDeletionPlanner.Plan(StorageTestData.Volume(),StorageTestData.Context(),evidence);
        var firstScope = StorageTestData.Require(first.Scope);
        await Assert.That(first.Action).IsEqualTo(StorageAction.Delete);
        await Assert.That(first.Target).IsEqualTo(StorageIntentTarget.ProviderVolume);
        await Assert.That(firstScope.ProviderVolume).IsEqualTo(StorageTestData.Provider());
        await Assert.That(firstScope.Operation).IsEqualTo(StorageTestData.Operation());
        await Assert.That(firstScope.Fence).IsEqualTo(StorageTestData.Fence());
        await Assert.That(firstScope.ToString()).DoesNotContain("provider-volume-a");
        await Assert.That(first).IsEqualTo(replay);
    }

    [Test]
    public async Task Audit_readiness_cannot_masquerade_as_post_delete_completion()
    {
        var readinessOnly=StorageDeletionPlanner.Plan(StorageTestData.Volume(),StorageTestData.Context(),
            StorageTestData.Deletion(requested:StorageProof.Proven,absent:StorageProof.Proven,auditPassed:StorageProof.Unknown));
        var completed=StorageDeletionPlanner.Plan(StorageTestData.Volume(),StorageTestData.Context(),
            StorageTestData.Deletion(requested:StorageProof.Proven,absent:StorageProof.Proven,auditPassed:StorageProof.Proven));
        await Assert.That(readinessOnly.Action).IsEqualTo(StorageAction.Observe);
        await Assert.That(readinessOnly.Target).IsEqualTo(StorageIntentTarget.PostDeleteAudit);
        await Assert.That(readinessOnly.Code).IsEqualTo(StorageDecisionCode.PostDeleteAuditRequired);
        await Assert.That(completed.Action).IsEqualTo(StorageAction.Verify);
        await Assert.That(completed.Code).IsEqualTo(StorageDecisionCode.Completed);
    }

    [Test]
    public async Task Deletion_replay_observes_provider_convergence_without_duplicate_delete()
    {
        var decision=StorageDeletionPlanner.Plan(StorageTestData.Volume(),StorageTestData.Context(),
            StorageTestData.Deletion(requested:StorageProof.Proven));
        await Assert.That(decision.Action).IsEqualTo(StorageAction.Observe);
        await Assert.That(decision.Code).IsEqualTo(StorageDecisionCode.ProviderConvergencePending);
        await Assert.That(decision.Action).IsNotEqualTo(StorageAction.Delete);
    }

    [Test]
    public async Task Wrong_owner_fence_generation_and_epoch_block_deletion()
    {
        var decisions=new[]
        {
            StorageDeletionPlanner.Plan(StorageTestData.Volume(),StorageTestData.Context(claim:StorageTestData.Claim("other")),StorageTestData.Deletion()),
            StorageDeletionPlanner.Plan(StorageTestData.Volume(),StorageTestData.Context(fence:StorageTestData.Fence("other")),StorageTestData.Deletion()),
            StorageDeletionPlanner.Plan(StorageTestData.Volume(),StorageTestData.Context(generation:StorageTestData.Generation(3)),StorageTestData.Deletion()),
            StorageDeletionPlanner.Plan(StorageTestData.Volume(),StorageTestData.Context(epoch:StorageTestData.Epoch(6)),StorageTestData.Deletion()),
        };
        await Assert.That(decisions.Select(static d=>d.Code).ToArray()).IsEquivalentTo(new[]{
            StorageDecisionCode.WrongOwner,StorageDecisionCode.WrongFence,StorageDecisionCode.StaleGeneration,StorageDecisionCode.StaleWriterEpoch});
        await Assert.That(decisions.Any(static d=>d.IsMutationAuthorized)).IsFalse();
    }

    [Test]
    public async Task Otherwise_complete_deletion_evidence_cannot_replay_across_operation_fence_or_generation()
    {
        var scopes=new[]
        {
            StorageTestData.Scope(operation:StorageTestData.Operation("other")),
            StorageTestData.Scope(fence:StorageTestData.Fence("other")),
            StorageTestData.Scope(generation:StorageTestData.Generation(9)),
        };
        foreach(var scope in scopes)
        {
            var evidence=StorageTestData.Deletion(requested:StorageProof.Proven,absent:StorageProof.Proven,
                auditPassed:StorageProof.Proven,scope:scope);
            var decision=StorageDeletionPlanner.Plan(StorageTestData.Volume(),StorageTestData.Context(),evidence);
            await Assert.That(decision.Code).IsEqualTo(StorageDecisionCode.WrongEvidenceScope);
            await Assert.That(decision.IsMutationAuthorized).IsFalse();
        }
    }
}

