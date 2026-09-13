using TerraScale.Orchestrator.ControlPlane.TerraBase;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class TerraBaseSecondAuditRegressionTests
{
    [Test]
    public async Task Every_entrypoint_rejects_all_ten_malformed_expected_scope_dimensions()
    {
        var valid = TerraBaseTestData.Scope();
        var invalidScopes = new[]
        {
            valid with { Region = null! },
            valid with { Database = null! },
            valid with { Member = null! },
            valid with { Node = null! },
            valid with { RetainedVolume = null! },
            valid with { Fence = null! },
            valid with { DatabaseGeneration = default },
            valid with { TopologyGeneration = default },
            valid with { AuthorityEpoch = default },
            valid with { Operation = null! },
        };

        foreach (var scope in invalidScopes)
        {
            foreach (var decision in Decisions(scope, scope))
            {
                await Assert.That(decision.Action).IsEqualTo(TerraBaseAction.Hold);
                await Assert.That(decision.Code).IsEqualTo(TerraBaseCode.InvalidInput);
                await Assert.That(decision.Trace).IsNull();
                await Assert.That(decision.Subject).IsNull();
            }
        }
    }

    [Test]
    public async Task Invalid_expected_release_and_restore_parameters_precede_evidence_matching()
    {
        var scope = TerraBaseTestData.Scope();
        var current = TerraBaseTestData.Release("current");
        var target = TerraBaseTestData.Release("target");
        var invalidUpgrade = TerraBaseUpgradePlanner.Plan(scope, null!, target,
            new(scope, null!, target, TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne,
                TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven,
                TerraBaseProof.Proven, TerraBaseProof.Unknown, TerraBaseProof.Unknown,
                TerraBaseProof.Unknown, TerraBaseProof.Unknown, TerraBaseProof.Unknown,
                TerraBaseProof.Unknown));
        var sameRelease = TerraBaseUpgradePlanner.Plan(scope, current, current,
            new(scope, current, current, TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne,
                TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven,
                TerraBaseProof.Proven, TerraBaseProof.Unknown, TerraBaseProof.Unknown,
                TerraBaseProof.Unknown, TerraBaseProof.Unknown, TerraBaseProof.Unknown,
                TerraBaseProof.Unknown));
        var chain = TerraBaseTestData.Chain(scope);
        var nullRestore = TerraBaseRestorePlanner.Plan(scope, null!, TerraBaseTestData.Backup("b2"),
            TerraBaseTestData.O(5), new(scope, null!, TerraBaseTestData.O(4), TerraBaseTestData.O(5),
                chain, TerraBaseProof.Proven, TerraBaseProof.Unknown, TerraBaseProof.Unknown,
                TerraBaseProof.Unknown, TerraBaseProof.Unknown));
        var invalidTarget = TerraBaseRestorePlanner.Plan(scope, TerraBaseTestData.Restore(),
            TerraBaseTestData.Backup("b2"), default, new(scope, TerraBaseTestData.Restore(),
                TerraBaseTestData.O(4), default, chain, TerraBaseProof.Proven, TerraBaseProof.Unknown,
                TerraBaseProof.Unknown, TerraBaseProof.Unknown, TerraBaseProof.Unknown));

        foreach (var decision in new[] { invalidUpgrade, sameRelease, nullRestore, invalidTarget })
        {
            await Assert.That(decision.Code).IsEqualTo(TerraBaseCode.InvalidInput);
            await Assert.That(decision.Trace).IsNull();
            await Assert.That(decision.Subject).IsNull();
        }

        var restore = TerraBaseTestData.Restore();
        var mismatchedEvidence = TerraBaseRestorePlanner.Plan(scope, restore,
            TerraBaseTestData.Backup("b2"), TerraBaseTestData.O(5),
            new(scope, null!, TerraBaseTestData.O(4), TerraBaseTestData.O(5), chain,
                TerraBaseProof.Proven, TerraBaseProof.Unknown, TerraBaseProof.Unknown,
                TerraBaseProof.Unknown, TerraBaseProof.Unknown));
        await Assert.That(mismatchedEvidence.Code).IsEqualTo(TerraBaseCode.WrongEvidenceScope);
        await Assert.That(mismatchedEvidence.Trace!.Scope).IsEqualTo(scope);
        await Assert.That(mismatchedEvidence.Subject).IsNull();
    }

    [Test]
    public async Task Runtime_null_expected_is_invalid_without_throwing_at_all_seven_entrypoints()
    {
        var scope = TerraBaseTestData.Scope();
        var topology = TerraBaseTestData.Topology(scope: scope);
        var current = TerraBaseTestData.Release("current");
        var target = TerraBaseTestData.Release("target");
        var chain = TerraBaseTestData.Chain(scope);
        var restoreId = TerraBaseTestData.Restore();
        var restoreTarget = TerraBaseTestData.O(5);
        var calls = new Func<TerraBaseDecision>[]
        {
            () => TerraBaseTopologyPlanner.PlanAdd(null, topology),
            () => TerraBaseTopologyPlanner.PlanRemove(null, topology),
            () => TerraBaseRetainedVolumePlanner.Plan(null!, new(scope, [], TerraBaseProof.Proven,
                TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven,
                TerraBaseTestData.O(4), 8)),
            () => TerraBaseUpgradePlanner.Plan(null!, current, target, new(scope, current, target,
                TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne, TerraBaseProof.Proven,
                TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven,
                TerraBaseProof.Unknown, TerraBaseProof.Unknown, TerraBaseProof.Unknown,
                TerraBaseProof.Unknown, TerraBaseProof.Unknown, TerraBaseProof.Unknown)),
            () => TerraBaseBackupPlanner.Authorize(null!, new(scope, TerraBaseTestData.Backup(),
                TerraBaseTestData.O(1), null, null, null, true, TerraBaseTestData.Object(),
                TerraBaseTestData.Key(), TerraBaseProof.Proven, TerraBaseProof.Proven)),
            () => TerraBaseBackupPlanner.Accept(null!, chain),
            () => TerraBaseRestorePlanner.Plan(null!, restoreId, TerraBaseTestData.Backup("b2"),
                restoreTarget, new(scope, restoreId, TerraBaseTestData.O(4), restoreTarget, chain,
                    TerraBaseProof.Proven, TerraBaseProof.Unknown, TerraBaseProof.Unknown,
                    TerraBaseProof.Unknown, TerraBaseProof.Unknown)),
        };

        foreach (var call in calls)
        {
            TerraBaseDecision? decision = null;
            Exception? error = null;
            try { decision = call(); }
            catch (Exception exception) { error = exception; }

            await Assert.That(error).IsNull();
            await Assert.That(decision!.Value.Code).IsEqualTo(TerraBaseCode.InvalidInput);
            await Assert.That(decision.Value.Trace).IsNull();
            await Assert.That(decision.Value.Subject).IsNull();
        }
    }

    [Test]
    public async Task Removal_requires_safe_replication_and_a_valid_position_before_any_mutation()
    {
        var scope = TerraBaseTestData.Scope();
        var baseline = TerraBaseTestData.Topology(scope: scope, topologyApplied: TerraBaseProof.Unknown);
        var unsafeEvidence = new[]
        {
            baseline with { Replication = TerraBaseReplication.Unknown },
            baseline with { Replication = TerraBaseReplication.Lagging },
            baseline with { Replication = TerraBaseReplication.Conflicting },
            baseline with { Replication = TerraBaseReplication.Future },
            baseline with { ReplicationPosition = default },
        };

        foreach (var evidence in unsafeEvidence)
        {
            var decision = TerraBaseTopologyPlanner.PlanRemove(scope, evidence);
            await Assert.That(decision.IsMutationAuthorized).IsFalse();
            await Assert.That(decision.Subject).IsNull();
        }

        var addWithInvalidPosition = TerraBaseTopologyPlanner.PlanAdd(scope,
            TerraBaseTestData.Topology(scope: scope, topologyApplied: TerraBaseProof.Unknown,
                replication: TerraBaseReplication.Unknown) with
            {
                PostChangeReplication = TerraBaseProof.Unknown,
                ReplicationPosition = default,
            });
        await Assert.That(addWithInvalidPosition.IsMutationAuthorized).IsFalse();
        await Assert.That(addWithInvalidPosition.Subject).IsNull();
    }

    [Test]
    public async Task Future_observations_cannot_authorize_an_earlier_mutation_checkpoint()
    {
        var scope = TerraBaseTestData.Scope();
        var topology = TerraBaseTopologyPlanner.PlanAdd(scope,
            TerraBaseTestData.Topology(scope: scope, topologyApplied: TerraBaseProof.Unknown) with
            {
                PostChangeReplication = TerraBaseProof.Proven,
            });

        var current = TerraBaseTestData.Release("current");
        var target = TerraBaseTestData.Release("target");
        var upgrade = TerraBaseUpgradePlanner.Plan(scope, current, target,
            new(scope, current, target, TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne,
                TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven,
                TerraBaseProof.Proven, TerraBaseProof.Unknown, TerraBaseProof.Proven,
                TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Unknown,
                TerraBaseProof.Unknown));

        var restoreId = TerraBaseTestData.Restore();
        var restoreTarget = TerraBaseTestData.O(scope.DatabaseGeneration.Value + 1);
        var restore = TerraBaseRestorePlanner.Plan(scope, restoreId, TerraBaseTestData.Backup("b2"),
            restoreTarget, new(scope, restoreId, scope.DatabaseGeneration, restoreTarget,
                TerraBaseTestData.Chain(scope), TerraBaseProof.Proven, TerraBaseProof.Unknown,
                TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Unknown));

        await Assert.That(topology.IsMutationAuthorized).IsFalse();
        await Assert.That(upgrade.IsMutationAuthorized).IsFalse();
        await Assert.That(restore.IsMutationAuthorized).IsFalse();
    }

    private static TerraBaseDecision[] Decisions(TerraBaseEvidenceScope? expected, TerraBaseEvidenceScope scope)
    {
        var topology = TerraBaseTestData.Topology(scope: scope);
        var writer = new TerraBaseWriterEvidence(scope, [], TerraBaseProof.Proven, TerraBaseProof.Proven,
            TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseTestData.O(4), 8);
        var current = TerraBaseTestData.Release("current");
        var target = TerraBaseTestData.Release("target");
        var upgrade = new TerraBaseUpgradeEvidence(scope, current, target,
            TerraBaseUpgradeCompatibility.CompatibleNAndNMinusOne, TerraBaseProof.Proven,
            TerraBaseProof.Proven, TerraBaseProof.Proven, TerraBaseProof.Proven,
            TerraBaseProof.Unknown, TerraBaseProof.Unknown, TerraBaseProof.Unknown,
            TerraBaseProof.Unknown, TerraBaseProof.Unknown, TerraBaseProof.Unknown);
        var backup = new TerraBaseBackupRequestEvidence(scope, TerraBaseTestData.Backup(),
            TerraBaseTestData.O(1), null, null, null, true, TerraBaseTestData.Object(),
            TerraBaseTestData.Key(), TerraBaseProof.Proven, TerraBaseProof.Proven);
        var chain = TerraBaseTestData.Chain(scope);
        var restoreId = TerraBaseTestData.Restore();
        var restoreTarget = TerraBaseTestData.O(5);
        var restore = new TerraBaseRestoreEvidence(scope, restoreId, TerraBaseTestData.O(4),
            restoreTarget, chain, TerraBaseProof.Proven, TerraBaseProof.Unknown,
            TerraBaseProof.Unknown, TerraBaseProof.Unknown, TerraBaseProof.Unknown);
        return
        [
            TerraBaseTopologyPlanner.PlanAdd(expected, topology),
            TerraBaseTopologyPlanner.PlanRemove(expected, topology),
            TerraBaseRetainedVolumePlanner.Plan(expected, writer),
            TerraBaseUpgradePlanner.Plan(expected, current, target, upgrade),
            TerraBaseBackupPlanner.Authorize(expected, backup),
            TerraBaseBackupPlanner.Accept(expected, chain),
            TerraBaseRestorePlanner.Plan(expected, restoreId, TerraBaseTestData.Backup("b2"),
                restoreTarget, restore),
        ];
    }
}

