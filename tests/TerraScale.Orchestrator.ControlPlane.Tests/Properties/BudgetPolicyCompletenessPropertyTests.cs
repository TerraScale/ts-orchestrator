using TerraScale.Orchestrator.ControlPlane.Budgets;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class BudgetPolicyCompletenessPropertyTests
{
    private const int Cases = 1_000;

    [Test]
    public async Task Safety_purpose_inventory_is_closed_and_unspecified_fails_before_evidence()
    {
        var values = Enum.GetValues<BudgetSafetyPurpose>();
        await Assert.That(values).Count().IsEqualTo(4);
        await Assert.That(values).IsEquivalentTo(new[]
        {
            BudgetSafetyPurpose.Unspecified,
            BudgetSafetyPurpose.OrdinaryCapacity,
            BudgetSafetyPurpose.AvailabilityRepair,
            BudgetSafetyPurpose.DataLossPreventionStorageExpansion,
        });
        await Assert.That(values.Select(static value => (int)value)).IsEquivalentTo(new[] { 0, 1, 2, 3 });
        await Assert.That(Enum.GetNames<BudgetSafetyPurpose>()).IsEquivalentTo(new[]
        {
            nameof(BudgetSafetyPurpose.Unspecified),
            nameof(BudgetSafetyPurpose.OrdinaryCapacity),
            nameof(BudgetSafetyPurpose.AvailabilityRepair),
            nameof(BudgetSafetyPurpose.DataLossPreventionStorageExpansion),
        });

        var decision = BudgetAuthorizationEngine.Evaluate(
            BudgetTestData.Policy(), BudgetTestData.Proposal(purpose: BudgetSafetyPurpose.Unspecified), null, null, null);

        await AssertHeldBeforeEvidence(decision, BudgetDecisionReason.MalformedProposal);
    }

    [Test]
    public async Task Undefined_safety_purposes_fail_closed_for_1000_cases()
    {
        for (var seed = 0; seed < Cases; seed++)
        {
            var undefined = (BudgetSafetyPurpose)(seed % 2 == 0 ? 4 + seed : -1 - seed);
            var decision = BudgetTestData.Evaluate(
                proposal: BudgetTestData.Proposal(purpose: undefined));

            await Assert.That(Enum.IsDefined(undefined)).IsFalse();
            await AssertHeldBeforeEvidence(decision, BudgetDecisionReason.MalformedProposal);
        }
    }

    [Test]
    public async Task Every_defined_safety_purpose_has_exact_normal_and_emergency_semantics_for_1000_cases()
    {
        for (var seed = 0; seed < Cases; seed++)
        {
            var purpose = (BudgetSafetyPurpose)(1 + seed % 3);
            var emergency = (seed & 1) != 0;
            var delta = purpose == BudgetSafetyPurpose.DataLossPreventionStorageExpansion
                ? BudgetTestData.VectorAt(2, 1)
                : BudgetTestData.VectorAt(seed % 9, 1);
            var decision = BudgetTestData.Evaluate(
                policy: BudgetTestData.Policy(emergency
                    ? BudgetEmergencyPosture.Emergency
                    : BudgetEmergencyPosture.Normal),
                proposal: BudgetTestData.Proposal(delta: delta, purpose: purpose, nodeCount: 0));
            var expectedKind = emergency && purpose == BudgetSafetyPurpose.OrdinaryCapacity
                ? BudgetDecisionKind.Forbidden
                : BudgetDecisionKind.Automatic;
            var expectedReason = (emergency, purpose) switch
            {
                (true, BudgetSafetyPurpose.OrdinaryCapacity) => BudgetDecisionReason.EmergencyNonSafetyGrowth,
                (true, BudgetSafetyPurpose.DataLossPreventionStorageExpansion) => BudgetDecisionReason.EmergencyDataLossPrevention,
                _ => BudgetDecisionReason.WithinAutomaticBand,
            };

            await Assert.That(decision.Kind).IsEqualTo(expectedKind);
            await Assert.That(decision.Reason).IsEqualTo(expectedReason);
            await Assert.That(decision.IsAuthorized).IsEqualTo(expectedKind == BudgetDecisionKind.Automatic);
            await Assert.That(decision.Trace).IsNotNull();
            await Assert.That(decision.ApprovalScope).IsNull();
            await Assert.That(decision.Trace!.Delta).IsEqualTo(delta);
            await Assert.That(decision.Trace.BindingDimensions).IsEqualTo(BudgetDimension.None);
        }
    }

    [Test]
    public async Task Every_dimension_obeys_hard_limit_budget_band_and_approval_precedence()
    {
        var zero = BudgetTestData.Vector(0);
        for (var dimension = 0; dimension < 9; dimension++)
        {
            foreach (var expected in new[]
            {
                (Value: 41L, Kind: BudgetDecisionKind.Forbidden, Reason: BudgetDecisionReason.ProviderAccountLimitExceeded),
                (Value: 31L, Kind: BudgetDecisionKind.Forbidden, Reason: BudgetDecisionReason.BudgetCeilingExceeded),
                (Value: 21L, Kind: BudgetDecisionKind.Forbidden, Reason: BudgetDecisionReason.ForbiddenBand),
                (Value: 11L, Kind: BudgetDecisionKind.ApprovalRequired, Reason: BudgetDecisionReason.ApprovalBand),
                (Value: 10L, Kind: BudgetDecisionKind.Automatic, Reason: BudgetDecisionReason.WithinAutomaticBand),
            })
            {
                var delta = BudgetTestData.VectorAt(dimension, expected.Value);
                var decision = BudgetTestData.Evaluate(
                    policy: BudgetTestData.Policy(
                        automatic: BudgetTestData.Vector(10), approval: BudgetTestData.Vector(20),
                        ceiling: BudgetTestData.Vector(30), provider: BudgetTestData.Vector(40)),
                    proposal: BudgetTestData.Proposal(delta: delta, nodeCount: 0),
                    usage: [BudgetTestData.CellUsage(zero), BudgetTestData.GlobalUsage(zero)]);
                var binding = expected.Kind == BudgetDecisionKind.Automatic
                    ? BudgetDimension.None
                    : (BudgetDimension)(1 << dimension);

                await Assert.That(decision.Kind).IsEqualTo(expected.Kind);
                await Assert.That(decision.Reason).IsEqualTo(expected.Reason);
                await Assert.That(decision.IsAuthorized).IsEqualTo(expected.Kind == BudgetDecisionKind.Automatic);
                await Assert.That(decision.Trace).IsNotNull();
                await Assert.That(decision.Trace!.CurrentCell).IsEqualTo(zero);
                await Assert.That(decision.Trace.ProjectedCell).IsEqualTo(delta);
                await Assert.That(decision.Trace.CurrentGlobal).IsEqualTo(zero);
                await Assert.That(decision.Trace.ProjectedGlobal).IsEqualTo(delta);
                await Assert.That(decision.Trace.Delta).IsEqualTo(delta);
                await Assert.That(decision.Trace.BindingDimensions).IsEqualTo(binding);
                await Assert.That(decision.Trace.CurrentNodeCount).IsEqualTo(3);
                await Assert.That(decision.Trace.ProjectedNodeCount).IsEqualTo(3);
                await Assert.That(decision.Trace.MinimumNodeCount).IsEqualTo(1);
                await Assert.That(decision.Trace.WarmNodeCount).IsEqualTo(2);
                await Assert.That(decision.Trace.MaximumNodeCount).IsEqualTo(5);
                await Assert.That(decision.Trace.MaximumEvidenceAge).IsEqualTo(BudgetTestData.Q(100));
                await Assert.That(decision.Trace.CellEvidenceAge).IsEqualTo(BudgetTestData.Q(1));
                await Assert.That(decision.Trace.GlobalEvidenceAge).IsEqualTo(BudgetTestData.Q(1));
                await Assert.That(decision.Trace.NodeEvidenceAge).IsEqualTo(BudgetTestData.Q(1));
                await Assert.That(decision.Trace.PriceEvidenceAge).IsEqualTo(BudgetTestData.Q(1));
                await Assert.That(decision.ApprovalScope is not null)
                    .IsEqualTo(expected.Kind == BudgetDecisionKind.ApprovalRequired);
                if (decision.ApprovalScope is not null)
                {
                    await Assert.That(decision.ApprovalScope.ApprovalId).IsEqualTo(BudgetTestData.Approval());
                    await Assert.That(decision.ApprovalScope.Cell).IsEqualTo(BudgetTestData.Cell());
                    await Assert.That(decision.ApprovalScope.CostCenter).IsEqualTo(BudgetTestData.CostCenter());
                    await Assert.That(decision.ApprovalScope.NodeClass).IsEqualTo(BudgetTestData.NodeClass());
                    await Assert.That(decision.ApprovalScope.Resource).IsEqualTo(BudgetTestData.Resource());
                    await Assert.That(decision.ApprovalScope.Purpose).IsEqualTo(BudgetSafetyPurpose.OrdinaryCapacity);
                }
            }
        }
    }

    [Test]
    public async Task Undefined_evidence_enums_fail_closed_with_exact_reason_for_1000_cases()
    {
        for (var seed = 0; seed < Cases; seed++)
        {
            var undefinedStatus = (BudgetEvidenceStatus)(seed % 2 == 0 ? 3 + seed : -1 - seed);
            var undefinedScope = (BudgetUsageScope)(seed % 2 == 0 ? 3 + seed : -1 - seed);
            var undefinedAttachment = (BudgetResourceAttachment)(seed % 2 == 0 ? 4 + seed : -1 - seed);
            var statusDecision = (seed % 3) switch
            {
                0 => BudgetTestData.Evaluate(usage:
                    [BudgetTestData.CellUsage(status: undefinedStatus), BudgetTestData.GlobalUsage()]),
                1 => BudgetTestData.Evaluate(nodes: [BudgetTestData.NodeUsage(status: undefinedStatus)]),
                _ => BudgetTestData.Evaluate(prices: [BudgetTestData.Price(undefinedStatus)]),
            };
            var scopeDecision = BudgetTestData.Evaluate(usage:
            [
                new BudgetUsageObservation(undefinedScope, BudgetTestData.Cell(), BudgetTestData.CostCenter(),
                    BudgetTestData.Evidence(), BudgetEvidenceStatus.Current, BudgetTestData.Q(1), BudgetTestData.Vector(10)),
                BudgetTestData.GlobalUsage(),
            ]);
            var anomaly = BudgetAnomalyDetector.Detect(
                BudgetTestData.Cell(), BudgetTestData.CostCenter(), 10, BudgetTestData.Q(100), true,
                [new BudgetResourceObservation(BudgetTestData.Resource(), BudgetTestData.Cell(), BudgetTestData.CostCenter(),
                    BudgetTestData.Evidence(), BudgetEvidenceStatus.Current, BudgetTestData.Q(1),
                    true, true, true, undefinedAttachment)]);

            await Assert.That(Enum.IsDefined(undefinedStatus)).IsFalse();
            await Assert.That(Enum.IsDefined(undefinedScope)).IsFalse();
            await Assert.That(Enum.IsDefined(undefinedAttachment)).IsFalse();
            await AssertHeldBeforeEvidence(statusDecision, BudgetDecisionReason.UnknownEvidence);
            await AssertHeldBeforeEvidence(scopeDecision, BudgetDecisionReason.WrongScope);
            await Assert.That(anomaly.Error).IsEqualTo(BudgetAnomalyError.ConflictingEvidence);
            await Assert.That(anomaly.IsComplete).IsFalse();
            await Assert.That(anomaly.Findings).IsEmpty();
        }
    }

    private static async Task AssertHeldBeforeEvidence(BudgetDecision decision, BudgetDecisionReason reason)
    {
        await Assert.That(decision.Kind).IsEqualTo(BudgetDecisionKind.Held);
        await Assert.That(decision.Reason).IsEqualTo(reason);
        await Assert.That(decision.IsAuthorized).IsFalse();
        await Assert.That(decision.Trace).IsNull();
        await Assert.That(decision.ApprovalScope).IsNull();
    }
}

