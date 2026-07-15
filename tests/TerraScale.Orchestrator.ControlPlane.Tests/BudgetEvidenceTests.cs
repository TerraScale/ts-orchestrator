using TerraScale.Orchestrator.ControlPlane.Budgets;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class BudgetEvidenceTests
{
    [Test]
    public async Task Missing_unknown_stale_wrong_scope_and_negative_evidence_fail_closed()
    {
        await Assert.That(BudgetAuthorizationEngine.Evaluate(BudgetTestData.Policy(), BudgetTestData.Proposal(), null, [], []).Reason)
            .IsEqualTo(BudgetDecisionReason.MissingEvidence);
        await Assert.That(BudgetTestData.Evaluate(usage: [BudgetTestData.CellUsage()]).Reason)
            .IsEqualTo(BudgetDecisionReason.MissingEvidence);
        await Assert.That(BudgetTestData.Evaluate(prices: [BudgetTestData.Price(BudgetEvidenceStatus.Unknown)]).Reason)
            .IsEqualTo(BudgetDecisionReason.UnknownEvidence);
        await Assert.That(BudgetTestData.Evaluate(nodes: [BudgetTestData.NodeUsage(status: BudgetEvidenceStatus.Stale)]).Reason)
            .IsEqualTo(BudgetDecisionReason.StaleEvidence);
        await Assert.That(BudgetTestData.Evaluate(prices: [BudgetTestData.Price(age: 101)]).Reason)
            .IsEqualTo(BudgetDecisionReason.StaleEvidence);
        await Assert.That(BudgetTestData.Evaluate(usage: [BudgetTestData.CellUsage(cell: BudgetTestData.Cell("sfo")), BudgetTestData.GlobalUsage()]).Reason)
            .IsEqualTo(BudgetDecisionReason.WrongScope);
        await Assert.That(BudgetTestData.Evaluate(nodes: [BudgetTestData.NodeUsage(-1)]).Reason)
            .IsEqualTo(BudgetDecisionReason.ConflictingEvidence);
    }

    [Test]
    public async Task Evidence_age_boundary_is_inclusive_and_recorded_in_trace()
    {
        var decision = BudgetTestData.Evaluate(prices: [BudgetTestData.Price(age: 100)]);

        await Assert.That(decision.IsAuthorized).IsTrue();
        await Assert.That(decision.Trace!.PriceEvidenceAge.Value).IsEqualTo(100);
        await Assert.That(decision.Trace.MaximumEvidenceAge.Value).IsEqualTo(100);
    }

    [Test]
    public async Task Duplicate_and_conflicting_evidence_are_distinct()
    {
        var cell = BudgetTestData.CellUsage();
        var duplicate = BudgetTestData.Evaluate(usage: [cell, cell, BudgetTestData.GlobalUsage()]);
        var conflict = BudgetTestData.Evaluate(usage: [cell, BudgetTestData.CellUsage(BudgetTestData.Vector(11)), BudgetTestData.GlobalUsage()]);
        var duplicatePrice = BudgetTestData.Evaluate(prices: [BudgetTestData.Price(), BudgetTestData.Price()]);
        var conflictingPrice = BudgetTestData.Evaluate(prices: [BudgetTestData.Price(), BudgetTestData.Price(BudgetEvidenceStatus.Stale)]);

        await Assert.That(duplicate.Reason).IsEqualTo(BudgetDecisionReason.DuplicateEvidence);
        await Assert.That(conflict.Reason).IsEqualTo(BudgetDecisionReason.ConflictingEvidence);
        await Assert.That(duplicatePrice.Reason).IsEqualTo(BudgetDecisionReason.DuplicateEvidence);
        await Assert.That(conflictingPrice.Reason).IsEqualTo(BudgetDecisionReason.ConflictingEvidence);
    }

    [Test]
    public async Task Evidence_enumeration_is_explicitly_bounded()
    {
        var decision = BudgetTestData.Evaluate(
            policy: BudgetTestData.Policy(maximumEvidence: 3));
        await Assert.That(decision.Kind).IsEqualTo(BudgetDecisionKind.Held);
        await Assert.That(decision.Reason).IsEqualTo(BudgetDecisionReason.EvidenceLimitExceeded);
    }

    [Test]
    public async Task Malformed_wrong_scope_and_unknown_class_proposals_fail_before_evidence()
    {
        var malformed = new BudgetProposal(
            default, BudgetTestData.Cell(), BudgetTestData.CostCenter(), BudgetTestData.NodeClass(),
            BudgetTestData.Evidence(), BudgetChangeDirection.Increase, BudgetSafetyPurpose.OrdinaryCapacity,
            1, BudgetTestData.Vector(1));
        var wrongScope = BudgetTestData.Proposal(cell: BudgetTestData.Cell("sfo"));
        var unknownClass = BudgetTestData.Proposal(nodeClass: BudgetTestData.NodeClass("unknown"));

        await Assert.That(BudgetAuthorizationEngine.Evaluate(BudgetTestData.Policy(), malformed, null, null, null).Reason)
            .IsEqualTo(BudgetDecisionReason.MalformedProposal);
        await Assert.That(BudgetAuthorizationEngine.Evaluate(BudgetTestData.Policy(), wrongScope, null, null, null).Reason)
            .IsEqualTo(BudgetDecisionReason.WrongScope);
        await Assert.That(BudgetAuthorizationEngine.Evaluate(BudgetTestData.Policy(), unknownClass, null, null, null).Reason)
            .IsEqualTo(BudgetDecisionReason.UnknownNodeClass);
    }
}
