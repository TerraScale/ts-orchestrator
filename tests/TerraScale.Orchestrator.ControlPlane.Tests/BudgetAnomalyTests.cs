using TerraScale.Orchestrator.ControlPlane.Budgets;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class BudgetAnomalyTests
{
    [Test]
    public async Task Detector_reports_orphan_unattached_and_three_way_discrepancies_without_deletion_decision()
    {
        var orphan = Observation("orphan", desired: false, owned: true, billed: true, BudgetResourceAttachment.Unattached);
        var missing = Observation("missing", desired: true, owned: false, billed: false, BudgetResourceAttachment.NotApplicable);
        var billedOnly = Observation("billed", desired: false, owned: false, billed: true, BudgetResourceAttachment.NotApplicable);
        var unbilledOwned = Observation("unbilled", desired: true, owned: true, billed: false, BudgetResourceAttachment.Attached);

        var result = BudgetAnomalyDetector.Detect(BudgetTestData.Cell(), BudgetTestData.CostCenter(), 10, BudgetTestData.Q(100), true,
            [unbilledOwned, billedOnly, missing, orphan]);

        await Assert.That(result.IsComplete).IsTrue();
        await Assert.That(result.Findings.Select(static item => item.Kind).ToArray()).IsEquivalentTo(new[]
        {
            BudgetAnomalyKind.OrphanedOwnedResource,
            BudgetAnomalyKind.UnattachedResource,
            BudgetAnomalyKind.DesiredResourceMissing,
            BudgetAnomalyKind.BillingWithoutOwnedResource,
            BudgetAnomalyKind.OwnedResourceMissingFromBilling,
        });
        await Assert.That(result.Findings.All(static finding => !finding.ToString().Contains("delete", StringComparison.OrdinalIgnoreCase))).IsTrue();
    }

    [Test]
    public async Task Anomaly_findings_are_permutation_deterministic_and_defensively_copied()
    {
        var observations = new List<BudgetResourceObservation?>
        {
            Observation("zeta", false, true, true, BudgetResourceAttachment.Unattached),
            Observation("alpha", true, false, false, BudgetResourceAttachment.NotApplicable),
        };
        var first = BudgetAnomalyDetector.Detect(BudgetTestData.Cell(), BudgetTestData.CostCenter(), 10, BudgetTestData.Q(100), true, observations);
        observations.Reverse();
        var second = BudgetAnomalyDetector.Detect(BudgetTestData.Cell(), BudgetTestData.CostCenter(), 10, BudgetTestData.Q(100), true, observations);
        observations.Clear();

        await Assert.That(second.Findings).IsEquivalentTo(first.Findings);
        await Assert.That(first.Findings.Count).IsEqualTo(3);
        await Assert.That(first.Findings[0].Resource).IsEqualTo(BudgetTestData.Resource("alpha"));
    }

    [Test]
    public async Task Anomaly_evidence_failures_are_closed_and_secret_safe()
    {
        var original = Observation("credential-SUPERSECRET", false, true, true, BudgetResourceAttachment.Attached);
        var duplicate = BudgetAnomalyDetector.Detect(BudgetTestData.Cell(), BudgetTestData.CostCenter(), 10, BudgetTestData.Q(100), true, [original, original]);
        var conflicting = BudgetAnomalyDetector.Detect(BudgetTestData.Cell(), BudgetTestData.CostCenter(), 10, BudgetTestData.Q(100), true,
            [original, Observation("credential-SUPERSECRET", true, true, true, BudgetResourceAttachment.Attached)]);
        var stale = BudgetAnomalyDetector.Detect(BudgetTestData.Cell(), BudgetTestData.CostCenter(), 10, BudgetTestData.Q(100), true,
            [Observation("stale", true, true, true, BudgetResourceAttachment.Attached, BudgetEvidenceStatus.Stale)]);
        var wrong = BudgetAnomalyDetector.Detect(BudgetTestData.Cell(), BudgetTestData.CostCenter(), 10, BudgetTestData.Q(100), true,
            [new BudgetResourceObservation(BudgetTestData.Resource(), BudgetTestData.Cell("sfo"), BudgetTestData.CostCenter(),
                BudgetTestData.Evidence(), BudgetEvidenceStatus.Current, BudgetTestData.Q(1), true, true, true, BudgetResourceAttachment.Attached)]);

        await Assert.That(duplicate.Error).IsEqualTo(BudgetAnomalyError.DuplicateEvidence);
        await Assert.That(conflicting.Error).IsEqualTo(BudgetAnomalyError.ConflictingEvidence);
        await Assert.That(stale.Error).IsEqualTo(BudgetAnomalyError.StaleEvidence);
        await Assert.That(wrong.Error).IsEqualTo(BudgetAnomalyError.InvalidScope);
        await Assert.That(duplicate.ToString()).DoesNotContain("SUPERSECRET");
        await Assert.That(conflicting.ToString()).DoesNotContain("SUPERSECRET");
    }

    [Test]
    public async Task Empty_inventory_requires_explicit_completeness_and_age_is_policy_checked()
    {
        var incomplete = BudgetAnomalyDetector.Detect(
            BudgetTestData.Cell(), BudgetTestData.CostCenter(), 10, BudgetTestData.Q(100), false, []);
        var completeEmpty = BudgetAnomalyDetector.Detect(
            BudgetTestData.Cell(), BudgetTestData.CostCenter(), 10, BudgetTestData.Q(100), true, []);
        var old = new BudgetResourceObservation(
            BudgetTestData.Resource(), BudgetTestData.Cell(), BudgetTestData.CostCenter(), BudgetTestData.Evidence(),
            BudgetEvidenceStatus.Current, BudgetTestData.Q(101), true, true, true, BudgetResourceAttachment.Attached);
        var stale = BudgetAnomalyDetector.Detect(
            BudgetTestData.Cell(), BudgetTestData.CostCenter(), 10, BudgetTestData.Q(100), true, [old]);

        await Assert.That(incomplete.Error).IsEqualTo(BudgetAnomalyError.MissingEvidence);
        await Assert.That(completeEmpty.IsComplete).IsTrue();
        await Assert.That(completeEmpty.Findings.Count).IsEqualTo(0);
        await Assert.That(stale.Error).IsEqualTo(BudgetAnomalyError.StaleEvidence);
    }

    private static BudgetResourceObservation Observation(
        string id, bool desired, bool owned, bool billed, BudgetResourceAttachment attachment,
        BudgetEvidenceStatus status = BudgetEvidenceStatus.Current) =>
        new(BudgetTestData.Resource(id), BudgetTestData.Cell(), BudgetTestData.CostCenter(),
            BudgetTestData.Evidence($"evidence-{id}"), status, BudgetTestData.Q(1), desired, owned, billed, attachment);
}

