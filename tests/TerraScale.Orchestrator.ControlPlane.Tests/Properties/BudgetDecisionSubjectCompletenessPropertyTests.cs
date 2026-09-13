using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Budgets;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class BudgetDecisionSubjectCompletenessPropertyTests
{
    [Test]
    public async Task Every_traced_create_outcome_binds_the_exact_validated_proposal_subject()
    {
        var automaticProposal = BudgetTestData.Proposal();
        var approvalProposal = BudgetTestData.Proposal(nodeCount: 0);
        var forbiddenProposal = BudgetTestData.Proposal(nodeCount: 0);
        var ceilingProposal = BudgetTestData.Proposal(nodeCount: 0);
        var providerProposal = BudgetTestData.Proposal(nodeCount: 0);
        var emergencyDecrease = BudgetTestData.Proposal(direction: BudgetChangeDirection.Decrease);
        var invalidEmergency = BudgetTestData.Proposal(purpose: BudgetSafetyPurpose.DataLossPreventionStorageExpansion);
        var emergencySafety = BudgetTestData.Proposal(
            delta: BudgetTestData.VectorAt(2, 1), purpose: BudgetSafetyPurpose.DataLossPreventionStorageExpansion, nodeCount: 0);
        var emergencyOrdinary = BudgetTestData.Proposal();
        var minimumProposal = BudgetTestData.Proposal(direction: BudgetChangeDirection.Decrease, nodeCount: 3);
        var maximumProposal = BudgetTestData.Proposal(nodeCount: 3);

        var cases = new[]
        {
            (Decision: BudgetTestData.Evaluate(proposal: automaticProposal), Proposal: automaticProposal,
                Kind: BudgetDecisionKind.Automatic, Reason: BudgetDecisionReason.WithinAutomaticBand),
            (Decision: BudgetTestData.Evaluate(policy: BudgetTestData.Policy(automatic: BudgetTestData.Vector(10)), proposal: approvalProposal), Proposal: approvalProposal,
                Kind: BudgetDecisionKind.ApprovalRequired, Reason: BudgetDecisionReason.ApprovalBand),
            (Decision: BudgetTestData.Evaluate(policy: BudgetTestData.Policy(automatic: BudgetTestData.Vector(5), approval: BudgetTestData.Vector(10)), proposal: forbiddenProposal), Proposal: forbiddenProposal,
                Kind: BudgetDecisionKind.Forbidden, Reason: BudgetDecisionReason.ForbiddenBand),
            (Decision: BudgetTestData.Evaluate(policy: BudgetTestData.Policy(automatic: BudgetTestData.Vector(5), approval: BudgetTestData.Vector(10), ceiling: BudgetTestData.Vector(10)), proposal: ceilingProposal), Proposal: ceilingProposal,
                Kind: BudgetDecisionKind.Forbidden, Reason: BudgetDecisionReason.BudgetCeilingExceeded),
            (Decision: BudgetTestData.Evaluate(policy: BudgetTestData.Policy(automatic: BudgetTestData.Vector(5), approval: BudgetTestData.Vector(10), ceiling: BudgetTestData.Vector(10), provider: BudgetTestData.Vector(10)), proposal: providerProposal), Proposal: providerProposal,
                Kind: BudgetDecisionKind.Forbidden, Reason: BudgetDecisionReason.ProviderAccountLimitExceeded),
            (Decision: BudgetTestData.Evaluate(proposal: minimumProposal), Proposal: minimumProposal,
                Kind: BudgetDecisionKind.Forbidden, Reason: BudgetDecisionReason.NodeClassMinimumViolated),
            (Decision: BudgetTestData.Evaluate(proposal: maximumProposal), Proposal: maximumProposal,
                Kind: BudgetDecisionKind.Forbidden, Reason: BudgetDecisionReason.NodeClassMaximumExceeded),
            (Decision: BudgetTestData.Evaluate(policy: BudgetTestData.Policy(BudgetEmergencyPosture.Emergency), proposal: emergencyDecrease), Proposal: emergencyDecrease,
                Kind: BudgetDecisionKind.Held, Reason: BudgetDecisionReason.EmergencyDecreaseHeld),
            (Decision: BudgetTestData.Evaluate(policy: BudgetTestData.Policy(BudgetEmergencyPosture.Emergency), proposal: invalidEmergency), Proposal: invalidEmergency,
                Kind: BudgetDecisionKind.Held, Reason: BudgetDecisionReason.InvalidEmergencySafetyClaim),
            (Decision: BudgetTestData.Evaluate(policy: BudgetTestData.Policy(BudgetEmergencyPosture.Emergency), proposal: emergencySafety), Proposal: emergencySafety,
                Kind: BudgetDecisionKind.Automatic, Reason: BudgetDecisionReason.EmergencyDataLossPrevention),
            (Decision: BudgetTestData.Evaluate(policy: BudgetTestData.Policy(BudgetEmergencyPosture.Emergency), proposal: emergencyOrdinary), Proposal: emergencyOrdinary,
                Kind: BudgetDecisionKind.Forbidden, Reason: BudgetDecisionReason.EmergencyNonSafetyGrowth),
        };

        foreach (var item in cases)
        {
            await Assert.That(item.Decision.Kind).IsEqualTo(item.Kind);
            await Assert.That(item.Decision.Reason).IsEqualTo(item.Reason);
            await Assert.That(item.Decision.Trace).IsNotNull();
            await AssertExactSubject(item.Decision.Subject, item.Proposal);
        }
    }

    [Test]
    public async Task Subject_fingerprint_distinguishes_all_nine_proposal_fields_and_replays_canonically()
    {
        var baseline = BudgetTestData.Proposal();
        var baselineDecision = EvaluateFor(baseline);
        var baselineFingerprint = DecisionFingerprint(baselineDecision);
        await Assert.That(DecisionFingerprint(EvaluateFor(BudgetTestData.Proposal()))).IsEqualTo(baselineFingerprint);

        var variants = new[]
        {
            BudgetTestData.Proposal(resource: BudgetTestData.Resource("node-43")),
            BudgetTestData.Proposal(cell: BudgetTestData.Cell("sfo")),
            BudgetTestData.Proposal(costCenter: BudgetTestData.CostCenter("database")),
            BudgetTestData.Proposal(nodeClass: BudgetTestData.NodeClass("a2-compact")),
            BudgetTestData.Proposal(price: BudgetTestData.Evidence("price-v2")),
            BudgetTestData.Proposal(direction: BudgetChangeDirection.Decrease),
            BudgetTestData.Proposal(purpose: BudgetSafetyPurpose.AvailabilityRepair),
            BudgetTestData.Proposal(nodeCount: 2),
            BudgetTestData.Proposal(delta: BudgetTestData.Vector(2)),
        };

        foreach (var variant in variants)
        {
            var decision = EvaluateFor(variant);
            await Assert.That(decision.IsAuthorized).IsTrue();
            await Assert.That(SubjectFingerprint(decision.Subject!)).IsNotEqualTo(SubjectFingerprint(baselineDecision.Subject!));
            await Assert.That(DecisionFingerprint(decision)).IsNotEqualTo(baselineFingerprint);
        }
    }

    [Test]
    public async Task Subject_exists_exactly_when_the_current_decision_path_has_a_trace()
    {
        var malformed = new BudgetProposal(default, BudgetTestData.Cell(), BudgetTestData.CostCenter(), BudgetTestData.NodeClass(),
            BudgetTestData.Evidence(), BudgetChangeDirection.Increase, BudgetSafetyPurpose.OrdinaryCapacity, 1, BudgetTestData.Vector(1));
        var early = new[]
        {
            BudgetAuthorizationEngine.Evaluate(null, BudgetTestData.Proposal(), null, null, null),
            BudgetAuthorizationEngine.Evaluate(BudgetTestData.Policy(), malformed, null, null, null),
            BudgetAuthorizationEngine.Evaluate(BudgetTestData.Policy(), BudgetTestData.Proposal(cell: BudgetTestData.Cell("sfo")), null, null, null),
            BudgetAuthorizationEngine.Evaluate(BudgetTestData.Policy(), BudgetTestData.Proposal(nodeClass: BudgetTestData.NodeClass("unknown")), null, null, null),
            BudgetAuthorizationEngine.Evaluate(BudgetTestData.Policy(), BudgetTestData.Proposal(), null, null, null),
            BudgetTestData.Evaluate(proposal: BudgetTestData.Proposal(BudgetTestData.Vector(11), BudgetChangeDirection.Decrease, nodeCount: 0)),
        };
        foreach (var decision in early)
        {
            await Assert.That(decision.Trace).IsNull();
            await Assert.That(decision.Subject).IsNull();
            await Assert.That(decision.Basis).IsNull();
        }

        foreach (var decision in new[]
        {
            BudgetTestData.Evaluate(),
            BudgetTestData.Evaluate(policy: BudgetTestData.Policy(automatic: BudgetTestData.Vector(10))),
            BudgetTestData.Evaluate(policy: BudgetTestData.Policy(BudgetEmergencyPosture.Emergency),
                proposal: BudgetTestData.Proposal(direction: BudgetChangeDirection.Decrease)),
        })
        {
            await Assert.That(decision.Trace).IsNotNull();
            await Assert.That(decision.Subject).IsNotNull();
            await Assert.That(decision.Basis).IsNotNull();
        }
    }

    [Test]
    public async Task Approval_scope_is_unchanged_and_subject_is_construction_closed_and_redacted()
    {
        const string secretLike = "resource.sk_live_SUPERSECRET";
        var proposal = BudgetTestData.Proposal(resource: BudgetTestData.Resource(secretLike), nodeCount: 0);
        var policy = BudgetTestData.Policy(automatic: BudgetTestData.Vector(10));
        var decision = BudgetTestData.Evaluate(policy: policy, proposal: proposal);

        await Assert.That(decision.Kind).IsEqualTo(BudgetDecisionKind.ApprovalRequired);
        await Assert.That(decision.ApprovalScope!.ApprovalId).IsEqualTo(policy.ApprovalScope);
        await Assert.That(decision.ApprovalScope.Cell).IsEqualTo(proposal.Cell);
        await Assert.That(decision.ApprovalScope.CostCenter).IsEqualTo(proposal.CostCenter);
        await Assert.That(decision.ApprovalScope.NodeClass).IsEqualTo(proposal.NodeClass);
        await Assert.That(decision.ApprovalScope.Resource).IsEqualTo(proposal.Resource);
        await Assert.That(decision.ApprovalScope.Purpose).IsEqualTo(proposal.Purpose);
        await Assert.That(decision.Subject!.ToString()).DoesNotContain(secretLike);
        await Assert.That(decision.ToString()).DoesNotContain(secretLike);

        var subjectType = typeof(BudgetDecisionSubject);
        await Assert.That(subjectType.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(subjectType.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Any(property => property.SetMethod?.IsPublic == true)).IsFalse();
        await Assert.That(subjectType.GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Any(method => method.Name == "Deconstruct")).IsFalse();
        var externalFactories = subjectType.Assembly.GetExportedTypes()
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(method => method.ReturnType == subjectType)
            .Where(method => !(method.IsSpecialName && method.DeclaringType == typeof(BudgetDecision) && method.Name == "get_Subject"))
            .Select(method => $"{method.DeclaringType!.FullName}.{method.Name}")
            .Order(StringComparer.Ordinal)
            .ToArray();
        await Assert.That(externalFactories).IsEmpty();

        var defaultDecision = default(BudgetDecision);
        await Assert.That(defaultDecision.Subject).IsNull();
        await Assert.That(defaultDecision.Trace).IsNull();
        await Assert.That(defaultDecision.Basis).IsNull();
    }

    private static async Task AssertExactSubject(BudgetDecisionSubject? subject, BudgetProposal proposal)
    {
        await Assert.That(subject).IsNotNull();
        await Assert.That(subject!.Resource).IsEqualTo(proposal.Resource);
        await Assert.That(subject.Cell).IsEqualTo(proposal.Cell);
        await Assert.That(subject.CostCenter).IsEqualTo(proposal.CostCenter);
        await Assert.That(subject.NodeClass).IsEqualTo(proposal.NodeClass);
        await Assert.That(subject.PriceEvidence).IsEqualTo(proposal.PriceEvidence);
        await Assert.That(subject.Direction).IsEqualTo(proposal.Direction);
        await Assert.That(subject.Purpose).IsEqualTo(proposal.Purpose);
        await Assert.That(subject.NodeCount).IsEqualTo(proposal.NodeCount);
        await Assert.That(subject.Delta).IsSameReferenceAs(proposal.Delta);
    }

    private static BudgetDecision EvaluateFor(BudgetProposal proposal)
    {
        var policy = PolicyFor(proposal);
        return BudgetAuthorizationEngine.Evaluate(policy, proposal,
            [BudgetTestData.CellUsage(cell: proposal.Cell, costCenter: proposal.CostCenter),
             BudgetTestData.GlobalUsage(costCenter: proposal.CostCenter)],
            [BudgetTestData.NodeUsage(nodeClass: proposal.NodeClass, cell: proposal.Cell, costCenter: proposal.CostCenter)],
            [BudgetTestData.Price(id: proposal.PriceEvidence, costCenter: proposal.CostCenter)]);
    }

    private static BudgetPolicy PolicyFor(BudgetProposal proposal)
    {
        var maximum = BudgetTestData.Vector(50);
        BudgetPolicy.TryCreate(proposal.Cell, proposal.CostCenter, BudgetTestData.Approval(), BudgetEmergencyPosture.Normal,
            BudgetTestData.Q(100), 16, [new NodeClassCapacityPolicy(proposal.NodeClass, 1, 10, 2)],
            maximum, maximum, maximum, maximum,
            new BudgetBandPolicy(BudgetTestData.Vector(20), BudgetTestData.Vector(20),
                BudgetTestData.Vector(30), BudgetTestData.Vector(30)), out var policy, out var error);
        if (error != BudgetPolicyError.None) throw new InvalidOperationException($"Policy failed: {error}.");
        return policy!;
    }

    private static string DecisionFingerprint(BudgetDecision decision) =>
        $"{decision.Kind}|{decision.Reason}|{(decision.Subject is null ? "none" : SubjectFingerprint(decision.Subject))}|{decision.Trace}";

    private static string SubjectFingerprint(BudgetDecisionSubject subject) =>
        $"resource={subject.Resource.Value}|cell={subject.Cell.Value}|cost={subject.CostCenter.Value}|node={subject.NodeClass.Value}|" +
        $"price={subject.PriceEvidence.Value}|direction={subject.Direction}|purpose={subject.Purpose}|count={subject.NodeCount}|delta={subject.Delta}";
}

