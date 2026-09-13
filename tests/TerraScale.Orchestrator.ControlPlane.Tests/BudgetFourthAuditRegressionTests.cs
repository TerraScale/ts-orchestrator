using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Budgets;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class BudgetFourthAuditRegressionTests
{
    [Test]
    public async Task Distinct_selected_evidence_can_no_longer_produce_the_same_accepted_basis()
    {
        var original = Inputs("a");
        var substituted = Inputs("b", policy: original.Policy, proposal: original.Proposal);

        var first = Evaluate(original);
        var second = Evaluate(substituted);

        await Assert.That(first.IsAuthorized).IsTrue();
        await Assert.That(second.IsAuthorized).IsTrue();
        await Assert.That(LegacyFingerprint(first)).IsEqualTo(LegacyFingerprint(second));
        await Assert.That(BasisFingerprint(first.Basis!)).IsNotEqualTo(BasisFingerprint(second.Basis!));
        await AssertExactBasis(first.Basis, original);
        await AssertExactBasis(second.Basis, substituted);
    }

    [Test]
    public async Task Every_post_selection_decision_retains_the_exact_policy_and_evidence_basis()
    {
        var automatic = Inputs("automatic");
        var approval = Inputs("approval", policy: BudgetTestData.Policy(automatic: BudgetTestData.Vector(10)),
            proposal: BudgetTestData.Proposal(nodeCount: 0));
        var forbidden = Inputs("forbidden",
            policy: BudgetTestData.Policy(automatic: BudgetTestData.Vector(5), approval: BudgetTestData.Vector(10)),
            proposal: BudgetTestData.Proposal(nodeCount: 0));
        var provider = Inputs("provider",
            policy: BudgetTestData.Policy(automatic: BudgetTestData.Vector(5), approval: BudgetTestData.Vector(10),
                ceiling: BudgetTestData.Vector(10), provider: BudgetTestData.Vector(10)),
            proposal: BudgetTestData.Proposal(nodeCount: 0));
        var emergencyHeld = Inputs("emergency-held", policy: BudgetTestData.Policy(BudgetEmergencyPosture.Emergency),
            proposal: BudgetTestData.Proposal(direction: BudgetChangeDirection.Decrease));
        var emergencyAutomatic = Inputs("emergency-automatic",
            policy: BudgetTestData.Policy(BudgetEmergencyPosture.Emergency),
            proposal: BudgetTestData.Proposal(delta: BudgetTestData.VectorAt(2, 1),
                purpose: BudgetSafetyPurpose.DataLossPreventionStorageExpansion, nodeCount: 0));

        var cases = new[]
        {
            (automatic, BudgetDecisionKind.Automatic),
            (approval, BudgetDecisionKind.ApprovalRequired),
            (forbidden, BudgetDecisionKind.Forbidden),
            (provider, BudgetDecisionKind.Forbidden),
            (emergencyHeld, BudgetDecisionKind.Held),
            (emergencyAutomatic, BudgetDecisionKind.Automatic),
        };
        foreach (var (inputs, kind) in cases)
        {
            var decision = Evaluate(inputs);
            await Assert.That(decision.Kind).IsEqualTo(kind);
            await Assert.That(decision.Trace).IsNotNull();
            await Assert.That(decision.Subject).IsNotNull();
            await AssertExactBasis(decision.Basis, inputs);
        }
    }

    [Test]
    public async Task Decisions_before_trace_construction_remain_basis_free()
    {
        var malformed = new BudgetProposal(default, BudgetTestData.Cell(), BudgetTestData.CostCenter(),
            BudgetTestData.NodeClass(), BudgetTestData.Evidence(), BudgetChangeDirection.Increase,
            BudgetSafetyPurpose.OrdinaryCapacity, 1, BudgetTestData.Vector(1));
        var exact = Inputs("early");
        var duplicateCell = new[] { exact.CellUsage, exact.CellUsage, exact.GlobalUsage };
        var conflictingCell = new[]
        {
            exact.CellUsage,
            new BudgetUsageObservation(BudgetUsageScope.Cell, BudgetTestData.Cell(), BudgetTestData.CostCenter(),
                BudgetTestData.Evidence("conflict"), BudgetEvidenceStatus.Current, BudgetTestData.Q(1), BudgetTestData.Vector(11)),
            exact.GlobalUsage,
        };
        var stale = Inputs("stale", cellStatus: BudgetEvidenceStatus.Stale);
        var unknown = Inputs("unknown", cellStatus: BudgetEvidenceStatus.Unknown);
        var limitedPolicy = BudgetTestData.Policy(maximumEvidence: 3);

        var decisions = new[]
        {
            BudgetAuthorizationEngine.Evaluate(null, exact.Proposal, null, null, null),
            BudgetAuthorizationEngine.Evaluate(exact.Policy, malformed, null, null, null),
            BudgetAuthorizationEngine.Evaluate(exact.Policy,
                BudgetTestData.Proposal(cell: BudgetTestData.Cell("sfo")), null, null, null),
            BudgetAuthorizationEngine.Evaluate(exact.Policy,
                BudgetTestData.Proposal(nodeClass: BudgetTestData.NodeClass("unknown")), null, null, null),
            BudgetAuthorizationEngine.Evaluate(exact.Policy, exact.Proposal, null, null, null),
            BudgetAuthorizationEngine.Evaluate(exact.Policy, exact.Proposal, duplicateCell, [exact.NodeUsage], [exact.PriceEvidence]),
            BudgetAuthorizationEngine.Evaluate(exact.Policy, exact.Proposal, conflictingCell, [exact.NodeUsage], [exact.PriceEvidence]),
            Evaluate(stale),
            Evaluate(unknown),
            BudgetAuthorizationEngine.Evaluate(limitedPolicy, exact.Proposal,
                [exact.CellUsage, exact.GlobalUsage], [exact.NodeUsage], [exact.PriceEvidence]),
            BudgetTestData.Evaluate(proposal: BudgetTestData.Proposal(BudgetTestData.Vector(long.MaxValue))),
            BudgetTestData.Evaluate(proposal: BudgetTestData.Proposal(BudgetTestData.Vector(11),
                BudgetChangeDirection.Decrease, nodeCount: 0)),
        };
        foreach (var decision in decisions)
        {
            await Assert.That(decision.Kind).IsEqualTo(BudgetDecisionKind.Held);
            await Assert.That(decision.Trace).IsNull();
            await Assert.That(decision.Subject).IsNull();
            await Assert.That(decision.Basis).IsNull();
        }
    }

    [Test]
    public async Task Basis_is_construction_closed_getter_only_and_redacted()
    {
        const string marker = "sk-live-supersecret";
        var inputs = Inputs(marker);
        var basis = Evaluate(inputs).Basis!;
        await Assert.That(basis.ToString()).IsEqualTo("<budget-decision-basis>");
        await Assert.That(basis.ToString()).DoesNotContain(marker);

        var type = typeof(BudgetDecisionBasis);
        await Assert.That(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .All(property => property.SetMethod is null)).IsTrue();
        await Assert.That(type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)
            .Any(method => method.Name is "Deconstruct" or "Clone" or "<Clone>$" ||
                           method.ReturnType == type && method.Name != "get_Basis")).IsFalse();
        var factories = type.Assembly.GetExportedTypes()
            .SelectMany(candidate => candidate.GetMethods(BindingFlags.Public | BindingFlags.Instance |
                BindingFlags.Static | BindingFlags.DeclaredOnly))
            .Where(method => method.ReturnType == type)
            .Where(method => !(method.IsSpecialName && method.DeclaringType == typeof(BudgetDecision) &&
                               method.Name == "get_Basis"));
        await Assert.That(factories).IsEmpty();
    }

    [Test]
    public async Task Basis_replay_is_permutation_culture_and_policy_sensitive_for_1000_cases()
    {
        var cultures = new[] { "en-US", "tr-TR", "ar-SA", "ja-JP" };
        for (var seed = 0; seed < 1_000; seed++)
        {
            var policy = BudgetTestData.Policy();
            var inputs = Inputs($"seed-{seed}", policy: policy, age: 1 + seed % 99,
                usage: 1 + seed % 10);
            var usage = seed % 2 == 0
                ? new[] { inputs.CellUsage, inputs.GlobalUsage }
                : new[] { inputs.GlobalUsage, inputs.CellUsage };
            var originalCulture = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultures[seed % cultures.Length]);
                var decision = BudgetAuthorizationEngine.Evaluate(inputs.Policy, inputs.Proposal,
                    usage, [inputs.NodeUsage], [inputs.PriceEvidence]);
                await Assert.That(decision.IsAuthorized).IsTrue();
                await AssertExactBasis(decision.Basis, inputs);
                await Assert.That(BasisFingerprint(decision.Basis!)).IsEqualTo(BasisFingerprint(Evaluate(inputs).Basis!));
            }
            finally
            {
                CultureInfo.CurrentCulture = originalCulture;
            }

            var equivalentPolicy = BudgetTestData.Policy();
            var replay = Inputs($"seed-{seed}", policy: equivalentPolicy, proposal: inputs.Proposal,
                age: 1 + seed % 99, usage: 1 + seed % 10);
            var replayDecision = Evaluate(replay);
            await Assert.That(ReferenceEquals(replayDecision.Basis!.Policy, policy)).IsFalse();
            await Assert.That(ReferenceEquals(replayDecision.Basis.Policy, equivalentPolicy)).IsTrue();
        }
    }

    private static EvaluationInputs Inputs(string suffix, BudgetPolicy? policy = null, BudgetProposal? proposal = null,
        BudgetEvidenceStatus cellStatus = BudgetEvidenceStatus.Current, int age = 1, int usage = 10)
    {
        var actualPolicy = policy ?? BudgetTestData.Policy();
        var actualProposal = proposal ?? BudgetTestData.Proposal();
        var cell = new BudgetUsageObservation(BudgetUsageScope.Cell, actualProposal.Cell, actualProposal.CostCenter,
            BudgetTestData.Evidence($"cell-{suffix}"), cellStatus, BudgetTestData.Q(age), BudgetTestData.Vector(usage));
        var global = new BudgetUsageObservation(BudgetUsageScope.Global, default, actualProposal.CostCenter,
            BudgetTestData.Evidence($"global-{suffix}"), BudgetEvidenceStatus.Current,
            BudgetTestData.Q(age), BudgetTestData.Vector(usage));
        var node = new NodeClassUsageObservation(actualProposal.Cell, actualProposal.CostCenter,
            actualProposal.NodeClass, BudgetTestData.Evidence($"node-{suffix}"), BudgetEvidenceStatus.Current,
            BudgetTestData.Q(age), 3);
        var price = new PriceEvidenceObservation(actualProposal.PriceEvidence, actualProposal.CostCenter,
            BudgetEvidenceStatus.Current, BudgetTestData.Q(age));
        return new(actualPolicy, actualProposal, cell, global, node, price);
    }

    private static BudgetDecision Evaluate(EvaluationInputs inputs) => BudgetAuthorizationEngine.Evaluate(
        inputs.Policy, inputs.Proposal, [inputs.CellUsage, inputs.GlobalUsage],
        [inputs.NodeUsage], [inputs.PriceEvidence]);

    private static async Task AssertExactBasis(BudgetDecisionBasis? basis, EvaluationInputs inputs)
    {
        await Assert.That(basis).IsNotNull();
        await Assert.That(ReferenceEquals(basis!.Policy, inputs.Policy)).IsTrue();
        await Assert.That(ReferenceEquals(basis.CellUsage, inputs.CellUsage)).IsTrue();
        await Assert.That(ReferenceEquals(basis.GlobalUsage, inputs.GlobalUsage)).IsTrue();
        await Assert.That(ReferenceEquals(basis.NodeUsage, inputs.NodeUsage)).IsTrue();
        await Assert.That(ReferenceEquals(basis.PriceEvidence, inputs.PriceEvidence)).IsTrue();
    }

    private static string LegacyFingerprint(BudgetDecision decision) =>
        $"{decision.Kind}|{decision.Reason}|{decision.Subject!.Resource.Value}|{decision.Subject.Cell.Value}|" +
        $"{decision.Subject.CostCenter.Value}|{decision.Subject.NodeClass.Value}|{decision.Subject.PriceEvidence.Value}|" +
        $"{decision.Subject.Direction}|{decision.Subject.Purpose}|{decision.Subject.NodeCount}|{decision.Subject.Delta}|{decision.Trace}";

    private static string BasisFingerprint(BudgetDecisionBasis basis) => string.Join('|',
        basis.CellUsage.EvidenceId.Value, basis.GlobalUsage.EvidenceId.Value,
        basis.NodeUsage.EvidenceId.Value, basis.PriceEvidence.EvidenceId.Value,
        basis.CellUsage.Usage.ToString(), basis.CellUsage.Age.Value.ToString(CultureInfo.InvariantCulture));

    private sealed record EvaluationInputs(
        BudgetPolicy Policy,
        BudgetProposal Proposal,
        BudgetUsageObservation CellUsage,
        BudgetUsageObservation GlobalUsage,
        NodeClassUsageObservation NodeUsage,
        PriceEvidenceObservation PriceEvidence);
}

