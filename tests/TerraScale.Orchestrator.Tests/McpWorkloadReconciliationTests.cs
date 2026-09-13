using TerraScale.Orchestrator.Runtime;
using TerraScale.Orchestrator.Runtime.Mcp;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// In-process reconciliation semantics of the stateless MCP workload
/// (TerraScale.Orchestrator#9): create, idempotent restart, two-instance stateless routing,
/// partial failure, stale generation, upgrade, rollback, and emergency route withdrawal.
/// </summary>
public sealed class McpWorkloadReconciliationTests
{
    private const string FirstDomain = "fault-domain-a";
    private const string SecondDomain = "fault-domain-b";
    private const string DeployedDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string UpgradedDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    private static readonly IReadOnlyList<string> OtherProductRoutes =
        ["platform-api", "authentication", "dashboard"];

    private static readonly McpIngressEvidence OpenIngress = new(true, true, true, true, true);

    private static McpDesiredWorkload Desired(
        McpChangeKind changeKind = McpChangeKind.InitialCreation,
        string digest = DeployedDigest,
        long generation = 1) => new(
        generation,
        McpWorkloadAdmissionTests.Manifest(digest),
        [FirstDomain, SecondDomain],
        changeKind);

    private static McpProductRouteTable RoutesOpen() =>
        McpProductRouteTable.WithRoutesOpen([McpProductRouteTable.McpRouteName, .. OtherProductRoutes]);

    private static McpInstanceObservation Ready(
        string domain,
        long generation = 1,
        string digest = DeployedDigest) =>
        new(domain, generation, digest, McpInstanceCondition.Ready);

    [Test]
    public async Task Create_plans_one_instance_per_failure_domain()
    {
        var plan = McpWorkloadReconciler.Plan(Desired(), null, RoutesOpen(), OpenIngress);

        await Assert.That(plan.InstanceActions.Select(static action => action.Kind))
            .IsEquivalentTo([McpInstanceActionKind.Create, McpInstanceActionKind.Create]);
        await Assert.That(plan.InstanceActions.Select(static action => action.FailureDomain))
            .IsEquivalentTo([FirstDomain, SecondDomain]);
        await Assert.That(plan.Route).IsEqualTo(McpRouteDecisionCode.ClosedNoHealthyBackend);
    }

    [Test]
    public async Task Idempotent_restart_of_a_converged_workload_is_a_no_op()
    {
        var plan = McpWorkloadReconciler.Plan(
            Desired(),
            [Ready(FirstDomain), Ready(SecondDomain)],
            RoutesOpen(),
            OpenIngress);

        await Assert.That(plan.InstanceActions).IsEmpty();
        await Assert.That(plan.HealthyFailureDomains).IsEquivalentTo([FirstDomain, SecondDomain]);
        await Assert.That(plan.Route).IsEqualTo(McpRouteDecisionCode.Open);
    }

    [Test]
    public async Task A_lost_instance_restarts_on_the_same_artifact_without_changing_the_route()
    {
        var plan = McpWorkloadReconciler.Plan(
            Desired(),
            [Ready(FirstDomain), new(SecondDomain, 1, DeployedDigest, McpInstanceCondition.Absent)],
            RoutesOpen(),
            OpenIngress);

        var restart = plan.InstanceActions.Single();
        await Assert.That(restart.Kind).IsEqualTo(McpInstanceActionKind.Restart);
        await Assert.That(restart.FailureDomain).IsEqualTo(SecondDomain);
        await Assert.That(plan.Route).IsEqualTo(McpRouteDecisionCode.OpenDegraded);
    }

    [Test]
    public async Task Two_instances_route_statelessly_with_no_sticky_sessions()
    {
        var plan = McpWorkloadReconciler.Plan(
            Desired(),
            [Ready(FirstDomain), Ready(SecondDomain)],
            RoutesOpen(),
            OpenIngress);

        await Assert.That(plan.StickySessions is false).IsTrue();
        var first = plan.SelectBackend(0);
        var second = plan.SelectBackend(1);
        await Assert.That(first.FailureDomain).IsEqualTo(FirstDomain);
        await Assert.That(second.FailureDomain).IsEqualTo(SecondDomain);
        // The same request sequence always selects the same backend: there is no session state
        // to pin, so selection is a pure function of the sequence over the healthy set.
        await Assert.That(plan.SelectBackend(0)).IsEqualTo(first);
    }

    [Test]
    public async Task Partial_failure_keeps_the_route_serving_and_replaces_the_failed_instance()
    {
        var plan = McpWorkloadReconciler.Plan(
            Desired(),
            [Ready(FirstDomain), new(SecondDomain, 1, DeployedDigest, McpInstanceCondition.Failed)],
            RoutesOpen(),
            OpenIngress);

        var replacement = plan.InstanceActions.Single();
        await Assert.That(replacement.Kind).IsEqualTo(McpInstanceActionKind.Replace);
        await Assert.That(replacement.ChangeKind).IsEqualTo(McpChangeKind.Restart);
        await Assert.That(plan.Route).IsEqualTo(McpRouteDecisionCode.OpenDegraded);
        await Assert.That(plan.SelectBackend(0).FailureDomain).IsEqualTo(FirstDomain);
    }

    [Test]
    public async Task A_stale_generation_is_held_and_cannot_open_the_route()
    {
        var plan = McpWorkloadReconciler.Plan(
            Desired(generation: 1),
            [Ready(FirstDomain, generation: 2), Ready(SecondDomain, generation: 2)],
            RoutesOpen(),
            OpenIngress);

        await Assert.That(plan.InstanceActions).IsEmpty();
        await Assert.That(plan.HealthyFailureDomains).IsEmpty();
        await Assert.That(plan.Route).IsEqualTo(McpRouteDecisionCode.ClosedDesiredStale);
        await Assert.That(plan.Holds.All(hold => hold.Contains("exceeds-desired", StringComparison.Ordinal)))
            .IsTrue();
    }

    [Test]
    public async Task Crash_removed_domains_at_a_newer_generation_are_held_not_restarted()
    {
        // Both failure domains lost their instances (Absent) after a NEWER fenced writer
        // advanced them to generation 2. A stale writer at desired generation 1 must not
        // restart either domain onto its older artifact: the generation fence runs before the
        // Absent branch, so the plan holds and the route stays closed.
        var plan = McpWorkloadReconciler.Plan(
            Desired(generation: 1),
            [
                new(FirstDomain, 2, DeployedDigest, McpInstanceCondition.Absent),
                new(SecondDomain, 2, DeployedDigest, McpInstanceCondition.Absent),
            ],
            RoutesOpen(),
            OpenIngress);

        await Assert.That(plan.InstanceActions).IsEmpty();
        await Assert.That(plan.HealthyFailureDomains).IsEmpty();
        await Assert.That(plan.Route).IsEqualTo(McpRouteDecisionCode.ClosedDesiredStale);
        await Assert.That(plan.Holds.Count).IsEqualTo(2);
    }

    [Test]
    public async Task One_held_stale_domain_still_closes_the_route_and_never_acts_on_it()
    {
        var plan = McpWorkloadReconciler.Plan(
            Desired(generation: 1),
            [
                Ready(FirstDomain),
                new(SecondDomain, 2, DeployedDigest, McpInstanceCondition.Ready),
            ],
            RoutesOpen(),
            OpenIngress);

        await Assert.That(plan.InstanceActions).IsEmpty();
        await Assert.That(plan.HealthyFailureDomains).IsEquivalentTo([FirstDomain]);
        await Assert.That(plan.Route).IsEqualTo(McpRouteDecisionCode.ClosedDesiredStale);
    }

    [Test]
    public async Task An_upgrade_converges_every_domain_onto_the_new_qualified_digest()
    {
        const string upgraded = UpgradedDigest;
        var desired = Desired(McpChangeKind.Upgrade, upgraded, generation: 2);

        var plan = McpWorkloadReconciler.Plan(
            desired,
            [Ready(FirstDomain), Ready(SecondDomain)],
            RoutesOpen(),
            OpenIngress);

        await Assert.That(plan.InstanceActions.Select(static action => action.Kind))
            .IsEquivalentTo([McpInstanceActionKind.Converge, McpInstanceActionKind.Converge]);
        await Assert.That(plan.InstanceActions.Select(static action => action.ArtifactDigest).Distinct())
            .IsEquivalentTo([upgraded]);
        await Assert.That(plan.InstanceActions.Select(static action => action.ChangeKind).Distinct())
            .IsEquivalentTo([McpChangeKind.Upgrade]);
        await Assert.That(plan.HealthyFailureDomains).IsEmpty();
        await Assert.That(plan.Route).IsEqualTo(McpRouteDecisionCode.ClosedNoHealthyBackend);
    }

    [Test]
    public async Task A_rollback_converges_back_to_the_previous_qualified_digest()
    {
        const string upgraded = UpgradedDigest;
        const string previous = DeployedDigest;
        var afterUpgrade = McpWorkloadReconciler.Plan(
            Desired(McpChangeKind.Upgrade, upgraded, generation: 2),
            [Ready(FirstDomain, 2, upgraded), Ready(SecondDomain, 2, upgraded)],
            RoutesOpen(),
            OpenIngress);
        await Assert.That(afterUpgrade.HealthyFailureDomains).IsEquivalentTo([FirstDomain, SecondDomain]);

        var rollback = McpWorkloadReconciler.Plan(
            Desired(McpChangeKind.Rollback, previous, generation: 3),
            [Ready(FirstDomain, 2, upgraded), Ready(SecondDomain, 2, upgraded)],
            RoutesOpen(),
            OpenIngress);

        await Assert.That(rollback.InstanceActions.Select(static action => action.Kind))
            .IsEquivalentTo([McpInstanceActionKind.Converge, McpInstanceActionKind.Converge]);
        await Assert.That(rollback.InstanceActions.Select(static action => action.ArtifactDigest).Distinct())
            .IsEquivalentTo([previous]);
        await Assert.That(rollback.InstanceActions.Select(static action => action.ChangeKind).Distinct())
            .IsEquivalentTo([McpChangeKind.Rollback]);
    }

    [Test]
    public async Task Drift_at_the_same_generation_is_repaired_by_convergence()
    {
        var plan = McpWorkloadReconciler.Plan(
            Desired(),
            [Ready(FirstDomain), Ready(SecondDomain, digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")],
            RoutesOpen(),
            OpenIngress);

        var repair = plan.InstanceActions.Single();
        await Assert.That(repair.Kind).IsEqualTo(McpInstanceActionKind.Converge);
        await Assert.That(repair.Reason).Contains("drifted");
    }

    [Test]
    public async Task Ingress_stays_closed_until_the_live_evidence_bundle_passes()
    {
        var plan = McpWorkloadReconciler.Plan(
            Desired(),
            [Ready(FirstDomain), Ready(SecondDomain)],
            RoutesOpen(),
            McpIngressEvidence.None);

        await Assert.That(plan.Route).IsEqualTo(McpRouteDecisionCode.ClosedIngressNotProven);
    }

    [Test]
    public async Task Emergency_withdrawal_closes_only_the_mcp_route()
    {
        var table = RoutesOpen();
        var withdrawal = McpEmergencyRouteControl.Withdraw(table);

        await Assert.That(withdrawal.ClosedRoutes).IsEquivalentTo([McpProductRouteTable.McpRouteName]);
        await Assert.That(withdrawal.UntouchedRoutes).IsEquivalentTo(OtherProductRoutes);
        await Assert.That(withdrawal.UntouchedDistributionChannels)
            .IsEquivalentTo([McpStdioDistributionChannel.ChannelName]);
        await Assert.That(withdrawal.RemainingRoutes.OpenRouteNames).IsEquivalentTo(OtherProductRoutes);

        var plan = McpWorkloadReconciler.Plan(
            Desired(),
            [Ready(FirstDomain), Ready(SecondDomain)],
            withdrawal.RemainingRoutes,
            OpenIngress);

        await Assert.That(plan.Route).IsEqualTo(McpRouteDecisionCode.ClosedByEmergencyWithdrawal);
        // Withdrawal is a route action: the instances stay ready and untouched.
        await Assert.That(plan.HealthyFailureDomains).IsEquivalentTo([FirstDomain, SecondDomain]);
        await Assert.That(plan.InstanceActions).IsEmpty();
    }

    [Test]
    public async Task The_desired_placement_requires_two_independent_failure_domains()
    {
        await Assert.That(() => new McpDesiredWorkload(
            1,
            McpWorkloadAdmissionTests.Manifest(),
            ["same-domain", "same-domain"],
            McpChangeKind.InitialCreation)).Throws<ArgumentException>();
        await Assert.That(() => new McpDesiredWorkload(
            1,
            McpWorkloadAdmissionTests.Manifest(),
            ["only-one"],
            McpChangeKind.InitialCreation)).Throws<ArgumentException>();
        await Assert.That(() => new McpDesiredWorkload(
            0,
            McpWorkloadAdmissionTests.Manifest(),
            [FirstDomain, SecondDomain],
            McpChangeKind.InitialCreation)).Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task Routing_without_a_healthy_backend_fails_closed()
    {
        var plan = McpWorkloadReconciler.Plan(Desired(), null, RoutesOpen(), OpenIngress);

        await Assert.That(() => plan.SelectBackend(0)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Backend_selection_rejects_negative_request_sequences()
    {
        var plan = McpWorkloadReconciler.Plan(
            Desired(),
            [Ready(FirstDomain), Ready(SecondDomain)],
            RoutesOpen(),
            OpenIngress);

        await Assert.That(() => plan.SelectBackend(-1))
            .Throws<ArgumentOutOfRangeException>();
        // The guard is the first check: even a plan without healthy backends refuses a negative
        // sequence with the argument guard rather than the routing failure.
        var empty = McpWorkloadReconciler.Plan(Desired(), null, RoutesOpen(), OpenIngress);
        await Assert.That(() => empty.SelectBackend(-1))
            .Throws<ArgumentOutOfRangeException>();
    }
}

