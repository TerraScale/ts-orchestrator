using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Protocol.Tests;

public sealed class MessagingRegionalAutonomyTests
{
    [Test]
    public async Task Connected_cells_may_perform_every_operation_class()
    {
        foreach (var operationClass in Enum.GetValues<RegionalAutonomyOperationClass>()
                     .Where(static value => value != RegionalAutonomyOperationClass.Unspecified))
        {
            await Assert.That(RegionalAutonomyRules.Decide(
                    MessagingConnectivity.Connected, operationClass))
                .IsEqualTo(RegionalAutonomyDecision.Permitted);
        }
    }

    [Test]
    public async Task Globally_isolated_cells_keep_pre_authorized_regional_work()
    {
        await Assert.That(RegionalAutonomyRules.Decide(
                MessagingConnectivity.GlobalIsolated,
                RegionalAutonomyOperationClass.PreAuthorizedRegionalOperation))
            .IsEqualTo(RegionalAutonomyDecision.Permitted);

        await Assert.That(RegionalAutonomyRules.Decide(
                MessagingConnectivity.GlobalIsolated,
                RegionalAutonomyOperationClass.RegionalObservation))
            .IsEqualTo(RegionalAutonomyDecision.Permitted);
    }

    [Test]
    public async Task Globally_isolated_cells_freeze_new_global_generations_policy_and_releases()
    {
        foreach (var frozen in new[]
                 {
                     RegionalAutonomyOperationClass.NewGlobalGeneration,
                     RegionalAutonomyOperationClass.NewGlobalPolicy,
                     RegionalAutonomyOperationClass.NewGlobalRelease,
                 })
        {
            await Assert.That(RegionalAutonomyRules.Decide(MessagingConnectivity.GlobalIsolated, frozen))
                .IsEqualTo(RegionalAutonomyDecision.FrozenGlobalMutation);
        }

        await Assert.That(RegionalAutonomyRules.Decide(
                MessagingConnectivity.GlobalIsolated,
                RegionalAutonomyOperationClass.GlobalAuthorityClaim))
            .IsEqualTo(RegionalAutonomyDecision.FrozenGlobalAuthorityClaim);
    }

    [Test]
    public async Task Regions_that_lost_their_own_quorum_hold_all_mutations_but_keep_observation()
    {
        await Assert.That(RegionalAutonomyRules.Decide(
                MessagingConnectivity.RegionalQuorumLost,
                RegionalAutonomyOperationClass.PreAuthorizedRegionalOperation))
            .IsEqualTo(RegionalAutonomyDecision.HeldUntilRegionalQuorum);

        await Assert.That(RegionalAutonomyRules.Decide(
                MessagingConnectivity.RegionalQuorumLost,
                RegionalAutonomyOperationClass.NewGlobalRelease))
            .IsEqualTo(RegionalAutonomyDecision.HeldUntilRegionalQuorum);

        await Assert.That(RegionalAutonomyRules.Decide(
                MessagingConnectivity.RegionalQuorumLost,
                RegionalAutonomyOperationClass.RegionalObservation))
            .IsEqualTo(RegionalAutonomyDecision.Permitted);
    }

    [Test]
    public async Task Unknown_inputs_decide_nothing_rather_than_defaulting_to_permit()
    {
        await Assert.That(RegionalAutonomyRules.Decide(
                MessagingConnectivity.Unspecified,
                RegionalAutonomyOperationClass.NewGlobalRelease))
            .IsEqualTo(RegionalAutonomyDecision.Unspecified);

        await Assert.That(RegionalAutonomyRules.Decide(
                MessagingConnectivity.Connected,
                RegionalAutonomyOperationClass.Unspecified))
            .IsEqualTo(RegionalAutonomyDecision.Unspecified);
    }
}

public sealed class MessagingCompatibilityTests
{
    private static readonly MessagingSchemaVersion Current = new(1, 0);

    private static readonly IReadOnlySet<MessagingSchemaVersion> Migratable = new HashSet<MessagingSchemaVersion> { new(1, 0) };

    [Test]
    public async Task Exact_versions_are_accepted_and_known_older_versions_migrate_forward()
    {
        await Assert.That(MessagingSchemaNegotiation.Decide(new MessagingSchemaVersion(1, 0), Current, Migratable))
            .IsEqualTo(SchemaNegotiationOutcome.AcceptExact);

        var migratable = new HashSet<MessagingSchemaVersion> { new(1, 0) };
        await Assert.That(MessagingSchemaNegotiation.Decide(new MessagingSchemaVersion(1, 0), new MessagingSchemaVersion(1, 1), migratable))
            .IsEqualTo(SchemaNegotiationOutcome.MigrateForward);
    }

    [Test]
    public async Task Unknown_majors_fail_closed()
    {
        foreach (var offered in new[] { new MessagingSchemaVersion(2, 0), new MessagingSchemaVersion(99, 4) })
        {
            await Assert.That(MessagingSchemaNegotiation.Decide(offered, Current, Migratable))
                .IsEqualTo(SchemaNegotiationOutcome.RejectMajorMismatch);
        }
    }

    [Test]
    public async Task Malformed_versions_fail_closed_with_a_distinct_malformed_outcome()
    {
        // A malformed offered version is not a major mismatch: it never got far enough to
        // compare majors, and reporting a mismatch would mislead the operator.
        foreach (var offered in new[]
                 {
                     new MessagingSchemaVersion(0, 1),
                     new MessagingSchemaVersion(-1, 0),
                     new MessagingSchemaVersion(1, -1),
                 })
        {
            await Assert.That(MessagingSchemaNegotiation.Decide(offered, Current, Migratable))
                .IsEqualTo(SchemaNegotiationOutcome.RejectMalformed);
        }

        // A malformed CURRENT version is equally undecidable and fails closed the same way.
        await Assert.That(MessagingSchemaNegotiation.Decide(
                new MessagingSchemaVersion(1, 0), new MessagingSchemaVersion(0, 0), Migratable))
            .IsEqualTo(SchemaNegotiationOutcome.RejectMalformed);
    }

    [Test]
    public async Task Newer_versions_fail_closed_so_an_n_minus_1_node_never_guesses()
    {
        await Assert.That(MessagingSchemaNegotiation.Decide(new MessagingSchemaVersion(1, 1), Current, Migratable))
            .IsEqualTo(SchemaNegotiationOutcome.RejectNewerVersion);

        await Assert.That(MessagingSchemaNegotiation.Decide(new MessagingSchemaVersion(2, 0), Current, Migratable))
            .IsEqualTo(SchemaNegotiationOutcome.RejectMajorMismatch);
    }

    [Test]
    public async Task Older_versions_without_a_registered_migration_fail_closed()
    {
        var none = new HashSet<MessagingSchemaVersion>();
        await Assert.That(MessagingSchemaNegotiation.Decide(new MessagingSchemaVersion(1, 0), new MessagingSchemaVersion(1, 2), none))
            .IsEqualTo(SchemaNegotiationOutcome.RejectUnmigratableOlderVersion);
    }

    [Test]
    public async Task Compatibility_rules_cover_every_named_area()
    {
        await Assert.That(MessagingCompatibilityRules.IsComplete).IsTrue();

        var areas = MessagingCompatibilityRules.Rules.Select(static rule => rule.RuleArea).Distinct().ToArray();
        foreach (var expected in new[]
                 {
                     MessagingCompatibilityRules.Area.Clients,
                     MessagingCompatibilityRules.Area.Servers,
                     MessagingCompatibilityRules.Area.Streams,
                     MessagingCompatibilityRules.Area.Consumers,
                     MessagingCompatibilityRules.Area.KeyValueValues,
                     MessagingCompatibilityRules.Area.ObjectStoreMetadata,
                     MessagingCompatibilityRules.Area.RollingUpgrades,
                 })
        {
            await Assert.That(areas).Contains(expected);
        }
    }

    [Test]
    public async Task Rolling_upgrades_require_forward_and_rollback_artifacts_and_cannot_break_quorum_floors()
    {
        var rolling = MessagingCompatibilityRules.Rules.Where(
            static rule => rule.RuleArea == MessagingCompatibilityRules.Area.RollingUpgrades).ToArray();

        await Assert.That(rolling.Length).IsGreaterThanOrEqualTo(2);
        await Assert.That(rolling.Any(static rule => rule.Rule.Contains("rollback"))).IsTrue();
        await Assert.That(MessagingCompatibilityRules.Rules.Any(static rule =>
            rule.RuleArea == MessagingCompatibilityRules.Area.Servers &&
            rule.Rule.Contains("disruption budget"))).IsTrue();
    }
}
