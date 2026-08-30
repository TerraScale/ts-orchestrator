using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Protocol.Tests;

public sealed class DurableWorkInventoryTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 25, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task The_inventory_is_complete_and_well_formed()
    {
        await Assert.That(DurableWorkInventory.IsComplete).IsTrue();
        await Assert.That(DurableWorkInventory.CompletenessViolations()).IsEmpty();
    }

    [Test]
    public async Task Every_durable_stream_declares_the_full_policy_surface()
    {
        var names = DurableWorkInventory.Streams.Select(static stream => stream.Stream).ToArray();
        await Assert.That(names).IsEquivalentTo(["CELL_SPEC", "CELL_OPERATIONS", "CELL_EVENTS", "GLOBAL_SPEC", "GLOBAL_CI"]);

        foreach (var stream in DurableWorkInventory.Streams)
        {
            await Assert.That(stream.Retention).IsEqualTo(DurableStreamRetention.Limits);
            await Assert.That(stream.Discard).IsEqualTo(DurableStreamDiscard.Old);
            await Assert.That(stream.Replicas).IsEqualTo(3);
            await Assert.That(stream.MaximumAge).IsEqualTo(TimeSpan.FromDays(30));
            await Assert.That(stream.DuplicateWindow.IsWellFormed).IsTrue();
        }

        var global = DurableWorkInventory.Streams.Single(stream => stream.Stream == "GLOBAL_CI");
        await Assert.That(global.TerminalEvidenceBehavior).Contains("terminate");
        await Assert.That(global.Domain).IsEqualTo(DurableWorkDomain.GlobalControl);
        await Assert.That(global.SemanticClass).IsEqualTo(MessagingSemanticClass.WorkQueue);
        await Assert.That(global.DuplicateWindow.Window).IsEqualTo(TimeSpan.FromHours(24));
        await Assert.That(global.MaximumBytes).IsEqualTo(1024L * 1024 * 1024);

        var regional = DurableWorkInventory.Streams.Single(stream => stream.Stream == "CELL_SPEC");
        await Assert.That(regional.TerminalEvidenceBehavior).Contains("terminate");
        await Assert.That(regional.Domain).IsEqualTo(DurableWorkDomain.RegionalCell);
        await Assert.That(regional.DuplicateWindow.Window).IsEqualTo(TimeSpan.FromMinutes(2));
    }

    [Test]
    public async Task Regional_stream_templates_instantiate_only_valid_cell_tokens()
    {
        var regional = DurableWorkInventory.Streams.Single(stream => stream.Stream == "CELL_EVENTS");

        await Assert.That(regional.SubjectFor("gru"))
            .IsEquivalentTo([
                NatsSubjectTaxonomy.RegionalFamilyPattern(
                    "gru", NatsSubjectTaxonomy.ObservationFamilySegment),
            ]);
        await Assert.That(() => regional.SubjectFor("GRU")).Throws<ArgumentException>();
        await Assert.That(() => regional.SubjectFor("bad cell")).Throws<ArgumentException>();

        var consumer = DurableWorkInventory.Consumers.Single(plan => plan.Consumer == "gitops_cell_spec_{instance}");
        await Assert.That(consumer.FilterSubjectFor("sfo"))
            .IsEqualTo(NatsSubjectTaxonomy.CellSpecSubject("sfo"));
    }

    [Test]
    public async Task Every_durable_consumer_satisfies_the_bounded_redelivery_contract()
    {
        foreach (var consumer in DurableWorkInventory.Consumers)
        {
            await Assert.That(DurableWorkInventory.Redelivery.BoundedBy(consumer)).IsTrue();
            await Assert.That(consumer.Acknowledgement).IsEqualTo(DurableAcknowledgement.Explicit);
            await Assert.That(consumer.AckWait).IsEqualTo(TimeSpan.FromSeconds(1));
            await Assert.That(consumer.MaximumDeliveries).IsEqualTo(5);
            await Assert.That(consumer.MaximumAckPending).IsGreaterThanOrEqualTo(1);
        }

        var runners = DurableWorkInventory.Consumers.Single(plan => plan.Consumer == "ci_runner_{zone}_{runner}");
        await Assert.That(runners.Ownership).IsEqualTo(DurableWorkOwnership.ReconciledRunnerIdentity);
        await Assert.That(runners.MaximumAckPending).IsEqualTo(1);
        await Assert.That(runners.MaximumBatch).IsEqualTo(1);
        await Assert.That(runners.MaximumExpires).IsEqualTo(TimeSpan.FromSeconds(30));
        await Assert.That(runners.MaximumWaiting).IsEqualTo(4);

        var trigger = DurableWorkInventory.Consumers.Single(plan => plan.Consumer == "global_ci_trigger");
        await Assert.That(trigger.Ownership).IsEqualTo(DurableWorkOwnership.GlobalFencedAuthority);

        var startup = DurableWorkInventory.Consumers.Single(plan => plan.Consumer == "runtime_startup");
        await Assert.That(startup.Ownership).IsEqualTo(DurableWorkOwnership.RegionalEquivalentWorkers);
        await Assert.That(startup.MaximumAckPending).IsEqualTo(32);
    }

    [Test]
    public async Task Queue_groups_stay_regional_and_equivalent_worker_only()
    {
        var names = DurableWorkInventory.QueueGroups.Select(static group => group.Group).ToArray();
        await Assert.That(names).IsEquivalentTo(
            ["orchestrator_{cell}", "terrascale_orchestrator_journal_writer_{cell}"]);

        foreach (var group in DurableWorkInventory.QueueGroups)
        {
            await Assert.That(group.Domain).IsEqualTo(DurableWorkDomain.RegionalCell);
            await Assert.That(group.FencingBasis).IsNotEmpty();
        }

        var writer = DurableWorkInventory.QueueGroups.Single(group =>
            group.Group == "terrascale_orchestrator_journal_writer_{cell}");
        await Assert.That(writer.FencingBasis).Contains("epoch");
    }

    [Test]
    public async Task The_duplicate_window_inspection_never_records_observations()
    {
        var window = new MessageIdDuplicateWindow(TimeSpan.FromMinutes(2), capacity: 4);

        await Assert.That(window.Inspect("m1", "d1", Now))
            .IsEqualTo(DuplicateWindowDecision.Admit);
        await Assert.That(window.Count).IsEqualTo(0);
        await Assert.That(window.Observe("m1", "d1", Now))
            .IsEqualTo(DuplicateWindowDecision.Admit);
        await Assert.That(window.Count).IsEqualTo(1);
        await Assert.That(window.Inspect("m1", "d1", Now))
            .IsEqualTo(DuplicateWindowDecision.Suppress);
        await Assert.That(window.Inspect("m1", "d2", Now))
            .IsEqualTo(DuplicateWindowDecision.Conflict);
        await Assert.That(
                window.Inspect("m1", "d1", Now.AddMinutes(3)))
            .IsEqualTo(DuplicateWindowDecision.AdmitBeyondWindow);
        await Assert.That(window.Count).IsEqualTo(1);
        await Assert.That(window.Inspect("", "d1", Now))
            .IsEqualTo(DuplicateWindowDecision.Admit);
    }

    [Test]
    public async Task Duplicate_window_decisions_map_to_delivery_actions_fail_closed()
    {
        await Assert.That(DuplicateWindowDelivery.Decide(DuplicateWindowDecision.Admit))
            .IsEqualTo(DuplicateWindowDeliveryAction.Process);
        await Assert.That(DuplicateWindowDelivery.Decide(DuplicateWindowDecision.AdmitBeyondWindow))
            .IsEqualTo(DuplicateWindowDeliveryAction.Process);
        await Assert.That(DuplicateWindowDelivery.Decide(DuplicateWindowDecision.Suppress))
            .IsEqualTo(DuplicateWindowDeliveryAction.AcknowledgeSuppressedReplay);
        await Assert.That(DuplicateWindowDelivery.Decide(DuplicateWindowDecision.Conflict))
            .IsEqualTo(DuplicateWindowDeliveryAction.TerminateConflictingIdentity);
        await Assert.That(DuplicateWindowDelivery.Decide(DuplicateWindowDecision.Unspecified))
            .IsEqualTo(DuplicateWindowDeliveryAction.Unspecified);
    }

    [Test]
    public async Task The_canonical_inventory_document_carries_every_declared_row()
    {
        var document = File.ReadAllText(Path.Combine(
            FindRepositoryRoot(), "docs", "contracts", "durable-work-inventory.md"));

        foreach (var stream in DurableWorkInventory.Streams)
        {
            await Assert.That(document.Contains($"| `{stream.Stream}` |", StringComparison.Ordinal))
                .IsTrue()
                .Because($"the canonical inventory must carry the stream {stream.Stream}");
        }

        foreach (var consumer in DurableWorkInventory.Consumers)
        {
            await Assert.That(document.Contains($"| `{consumer.Consumer}` |", StringComparison.Ordinal))
                .IsTrue()
                .Because($"the canonical inventory must carry the consumer {consumer.Consumer}");
        }

        foreach (var group in DurableWorkInventory.QueueGroups)
        {
            await Assert.That(document.Contains($"| `{group.Group}` |", StringComparison.Ordinal))
                .IsTrue()
                .Because($"the canonical inventory must carry the queue group {group.Group}");
        }

        // The document must not weaken the delivery claim: effectively-once only.
        await Assert.That(document.Contains("never exactly-once delivery", StringComparison.Ordinal))
            .IsTrue();
    }

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null;
             directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "TerraScale.Orchestrator.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException(
            "The repository root was not found; the durable-work-inventory drift test must run from the repository.");
    }
}
