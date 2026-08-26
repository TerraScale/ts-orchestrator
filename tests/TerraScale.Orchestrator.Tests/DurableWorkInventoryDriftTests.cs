using NATS.Client.JetStream.Models;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Issue #22 inventory drift: the typed durable work inventory is the contract; the
/// provisioning topologies are the implementation. Any divergence between the two is a
/// failure — adding a stream, changing a window, or loosening a consumer profile must be an
/// explicit contract change, never a silent topology edit.
/// </summary>
public sealed class DurableWorkInventoryDriftTests
{
    private const string Cell = "gru";
    private const string Instance = "controller-1";

    [Test]
    public async Task Regional_topology_streams_match_the_inventory_exactly()
    {
        var topology = new NatsTopology(Cell, 3, Instance);
        var plans = DurableWorkInventory.Streams
            .Where(plan => plan.Domain == DurableWorkDomain.RegionalCell)
            .ToDictionary(plan => plan.Stream, plan => plan);

        await Assert.That(topology.Streams.Select(static stream => stream.Name!))
            .IsEquivalentTo(plans.Keys);

        foreach (var stream in topology.Streams)
        {
            var plan = plans[stream.Name!];
            await Assert.That(stream.Subjects).IsEquivalentTo(plan.SubjectFor(Cell));
            await Assert.That(stream.NumReplicas).IsEqualTo(plan.Replicas);
            await Assert.That(stream.Retention).IsEqualTo(StreamConfigRetention.Limits);
            await Assert.That(stream.MaxAge).IsEqualTo(plan.MaximumAge);
            await Assert.That(stream.MaxBytes).IsEqualTo(plan.MaximumBytes);
            await Assert.That(stream.Discard).IsEqualTo(StreamConfigDiscard.Old);
            await Assert.That(stream.Storage).IsEqualTo(StreamConfigStorage.File);
            await Assert.That(stream.DuplicateWindow).IsEqualTo(plan.DuplicateWindow.Window);
        }

        var cellSpec = topology.Streams.Single(stream => stream.Name == "CELL_SPEC");
        var cellEvents = topology.Streams.Single(stream => stream.Name == "CELL_EVENTS");
        await Assert.That(cellSpec.DuplicateWindow).IsEqualTo(DuplicateWindowPolicy.CellStreams.Window);
        await Assert.That(cellEvents.DuplicateWindow).IsEqualTo(DuplicateWindowPolicy.CellStreams.Window);
    }

    [Test]
    public async Task Global_topology_streams_match_the_inventory_exactly()
    {
        var topology = new GlobalNatsTopology(3);
        var plans = DurableWorkInventory.Streams
            .Where(plan => plan.Domain == DurableWorkDomain.GlobalControl)
            .ToDictionary(plan => plan.Stream, plan => plan);

        await Assert.That(topology.Streams.Select(static stream => stream.Name!))
            .IsEquivalentTo(plans.Keys);

        foreach (var stream in topology.Streams)
        {
            var plan = plans[stream.Name!];
            await Assert.That(stream.Subjects).IsEquivalentTo(plan.SubjectFor(Cell));
            await Assert.That(stream.NumReplicas).IsEqualTo(plan.Replicas);
            await Assert.That(stream.Retention).IsEqualTo(StreamConfigRetention.Limits);
            await Assert.That(stream.MaxAge).IsEqualTo(plan.MaximumAge);
            await Assert.That(stream.MaxBytes).IsEqualTo(plan.MaximumBytes);
            await Assert.That(stream.Discard).IsEqualTo(StreamConfigDiscard.Old);
            await Assert.That(stream.Storage).IsEqualTo(StreamConfigStorage.File);
            await Assert.That(stream.DuplicateWindow).IsEqualTo(plan.DuplicateWindow.Window);
        }

        var ci = topology.Streams.Single(stream => stream.Name == GlobalNatsTopology.CiStream);
        await Assert.That(ci.DuplicateWindow).IsEqualTo(DuplicateWindowPolicy.GlobalCiStream.Window);
        var specification = topology.Streams.Single(stream => stream.Name == GlobalNatsTopology.CellSpecStream);
        await Assert.That(specification.DuplicateWindow).IsEqualTo(DuplicateWindowPolicy.CellStreams.Window);
    }

    [Test]
    public async Task Regional_consumer_profiles_match_the_inventory_exactly()
    {
        var topology = new NatsTopology(Cell, 3, Instance);
        var startup = Plan("runtime_startup");
        var cellSpec = Plan("gitops_cell_spec_{instance}");

        await Assert.That(topology.StartupConsumer.Name).IsEqualTo(startup.Consumer);
        await Assert.That(topology.StartupConsumer.FilterSubject).IsEqualTo(startup.FilterSubjectFor(Cell));
        await Assert.That(topology.StartupConsumer.AckPolicy).IsEqualTo(ConsumerConfigAckPolicy.Explicit);
        await Assert.That(topology.StartupConsumer.MaxDeliver).IsEqualTo(startup.MaximumDeliveries);
        await Assert.That(topology.StartupConsumer.Backoff).IsEquivalentTo(startup.BackoffLadder);
        await Assert.That(topology.StartupConsumer.AckWait).IsEqualTo(startup.AckWait);
        await Assert.That(topology.StartupConsumer.MaxAckPending).IsEqualTo(startup.MaximumAckPending);
        await Assert.That(topology.StartupConsumer.MaxWaiting).IsEqualTo(startup.MaximumWaiting!.Value);

        await Assert.That(topology.CellSpecConsumer.Name)
            .IsEqualTo(cellSpec.Consumer.Replace("{instance}", Instance, StringComparison.Ordinal));
        await Assert.That(topology.CellSpecConsumer.FilterSubject).IsEqualTo(cellSpec.FilterSubjectFor(Cell));
        await Assert.That(topology.CellSpecConsumer.DeliverPolicy).IsEqualTo(ConsumerConfigDeliverPolicy.All);
        await Assert.That(topology.CellSpecConsumer.ReplayPolicy).IsEqualTo(ConsumerConfigReplayPolicy.Instant);
        await Assert.That(topology.CellSpecConsumer.MaxDeliver).IsEqualTo(cellSpec.MaximumDeliveries);
        await Assert.That(topology.CellSpecConsumer.Backoff).IsEquivalentTo(cellSpec.BackoffLadder);
        await Assert.That(topology.CellSpecConsumer.MaxAckPending).IsEqualTo(cellSpec.MaximumAckPending);
        await Assert.That(topology.CellSpecConsumer.MaxBatch).IsEqualTo(cellSpec.MaximumBatch!.Value);
        await Assert.That(topology.CellSpecConsumer.MaxExpires).IsEqualTo(cellSpec.MaximumExpires!.Value);
        await Assert.That(topology.CellSpecConsumer.MaxWaiting).IsEqualTo(cellSpec.MaximumWaiting!.Value);
    }

    [Test]
    public async Task Global_consumer_profiles_match_the_inventory_exactly()
    {
        var topology = new GlobalNatsTopology(3);
        var trigger = Plan("global_ci_trigger");
        var proof = Plan("global_ci_runtime_proof");
        var cellSpec = Plan("gitops_global_cell_spec_{cell}");
        var runner = Plan("ci_runner_{zone}_{runner}");

        await Assert.That(topology.CiConsumer.Name).IsEqualTo(trigger.Consumer);
        await Assert.That(topology.CiConsumer.FilterSubject).IsEqualTo(trigger.FilterSubject);
        await Assert.That(topology.CiConsumer.AckPolicy).IsEqualTo(ConsumerConfigAckPolicy.Explicit);
        await Assert.That(topology.CiConsumer.MaxDeliver).IsEqualTo(trigger.MaximumDeliveries);
        await Assert.That(topology.CiConsumer.Backoff).IsEquivalentTo(trigger.BackoffLadder);
        await Assert.That(topology.CiConsumer.MaxAckPending).IsEqualTo(trigger.MaximumAckPending);
        await Assert.That(topology.CiConsumer.MaxWaiting).IsEqualTo(trigger.MaximumWaiting!.Value);

        await Assert.That(topology.CiRuntimeProofConsumer.Name).IsEqualTo(proof.Consumer);
        await Assert.That(topology.CiRuntimeProofConsumer.FilterSubject).IsEqualTo(proof.FilterSubject);
        await Assert.That(topology.CiRuntimeProofConsumer.MaxDeliver).IsEqualTo(proof.MaximumDeliveries);
        await Assert.That(topology.CiRuntimeProofConsumer.Backoff).IsEquivalentTo(proof.BackoffLadder);
        await Assert.That(topology.CiRuntimeProofConsumer.MaxAckPending).IsEqualTo(proof.MaximumAckPending);
        await Assert.That(topology.CiRuntimeProofConsumer.MaxBatch).IsEqualTo(proof.MaximumBatch!.Value);
        await Assert.That(topology.CiRuntimeProofConsumer.MaxExpires).IsEqualTo(proof.MaximumExpires!.Value);
        await Assert.That(topology.CiRuntimeProofConsumer.MaxWaiting).IsEqualTo(proof.MaximumWaiting!.Value);

        var cell = "sfo";
        await Assert.That(topology.CellSpecConsumer(cell).Name)
            .IsEqualTo(cellSpec.Consumer.Replace("{cell}", cell, StringComparison.Ordinal));
        await Assert.That(topology.CellSpecConsumer(cell).FilterSubject)
            .IsEqualTo(cellSpec.FilterSubjectFor(cell));
        await Assert.That(topology.CellSpecConsumer(cell).MaxAckPending).IsEqualTo(cellSpec.MaximumAckPending);
        await Assert.That(topology.CellSpecConsumer(cell).MaxBatch).IsEqualTo(cellSpec.MaximumBatch!.Value);

        // The runner inbox name is derived (zone underscores plus runner identity hash); the
        // profile must still be the inventory's fenced per-runner shape with pending 1.
        var observedRunner = topology.CiJobConsumer("untrusted-product", "runner-static");
        var runnerPrefix = runner.FilterSubject
            .Replace("{zone}", "untrusted-product", StringComparison.Ordinal)[..^"{runner}".Length];
        await Assert.That(observedRunner.Name)
            .StartsWith("ci_runner_untrusted_product_");
        await Assert.That(observedRunner.FilterSubject)
            .StartsWith(runnerPrefix);
        await Assert.That(observedRunner.MaxAckPending).IsEqualTo(runner.MaximumAckPending);
        await Assert.That(observedRunner.MaxBatch).IsEqualTo(runner.MaximumBatch!.Value);
        await Assert.That(observedRunner.MaxExpires).IsEqualTo(runner.MaximumExpires!.Value);
        await Assert.That(observedRunner.MaxWaiting).IsEqualTo(runner.MaximumWaiting!.Value);
        await Assert.That(observedRunner.MaxDeliver).IsEqualTo(runner.MaximumDeliveries);
        await Assert.That(observedRunner.Backoff).IsEquivalentTo(runner.BackoffLadder);
    }

    [Test]
    public async Task Queue_group_plans_match_the_regional_topology()
    {
        var topology = new NatsTopology(Cell, 3, Instance);
        var service = DurableWorkInventory.QueueGroups
            .Single(group => group.Group == "orchestrator_{cell}");
        var writer = DurableWorkInventory.QueueGroups
            .Single(group => group.Group == "terrascale_orchestrator_journal_writer_{cell}");

        await Assert.That(topology.ServiceQueueGroup)
            .IsEqualTo(service.Group.Replace("{cell}", Cell, StringComparison.Ordinal));
        await Assert.That(topology.OperationJournalWriterQueueGroup)
            .IsEqualTo(writer.Group.Replace("{cell}", Cell, StringComparison.Ordinal));
    }

    [Test]
    public async Task The_inventory_names_every_consumer_the_runtimes_reconcile()
    {
        // Every consumer name a runtime opens or reconciles must be declared by the inventory:
        // this is the completeness half of the drift binding (no undeclared durable consumer).
        var topology = new NatsTopology(Cell, 3, Instance);
        var global = new GlobalNatsTopology(3);
        var declared = DurableWorkInventory.Consumers.Select(static plan => plan.Consumer).ToHashSet();
        var templates = new[]
        {
            topology.StartupConsumer.Name!,
            topology.CellSpecConsumer.Name!,
            global.CiConsumer.Name!,
            global.CiRuntimeProofConsumer.Name!,
            global.CellSpecConsumer("sfo").Name!,
            global.CiJobConsumer("trusted-build", "runner-static").Name!,
        };

        foreach (var observed in templates)
        {
            await Assert.That(declared.Any(template =>
                TemplatesMatch(template, observed))).IsTrue();
        }

        await Assert.That(() => global.CiJobConsumer("production-release", "runner-static"))
            .Throws<ArgumentException>();
    }

    private static bool TemplatesMatch(string template, string observed)
    {
        // A template matches an observed name when every literal segment outside the
        // placeholders is a prefix/suffix of the observed name.
        var segments = template.Split('{', '}');
        if (segments.Length == 1) return string.Equals(template, observed, StringComparison.Ordinal);
        var head = segments[0];
        var tail = segments[^1];
        return observed.Length >= head.Length + tail.Length &&
               observed.StartsWith(head, StringComparison.Ordinal) &&
               (tail.Length == 0 || observed.EndsWith(tail, StringComparison.Ordinal));
    }

    private static DurableConsumerPlan Plan(string consumer) =>
        DurableWorkInventory.Consumers.Single(plan => plan.Consumer == consumer);
}
