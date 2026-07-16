using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentReconciliationTests
{
    [Test]
    public async Task MissingProcessesProduceOnlyBoundedObservationIntents()
    {
        var topology = DevelopmentTopology.CreateThreeCellR3();

        var result = DevelopmentReconciliation.Evaluate(topology, 1, []);

        await Assert.That(result.DesiredResources).IsEqualTo(47);
        await Assert.That(result.ObservedResources).IsEqualTo(0);
        await Assert.That(result.ObserveIntents).IsEqualTo(47);
        await Assert.That(result.Errors).IsEmpty();
    }

    [Test]
    public async Task ReadyExactTopologyMustConvergeInDependencyOrder()
    {
        var topology = DevelopmentTopology.CreateThreeCellR3();
        var observations = topology.Cells.SelectMany(cell => cell.Resources)
            .Concat(topology.GlobalResources)
            .Select((resource, index) => new DevelopmentResourceObservation(
                resource.Name,
                resource.Cell,
                resource.Kind,
                resource.Replica,
                DevelopmentResourceState.Ready,
                true,
                10_000 + index,
                null,
                "ready",
                DateTimeOffset.UtcNow))
            .ToArray();

        var result = DevelopmentReconciliation.Evaluate(topology, 7, observations);

        await Assert.That(result.ObservedResources).IsEqualTo(47);
        await Assert.That(result.ConvergedResources).IsEqualTo(47);
        await Assert.That(result.ReconcileIntents).IsEqualTo(0);
        await Assert.That(result.ObserveIntents).IsEqualTo(0);
        await Assert.That(result.HeldResources).IsEqualTo(0);
        await Assert.That(result.Errors).IsEmpty();
        var order = result.OrderedResources.ToList();
        await Assert.That(order.IndexOf("gru-control-nats-1"))
            .IsLessThan(order.IndexOf("gru-controller-1"));
        await Assert.That(order.IndexOf("gru-authentication"))
            .IsLessThan(order.IndexOf("gru-api"));
        await Assert.That(order.IndexOf("gru-api"))
            .IsLessThan(order.IndexOf("gru-dashboard"));
    }

    [Test]
    public async Task ForeignObservationIsRejectedBeforePlanning()
    {
        var topology = DevelopmentTopology.CreateThreeCellR3();
        var foreign = new DevelopmentResourceObservation(
            "foreign",
            "gru",
            DevelopmentResourceKind.Api,
            1,
            DevelopmentResourceState.Ready,
            true,
            123,
            null,
            "ready",
            DateTimeOffset.UtcNow);

        await Assert.That(() => DevelopmentReconciliation.Evaluate(topology, 1, [foreign]))
            .Throws<InvalidOperationException>();
    }
}
