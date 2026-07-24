using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentReconciliationTests
{
    [Test]
    public async Task MissingProcessesProduceOnlyBoundedObservationIntents()
    {
        var topology = DevelopmentTopology.CreateRegional();

        var result = DevelopmentReconciliation.Evaluate(topology, 1, []);

        await Assert.That(result.DesiredResources).IsEqualTo(22);
        await Assert.That(result.ObservedResources).IsEqualTo(0);
        await Assert.That(result.ObserveIntents).IsEqualTo(22);
        await Assert.That(result.Errors).IsEmpty();
    }

    [Test]
    public async Task ReadyExactTopologyMustConvergeInDependencyOrder()
    {
        var topology = DevelopmentTopology.CreateRegional();
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
                $"container-{index}",
                null,
                "ready",
                DateTimeOffset.UtcNow))
            .ToArray();

        var result = DevelopmentReconciliation.Evaluate(topology, 7, observations);

        await Assert.That(result.ObservedResources).IsEqualTo(22);
        await Assert.That(result.ConvergedResources).IsEqualTo(22);
        await Assert.That(result.ReconcileIntents).IsEqualTo(0);
        await Assert.That(result.ObserveIntents).IsEqualTo(0);
        await Assert.That(result.HeldResources).IsEqualTo(0);
        await Assert.That(result.Errors).IsEmpty();
        var order = result.OrderedResources.ToList();
        await Assert.That(order.IndexOf("gru-control-nats-1"))
            .IsLessThan(order.IndexOf("gru-controller-1"));
        await Assert.That(order.IndexOf("gru-authentication"))
            .IsLessThan(order.IndexOf("gru-platform"));
        await Assert.That(order.IndexOf("gru-platform"))
            .IsLessThan(order.IndexOf("gru-dashboard"));
    }

    [Test]
    public async Task ForeignObservationIsRejectedBeforePlanning()
    {
        var topology = DevelopmentTopology.CreateRegional();
        var foreign = new DevelopmentResourceObservation(
            "foreign",
            "gru",
            DevelopmentResourceKind.Platform,
            1,
            DevelopmentResourceState.Ready,
            true,
            123,
            "foreign-container",
            null,
            "ready",
            DateTimeOffset.UtcNow);

        await Assert.That(() => DevelopmentReconciliation.Evaluate(topology, 1, [foreign]))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task FailedRegionalApiAndItsDashboardAreHeldWithoutCrossRegionImpact()
    {
        var topology = DevelopmentTopology.CreateRegional();
        var observations = topology.Cells.SelectMany(cell => cell.Resources)
            .Concat(topology.GlobalResources)
            .Select((resource, index) => new DevelopmentResourceObservation(
                resource.Name,
                resource.Cell,
                resource.Kind,
                resource.Replica,
                resource.Name == "sfo-platform" ? DevelopmentResourceState.Failed : DevelopmentResourceState.Ready,
                resource.Name != "sfo-platform",
                20_000 + index,
                $"container-{index}",
                null,
                resource.Name == "sfo-platform" ? "failed" : "ready",
                DateTimeOffset.UtcNow))
            .ToArray();

        var result = DevelopmentReconciliation.Evaluate(topology, 11, observations);

        await Assert.That(result.ConvergedResources).IsEqualTo(20);
        await Assert.That(result.ReconcileIntents).IsEqualTo(0);
        await Assert.That(result.HeldResources).IsEqualTo(2);
        await Assert.That(result.Errors).IsEmpty();
    }
}
