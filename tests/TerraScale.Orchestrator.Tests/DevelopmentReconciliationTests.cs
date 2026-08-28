using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentReconciliationTests
{
    [Test]
    public async Task MissingProcessesProduceOnlyBoundedObservationIntents()
    {
        var topology = DevelopmentTopology.CreateRegional();

        var result = DevelopmentReconciliation.Evaluate(topology, 1, []);

        await Assert.That(result.DesiredResources).IsEqualTo(18);
        await Assert.That(result.ObservedResources).IsEqualTo(0);
        await Assert.That(result.ObserveIntents).IsEqualTo(18);
        await Assert.That(result.Errors).IsEmpty();
    }

    [Test]
    public async Task ReadyExactTopologyMustConvergeInDependencyOrder()
    {
        var topology = DevelopmentTopology.CreateRegional();
        var observations = topology.Cells.SelectMany(cell => cell.Resources)
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

        await Assert.That(result.ObservedResources).IsEqualTo(18);
        await Assert.That(result.ConvergedResources).IsEqualTo(18);
        await Assert.That(result.ReconcileIntents).IsEqualTo(0);
        await Assert.That(result.ObserveIntents).IsEqualTo(0);
        await Assert.That(result.HeldResources).IsEqualTo(0);
        await Assert.That(result.Errors).IsEmpty();
        var order = result.OrderedResources.ToList();
        await Assert.That(order.IndexOf("gru-control-nats-1"))
            .IsLessThan(order.IndexOf("gru-controller-1"));
        await Assert.That(order.IndexOf("gru-authentication"))
            .IsLessThan(order.IndexOf("gru-dashboard"));
    }

    [Test]
    public async Task ForeignObservationIsRejectedBeforePlanning()
    {
        var topology = DevelopmentTopology.CreateRegional();
        var foreign = new DevelopmentResourceObservation(
            "foreign",
            "gru",
            DevelopmentResourceKind.Dashboard,
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
    public async Task FailedRegionalDashboardIsHeldWithoutCrossRegionImpact()
    {
        var topology = DevelopmentTopology.CreateRegional();
        var observations = topology.Cells.SelectMany(cell => cell.Resources)
            .Select((resource, index) => new DevelopmentResourceObservation(
                resource.Name,
                resource.Cell,
                resource.Kind,
                resource.Replica,
                resource.Name == "sfo-dashboard" ? DevelopmentResourceState.Failed : DevelopmentResourceState.Ready,
                resource.Name != "sfo-dashboard",
                20_000 + index,
                $"container-{index}",
                null,
                resource.Name == "sfo-dashboard" ? "failed" : "ready",
                DateTimeOffset.UtcNow))
            .ToArray();

        var result = DevelopmentReconciliation.Evaluate(topology, 11, observations);

        await Assert.That(result.ConvergedResources).IsEqualTo(17);
        await Assert.That(result.ReconcileIntents).IsEqualTo(0);
        await Assert.That(result.HeldResources).IsEqualTo(1);
        await Assert.That(result.Errors).IsEmpty();
    }
}
