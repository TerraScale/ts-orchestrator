using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// The direct-delivery mutation endpoint must not share the controller queue group: only the
/// authority leader can execute a mutation, so queue-group load balancing would route requests
/// to followers that can only deny. The endpoint opts out of the group and the handler drops
/// every non-leader request — the leader receives its own copy and answers it.
/// </summary>
public sealed class NatsRuntimeEndpointTests
{
    [Test]
    public async Task OnlyTheCurrentLeaderServesDirectDeliveryRequests()
    {
        // A follower — even a ready one — never executes nor replies: serving would produce
        // an authorization-shaped denial for a request only the leader can run.
        await Assert.That(NatsRuntime.ServesDirectDeliveryRequests(
            Snapshot("follower", false, epoch: 7, revision: 21))).IsFalse();
        await Assert.That(NatsRuntime.ServesDirectDeliveryRequests(
            Snapshot("unavailable", false, epoch: 7, revision: 21))).IsFalse();
        await Assert.That(NatsRuntime.ServesDirectDeliveryRequests(
            Snapshot("leader", true, epoch: 7, revision: 21))).IsTrue();
    }

    [Test]
    public async Task DirectDeliveryServiceOptsOutOfTheSharedQueueGroup()
    {
        var topology = new NatsTopology("gru", 3, "i1");
        var config = NatsRuntime.DirectDeliveryServiceConfig(topology, "i1");

        await Assert.That(config.UseQueueGroup).IsFalse();
        await Assert.That(config.Name).IsEqualTo($"{topology.ServiceName}_direct_delivery");
        await Assert.That(config.Metadata?["cell"]).IsEqualTo("gru");
    }

    private static RegionalAuthoritySnapshot Snapshot(
        string state,
        bool leader,
        long epoch,
        long revision) => new(
        state,
        leader,
        epoch,
        revision,
        DateTimeOffset.UtcNow.AddMinutes(1),
        DateTimeOffset.UtcNow,
        null);
}
