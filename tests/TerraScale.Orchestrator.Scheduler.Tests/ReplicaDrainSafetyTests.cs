using TerraScale.Orchestrator.Scheduler.Autoscaling;

namespace TerraScale.Orchestrator.Scheduler.Tests;

public sealed class ReplicaDrainSafetyTests
{
    private readonly ReplicaDrainSafetyEvaluator evaluator = new(new DrainPolicy(maxLagBytes: 1_048_576));

    [Test]
    public async Task UpCaughtUpAndReplicatedReplicaAllowsTheDrain()
    {
        // Survivors are up replicas of the same role kind hosted elsewhere:
        // the peer's distinct allocation plus the candidate's own observed
        // acknowledgements reach the replica floor.
        var decision = evaluator.Evaluate(
            Candidate([Replica(up: true, lagBytes: 0, peerAckCount: 1, minReplicas: 2)]),
            [Candidate([Replica(up: true, lagBytes: 0, peerAckCount: 0, minReplicas: 2, allocationId: "member-y")], "node-b")]);

        await Assert.That(decision.Allowed).IsTrue();
    }

    [Test]
    public async Task DownReplicaBlocksTheDrain()
    {
        var decision = evaluator.Evaluate(
            Candidate([Replica(up: false, lagBytes: 0, peerAckCount: 2, minReplicas: 2)]),
            [Candidate([Replica(up: true, lagBytes: 0, peerAckCount: 0, minReplicas: 2)], "node-b")]);

        await Assert.That(decision.Allowed).IsFalse();
        await Assert.That(decision.BlockingAllocationIds).Contains("member-x");
    }

    [Test]
    public async Task LaggingReplicaBlocksTheDrainAtTheExclusiveBound()
    {
        var decision = evaluator.Evaluate(
            Candidate([Replica(up: true, lagBytes: 1_048_576, peerAckCount: 2, minReplicas: 2)]),
            [Candidate([Replica(up: true, lagBytes: 0, peerAckCount: 0, minReplicas: 2)], "node-b")]);

        await Assert.That(decision.Allowed).IsFalse();
    }

    [Test]
    public async Task UnderReplicatedReplicaBlocksTheDrainEvenWhenPeersAreUp()
    {
        // Two replicas total; candidate's PeerAckCount already counts its own
        // quorum contribution, so peers are not summed again.
        var decision = evaluator.Evaluate(
            Candidate([Replica(up: true, lagBytes: 0, peerAckCount: 1, minReplicas: 3)]),
            [Candidate([Replica(up: true, lagBytes: 0, peerAckCount: 0, minReplicas: 3)], "node-b")]);

        await Assert.That(decision.Allowed).IsFalse();
    }

    [Test]
    public async Task BlockingAllocationIdsAreSortedAndDeduplicated()
    {
        var decision = evaluator.Evaluate(
            Candidate(
            [
                Replica(up: false, lagBytes: 0, peerAckCount: 2, minReplicas: 2, allocationId: "member-z"),
                Replica(up: true, lagBytes: 9_000_000, peerAckCount: 2, minReplicas: 2, allocationId: "member-a"),
            ]),
            []);

        await Assert.That(decision.Allowed).IsFalse();
        await Assert.That(string.Join(',', decision.BlockingAllocationIds)).IsEqualTo("member-a,member-z");
    }

    [Test]
    public async Task CandidateMayNotAppearAmongItsOwnPeers()
    {
        var candidate = Candidate([Replica(up: true, lagBytes: 0, peerAckCount: 1, minReplicas: 2)]);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            Task.Run(() => evaluator.Evaluate(candidate, [candidate])));
    }

    private static NodeDrainCandidate Candidate(IEnumerable<StatefulReplicaHealth> replicas, string nodeId = "node-a") =>
        new(nodeId, replicas);

    private static StatefulReplicaHealth Replica(
        bool up,
        long lagBytes,
        int peerAckCount,
        int minReplicas,
        string allocationId = "member-x") =>
        new("terrabase-member", allocationId, up, peerAckCount, minReplicas, lagBytes);
}
