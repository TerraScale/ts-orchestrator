using TerraScale.Orchestrator.ControlPlane.Snapshots;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class SnapshotGenerationAntiRollbackRegressionTests
{
    [Test]
    public async Task Older_snapshot_generation_cannot_authorize_restore_at_a_later_stream_position()
    {
        var previouslyAcceptedGeneration = SnapshotTestData.Generation(3);
        var staleGeneration = SnapshotTestData.Generation(previouslyAcceptedGeneration.Value - 1);
        var result = SnapshotRestorePlanner.Plan(
            SnapshotTestData.Snapshot(SnapshotTestData.Material(
                generation: staleGeneration,
                sequence: SnapshotTestData.Sequence(102))),
            SnapshotTestData.Context(
                currentSequence: SnapshotTestData.Sequence(101),
                currentGeneration: previouslyAcceptedGeneration));

        await Assert.That(result.IsPlanned).IsFalse();
        await Assert.That(result.Error).IsEqualTo(SnapshotRestorePlanError.SnapshotRejected);
        await Assert.That(result.ValidationError).IsEqualTo(SnapshotValidationError.GenerationRollback);
        await Assert.That(result.Plan).IsNull();
    }

    [Test]
    public async Task Equal_snapshot_generation_remains_valid_at_a_later_stream_position()
    {
        var generation = SnapshotTestData.Generation(3);
        var result = SnapshotRestorePlanner.Plan(
            SnapshotTestData.Snapshot(SnapshotTestData.Material(
                generation: generation,
                sequence: SnapshotTestData.Sequence(102))),
            SnapshotTestData.Context(
                currentSequence: SnapshotTestData.Sequence(101),
                currentGeneration: generation));

        await Assert.That(result.IsPlanned).IsTrue();
        await Assert.That(result.Error).IsEqualTo(SnapshotRestorePlanError.None);
        await Assert.That(result.ValidationError).IsEqualTo(SnapshotValidationError.None);
        await Assert.That(result.Plan!.Generation).IsEqualTo(generation);
        await Assert.That(result.Plan.ReplayStartSequence).IsEqualTo(SnapshotTestData.Sequence(103));
    }
}

