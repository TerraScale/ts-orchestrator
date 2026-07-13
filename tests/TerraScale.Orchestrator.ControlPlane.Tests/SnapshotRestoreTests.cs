using TerraScale.Orchestrator.ControlPlane.Snapshots;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class SnapshotRestoreTests
{
    [Test]
    public async Task Plan_starts_replay_exactly_after_snapshot_and_is_deterministic()
    {
        var snapshot = SnapshotTestData.Snapshot();
        var context = SnapshotTestData.Context();

        var first = SnapshotRestorePlanner.Plan(snapshot, context);
        var replay = SnapshotRestorePlanner.Plan(snapshot, context);

        await Assert.That(first.IsPlanned).IsTrue();
        await Assert.That(first.Error).IsEqualTo(SnapshotRestorePlanError.None);
        await Assert.That(first.Plan!.ReplayStartSequence).IsEqualTo(SnapshotTestData.Sequence(102));
        await Assert.That(first.Plan.ExpectedRestoredEpoch).IsEqualTo(SnapshotTestData.Epoch(7));
        await Assert.That(first.Plan.ExpectedRestoredDigest).IsEqualTo(SnapshotTestData.Digest());
        await Assert.That(first.Plan.SnapshotId).IsEqualTo(SnapshotTestData.Id());
        await Assert.That(first.Plan.Generation).IsEqualTo(SnapshotTestData.Generation());
        await Assert.That(replay.Plan!.ReplayStartSequence).IsEqualTo(first.Plan.ReplayStartSequence);
        await Assert.That(first.Plan.ToString()).DoesNotContain("state-digest-secret");
    }

    [Test]
    public async Task Older_epoch_and_older_or_equal_position_never_produce_plan()
    {
        var staleEpoch = SnapshotRestorePlanner.Plan(
            SnapshotTestData.Snapshot(SnapshotTestData.Material(epoch: SnapshotTestData.Epoch(6))),
            SnapshotTestData.Context());
        var equal = SnapshotRestorePlanner.Plan(
            SnapshotTestData.Snapshot(SnapshotTestData.Material(sequence: SnapshotTestData.Sequence(100))),
            SnapshotTestData.Context());
        var older = SnapshotRestorePlanner.Plan(
            SnapshotTestData.Snapshot(SnapshotTestData.Material(sequence: SnapshotTestData.Sequence(99))),
            SnapshotTestData.Context());

        await Assert.That(staleEpoch.ValidationError).IsEqualTo(SnapshotValidationError.StaleEpoch);
        await Assert.That(equal.ValidationError).IsEqualTo(SnapshotValidationError.StreamRollback);
        await Assert.That(older.ValidationError).IsEqualTo(SnapshotValidationError.StreamRollback);
        await Assert.That(new[] { staleEpoch, equal, older }.Any(static result => result.IsPlanned)).IsFalse();
    }

    [Test]
    public async Task Maximum_stream_position_fails_closed_without_overflow()
    {
        var material = SnapshotTestData.Material(sequence: SnapshotTestData.Sequence(ulong.MaxValue));
        var result = SnapshotRestorePlanner.Plan(
            SnapshotTestData.Snapshot(material),
            SnapshotTestData.Context(currentSequence: SnapshotTestData.Sequence(1)));

        await Assert.That(result.IsPlanned).IsFalse();
        await Assert.That(result.Error).IsEqualTo(SnapshotRestorePlanError.ReplayStartOverflow);
        await Assert.That(result.Plan).IsNull();
    }
}
