using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsCellConvergenceJournalTests
{
    private const string ApiV1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ApiV2 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ApiV3 = "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Test]
    public async Task DecisionIsDurableBeforeDispatchAndExactRetriesRecoverIt()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var accepted = Accepted(null, Plan(1, ApiV1));
        var journal = new NativeGitOpsCellConvergenceJournal(ledger);

        var first = await Advance(journal, accepted, [], watermark: 1);
        var recovered = await new NativeGitOpsCellConvergenceJournal(ledger).ReadAsync("gru");
        var duplicate = await Advance(new(ledger), accepted, [], watermark: 1);

        await Assert.That(first.Disposition).IsEqualTo(NativeGitOpsCellConvergenceJournalDisposition.Recorded);
        await Assert.That(first.CanDispatch).IsTrue();
        await Assert.That(first.Checkpoint!.Decision.Intent!.Kind)
            .IsEqualTo(NativeGitOpsCellConvergenceIntentKind.Observe);
        await Assert.That(recovered!.CheckpointDigest).IsEqualTo(first.Checkpoint.CheckpointDigest);
        await Assert.That(duplicate.Disposition).IsEqualTo(NativeGitOpsCellConvergenceJournalDisposition.Duplicate);
        await Assert.That(duplicate.Checkpoint!.JournalRevision).IsEqualTo(first.Checkpoint.JournalRevision);

        var absent = Absent(sequence: 2);
        var apply = await Advance(journal, accepted, [absent], watermark: 2);
        await Assert.That(apply.CanDispatch).IsTrue();
        await Assert.That(apply.Checkpoint!.Decision.Intent!.Kind)
            .IsEqualTo(NativeGitOpsCellConvergenceIntentKind.Apply);
        await Assert.That(apply.Checkpoint.CheckpointSequence).IsEqualTo(2);
        await Assert.That(apply.Checkpoint.PreviousCheckpointDigest)
            .IsEqualTo(first.Checkpoint.CheckpointDigest);

        var applying = Present(
            accepted,
            NativeGitOpsWorkloadState.Applying,
            sequence: 2);
        var stale = await Advance(journal, accepted, [applying], watermark: 2);
        await Assert.That(stale.Disposition)
            .IsEqualTo(NativeGitOpsCellConvergenceJournalDisposition.StaleObservation);
        await Assert.That(stale.Checkpoint!.CheckpointDigest).IsEqualTo(apply.Checkpoint.CheckpointDigest);
    }

    [Test]
    public async Task MutationCrashAndAuthorityLossNeverCreateDispatchAuthority()
    {
        var accepted = Accepted(null, Plan(1, ApiV1));
        var crashingLedger = new ForgejoWebhookJournalTests.TestLedger(failOnMutation: 1);
        var crashing = new NativeGitOpsCellConvergenceJournal(crashingLedger);

        await Assert.That(async () => await Advance(crashing, accepted, [], watermark: 1))
            .Throws<IOException>();
        await Assert.That(crashingLedger.Values).IsEmpty();
        var retried = await Advance(new(crashingLedger), accepted, [], watermark: 1);
        await Assert.That(retried.CanDispatch).IsTrue();

        var staleLedger = new ForgejoWebhookJournalTests.TestLedger();
        var stale = await Advance(
            new(staleLedger),
            accepted,
            [],
            watermark: 1,
            authorityStillValid: false);
        await Assert.That(stale.Disposition)
            .IsEqualTo(NativeGitOpsCellConvergenceJournalDisposition.StaleAuthority);
        await Assert.That(stale.CanDispatch).IsFalse();
        await Assert.That(staleLedger.Values).IsEmpty();
    }

    [Test]
    public async Task GenerationsBaseOnDurableHistoryAndFencedTakeoverGetsANewCheckpoint()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NativeGitOpsCellConvergenceJournal(ledger);
        var generation1Content = Plan(1, ApiV1);
        var generation1 = Accepted(null, generation1Content);
        var first = await Advance(
            journal,
            generation1,
            [Present(generation1, NativeGitOpsWorkloadState.Healthy, 10)],
            watermark: 10);
        await Assert.That(first.CanAdvanceGlobal).IsTrue();

        var generation2 = Accepted(generation1Content, Plan(2, ApiV2)) with
        {
            StreamSequence = 2,
            SignatureSha256 = Hash("signature-generation-2"),
            JournalRevision = 2,
        };
        var previousDigest = NativeGitOpsCellSpecCompiler.WorkloadDigest(
            NativeGitOpsManifest.Parse(generation1Content).Workloads.Single());
        var oldLive = Observation(1, previousDigest, NativeGitOpsWorkloadState.Healthy, 11);
        var second = await Advance(journal, generation2, [oldLive], watermark: 11);
        await Assert.That(second.Disposition).IsEqualTo(NativeGitOpsCellConvergenceJournalDisposition.Recorded);
        await Assert.That(second.Checkpoint!.Decision.Intent!.Kind)
            .IsEqualTo(NativeGitOpsCellConvergenceIntentKind.Apply);

        var wrongBase = Accepted(generation1Content, Plan(3, ApiV3)) with
        {
            StreamSequence = 3,
            SignatureSha256 = Hash("signature-generation-3"),
            JournalRevision = 3,
        };
        var baseMismatch = await Advance(journal, wrongBase, [], watermark: 12);
        await Assert.That(baseMismatch.Disposition)
            .IsEqualTo(NativeGitOpsCellConvergenceJournalDisposition.AcceptedBaseMismatch);
        var staleGeneration = await Advance(journal, generation1, [], watermark: 12);
        await Assert.That(staleGeneration.Disposition)
            .IsEqualTo(NativeGitOpsCellConvergenceJournalDisposition.StaleGeneration);

        var conflicting = Accepted(generation1Content, Plan(2, ApiV3));
        var conflict = await Advance(journal, conflicting, [], watermark: 12);
        await Assert.That(conflict.Disposition)
            .IsEqualTo(NativeGitOpsCellConvergenceJournalDisposition.GenerationConflict);
        var staleWriter = await Advance(journal, generation2 with { WriterEpoch = 6 }, [], watermark: 12);
        await Assert.That(staleWriter.Disposition)
            .IsEqualTo(NativeGitOpsCellConvergenceJournalDisposition.StaleWriter);
        var acceptanceConflict = await Advance(journal, generation2 with
        {
            SignatureSha256 = Hash("conflicting-same-writer-signature"),
        }, [], watermark: 12);
        await Assert.That(acceptanceConflict.Disposition)
            .IsEqualTo(NativeGitOpsCellConvergenceJournalDisposition.AcceptanceConflict);
        var replayedTakeover = await Advance(journal, generation2 with { WriterEpoch = 8 }, [], watermark: 12);
        await Assert.That(replayedTakeover.Disposition)
            .IsEqualTo(NativeGitOpsCellConvergenceJournalDisposition.StaleAcceptance);

        var takeover = await Advance(
            journal,
            generation2 with
            {
                WriterEpoch = 8,
                StreamSequence = 3,
                SignatureSha256 = Hash("signature-takeover"),
                JournalRevision = 3,
            },
            [oldLive],
            watermark: 11);
        await Assert.That(takeover.Disposition).IsEqualTo(NativeGitOpsCellConvergenceJournalDisposition.Recorded);
        await Assert.That(takeover.Checkpoint!.WriterEpoch).IsEqualTo(8);
        await Assert.That(takeover.Checkpoint.CheckpointSequence).IsEqualTo(3);
        await Assert.That(takeover.Checkpoint.CheckpointDigest)
            .IsNotEqualTo(second.Checkpoint.CheckpointDigest);
    }

    [Test]
    public async Task OnlyDurableExactLiveCheckpointCanAdvanceAndCorruptionFailsClosed()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var accepted = Accepted(null, Plan(1, ApiV1));
        var journal = new NativeGitOpsCellConvergenceJournal(ledger);
        var complete = await Advance(
            journal,
            accepted,
            [Present(accepted, NativeGitOpsWorkloadState.Healthy, 7)],
            watermark: 7);

        await Assert.That(complete.CanAdvanceGlobal).IsTrue();
        await Assert.That(complete.CanDispatch).IsFalse();
        await Assert.That(complete.Checkpoint!.Decision.ConvergenceDigest).IsNotNull();
        var duplicate = await Advance(
            journal,
            accepted,
            [Present(accepted, NativeGitOpsWorkloadState.Healthy, 7)],
            watermark: 7);
        await Assert.That(duplicate.Disposition).IsEqualTo(NativeGitOpsCellConvergenceJournalDisposition.Duplicate);
        await Assert.That(duplicate.CanAdvanceGlobal).IsTrue();

        ledger.CorruptFirst();
        await Assert.That(async () => await journal.ReadAsync("gru")).Throws<InvalidDataException>();
        await Assert.That(async () => await Advance(journal, accepted, [], watermark: 8))
            .Throws<InvalidDataException>();
    }

    private static Task<NativeGitOpsCellConvergenceJournalReceipt> Advance(
        NativeGitOpsCellConvergenceJournal journal,
        NativeGitOpsAcceptedCellSpec accepted,
        IEnumerable<NativeGitOpsWorkloadObservation> observations,
        long watermark,
        bool authorityStillValid = true) => journal.AdvanceAsync(
        accepted,
        observations,
        [],
        null,
        watermark,
        () => authorityStillValid);

    private static NativeGitOpsWorkloadObservation Absent(long sequence) => new(
        "api",
        0,
        null,
        NativeGitOpsWorkloadState.Absent,
        NativeGitOpsWorkloadOwnership.Unspecified,
        sequence,
        Hash($"absent-{sequence}"));

    private static NativeGitOpsWorkloadObservation Present(
        NativeGitOpsAcceptedCellSpec accepted,
        NativeGitOpsWorkloadState state,
        long sequence) => Observation(
        accepted.Generation,
        NativeGitOpsCellSpecCompiler.WorkloadDigest(
            NativeGitOpsCellPayload.Parse(accepted).DesiredWorkloads.Single()),
        state,
        sequence);

    private static NativeGitOpsWorkloadObservation Observation(
        long generation,
        string workloadDigest,
        NativeGitOpsWorkloadState state,
        long sequence) => new(
        "api",
        generation,
        workloadDigest,
        state,
        NativeGitOpsWorkloadOwnership.NativeGitOpsParent,
        sequence,
        Hash($"api-{generation}-{workloadDigest}-{state}-{sequence}"));

    private static NativeGitOpsAcceptedCellSpec Accepted(byte[]? prior, byte[] proposed)
    {
        var handoff = Handoff(prior, proposed);
        var cell = handoff.Cells.Single();
        return new(
            cell.Cell,
            cell.Generation,
            cell.GlobalPlanDigest,
            handoff.HandoffDigest,
            cell.PayloadSha256,
            cell.Payload.ToArray(),
            7,
            1,
            $"gitops/{handoff.HandoffDigest}/{cell.Cell}",
            $"gitops/{cell.PayloadSha256}",
            1,
            new(2026, 7, 17, 11, 59, 0, TimeSpan.Zero),
            new(2026, 7, 17, 12, 1, 0, TimeSpan.Zero),
            new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero),
            1,
            Hash("signature"),
            1);
    }

    private static NativeGitOpsCellHandoff Handoff(byte[]? prior, byte[] proposedContent)
    {
        const string repository = "TerraScale/TerraScale.Orchestrator";
        const string commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
        const string tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
        const string blob = "217eb74224043ba2feb48d137756c8a9331c44ee";
        var accepted = prior is null ? null : NativeGitOpsManifest.Parse(prior);
        var proposed = NativeGitOpsManifest.Parse(proposedContent);
        return NativeGitOpsCellSpecCompiler.Compile(new(
            new(repository, commit, tree, signatureVerified: true),
            new(
                repository,
                commit,
                NativeGitOpsSourceLoader.ManifestPath,
                blob,
                Convert.ToHexStringLower(SHA256.HashData(proposedContent)),
                proposedContent),
            proposed,
            NativeGitOpsDiff.Compare(accepted, proposed)));
    }

    private static byte[] Plan(long generation, string artifactDigest) => Encoding.UTF8.GetBytes($$"""
        {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":{{generation}},"workloads":[{"id":"api","role":"Api","artifactDigest":"{{artifactDigest}}","cells":["gru"]}]}
        """);

    private static string Hash(string value) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
