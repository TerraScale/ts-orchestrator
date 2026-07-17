using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsGlobalLiveJournalTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);
    private const string DigestV1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string DigestV2 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Test]
    public async Task CompleteExactDurableSetRecordsOneRestartSafeGlobalBarrier()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var handoff = Handoff(4, DigestV1, "gru", "sfo", "fra");
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var epochs = Epochs(handoff, 7);
        var regional = new NativeGitOpsLiveReceiptJournal(ledger);
        var durable = new List<NativeGitOpsDurableLiveReceipt>();
        foreach (var (cell, index) in handoff.Cells.Select((cell, index) => (cell, index)))
        {
            var accepted = await regional.AcceptAsync(
                descriptor,
                epochs,
                Signed(handoff, cell.Cell, 7, (ulong)index + 1, index + 1),
                11,
                Now,
                TimeSpan.Zero,
                new TestVerifier(),
                () => true);
            durable.Add(accepted.Receipt!);
        }
        var journal = new NativeGitOpsGlobalLiveJournal(ledger);

        var recorded = await Complete(journal, descriptor, epochs, durable.AsEnumerable().Reverse(), 11, Now);
        var recovered = await new NativeGitOpsGlobalLiveJournal(ledger).ReadAsync();
        var duplicate = await Complete(new(ledger), descriptor, epochs, durable, 11, Now.AddSeconds(10));

        await Assert.That(recorded.Disposition).IsEqualTo(NativeGitOpsGlobalLiveJournalDisposition.Recorded);
        await Assert.That(recorded.CanAdvanceGlobal).IsTrue();
        await Assert.That(recovered).IsNotNull();
        await Assert.That(string.Join(',', recovered!.Cells.Select(static cell => cell.Cell)))
            .IsEqualTo("fra,gru,sfo");
        await Assert.That(recovered.BarrierDigest).IsEqualTo(recorded.Barrier!.BarrierDigest);
        await Assert.That(recovered.CompletionDigest).IsEqualTo(recorded.Barrier.CompletionDigest);
        await Assert.That(recovered.CompletionDigest.Length).IsEqualTo(64);
        await Assert.That(duplicate.Disposition).IsEqualTo(NativeGitOpsGlobalLiveJournalDisposition.Duplicate);
        await Assert.That(duplicate.CanAdvanceGlobal).IsTrue();
        await Assert.That(duplicate.Barrier!.JournalRevision).IsEqualTo(recorded.Barrier.JournalRevision);
        await Assert.That(duplicate.Barrier.CompletedAt).IsEqualTo(Now);
    }

    [Test]
    public async Task MissingOrWrongAuthorityReceiptSetsNeverCreateGlobalSuccess()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var handoff = Handoff(4, DigestV1, "gru", "sfo", "fra");
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var epochs = Epochs(handoff, 7);
        var complete = handoff.Cells.Select((cell, index) => Durable(
            Signed(handoff, cell.Cell, 7, (ulong)index + 1, index + 1),
            11,
            (ulong)index + 1)).ToArray();
        var journal = new NativeGitOpsGlobalLiveJournal(ledger);

        var incomplete = await Complete(journal, descriptor, epochs, complete.Take(2), 11, Now);
        var staleReceipts = await Complete(
            journal,
            descriptor,
            epochs,
            complete.Select(static receipt => receipt with { GlobalAuthorityEpoch = 10 }),
            11,
            Now);
        var staleLeader = await Complete(
            journal,
            descriptor,
            epochs,
            complete.Select(static receipt => receipt with { GlobalAuthorityEpoch = 12 }),
            11,
            Now);

        await Assert.That(incomplete.Disposition).IsEqualTo(NativeGitOpsGlobalLiveJournalDisposition.Incomplete);
        await Assert.That(staleReceipts.Disposition)
            .IsEqualTo(NativeGitOpsGlobalLiveJournalDisposition.StaleReceiptAuthority);
        await Assert.That(staleLeader.Disposition)
            .IsEqualTo(NativeGitOpsGlobalLiveJournalDisposition.StaleGlobalAuthority);
        await Assert.That(incomplete.CanAdvanceGlobal).IsFalse();
        await Assert.That(staleReceipts.CanAdvanceGlobal).IsFalse();
        await Assert.That(staleLeader.CanAdvanceGlobal).IsFalse();
        await Assert.That(ledger.Values).IsEmpty();
    }

    [Test]
    public async Task InvalidSignatureCrashAuthorityLossAndCorruptionFailClosed()
    {
        var handoff = Handoff(4, DigestV1, "gru");
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var epochs = Epochs(handoff, 7);
        var envelope = Signed(handoff, "gru", 7, 1, 1);
        var substituted = envelope with
        {
            Receipt = envelope.Receipt with { ConvergenceDigest = Hash("substituted") },
        };
        var invalidLedger = new ForgejoWebhookJournalTests.TestLedger();
        var invalidJournal = new NativeGitOpsGlobalLiveJournal(invalidLedger);
        await Assert.That(async () => await Complete(
                invalidJournal,
                descriptor,
                epochs,
                [Durable(substituted, 11, 1)],
                11,
                Now))
            .Throws<InvalidDataException>();
        await Assert.That(invalidLedger.Values).IsEmpty();

        var stale = await invalidJournal.CompleteAsync(
            descriptor,
            epochs,
            [Durable(envelope, 11, 1)],
            11,
            Now,
            TimeSpan.Zero,
            new TestVerifier(),
            () => false);
        await Assert.That(stale.Disposition).IsEqualTo(NativeGitOpsGlobalLiveJournalDisposition.StaleAuthority);
        await Assert.That(stale.CanAdvanceGlobal).IsFalse();
        await Assert.That(invalidLedger.Values).IsEmpty();

        var crashingLedger = new ForgejoWebhookJournalTests.TestLedger(failOnMutation: 1);
        var crashing = new NativeGitOpsGlobalLiveJournal(crashingLedger);
        await Assert.That(async () => await Complete(
                crashing,
                descriptor,
                epochs,
                [Durable(envelope, 11, 1)],
                11,
                Now))
            .Throws<IOException>();
        await Assert.That(crashingLedger.Values).IsEmpty();
        var recovered = await Complete(
            new(crashingLedger), descriptor, epochs, [Durable(envelope, 11, 1)], 11, Now);
        await Assert.That(recovered.CanAdvanceGlobal).IsTrue();
        crashingLedger.CorruptFirst();
        await Assert.That(async () => await crashing.ReadAsync()).Throws<InvalidDataException>();
        await Assert.That(async () => await Complete(
                crashing,
                descriptor,
                epochs,
                [Durable(envelope, 11, 1)],
                11,
                Now))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task GlobalAuthorityGenerationAndHandoffIdentityRemainFenced()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var current = Handoff(4, DigestV1, "gru");
        var currentDescriptor = NativeGitOpsCellEnvelope.Describe(current)!;
        var epochs = Epochs(current, 7);
        var currentEnvelope = Signed(current, "gru", 7, 1, 1);
        var journal = new NativeGitOpsGlobalLiveJournal(ledger);
        await Complete(journal, currentDescriptor, epochs, [Durable(currentEnvelope, 11, 1)], 11, Now);

        var staleGlobal = await Complete(
            journal, currentDescriptor, epochs, [Durable(currentEnvelope, 10, 1)], 10, Now);
        var globalTakeover = await Complete(
            journal,
            currentDescriptor,
            epochs,
            [Durable(currentEnvelope, 12, 2, Now.AddSeconds(1))],
            12,
            Now.AddSeconds(1));
        var conflict = Handoff(4, DigestV2, "gru");
        var generationConflict = await Complete(
            journal,
            NativeGitOpsCellEnvelope.Describe(conflict)!,
            Epochs(conflict, 7),
            [Durable(Signed(conflict, "gru", 7, 2, 2), 12, 3)],
            12,
            Now.AddSeconds(2));
        var stale = Handoff(3, DigestV1, "gru");
        var staleGeneration = await Complete(
            journal,
            NativeGitOpsCellEnvelope.Describe(stale)!,
            Epochs(stale, 7),
            [Durable(Signed(stale, "gru", 7, 2, 2), 12, 3)],
            12,
            Now.AddSeconds(2));
        var next = Handoff(5, DigestV2, "gru");
        var advanced = await Complete(
            journal,
            NativeGitOpsCellEnvelope.Describe(next)!,
            Epochs(next, 7),
            [Durable(Signed(next, "gru", 7, 2, 2), 12, 3)],
            12,
            Now.AddSeconds(2));
        var unprovenNext = Handoff(6, DigestV1, "gru");
        var staleProof = await Complete(
            journal,
            NativeGitOpsCellEnvelope.Describe(unprovenNext)!,
            Epochs(unprovenNext, 7),
            [Durable(Signed(unprovenNext, "gru", 7, 2, 3), 12, 4)],
            12,
            Now.AddSeconds(3));

        await Assert.That(staleGlobal.Disposition)
            .IsEqualTo(NativeGitOpsGlobalLiveJournalDisposition.StaleGlobalAuthority);
        await Assert.That(globalTakeover.Disposition).IsEqualTo(NativeGitOpsGlobalLiveJournalDisposition.Recorded);
        await Assert.That(globalTakeover.Barrier!.GlobalAuthorityEpoch).IsEqualTo(12);
        await Assert.That(generationConflict.Disposition)
            .IsEqualTo(NativeGitOpsGlobalLiveJournalDisposition.GenerationConflict);
        await Assert.That(staleGeneration.Disposition)
            .IsEqualTo(NativeGitOpsGlobalLiveJournalDisposition.StaleGeneration);
        await Assert.That(advanced.Disposition).IsEqualTo(NativeGitOpsGlobalLiveJournalDisposition.Recorded);
        await Assert.That(advanced.Barrier!.Generation).IsEqualTo(5);
        await Assert.That(staleProof.Disposition)
            .IsEqualTo(NativeGitOpsGlobalLiveJournalDisposition.StaleLiveProof);
    }

    [Test]
    public async Task SameGenerationCheckpointAndRegionalTakeoverRequireMonotonicProofs()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var handoff = Handoff(4, DigestV1, "gru");
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var journal = new NativeGitOpsGlobalLiveJournal(ledger);
        var firstEnvelope = Signed(handoff, "gru", 7, 1, 1);
        var first = await Complete(
            journal, descriptor, Epochs(handoff, 7), [Durable(firstEnvelope, 11, 1)], 11, Now);

        var checkpointEnvelope = Signed(handoff, "gru", 7, 1, 2);
        var checkpoint = await Complete(
            journal,
            descriptor,
            Epochs(handoff, 7),
            [Durable(checkpointEnvelope, 11, 2)],
            11,
            Now.AddSeconds(1));
        var staleCheckpoint = await Complete(
            journal, descriptor, Epochs(handoff, 7), [Durable(firstEnvelope, 11, 1)], 11, Now);
        var takeoverEnvelope = Signed(handoff, "gru", 8, 2, 3);
        var takeover = await Complete(
            journal,
            descriptor,
            Epochs(handoff, 8),
            [Durable(takeoverEnvelope, 11, 3)],
            11,
            Now.AddSeconds(2));
        var staleWriter = await Complete(
            journal,
            descriptor,
            Epochs(handoff, 7),
            [Durable(Signed(handoff, "gru", 7, 3, 4), 11, 4)],
            11,
            Now.AddSeconds(3));
        var relabeled = await Complete(
            journal,
            descriptor,
            Epochs(handoff, 8),
            [Durable(takeoverEnvelope, 11, 4, Now.AddSeconds(3))],
            11,
            Now.AddSeconds(3));

        await Assert.That(checkpoint.Disposition).IsEqualTo(NativeGitOpsGlobalLiveJournalDisposition.Recorded);
        await Assert.That(checkpoint.Barrier!.BarrierDigest).IsNotEqualTo(first.Barrier!.BarrierDigest);
        await Assert.That(staleCheckpoint.Disposition)
            .IsEqualTo(NativeGitOpsGlobalLiveJournalDisposition.StaleLiveProof);
        await Assert.That(takeover.Disposition).IsEqualTo(NativeGitOpsGlobalLiveJournalDisposition.Recorded);
        await Assert.That(takeover.Barrier!.BarrierDigest).IsNotEqualTo(checkpoint.Barrier.BarrierDigest);
        await Assert.That(staleWriter.Disposition)
            .IsEqualTo(NativeGitOpsGlobalLiveJournalDisposition.StaleLiveProof);
        await Assert.That(relabeled.Disposition)
            .IsEqualTo(NativeGitOpsGlobalLiveJournalDisposition.StaleLiveProof);
    }

    [Test]
    public async Task MaximumFanoutCompletionFitsTheDeliveryJournalValueBound()
    {
        var cells = Enumerable.Range(0, NativeGitOpsCellSpecCompiler.MaximumCellsPerHandoff)
            .Select(index => $"cell-{index:D2}-{new string((char)('a' + index % 26), 55)}")
            .ToArray();
        var handoff = Handoff(4, DigestV1, cells);
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var epochs = Epochs(handoff, long.MaxValue);
        var receipts = handoff.Cells.Select(cell => Durable(
            Signed(handoff, cell.Cell, long.MaxValue, ulong.MaxValue, long.MaxValue),
            11,
            ulong.MaxValue)).ToArray();
        var ledger = new ForgejoWebhookJournalTests.TestLedger();

        var completed = await Complete(
            new(ledger), descriptor, epochs, receipts, 11, Now);
        var serializedBytes = Encoding.UTF8.GetByteCount(ledger.Values.Single());

        await Assert.That(completed.CanAdvanceGlobal).IsTrue();
        await Assert.That(completed.Barrier!.Cells.Count)
            .IsEqualTo(NativeGitOpsCellSpecCompiler.MaximumCellsPerHandoff);
        await Assert.That(serializedBytes)
            .IsLessThanOrEqualTo(NativeGitOpsGlobalLiveJournal.MaximumRecordBytes);
    }

    private static Task<NativeGitOpsGlobalLiveJournalReceipt> Complete(
        NativeGitOpsGlobalLiveJournal journal,
        NativeGitOpsCellHandoffDescriptor descriptor,
        IReadOnlyDictionary<string, long> epochs,
        IEnumerable<NativeGitOpsDurableLiveReceipt> receipts,
        long globalAuthorityEpoch,
        DateTimeOffset now) => journal.CompleteAsync(
        descriptor,
        epochs,
        receipts,
        globalAuthorityEpoch,
        now,
        TimeSpan.Zero,
        new TestVerifier(),
        () => true);

    private static NativeGitOpsDurableLiveReceipt Durable(
        NativeGitOpsCellConvergenceReceiptEnvelope envelope,
        long globalAuthorityEpoch,
        ulong journalRevision,
        DateTimeOffset? acceptedAt = null) => new(
        envelope,
        globalAuthorityEpoch,
        acceptedAt ?? Now,
        journalRevision);

    private static Dictionary<string, long> Epochs(NativeGitOpsCellHandoff handoff, long writerEpoch) =>
        handoff.Cells.ToDictionary(static cell => cell.Cell, _ => writerEpoch, StringComparer.Ordinal);

    private static NativeGitOpsCellConvergenceReceiptEnvelope Signed(
        NativeGitOpsCellHandoff handoff,
        string cellName,
        long writerEpoch,
        ulong acceptanceSequence,
        long checkpointSequence)
    {
        var cell = handoff.Cells.Single(cell => cell.Cell == cellName);
        var checkpoint = new NativeGitOpsCellConvergenceCheckpoint(
            cell.Cell,
            cell.Generation,
            cell.GlobalPlanDigest,
            handoff.HandoffDigest,
            cell.PayloadSha256,
            writerEpoch,
            acceptanceSequence,
            Hash($"acceptance-signature-{cell.Cell}-{writerEpoch}-{acceptanceSequence}"),
            acceptanceSequence,
            checkpointSequence,
            new(
                NativeGitOpsCellConvergenceState.Converged,
                NativeGitOpsCellConvergenceHoldReason.None,
                null,
                Hash($"live-{cell.Cell}-{writerEpoch}-{acceptanceSequence}-{checkpointSequence}")),
            checkpointSequence,
            Hash($"previous-{cell.Cell}-{checkpointSequence}"),
            Hash($"checkpoint-{cell.Cell}-{writerEpoch}-{acceptanceSequence}-{checkpointSequence}"),
            (ulong)checkpointSequence);
        return NativeGitOpsCellConvergenceReceipt.Sign(
            checkpoint,
            Now.AddMinutes(-1),
            Now.AddMinutes(10),
            new TestSigner());
    }

    private static NativeGitOpsCellHandoff Handoff(
        long generation,
        string artifactDigest,
        params string[] cells)
    {
        const string repository = "TerraScale/TerraScale.Orchestrator";
        const string commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
        const string tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
        const string blob = "217eb74224043ba2feb48d137756c8a9331c44ee";
        var cellJson = string.Join(',', cells.Select(static cell => $"\"{cell}\""));
        var content = Encoding.UTF8.GetBytes($$"""
            {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":{{generation}},"workloads":[{"id":"platform","role":"Platform","artifactDigest":"{{artifactDigest}}","cells":[{{cellJson}}]}]}
            """);
        var proposed = NativeGitOpsManifest.Parse(content);
        return NativeGitOpsCellSpecCompiler.Compile(new(
            new(repository, commit, tree, signatureVerified: true),
            new(
                repository,
                commit,
                NativeGitOpsSourceLoader.ManifestPath,
                blob,
                Convert.ToHexStringLower(SHA256.HashData(content)),
                content),
            proposed,
            NativeGitOpsDiff.Compare(null, proposed)));
    }

    private static string Hash(string value) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private sealed class TestSigner : INativeGitOpsCellConvergenceReceiptSigner
    {
        public OpaqueSignature Sign(ReadOnlyMemory<byte> canonicalMaterial)
        {
            OpaqueSignature.TryCopyFrom(SHA256.HashData(canonicalMaterial.Span), out var signature);
            return signature!;
        }
    }

    private sealed class TestVerifier : INativeGitOpsCellConvergenceReceiptVerifier
    {
        public VerificationOutcome Verify(
            string cell,
            ReadOnlyMemory<byte> canonicalMaterial,
            OpaqueSignature signature) => CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(canonicalMaterial.Span),
                signature.Bytes)
            ? VerificationOutcome.Valid
            : VerificationOutcome.Invalid;
    }
}
