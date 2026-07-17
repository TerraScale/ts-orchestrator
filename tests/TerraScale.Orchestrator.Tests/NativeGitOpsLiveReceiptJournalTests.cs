using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsLiveReceiptJournalTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);
    private const string DigestV1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string DigestV2 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Test]
    public async Task SignedReceiptIsDurableBeforeAcknowledgementAndRestartRestoresBarrierMaterial()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var handoff = Handoff(4, DigestV1);
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var epochs = Epochs(7);
        var envelope = Signed(handoff, writerEpoch: 7, acceptanceSequence: 1, checkpointSequence: 1);
        var journal = new NativeGitOpsLiveReceiptJournal(ledger);

        var recorded = await journal.AcceptAsync(
            descriptor, epochs, envelope, 11, Now, TimeSpan.Zero, new TestVerifier(), () => true);
        var recovered = await new NativeGitOpsLiveReceiptJournal(ledger).ReadAsync("gru");
        var duplicate = await new NativeGitOpsLiveReceiptJournal(ledger).AcceptAsync(
            descriptor, epochs, envelope, 11, Now, TimeSpan.Zero, new TestVerifier(), () => true);
        var barrier = NativeGitOpsLiveBarrierEvaluator.Evaluate(
            descriptor, epochs, [recovered!.Envelope], Now, TimeSpan.Zero, new TestVerifier());

        await Assert.That(recorded.Disposition).IsEqualTo(NativeGitOpsLiveReceiptJournalDisposition.Recorded);
        await Assert.That(recorded.CanAcknowledge).IsTrue();
        await Assert.That(recovered).IsNotNull();
        await Assert.That(recovered!.Envelope.Signature.Bytes.SequenceEqual(envelope.Signature.Bytes)).IsTrue();
        await Assert.That(recovered.GlobalAuthorityEpoch).IsEqualTo(11);
        await Assert.That(duplicate.Disposition).IsEqualTo(NativeGitOpsLiveReceiptJournalDisposition.Duplicate);
        await Assert.That(duplicate.CanAcknowledge).IsTrue();
        await Assert.That(duplicate.Receipt!.JournalRevision).IsEqualTo(recorded.Receipt!.JournalRevision);
        await Assert.That(barrier.IsComplete).IsTrue();
    }

    [Test]
    public async Task InvalidSignatureAndAuthorityLossNeverMutateOrAcknowledge()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var handoff = Handoff(4, DigestV1);
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var epochs = Epochs(7);
        var signed = Signed(handoff, 7, 1, 1);
        var substituted = signed with
        {
            Receipt = signed.Receipt with { ConvergenceDigest = Hash("substituted") },
        };
        var journal = new NativeGitOpsLiveReceiptJournal(ledger);

        var invalid = await journal.AcceptAsync(
            descriptor, epochs, substituted, 11, Now, TimeSpan.Zero, new TestVerifier(), () => true);
        var stale = await journal.AcceptAsync(
            descriptor, epochs, signed, 11, Now, TimeSpan.Zero, new TestVerifier(), () => false);

        await Assert.That(invalid.Disposition).IsEqualTo(NativeGitOpsLiveReceiptJournalDisposition.InvalidReceipt);
        await Assert.That(invalid.ValidationError).IsEqualTo(NativeGitOpsCellConvergenceReceiptError.InvalidSignature);
        await Assert.That(invalid.CanAcknowledge).IsFalse();
        await Assert.That(stale.Disposition).IsEqualTo(NativeGitOpsLiveReceiptJournalDisposition.StaleAuthority);
        await Assert.That(stale.CanAcknowledge).IsFalse();
        await Assert.That(ledger.Values).IsEmpty();
    }

    [Test]
    public async Task CheckpointsAndRegionalTakeoverAdvanceMonotonically()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var handoff = Handoff(4, DigestV1);
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var journal = new NativeGitOpsLiveReceiptJournal(ledger);
        var firstEnvelope = Signed(handoff, 7, 1, 1);
        await journal.AcceptAsync(
            descriptor, Epochs(7), firstEnvelope, 11, Now, TimeSpan.Zero, new TestVerifier(), () => true);

        var advanced = await journal.AcceptAsync(
            descriptor, Epochs(7), Signed(handoff, 7, 1, 2), 11,
            Now, TimeSpan.Zero, new TestVerifier(), () => true);
        var staleCheckpoint = await journal.AcceptAsync(
            descriptor, Epochs(7), firstEnvelope, 11,
            Now, TimeSpan.Zero, new TestVerifier(), () => true);
        var staleWriter = await journal.AcceptAsync(
            descriptor, Epochs(6), Signed(handoff, 6, 2, 3), 11,
            Now, TimeSpan.Zero, new TestVerifier(), () => true);
        var takeover = await journal.AcceptAsync(
            descriptor, Epochs(8), Signed(handoff, 8, 2, 3), 11,
            Now, TimeSpan.Zero, new TestVerifier(), () => true);

        await Assert.That(advanced.Disposition).IsEqualTo(NativeGitOpsLiveReceiptJournalDisposition.Recorded);
        await Assert.That(advanced.Receipt!.Envelope.Receipt.CheckpointSequence).IsEqualTo(2);
        await Assert.That(staleCheckpoint.Disposition)
            .IsEqualTo(NativeGitOpsLiveReceiptJournalDisposition.StaleCheckpoint);
        await Assert.That(staleCheckpoint.CanAcknowledge).IsFalse();
        await Assert.That(staleWriter.Disposition)
            .IsEqualTo(NativeGitOpsLiveReceiptJournalDisposition.StaleRegionalWriter);
        await Assert.That(takeover.Disposition).IsEqualTo(NativeGitOpsLiveReceiptJournalDisposition.Recorded);
        await Assert.That(takeover.Receipt!.Envelope.Receipt.RegionalWriterEpoch).IsEqualTo(8);
    }

    [Test]
    public async Task GlobalAuthorityGenerationAndHandoffIdentityRemainFenced()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var current = Handoff(4, DigestV1);
        var currentDescriptor = NativeGitOpsCellEnvelope.Describe(current)!;
        var currentEnvelope = Signed(current, 7, 1, 1);
        var journal = new NativeGitOpsLiveReceiptJournal(ledger);
        await journal.AcceptAsync(
            currentDescriptor, Epochs(7), currentEnvelope, 11,
            Now, TimeSpan.Zero, new TestVerifier(), () => true);

        var globalTakeover = await journal.AcceptAsync(
            currentDescriptor, Epochs(7), currentEnvelope, 12,
            Now, TimeSpan.Zero, new TestVerifier(), () => true);
        var staleGlobal = await journal.AcceptAsync(
            currentDescriptor, Epochs(7), currentEnvelope, 11,
            Now, TimeSpan.Zero, new TestVerifier(), () => true);
        var conflict = Handoff(4, DigestV2);
        var generationConflict = await journal.AcceptAsync(
            NativeGitOpsCellEnvelope.Describe(conflict)!, Epochs(7), Signed(conflict, 7, 2, 2), 12,
            Now, TimeSpan.Zero, new TestVerifier(), () => true);
        var stale = Handoff(3, DigestV1);
        var staleGeneration = await journal.AcceptAsync(
            NativeGitOpsCellEnvelope.Describe(stale)!, Epochs(7), Signed(stale, 7, 2, 2), 12,
            Now, TimeSpan.Zero, new TestVerifier(), () => true);
        var next = Handoff(5, DigestV2);
        var advanced = await journal.AcceptAsync(
            NativeGitOpsCellEnvelope.Describe(next)!, Epochs(7), Signed(next, 7, 2, 2), 12,
            Now, TimeSpan.Zero, new TestVerifier(), () => true);

        await Assert.That(globalTakeover.Disposition).IsEqualTo(NativeGitOpsLiveReceiptJournalDisposition.Recorded);
        await Assert.That(globalTakeover.Receipt!.GlobalAuthorityEpoch).IsEqualTo(12);
        await Assert.That(staleGlobal.Disposition)
            .IsEqualTo(NativeGitOpsLiveReceiptJournalDisposition.StaleGlobalAuthority);
        await Assert.That(generationConflict.Disposition)
            .IsEqualTo(NativeGitOpsLiveReceiptJournalDisposition.GenerationConflict);
        await Assert.That(staleGeneration.Disposition)
            .IsEqualTo(NativeGitOpsLiveReceiptJournalDisposition.StaleGeneration);
        await Assert.That(advanced.Disposition).IsEqualTo(NativeGitOpsLiveReceiptJournalDisposition.Recorded);
        await Assert.That(advanced.Receipt!.Envelope.Receipt.Generation).IsEqualTo(5);
    }

    [Test]
    public async Task MutationCrashRetriesAndCorruptDurableReceiptFailsClosed()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger(failOnMutation: 1);
        var handoff = Handoff(4, DigestV1);
        var descriptor = NativeGitOpsCellEnvelope.Describe(handoff)!;
        var envelope = Signed(handoff, 7, 1, 1);
        var journal = new NativeGitOpsLiveReceiptJournal(ledger);

        await Assert.That(async () => await journal.AcceptAsync(
                descriptor, Epochs(7), envelope, 11,
                Now, TimeSpan.Zero, new TestVerifier(), () => true))
            .Throws<IOException>();
        await Assert.That(ledger.Values).IsEmpty();
        var recovered = await new NativeGitOpsLiveReceiptJournal(ledger).AcceptAsync(
            descriptor, Epochs(7), envelope, 11,
            Now, TimeSpan.Zero, new TestVerifier(), () => true);
        await Assert.That(recovered.CanAcknowledge).IsTrue();

        ledger.RewriteFirst(value =>
        {
            var document = JsonNode.Parse(value)!.AsObject();
            document[nameof(NativeGitOpsLiveReceiptDocument.SignatureBase64)] = null;
            return document.ToJsonString();
        });
        await Assert.That(async () => await journal.ReadAsync("gru")).Throws<InvalidDataException>();
        await Assert.That(async () => await journal.AcceptAsync(
                descriptor, Epochs(7), envelope, 11,
                Now, TimeSpan.Zero, new TestVerifier(), () => true))
            .Throws<InvalidDataException>();
    }

    private static Dictionary<string, long> Epochs(long writerEpoch) => new(StringComparer.Ordinal)
    {
        ["gru"] = writerEpoch,
    };

    private static NativeGitOpsCellConvergenceReceiptEnvelope Signed(
        NativeGitOpsCellHandoff handoff,
        long writerEpoch,
        ulong acceptanceSequence,
        long checkpointSequence)
    {
        var cell = handoff.Cells.Single();
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
            checkpoint, Now.AddMinutes(-1), Now.AddMinutes(1), new TestSigner());
    }

    private static NativeGitOpsCellHandoff Handoff(long generation, string artifactDigest)
    {
        const string repository = "TerraScale/TerraScale.Orchestrator";
        const string commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
        const string tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
        const string blob = "217eb74224043ba2feb48d137756c8a9331c44ee";
        var content = Encoding.UTF8.GetBytes($$"""
            {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":{{generation}},"workloads":[{"id":"api","role":"Api","artifactDigest":"{{artifactDigest}}","cells":["gru"]}]}
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
