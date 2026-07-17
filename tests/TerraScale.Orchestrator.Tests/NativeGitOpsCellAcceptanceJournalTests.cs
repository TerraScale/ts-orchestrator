using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsCellAcceptanceJournalTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);
    private const string DigestV1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string DigestV2 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Test]
    public async Task SignedPayloadAndFencedReceiptResumeAcrossJournalInstances()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var payloads = new TestPayloadStore();
        var handoff = Handoff(1, DigestV1);
        var envelope = Envelope(handoff, 7, [1, 2, 3]);

        var recorded = await new NativeGitOpsCellAcceptanceJournal(ledger, payloads).AcceptAsync(
            envelope, handoff, "gru", 7, 41, Now, TimeSpan.Zero,
            new TestVerifier([1, 2, 3]), () => true);
        var recovered = await new NativeGitOpsCellAcceptanceJournal(ledger, payloads).ReadAsync("gru");

        await Assert.That(recorded.Disposition).IsEqualTo(NativeGitOpsCellAcceptanceDisposition.Recorded);
        await Assert.That(recorded.CanAcknowledge).IsTrue();
        await Assert.That(recovered).IsNotNull();
        await Assert.That(recovered!.HandoffDigest).IsEqualTo(handoff.HandoffDigest);
        await Assert.That(recovered.GlobalPlanDigest).IsEqualTo(handoff.GlobalPlanDigest);
        await Assert.That(recovered.Generation).IsEqualTo(1);
        await Assert.That(recovered.WriterEpoch).IsEqualTo(7);
        await Assert.That(recovered.ProtocolVersion).IsEqualTo(1);
        await Assert.That(recovered.DeliveryAttempt).IsEqualTo(1);
        await Assert.That(recovered.StreamSequence).IsEqualTo(41UL);
        await Assert.That(recovered.Payload.Span.SequenceEqual(handoff.Cells.Single().Payload.Span)).IsTrue();
        await Assert.That(payloads.Values).HasSingleItem();
    }

    [Test]
    public async Task InvalidSignatureNeverMutatesDurableAcceptance()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var payloads = new TestPayloadStore();
        var handoff = Handoff(1, DigestV1);

        var receipt = await new NativeGitOpsCellAcceptanceJournal(ledger, payloads).AcceptAsync(
            Envelope(handoff, 7, [1]), handoff, "gru", 7, 1, Now, TimeSpan.Zero,
            new TestVerifier([2]), () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(NativeGitOpsCellAcceptanceDisposition.ProtocolRejected);
        await Assert.That(receipt.ProtocolError).IsEqualTo(CommandValidationError.InvalidSignature);
        await Assert.That(receipt.CanAcknowledge).IsFalse();
        await Assert.That(ledger.Values).IsEmpty();
        await Assert.That(payloads.Values).IsEmpty();
    }

    [Test]
    public async Task CrashAfterPayloadWriteResumesBeforeAcknowledgement()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger(failOnMutation: 1);
        var payloads = new TestPayloadStore();
        var handoff = Handoff(1, DigestV1);
        var envelope = Envelope(handoff, 7, [3]);
        var journal = new NativeGitOpsCellAcceptanceJournal(ledger, payloads);

        await Assert.That(async () => await journal.AcceptAsync(
                envelope, handoff, "gru", 7, 9, Now, TimeSpan.Zero,
                new TestVerifier([3]), () => true))
            .Throws<IOException>();
        var recovered = await new NativeGitOpsCellAcceptanceJournal(ledger, payloads).AcceptAsync(
            envelope, handoff, "gru", 7, 9, Now, TimeSpan.Zero,
            new TestVerifier([3]), () => true);

        await Assert.That(recovered.CanAcknowledge).IsTrue();
        await Assert.That(payloads.Values).HasSingleItem();
    }

    [Test]
    public async Task ConcurrentRedeliveryConvergesOnOneDurableReceipt()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var payloads = new TestPayloadStore();
        var handoff = Handoff(1, DigestV1);
        var envelope = Envelope(handoff, 7, [4]);
        var journal = new NativeGitOpsCellAcceptanceJournal(ledger, payloads);

        var receipts = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => journal.AcceptAsync(
            envelope, handoff, "gru", 7, 11, Now, TimeSpan.Zero,
            new TestVerifier([4]), () => true)));

        await Assert.That(receipts.Count(receipt =>
            receipt.Disposition == NativeGitOpsCellAcceptanceDisposition.Recorded)).IsEqualTo(1);
        await Assert.That(receipts.All(receipt => receipt.CanAcknowledge)).IsTrue();
        await Assert.That(payloads.Values).HasSingleItem();
    }

    [Test]
    public async Task WriterGenerationAndIdentityFencesFailClosedWhileTakeoverCanResume()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var payloads = new TestPayloadStore();
        var journal = new NativeGitOpsCellAcceptanceJournal(ledger, payloads);
        var current = Handoff(2, DigestV1);
        await journal.AcceptAsync(
            Envelope(current, 8, [5]), current, "gru", 8, 1, Now, TimeSpan.Zero,
            new TestVerifier([5]), () => true);

        var newer = Handoff(3, DigestV2);
        var staleWriter = await journal.AcceptAsync(
            Envelope(newer, 7, [6]), newer, "gru", 7, 2, Now, TimeSpan.Zero,
            new TestVerifier([6]), () => true);
        var older = Handoff(1, DigestV1);
        var staleGeneration = await journal.AcceptAsync(
            Envelope(older, 8, [7]), older, "gru", 8, 3, Now, TimeSpan.Zero,
            new TestVerifier([7]), () => true);
        var conflict = Handoff(2, DigestV2);
        var generationConflict = await journal.AcceptAsync(
            Envelope(conflict, 8, [8]), conflict, "gru", 8, 4, Now, TimeSpan.Zero,
            new TestVerifier([8]), () => true);
        var identityConflict = await journal.AcceptAsync(
            Envelope(current, 8, [9], Now.AddSeconds(-10)), current, "gru", 8, 5, Now,
            TimeSpan.Zero, new TestVerifier([9]), () => true);
        var takeover = await journal.AcceptAsync(
            Envelope(current, 9, [10]), current, "gru", 9, 6, Now, TimeSpan.Zero,
            new TestVerifier([10]), () => true);

        await Assert.That(staleWriter.Disposition)
            .IsEqualTo(NativeGitOpsCellAcceptanceDisposition.StaleWriter);
        await Assert.That(staleGeneration.Disposition)
            .IsEqualTo(NativeGitOpsCellAcceptanceDisposition.StaleGeneration);
        await Assert.That(generationConflict.Disposition)
            .IsEqualTo(NativeGitOpsCellAcceptanceDisposition.GenerationConflict);
        await Assert.That(identityConflict.Disposition)
            .IsEqualTo(NativeGitOpsCellAcceptanceDisposition.IdentityConflict);
        await Assert.That(takeover.Disposition).IsEqualTo(NativeGitOpsCellAcceptanceDisposition.Recorded);
        await Assert.That(takeover.Acceptance!.WriterEpoch).IsEqualTo(9);
    }

    [Test]
    public async Task AuthorityLossAndCorruptPayloadNeverBecomeAcknowledgeable()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var payloads = new TestPayloadStore();
        var handoff = Handoff(1, DigestV1);
        var envelope = Envelope(handoff, 7, [11]);
        var journal = new NativeGitOpsCellAcceptanceJournal(ledger, payloads);

        var stale = await journal.AcceptAsync(
            envelope, handoff, "gru", 7, 1, Now, TimeSpan.Zero,
            new TestVerifier([11]), () => false);
        var recorded = await journal.AcceptAsync(
            envelope, handoff, "gru", 7, 1, Now, TimeSpan.Zero,
            new TestVerifier([11]), () => true);
        payloads.Corrupt(handoff.Cells.Single().PayloadSha256);

        await Assert.That(stale.Disposition).IsEqualTo(NativeGitOpsCellAcceptanceDisposition.StaleAuthority);
        await Assert.That(stale.CanAcknowledge).IsFalse();
        await Assert.That(recorded.CanAcknowledge).IsTrue();
        await Assert.That(async () => await journal.ReadAsync("gru")).Throws<InvalidDataException>();
    }

    private static CommandEnvelope Envelope(
        NativeGitOpsCellHandoff handoff,
        long epoch,
        byte[] signature,
        DateTimeOffset? issuedAt = null) => NativeGitOpsCellEnvelope.Sign(
        handoff,
        "gru",
        epoch,
        issuedAt ?? Now.AddMinutes(-1),
        Now.AddMinutes(1),
        new TestSigner(signature));

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
        var source = new NativeGitOpsSourcePlan(
            new(repository, commit, tree, signatureVerified: true),
            new(repository, commit, NativeGitOpsSourceLoader.ManifestPath, blob,
                Convert.ToHexStringLower(SHA256.HashData(content)), content),
            proposed,
            NativeGitOpsDiff.Compare(null, proposed));
        return NativeGitOpsCellSpecCompiler.Compile(source);
    }

    private sealed class TestSigner(byte[] signature) : INativeGitOpsCellSpecSigner
    {
        public OpaqueSignature Sign(CommandSignedMaterial material)
        {
            OpaqueSignature.TryCopyFrom(signature, out var value);
            return value!;
        }
    }

    private sealed class TestVerifier(byte[] signature) : ICommandSignatureVerifier
    {
        public VerificationOutcome Verify(CommandSignedMaterial signedMaterial, OpaqueSignature candidate) =>
            candidate.Bytes.SequenceEqual(signature) ? VerificationOutcome.Valid : VerificationOutcome.Invalid;
    }

    private sealed class TestPayloadStore : INativeGitOpsManifestStore
    {
        private readonly ConcurrentDictionary<string, byte[]> values = new(StringComparer.Ordinal);

        internal IReadOnlyCollection<byte[]> Values => (IReadOnlyCollection<byte[]>)values.Values;

        public Task PutAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            values[name] = content.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!values.TryGetValue(name, out var content)) throw new IOException("Missing test payload.");
            return Task.FromResult(content.ToArray());
        }

        internal void Corrupt(string digest) =>
            values[$"native-gitops-cell-spec-{digest}"] = "corrupt"u8.ToArray();
    }
}
