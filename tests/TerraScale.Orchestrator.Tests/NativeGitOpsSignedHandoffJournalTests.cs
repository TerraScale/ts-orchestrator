using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsSignedHandoffJournalTests
{
    private static readonly DateTimeOffset IssuedAt = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task ExactSignedWireBytesSurviveRestartAndPublishWithoutResigning()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var signer = new CountingSigner();
        var source = Source(4, Artifact('0'), ["gru", "sfo"]);
        var journal = new NativeGitOpsSignedHandoffJournal(ledger, objects);

        var recorded = await Prepare(journal, source, 11, 7, signer);
        var recovered = await new NativeGitOpsSignedHandoffJournal(ledger, objects)
            .ReadAsync(source.Revision.Repository, "develop");
        var duplicate = await Prepare(journal, source, 12, 7, signer);
        var transport = new TestTransport();
        var publication = await new NativeGitOpsCellPublisher(transport).PublishPreparedAsync(
            recovered!.Descriptor,
            recovered.Cells[0],
            static () => true);

        await Assert.That(recorded.Disposition)
            .IsEqualTo(NativeGitOpsSignedHandoffJournalDisposition.Recorded);
        await Assert.That(duplicate.Disposition)
            .IsEqualTo(NativeGitOpsSignedHandoffJournalDisposition.Duplicate);
        await Assert.That(signer.Calls).IsEqualTo(2);
        await Assert.That(recovered.Cells.Select(Signature))
            .IsEquivalentTo(recorded.Handoff!.Cells.Select(Signature));
        await Assert.That(publication.IsDurable).IsTrue();
        await Assert.That(transport.Message!.Payload.Span.SequenceEqual(recovered.Cells[0].Message.Payload.Span))
            .IsTrue();
        await Assert.That(transport.Message.Headers["TS-Signature"])
            .IsEqualTo(recovered.Cells[0].Message.Headers["TS-Signature"]);
    }

    [Test]
    public async Task CrashBeforePointerLeavesOnlyOrphansAndRetryCommitsOneExactSet()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore { FailNextPut = true };
        var signer = new CountingSigner();
        var source = Source(4, Artifact('1'), ["gru", "sfo"]);
        var journal = new NativeGitOpsSignedHandoffJournal(ledger, objects);

        await Assert.That(async () => await Prepare(journal, source, 11, 7, signer))
            .Throws<IOException>();
        var recovered = await Prepare(journal, source, 11, 7, signer);
        var durable = await new NativeGitOpsSignedHandoffJournal(ledger, objects)
            .ReadAsync(source.Revision.Repository, "develop");

        await Assert.That(recovered.Disposition)
            .IsEqualTo(NativeGitOpsSignedHandoffJournalDisposition.Recorded);
        await Assert.That(signer.Calls).IsEqualTo(4);
        await Assert.That(objects.Count).IsEqualTo(3);
        await Assert.That(ledger.Mutations).IsEqualTo(1);
        await Assert.That(durable!.Cells.Select(static cell => cell.WireSha256))
            .IsEquivalentTo(recovered.Handoff!.Cells.Select(static cell => cell.WireSha256));
    }

    [Test]
    public async Task AuthorityGenerationAndSourceRevisionCannotBeRelabeled()
    {
        var journal = new NativeGitOpsSignedHandoffJournal(
            new ForgejoWebhookJournalTests.TestLedger(),
            new TestObjectStore());
        var signer = new CountingSigner();
        var current = Source(2, Artifact('2'), ["gru"]);
        await Prepare(journal, current, 5, 7, signer);

        var staleAuthority = await Prepare(journal, Source(3, Artifact('3'), ["gru"]), 6, 6, signer);
        var staleGeneration = await Prepare(journal, Source(1, Artifact('1'), ["gru"]), 6, 7, signer);
        var conflict = await Prepare(journal, Source(2, Artifact('4'), ["gru"]), 6, 7, signer);
        var staleSource = await Prepare(journal, Source(3, Artifact('3'), ["gru"]), 5, 7, signer);
        var takeover = await Prepare(journal, current, 5, 8, signer);
        var lost = await journal.PrepareAsync(
            "develop",
            Source(3, Artifact('3'), ["gru"]),
            6,
            8,
            IssuedAt,
            IssuedAt.AddHours(2),
            signer,
            static () => false);

        await Assert.That(staleAuthority.Disposition)
            .IsEqualTo(NativeGitOpsSignedHandoffJournalDisposition.StaleAuthority);
        await Assert.That(staleGeneration.Disposition)
            .IsEqualTo(NativeGitOpsSignedHandoffJournalDisposition.StaleGeneration);
        await Assert.That(conflict.Disposition)
            .IsEqualTo(NativeGitOpsSignedHandoffJournalDisposition.GenerationConflict);
        await Assert.That(staleSource.Disposition)
            .IsEqualTo(NativeGitOpsSignedHandoffJournalDisposition.StaleSourceRevision);
        await Assert.That(takeover.Disposition)
            .IsEqualTo(NativeGitOpsSignedHandoffJournalDisposition.Recorded);
        await Assert.That(takeover.Handoff!.AuthorityEpoch).IsEqualTo(8);
        await Assert.That(takeover.Handoff.Cells.All(cell =>
            NativeGitOpsCellWireCodec.Decode(cell.Message.Payload, cell.Message.Headers)
                .Envelope.WriterEpoch.Value == 8)).IsTrue();
        await Assert.That(lost.Disposition)
            .IsEqualTo(NativeGitOpsSignedHandoffJournalDisposition.StaleAuthority);
    }

    [Test]
    public async Task CorruptWireObjectFailsClosedAndSixtyFourCellPointerFitsGlobalKvBound()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var cells = Enumerable.Range(0, NativeGitOpsCellSpecCompiler.MaximumCellsPerHandoff)
            .Select(static index => $"cell-{index:00}-" + new string((char)('a' + index % 26), 55))
            .ToArray();
        var source = Source(9, Artifact('9'), cells);
        var journal = new NativeGitOpsSignedHandoffJournal(ledger, objects);
        var prepared = await Prepare(journal, source, 21, 12, new CountingSigner());

        await Assert.That(prepared.Handoff!.Cells.Count)
            .IsEqualTo(NativeGitOpsCellSpecCompiler.MaximumCellsPerHandoff);
        await Assert.That(Encoding.UTF8.GetByteCount(ledger.Values.Single()))
            .IsLessThanOrEqualTo(NativeGitOpsSignedHandoffJournal.MaximumPointerBytes);
        objects.Corrupt(prepared.Handoff.Cells[0].WireSha256);
        await Assert.That(async () => await journal.ReadAsync(source.Revision.Repository, "develop"))
            .Throws<InvalidDataException>();
    }

    private static Task<NativeGitOpsSignedHandoffJournalReceipt> Prepare(
        NativeGitOpsSignedHandoffJournal journal,
        NativeGitOpsSourcePlan source,
        ulong sourceRevision,
        long authorityEpoch,
        INativeGitOpsCellSpecSigner signer) => journal.PrepareAsync(
        "develop",
        source,
        sourceRevision,
        authorityEpoch,
        IssuedAt,
        IssuedAt.AddHours(2),
        signer,
        static () => true);

    private static string Signature(NativeGitOpsPreparedCellSpec cell) =>
        cell.Message.Headers["TS-Signature"];

    private static NativeGitOpsSourcePlan Source(
        long generation,
        string artifactDigest,
        IReadOnlyList<string> cells)
    {
        const string repository = "TerraScale/TerraScale.Orchestrator";
        const string commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
        const string tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
        const string blob = "217eb74224043ba2feb48d137756c8a9331c44ee";
        var content = Encoding.UTF8.GetBytes($$"""
            {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":{{generation}},"workloads":[{"id":"platform","role":"CustomerDashboard","artifactDigest":"{{artifactDigest}}","cells":{{JsonSerializer.Serialize(cells)}}}]}
            """);
        var proposed = NativeGitOpsManifest.Parse(content);
        return new(
            new(repository, commit, tree, signatureVerified: true),
            new(
                repository,
                commit,
                NativeGitOpsSourceLoader.ManifestPath,
                blob,
                Convert.ToHexStringLower(SHA256.HashData(content)),
                content),
            proposed,
            NativeGitOpsDiff.Compare(null, proposed));
    }

    private static string Artifact(char value) => new(value, 64);

    private sealed class CountingSigner : INativeGitOpsCellSpecSigner
    {
        internal int Calls { get; private set; }

        public OpaqueSignature Sign(CommandSignedMaterial material)
        {
            OpaqueSignature.TryCopyFrom([checked((byte)++Calls), 7, 11], out var signature);
            return signature!;
        }
    }

    private sealed class TestObjectStore : IDeliveryObjectStore
    {
        private readonly Dictionary<string, byte[]> values = new(StringComparer.Ordinal);

        internal bool FailNextPut { get; set; }
        internal int Count => values.Count;

        public Task PutAsync(
            string name,
            ReadOnlyMemory<byte> content,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            values[name] = content.ToArray();
            if (FailNextPut)
            {
                FailNextPut = false;
                throw new IOException("Simulated object-store interruption.");
            }
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!values.TryGetValue(name, out var value)) throw new IOException("Missing object.");
            return Task.FromResult(value.ToArray());
        }

        internal void Corrupt(string wireSha256) =>
            values[$"native-gitops-cell-wire-{wireSha256}"] = "corrupt"u8.ToArray();
    }

    private sealed class TestTransport : INativeGitOpsCellTransport
    {
        internal NativeGitOpsCellWireMessage? Message { get; private set; }

        public Task<NativeGitOpsCellTransportAck> PublishAsync(
            string subject,
            string messageId,
            NativeGitOpsCellWireMessage message,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Message = message;
            return Task.FromResult(new NativeGitOpsCellTransportAck("CELL_SPEC", 41, Duplicate: false));
        }
    }
}

