using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsGlobalHandoffPublisherTests
{
    [Test]
    public async Task RecoveredExactCellsAppendSequentiallyToGlobalSpec()
    {
        var prepared = await Prepared();
        var transport = new TestTransport(
            new NativeGitOpsGlobalHandoffTransportAck("GLOBAL_SPEC", 31, Duplicate: false),
            new NativeGitOpsGlobalHandoffTransportAck("GLOBAL_SPEC", 32, Duplicate: true));
        var receipt = await new NativeGitOpsGlobalHandoffPublisher(transport)
            .PublishAsync(prepared, static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffPublishDisposition.Complete);
        await Assert.That(receipt.IsComplete).IsTrue();
        await Assert.That(receipt.Cells.Select(static cell => cell.Disposition)).IsEquivalentTo([
            NativeGitOpsGlobalCellPublishDisposition.Published,
            NativeGitOpsGlobalCellPublishDisposition.Duplicate,
        ]);
        await Assert.That(transport.Published.Select(static message => message.Subject)).IsEquivalentTo([
            NatsSubjectTaxonomy.GlobalCellSpecSubject("gru"),
            NatsSubjectTaxonomy.GlobalCellSpecSubject("sfo"),
        ]);
        await Assert.That(transport.MaximumConcurrentPublishes).IsEqualTo(1);
        await Assert.That(transport.Published.Zip(prepared.Cells).All(pair =>
            pair.First.Message.Payload.Span.SequenceEqual(pair.Second.Message.Payload.Span) &&
            pair.First.Message.Headers["TS-Signature"] == pair.Second.Message.Headers["TS-Signature"]))
            .IsTrue();
    }

    [Test]
    public async Task AuthorityLossBeforeOrBetweenCellsCannotReportCompletion()
    {
        var prepared = await Prepared();
        var beforeTransport = new TestTransport(
            new NativeGitOpsGlobalHandoffTransportAck("GLOBAL_SPEC", 41, Duplicate: false));
        var before = await new NativeGitOpsGlobalHandoffPublisher(beforeTransport)
            .PublishAsync(prepared, static () => false);
        var checks = 0;
        var betweenTransport = new TestTransport(
            new NativeGitOpsGlobalHandoffTransportAck("GLOBAL_SPEC", 42, Duplicate: false));
        var between = await new NativeGitOpsGlobalHandoffPublisher(betweenTransport)
            .PublishAsync(prepared, () => ++checks <= 2);

        await Assert.That(before.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffPublishDisposition.AuthorityLostBeforePublish);
        await Assert.That(before.Cells).IsEmpty();
        await Assert.That(beforeTransport.Published).IsEmpty();
        await Assert.That(between.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffPublishDisposition.AuthorityLostBeforePublish);
        await Assert.That(between.IsComplete).IsFalse();
        await Assert.That(between.Cells).HasSingleItem();
        await Assert.That(betweenTransport.Published).HasSingleItem();
    }

    [Test]
    public async Task AuthorityLossAfterStorageRetainsDurablePartialEvidenceOnly()
    {
        var prepared = await Prepared();
        var checks = 0;
        var transport = new TestTransport(
            new NativeGitOpsGlobalHandoffTransportAck("GLOBAL_SPEC", 51, Duplicate: false));
        var receipt = await new NativeGitOpsGlobalHandoffPublisher(transport)
            .PublishAsync(prepared, () => ++checks == 1);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffPublishDisposition.AuthorityLostAfterPublish);
        await Assert.That(receipt.IsComplete).IsFalse();
        await Assert.That(receipt.Cells).HasSingleItem();
        await Assert.That(receipt.Cells[0].Disposition)
            .IsEqualTo(NativeGitOpsGlobalCellPublishDisposition.AuthorityLostAfterPublish);
        await Assert.That(receipt.Cells[0].IsDurable).IsTrue();
        await Assert.That(receipt.Cells[0].StreamSequence).IsEqualTo(51UL);
    }

    [Test]
    public async Task WrongAcknowledgementOrChangedPreparedBytesFailBeforeSuccess()
    {
        var prepared = await Prepared();
        await Assert.That(async () => await new NativeGitOpsGlobalHandoffPublisher(
                new TestTransport(new NativeGitOpsGlobalHandoffTransportAck(
                    "CELL_SPEC", 1, Duplicate: false)))
            .PublishAsync(prepared, static () => true)).Throws<InvalidDataException>();
        await Assert.That(async () => await new NativeGitOpsGlobalHandoffPublisher(
                new TestTransport(new NativeGitOpsGlobalHandoffTransportAck(
                    "GLOBAL_SPEC", 0, Duplicate: false)))
            .PublishAsync(prepared, static () => true)).Throws<InvalidDataException>();

        var original = prepared.Cells[0];
        var payload = original.Message.Payload.ToArray();
        payload[^2] ^= 1;
        var changed = original with { Message = original.Message with { Payload = payload } };
        var cells = prepared.Cells.ToArray();
        cells[0] = changed;
        var substituted = prepared with { Cells = Array.AsReadOnly(cells) };
        var transport = new TestTransport(
            new NativeGitOpsGlobalHandoffTransportAck("GLOBAL_SPEC", 2, Duplicate: false));
        await Assert.That(async () => await new NativeGitOpsGlobalHandoffPublisher(transport)
            .PublishAsync(substituted, static () => true)).Throws<InvalidDataException>();
        await Assert.That(transport.Published).IsEmpty();
    }

    [Test]
    public async Task DurableCellAcknowledgementsResumeToOneCompleteSnapshot()
    {
        var prepared = await Prepared();
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NativeGitOpsGlobalHandoffPublishJournal(ledger);

        var first = await journal.RecordAsync(
            prepared,
            Publication(prepared.Cells[0], 61),
            static () => true);
        var duplicate = await new NativeGitOpsGlobalHandoffPublishJournal(ledger).RecordAsync(
            prepared,
            Publication(prepared.Cells[0], 61),
            static () => true);
        var completed = await journal.RecordAsync(
            prepared,
            Publication(prepared.Cells[1], 62, duplicate: true),
            static () => true);
        var recovered = await new NativeGitOpsGlobalHandoffPublishJournal(ledger)
            .ReadAsync(prepared.Repository, prepared.Branch);

        await Assert.That(first.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffPublishJournalDisposition.Recorded);
        await Assert.That(first.Snapshot!.IsComplete).IsFalse();
        await Assert.That(duplicate.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffPublishJournalDisposition.Duplicate);
        await Assert.That(completed.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffPublishJournalDisposition.Recorded);
        await Assert.That(completed.Snapshot!.IsComplete).IsTrue();
        await Assert.That(recovered!.HandoffDigest).IsEqualTo(completed.Snapshot.HandoffDigest);
        await Assert.That(recovered.Cells).IsEquivalentTo(completed.Snapshot.Cells);
        await Assert.That(ledger.Mutations).IsEqualTo(2);
    }

    [Test]
    public async Task PublishJournalFencesAuthorityGenerationSourceAndSequenceRelabeling()
    {
        var current = await Prepared(generation: 2, sourceRevision: 5, authorityEpoch: 7);
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NativeGitOpsGlobalHandoffPublishJournal(ledger);
        await journal.RecordAsync(current, Publication(current.Cells[0], 71), static () => true);

        var staleAuthority = await Prepared(generation: 3, sourceRevision: 6, authorityEpoch: 6);
        var staleGeneration = await Prepared(generation: 1, sourceRevision: 6, authorityEpoch: 7);
        var conflict = await Prepared(
            generation: 2,
            sourceRevision: 6,
            authorityEpoch: 7,
            artifact: new string('9', 64));
        var staleSource = await Prepared(generation: 3, sourceRevision: 5, authorityEpoch: 7);
        var next = (await Prepared(generation: 3, sourceRevision: 6, authorityEpoch: 7)) with
        {
            JournalRevision = checked(current.JournalRevision + 1),
        };

        var authorityResult = await journal.RecordAsync(
            staleAuthority,
            Publication(staleAuthority.Cells[0], 72),
            static () => true);
        var generationResult = await journal.RecordAsync(
            staleGeneration,
            Publication(staleGeneration.Cells[0], 73),
            static () => true);
        var conflictResult = await journal.RecordAsync(
            conflict,
            Publication(conflict.Cells[0], 74),
            static () => true);
        var sourceResult = await journal.RecordAsync(
            staleSource,
            Publication(staleSource.Cells[0], 75),
            static () => true);
        var sequenceConflict = await journal.RecordAsync(
            current,
            Publication(current.Cells[0], 76),
            static () => true);
        var advanced = await journal.RecordAsync(
            next,
            Publication(next.Cells[0], 77),
            static () => true);

        await Assert.That(authorityResult.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffPublishJournalDisposition.StaleAuthority);
        await Assert.That(generationResult.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffPublishJournalDisposition.StaleGeneration);
        await Assert.That(conflictResult.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffPublishJournalDisposition.HandoffConflict);
        await Assert.That(sourceResult.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffPublishJournalDisposition.StaleSourceRevision);
        await Assert.That(sequenceConflict.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffPublishJournalDisposition.StreamSequenceConflict);
        await Assert.That(advanced.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffPublishJournalDisposition.Recorded);
        await Assert.That(advanced.Snapshot!.Generation).IsEqualTo(3);
        await Assert.That(advanced.Snapshot.Cells).HasSingleItem();
    }

    [Test]
    public async Task LostAuthorityAndNonCurrentPublicationNeverAdvanceAckJournal()
    {
        var prepared = await Prepared();
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NativeGitOpsGlobalHandoffPublishJournal(ledger);
        var lost = await journal.RecordAsync(
            prepared,
            Publication(prepared.Cells[0], 81),
            static () => false);
        var afterLoss = Publication(prepared.Cells[0], 82) with
        {
            Disposition = NativeGitOpsGlobalCellPublishDisposition.AuthorityLostAfterPublish,
        };

        await Assert.That(lost.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffPublishJournalDisposition.StaleAuthority);
        await Assert.That(lost.Snapshot).IsNull();
        await Assert.That(async () => await journal.RecordAsync(prepared, afterLoss, static () => true))
            .Throws<InvalidDataException>();
        await Assert.That(ledger.Mutations).IsEqualTo(0);
    }

    [Test]
    public async Task MaximumCellAckJournalFitsGlobalKvValueLimit()
    {
        var cells = Enumerable.Range(0, NativeGitOpsCellSpecCompiler.MaximumCellsPerHandoff)
            .Select(static index => $"cell-{index:00}-" + new string((char)('a' + index % 26), 55))
            .ToArray();
        var prepared = await Prepared(cells: cells);
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NativeGitOpsGlobalHandoffPublishJournal(ledger);

        for (var index = 0; index < prepared.Cells.Count; index++)
            await journal.RecordAsync(
                prepared,
                Publication(prepared.Cells[index], checked((ulong)index + 1)),
                static () => true);

        var recovered = await journal.ReadAsync(prepared.Repository, prepared.Branch);
        await Assert.That(recovered!.IsComplete).IsTrue();
        await Assert.That(Encoding.UTF8.GetByteCount(ledger.Values.Single()))
            .IsLessThanOrEqualTo(NativeGitOpsGlobalHandoffPublishJournal.MaximumRecordBytes);
    }

    [Test]
    public async Task DispatcherSkipsDurableCellsAndAnExactReplayPublishesNothing()
    {
        var prepared = await Prepared();
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NativeGitOpsGlobalHandoffPublishJournal(ledger);
        await journal.RecordAsync(
            prepared,
            Publication(prepared.Cells[0], 91),
            static () => true);
        var transport = new TestTransport(
            new NativeGitOpsGlobalHandoffTransportAck("GLOBAL_SPEC", 92, Duplicate: false));
        var dispatcher = new NativeGitOpsGlobalHandoffDispatcher(
            journal,
            new NativeGitOpsGlobalHandoffPublisher(transport));

        var completed = await dispatcher.DispatchAsync(prepared, static () => true);
        var replayTransport = new TestTransport();
        var replay = await new NativeGitOpsGlobalHandoffDispatcher(
                journal,
                new NativeGitOpsGlobalHandoffPublisher(replayTransport))
            .DispatchAsync(prepared, static () => true);

        await Assert.That(completed.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffDispatchDisposition.Completed);
        await Assert.That(completed.IsComplete).IsTrue();
        await Assert.That(completed.PublishedCells).IsEqualTo(1);
        await Assert.That(transport.Published).HasSingleItem();
        await Assert.That(transport.Published[0].Subject)
            .IsEqualTo(NatsSubjectTaxonomy.GlobalCellSpecSubject("sfo"));
        await Assert.That(replay.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffDispatchDisposition.AlreadyComplete);
        await Assert.That(replay.PublishedCells).IsEqualTo(0);
        await Assert.That(replayTransport.Published).IsEmpty();
    }

    [Test]
    public async Task DispatcherRejectsStalePreparedStateBeforePublishing()
    {
        var current = await Prepared(generation: 2, sourceRevision: 5);
        var stale = await Prepared(generation: 1, sourceRevision: 6);
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NativeGitOpsGlobalHandoffPublishJournal(ledger);
        await journal.RecordAsync(current, Publication(current.Cells[0], 101), static () => true);
        var transport = new TestTransport(
            new NativeGitOpsGlobalHandoffTransportAck("GLOBAL_SPEC", 102, Duplicate: false));

        var receipt = await new NativeGitOpsGlobalHandoffDispatcher(
                journal,
                new NativeGitOpsGlobalHandoffPublisher(transport))
            .DispatchAsync(stale, static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffDispatchDisposition.JournalRejected);
        await Assert.That(receipt.JournalDisposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffPublishJournalDisposition.StaleGeneration);
        await Assert.That(receipt.PublishedCells).IsEqualTo(0);
        await Assert.That(transport.Published).IsEmpty();
    }

    [Test]
    public async Task CrashBetweenStreamAckAndCasReplaysTheSameMessageThenConverges()
    {
        var prepared = await Prepared(cells: ["gru"]);
        var ledger = new ForgejoWebhookJournalTests.TestLedger(failOnMutation: 1);
        var journal = new NativeGitOpsGlobalHandoffPublishJournal(ledger);
        var firstTransport = new TestTransport(
            new NativeGitOpsGlobalHandoffTransportAck("GLOBAL_SPEC", 111, Duplicate: false));
        var first = new NativeGitOpsGlobalHandoffDispatcher(
            journal,
            new NativeGitOpsGlobalHandoffPublisher(firstTransport));

        await Assert.That(async () => await first.DispatchAsync(prepared, static () => true))
            .Throws<IOException>();
        var retryTransport = new TestTransport(
            new NativeGitOpsGlobalHandoffTransportAck("GLOBAL_SPEC", 111, Duplicate: true));
        var recovered = await new NativeGitOpsGlobalHandoffDispatcher(
                journal,
                new NativeGitOpsGlobalHandoffPublisher(retryTransport))
            .DispatchAsync(prepared, static () => true);

        await Assert.That(recovered.IsComplete).IsTrue();
        await Assert.That(firstTransport.Published).HasSingleItem();
        await Assert.That(retryTransport.Published).HasSingleItem();
        await Assert.That(firstTransport.Published[0].MessageId)
            .IsEqualTo(retryTransport.Published[0].MessageId);
        await Assert.That(firstTransport.Published[0].Message.Payload.Span.SequenceEqual(
            retryTransport.Published[0].Message.Payload.Span)).IsTrue();
    }

    [Test]
    public async Task AuthorityLossAfterStreamAckButBeforeCasRemainsIncomplete()
    {
        var prepared = await Prepared(cells: ["gru"]);
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var transport = new TestTransport(
            new NativeGitOpsGlobalHandoffTransportAck("GLOBAL_SPEC", 121, Duplicate: false));
        var checks = 0;
        var receipt = await new NativeGitOpsGlobalHandoffDispatcher(
                new NativeGitOpsGlobalHandoffPublishJournal(ledger),
                new NativeGitOpsGlobalHandoffPublisher(transport))
            .DispatchAsync(prepared, () => ++checks <= 2);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffDispatchDisposition.AuthorityLostBeforeJournal);
        await Assert.That(receipt.IsComplete).IsFalse();
        await Assert.That(receipt.PublishedCells).IsEqualTo(1);
        await Assert.That(transport.Published).HasSingleItem();
        await Assert.That(ledger.Mutations).IsEqualTo(0);
    }

    private static async Task<NativeGitOpsPreparedHandoff> Prepared(
        IReadOnlyList<string>? cells = null,
        long generation = 4,
        ulong sourceRevision = 11,
        long authorityEpoch = 7,
        string? artifact = null)
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var source = Source(cells ?? ["gru", "sfo"], generation, artifact ?? new string('0', 64));
        var receipt = await new NativeGitOpsSignedHandoffJournal(ledger, objects).PrepareAsync(
            "develop",
            source,
            sourceRevision,
            authorityEpoch,
            new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero),
            new(2026, 7, 17, 14, 0, 0, TimeSpan.Zero),
            new TestSigner(),
            static () => true);
        return receipt.Handoff!;
    }

    private static NativeGitOpsGlobalCellPublishReceipt Publication(
        NativeGitOpsPreparedCellSpec cell,
        ulong streamSequence,
        bool duplicate = false) => new(
        duplicate
            ? NativeGitOpsGlobalCellPublishDisposition.Duplicate
            : NativeGitOpsGlobalCellPublishDisposition.Published,
        cell.Cell,
        cell.WireSha256,
        streamSequence);

    private static NativeGitOpsSourcePlan Source(
        IReadOnlyList<string> cells,
        long generation,
        string artifact)
    {
        const string repository = "TerraScale/TerraScale.Orchestrator";
        const string commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
        const string tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
        const string blob = "217eb74224043ba2feb48d137756c8a9331c44ee";
        var content = Encoding.UTF8.GetBytes($$"""
            {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":{{generation}},"workloads":[{"id":"orchestrator","role":"Orchestrator","artifactDigest":"{{artifact}}","cells":{{System.Text.Json.JsonSerializer.Serialize(cells)}}}]}
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

    private sealed class TestSigner : INativeGitOpsCellSpecSigner
    {
        public OpaqueSignature Sign(CommandSignedMaterial material)
        {
            OpaqueSignature.TryCopyFrom([1, 2, 3], out var signature);
            return signature!;
        }
    }

    private sealed class TestObjectStore : IDeliveryObjectStore
    {
        private readonly Dictionary<string, byte[]> values = new(StringComparer.Ordinal);

        public Task PutAsync(
            string name,
            ReadOnlyMemory<byte> content,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            values[name] = content.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(values[name].ToArray());
        }
    }

    private sealed class TestTransport(params NativeGitOpsGlobalHandoffTransportAck[] acknowledgements)
        : INativeGitOpsGlobalHandoffTransport
    {
        private readonly Queue<NativeGitOpsGlobalHandoffTransportAck> acknowledgements = new(acknowledgements);
        private int activePublishes;

        internal List<PublishedMessage> Published { get; } = [];
        internal int MaximumConcurrentPublishes { get; private set; }

        public async Task<NativeGitOpsGlobalHandoffTransportAck> PublishAsync(
            string subject,
            string messageId,
            NativeGitOpsCellWireMessage message,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            activePublishes++;
            MaximumConcurrentPublishes = Math.Max(MaximumConcurrentPublishes, activePublishes);
            try
            {
                await Task.Yield();
                Published.Add(new(subject, messageId, message));
                return acknowledgements.Dequeue();
            }
            finally
            {
                activePublishes--;
            }
        }
    }

    private sealed record PublishedMessage(
        string Subject,
        string MessageId,
        NativeGitOpsCellWireMessage Message);
}
