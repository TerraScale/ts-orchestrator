using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

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
            "ts.orch.v1.global.desired.gitops.gru",
            "ts.orch.v1.global.desired.gitops.sfo",
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

    private static async Task<NativeGitOpsPreparedHandoff> Prepared()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var source = Source();
        var receipt = await new NativeGitOpsSignedHandoffJournal(ledger, objects).PrepareAsync(
            "develop",
            source,
            11,
            7,
            new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero),
            new(2026, 7, 17, 14, 0, 0, TimeSpan.Zero),
            new TestSigner(),
            static () => true);
        return receipt.Handoff!;
    }

    private static NativeGitOpsSourcePlan Source()
    {
        const string repository = "TerraScale/TerraScale.Orchestrator";
        const string commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
        const string tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
        const string blob = "217eb74224043ba2feb48d137756c8a9331c44ee";
        var artifact = new string('0', 64);
        var content = Encoding.UTF8.GetBytes($$"""
            {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":4,"workloads":[{"id":"api","role":"Api","artifactDigest":"{{artifact}}","cells":["gru","sfo"]}]}
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
