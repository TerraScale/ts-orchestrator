using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsCellPublisherTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task SignedCellSpecRequiresTheExpectedStreamAcknowledgement()
    {
        var transport = new TestTransport(new("CELL_SPEC", 41, Duplicate: false));
        var publisher = new NativeGitOpsCellPublisher(transport);
        var handoff = Handoff();
        var envelope = Envelope(handoff, 7);

        var receipt = await publisher.PublishAsync(handoff, envelope, () => true);
        var decoded = NativeGitOpsCellWireCodec.Decode(
            transport.Messages.Single().Message.Payload,
            transport.Messages.Single().Message.Headers);

        await Assert.That(receipt.Disposition).IsEqualTo(NativeGitOpsCellPublishDisposition.Published);
        await Assert.That(receipt.IsDurable).IsTrue();
        await Assert.That(receipt.StreamSequence).IsEqualTo(41UL);
        await Assert.That(transport.Messages.Single().Subject).IsEqualTo("ts.orch.v1.gru.desired.gitops");
        await Assert.That(transport.Messages.Single().MessageId)
            .IsEqualTo($"gitops:{handoff.HandoffDigest}:gru:7");
        await Assert.That(decoded.Handoff.HandoffDigest).IsEqualTo(handoff.HandoffDigest);
        await Assert.That(decoded.Envelope.Signature.Equals(envelope.Signature)).IsTrue();
    }

    [Test]
    public async Task ExactRetriesDeduplicateWithoutSuppressingANewWriterEpoch()
    {
        var transport = new TestTransport(new("CELL_SPEC", 51, Duplicate: true));
        var publisher = new NativeGitOpsCellPublisher(transport);
        var handoff = Handoff();

        var duplicate = await publisher.PublishAsync(handoff, Envelope(handoff, 7), () => true);
        transport.Acknowledgement = new("CELL_SPEC", 52, Duplicate: false);
        var takeover = await publisher.PublishAsync(handoff, Envelope(handoff, 8), () => true);

        await Assert.That(duplicate.Disposition).IsEqualTo(NativeGitOpsCellPublishDisposition.Duplicate);
        await Assert.That(takeover.Disposition).IsEqualTo(NativeGitOpsCellPublishDisposition.Published);
        await Assert.That(transport.Messages[0].MessageId).IsNotEqualTo(transport.Messages[1].MessageId);
        await Assert.That(transport.Messages[0].MessageId).EndsWith(":7");
        await Assert.That(transport.Messages[1].MessageId).EndsWith(":8");
    }

    [Test]
    public async Task AuthorityLossBeforeAndAfterPublishRemainDistinctFencedOutcomes()
    {
        var handoff = Handoff();
        var envelope = Envelope(handoff, 7);
        var beforeTransport = new TestTransport(new("CELL_SPEC", 61, Duplicate: false));
        var before = await new NativeGitOpsCellPublisher(beforeTransport)
            .PublishAsync(handoff, envelope, () => false);
        var checks = 0;
        var afterTransport = new TestTransport(new("CELL_SPEC", 62, Duplicate: false));
        var after = await new NativeGitOpsCellPublisher(afterTransport)
            .PublishAsync(handoff, envelope, () => ++checks == 1);

        await Assert.That(before.Disposition)
            .IsEqualTo(NativeGitOpsCellPublishDisposition.AuthorityLostBeforePublish);
        await Assert.That(before.IsDurable).IsFalse();
        await Assert.That(beforeTransport.Messages).IsEmpty();
        await Assert.That(after.Disposition)
            .IsEqualTo(NativeGitOpsCellPublishDisposition.AuthorityLostAfterPublish);
        await Assert.That(after.IsDurable).IsTrue();
        await Assert.That(afterTransport.Messages).HasSingleItem();
    }

    [Test]
    public async Task WrongStreamOrMissingSequenceNeverProducesADurableReceipt()
    {
        var handoff = Handoff();
        var envelope = Envelope(handoff, 7);

        await Assert.That(async () => await new NativeGitOpsCellPublisher(
                new TestTransport(new("GLOBAL_SPEC", 1, Duplicate: false)))
            .PublishAsync(handoff, envelope, () => true)).Throws<InvalidDataException>();
        await Assert.That(async () => await new NativeGitOpsCellPublisher(
                new TestTransport(new("CELL_SPEC", 0, Duplicate: false)))
            .PublishAsync(handoff, envelope, () => true)).Throws<InvalidDataException>();
    }

    private static CommandEnvelope Envelope(NativeGitOpsCellHandoff handoff, long epoch) =>
        NativeGitOpsCellEnvelope.Sign(
            handoff,
            "gru",
            epoch,
            Now.AddMinutes(-1),
            Now.AddMinutes(1),
            new TestSigner([1, 2, 3]));

    private static NativeGitOpsCellHandoff Handoff()
    {
        const string repository = "TerraScale/TerraScale.Orchestrator";
        const string commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
        const string tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
        const string blob = "217eb74224043ba2feb48d137756c8a9331c44ee";
        const string digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        var content = Encoding.UTF8.GetBytes($$"""
            {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":4,"workloads":[{"id":"api","role":"Api","artifactDigest":"{{digest}}","cells":["gru"]}]}
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

    private sealed class TestSigner(byte[] signature) : INativeGitOpsCellSpecSigner
    {
        public OpaqueSignature Sign(CommandSignedMaterial material)
        {
            OpaqueSignature.TryCopyFrom(signature, out var value);
            return value!;
        }
    }

    private sealed class TestTransport(NativeGitOpsCellTransportAck acknowledgement)
        : INativeGitOpsCellTransport
    {
        internal NativeGitOpsCellTransportAck Acknowledgement { get; set; } = acknowledgement;
        internal List<PublishedMessage> Messages { get; } = [];

        public Task<NativeGitOpsCellTransportAck> PublishAsync(
            string subject,
            string messageId,
            NativeGitOpsCellWireMessage message,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Messages.Add(new(subject, messageId, message));
            return Task.FromResult(Acknowledgement);
        }
    }

    private sealed record PublishedMessage(
        string Subject,
        string MessageId,
        NativeGitOpsCellWireMessage Message);
}
