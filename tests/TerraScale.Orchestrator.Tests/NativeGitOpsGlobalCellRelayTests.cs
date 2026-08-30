using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsGlobalCellRelayTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task ValidGlobalCellIsAcknowledgedOnlyAfterExactRegionalStorage()
    {
        var wire = Wire([1, 2, 3]);
        var transport = new TestTransport(new("CELL_SPEC", 41, Duplicate: false));
        var acknowledgements = 0;
        var receipt = await Relay(transport).RelayAsync(
            wire.Payload,
            wire.Headers,
            "gru",
            7,
            Now,
            TimeSpan.Zero,
            new TestVerifier([1, 2, 3]),
            static () => true,
            _ =>
            {
                acknowledgements++;
                return Task.CompletedTask;
            });

        await Assert.That(receipt.Disposition)
            .IsEqualTo(NativeGitOpsGlobalCellRelayDisposition.Acknowledged);
        await Assert.That(receipt.IsAcknowledged).IsTrue();
        await Assert.That(receipt.RegionalPublication!.IsDurable).IsTrue();
        await Assert.That(receipt.RegionalPublication.StreamSequence).IsEqualTo(41UL);
        await Assert.That(acknowledgements).IsEqualTo(1);
        await Assert.That(transport.Messages).HasSingleItem();
        await Assert.That(transport.Messages[0].Message.Payload.Span.SequenceEqual(wire.Payload.Span)).IsTrue();
        await Assert.That(transport.Messages[0].Message.Headers["TS-Signature"])
            .IsEqualTo(wire.Headers["TS-Signature"]);
    }

    [Test]
    public async Task MalformedWrongCellEpochAndSignatureNeverReachRegionalStream()
    {
        var wire = Wire([4]);
        var transport = new TestTransport(new("CELL_SPEC", 42, Duplicate: false));
        var relay = Relay(transport);
        var acknowledgements = 0;
        Task Ack(CancellationToken _) { acknowledgements++; return Task.CompletedTask; }

        var malformed = await relay.RelayAsync(
            wire.Payload,
            wire.Headers.Concat([wire.Headers.First()]),
            "gru", 7, Now, TimeSpan.Zero, new TestVerifier([4]), static () => true, Ack);
        var signature = await relay.RelayAsync(
            wire.Payload,
            wire.Headers,
            "gru", 7, Now, TimeSpan.Zero, new TestVerifier([5]), static () => true, Ack);
        var cell = await relay.RelayAsync(
            wire.Payload,
            wire.Headers,
            "sfo", 7, Now, TimeSpan.Zero, new TestVerifier([4]), static () => true, Ack);
        var epoch = await relay.RelayAsync(
            wire.Payload,
            wire.Headers,
            "gru", 8, Now, TimeSpan.Zero, new TestVerifier([4]), static () => true, Ack);

        await Assert.That(malformed.Disposition)
            .IsEqualTo(NativeGitOpsGlobalCellRelayDisposition.Malformed);
        await Assert.That(signature.Disposition)
            .IsEqualTo(NativeGitOpsGlobalCellRelayDisposition.Rejected);
        await Assert.That(signature.ProtocolError).IsEqualTo(CommandValidationError.InvalidSignature);
        await Assert.That(cell.Disposition).IsEqualTo(NativeGitOpsGlobalCellRelayDisposition.Rejected);
        await Assert.That(epoch.Disposition).IsEqualTo(NativeGitOpsGlobalCellRelayDisposition.Rejected);
        await Assert.That(transport.Messages).IsEmpty();
        await Assert.That(acknowledgements).IsEqualTo(0);
    }

    [Test]
    public async Task EveryRegionalAuthorityLossEdgeLeavesGlobalDeliveryUnacknowledged()
    {
        var wire = Wire([6]);
        var beforeTransport = new TestTransport(new("CELL_SPEC", 51, Duplicate: false));
        var before = await Relay(beforeTransport).RelayAsync(
            wire.Payload, wire.Headers, "gru", 7, Now, TimeSpan.Zero, new TestVerifier([6]),
            static () => false, _ => Task.CompletedTask);
        var afterChecks = 0;
        var afterTransport = new TestTransport(new("CELL_SPEC", 52, Duplicate: false));
        var after = await Relay(afterTransport).RelayAsync(
            wire.Payload, wire.Headers, "gru", 7, Now, TimeSpan.Zero, new TestVerifier([6]),
            () => ++afterChecks == 1, _ => Task.CompletedTask);
        var beforeAckChecks = 0;
        var beforeAckTransport = new TestTransport(new("CELL_SPEC", 53, Duplicate: false));
        var beforeAck = await Relay(beforeAckTransport).RelayAsync(
            wire.Payload, wire.Headers, "gru", 7, Now, TimeSpan.Zero, new TestVerifier([6]),
            () => ++beforeAckChecks <= 2, _ => Task.CompletedTask);

        await Assert.That(before.Disposition)
            .IsEqualTo(NativeGitOpsGlobalCellRelayDisposition.AuthorityLostBeforeRegionalPublish);
        await Assert.That(after.Disposition)
            .IsEqualTo(NativeGitOpsGlobalCellRelayDisposition.AuthorityLostAfterRegionalPublish);
        await Assert.That(beforeAck.Disposition)
            .IsEqualTo(NativeGitOpsGlobalCellRelayDisposition.AuthorityLostBeforeGlobalAcknowledge);
        await Assert.That(before.IsAcknowledged || after.IsAcknowledged || beforeAck.IsAcknowledged).IsFalse();
        await Assert.That(beforeTransport.Messages).IsEmpty();
        await Assert.That(afterTransport.Messages).HasSingleItem();
        await Assert.That(beforeAckTransport.Messages).HasSingleItem();
    }

    [Test]
    public async Task GlobalAckFailureRedeliversTheSameRegionalMessageIdentity()
    {
        var wire = Wire([7]);
        var firstTransport = new TestTransport(new("CELL_SPEC", 61, Duplicate: false));
        await Assert.That(async () => await Relay(firstTransport).RelayAsync(
                wire.Payload,
                wire.Headers,
                "gru",
                7,
                Now,
                TimeSpan.Zero,
                new TestVerifier([7]),
                static () => true,
                _ => throw new IOException("simulated global acknowledgement failure")))
            .Throws<IOException>();
        var retryTransport = new TestTransport(new("CELL_SPEC", 61, Duplicate: true));
        var recovered = await Relay(retryTransport).RelayAsync(
            wire.Payload,
            wire.Headers,
            "gru",
            7,
            Now,
            TimeSpan.Zero,
            new TestVerifier([7]),
            static () => true,
            _ => Task.CompletedTask);

        await Assert.That(recovered.IsAcknowledged).IsTrue();
        await Assert.That(firstTransport.Messages[0].MessageId)
            .IsEqualTo(retryTransport.Messages[0].MessageId);
        await Assert.That(firstTransport.Messages[0].Message.Payload.Span.SequenceEqual(
            retryTransport.Messages[0].Message.Payload.Span)).IsTrue();
    }

    private static NativeGitOpsGlobalCellRelay Relay(TestTransport transport) =>
        new(new NativeGitOpsCellPublisher(transport));

    private static NativeGitOpsCellWireMessage Wire(byte[] signature)
    {
        const string repository = "TerraScale/TerraScale.Orchestrator";
        const string commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
        const string tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
        const string blob = "217eb74224043ba2feb48d137756c8a9331c44ee";
        var artifact = new string('0', 64);
        var content = Encoding.UTF8.GetBytes($$"""
            {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":4,"workloads":[{"id":"platform","role":"CustomerDashboard","artifactDigest":"{{artifact}}","cells":["gru"]}]}
            """);
        var plan = NativeGitOpsManifest.Parse(content);
        var handoff = NativeGitOpsCellSpecCompiler.Compile(new(
            new(repository, commit, tree, signatureVerified: true),
            new(
                repository,
                commit,
                NativeGitOpsSourceLoader.ManifestPath,
                blob,
                Convert.ToHexStringLower(SHA256.HashData(content)),
                content),
            plan,
            NativeGitOpsDiff.Compare(null, plan)));
        var envelope = NativeGitOpsCellEnvelope.Sign(
            handoff,
            "gru",
            7,
            Now.AddMinutes(-1),
            Now.AddMinutes(1),
            new TestSigner(signature));
        return NativeGitOpsCellWireCodec.Encode(handoff, envelope);
    }

    private sealed class TestSigner(byte[] signature) : INativeGitOpsCellSpecSigner
    {
        public OpaqueSignature Sign(CommandSignedMaterial material)
        {
            OpaqueSignature.TryCopyFrom(signature, out var value);
            return value!;
        }
    }

    private sealed class TestVerifier(byte[] expected) : ICommandSignatureVerifier
    {
        public VerificationOutcome Verify(CommandSignedMaterial signedMaterial, OpaqueSignature signature) =>
            signature.Bytes.SequenceEqual(expected) ? VerificationOutcome.Valid : VerificationOutcome.Invalid;
    }

    private sealed class TestTransport(NativeGitOpsCellTransportAck acknowledgement)
        : INativeGitOpsCellTransport
    {
        internal List<PublishedMessage> Messages { get; } = [];

        public Task<NativeGitOpsCellTransportAck> PublishAsync(
            string subject,
            string messageId,
            NativeGitOpsCellWireMessage message,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Messages.Add(new(subject, messageId, message));
            return Task.FromResult(acknowledgement);
        }
    }

    private sealed record PublishedMessage(
        string Subject,
        string MessageId,
        NativeGitOpsCellWireMessage Message);
}
