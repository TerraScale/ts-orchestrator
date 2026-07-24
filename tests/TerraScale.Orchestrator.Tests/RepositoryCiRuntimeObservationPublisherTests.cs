using System.Security.Cryptography;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiRuntimeObservationPublisherTests
{
    private readonly HashSignature signer = new(1);

    [Test]
    public async Task CanonicalSignedObservationPublishesWithContentIdentity()
    {
        var runtime = Runtime(signer);
        var transport = new TestTransport();
        var publisher = new RepositoryCiRuntimeObservationPublisher(transport);

        var acknowledgement = await publisher.PublishAsync(runtime);
        var decoded = RepositoryCiRuntimeObservationWireCodec.Decode(transport.Payload.Span);

        await Assert.That(acknowledgement.Stream).IsEqualTo(GlobalNatsTopology.CiStream);
        await Assert.That(acknowledgement.Sequence).IsEqualTo(41UL);
        await Assert.That(decoded).IsEqualTo(runtime);
        await Assert.That(transport.MessageId)
            .IsEqualTo(RepositoryCiRuntimeObservationWireCodec.MessageId(runtime));
        await Assert.That(transport.MessageId).Contains(
            RepositoryCiArtifactAttestation.SubjectDigest(runtime.Subject));
    }

    [Test]
    public async Task VerifiedObservationIsFencedDurableAndReplayConverges()
    {
        var runtime = Runtime(signer);
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var inbox = new RepositoryCiRuntimeObservationInbox(new(ledger, objects), signer);
        var payload = RepositoryCiRuntimeObservationWireCodec.Encode(runtime);

        var recorded = await inbox.HandleAsync(payload, 7, 11, static () => true);
        var replayed = await inbox.HandleAsync(payload, 7, 11, static () => true);

        await Assert.That(recorded.Disposition)
            .IsEqualTo(RepositoryCiRuntimeObservationInboxDisposition.Recorded);
        await Assert.That(replayed.Disposition)
            .IsEqualTo(RepositoryCiRuntimeObservationInboxDisposition.Duplicate);
        await Assert.That(recorded.CanAcknowledge && replayed.CanAcknowledge).IsTrue();
        await Assert.That(ledger.Mutations).IsEqualTo(1);
        await Assert.That(objects.Values.Count).IsEqualTo(1);
    }

    [Test]
    public async Task InvalidSignatureAuthorityLossAndNoncanonicalWireStoreNothing()
    {
        var runtime = Runtime(signer);
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new TestObjectStore();
        var inbox = new RepositoryCiRuntimeObservationInbox(
            new(ledger, objects),
            new HashSignature(2));
        var payload = RepositoryCiRuntimeObservationWireCodec.Encode(runtime);
        var noncanonical = payload.Concat([(byte)' ']).ToArray();

        var invalid = await inbox.HandleAsync(payload, 7, 11, static () => true);
        var stale = await new RepositoryCiRuntimeObservationInbox(new(ledger, objects), signer)
            .HandleAsync(payload, 7, 11, static () => false);
        var malformed = await inbox.HandleAsync(noncanonical, 7, 11, static () => true);

        await Assert.That(invalid.Disposition)
            .IsEqualTo(RepositoryCiRuntimeObservationInboxDisposition.InvalidProof);
        await Assert.That(stale.Disposition)
            .IsEqualTo(RepositoryCiRuntimeObservationInboxDisposition.AuthorityLost);
        await Assert.That(malformed.Disposition)
            .IsEqualTo(RepositoryCiRuntimeObservationInboxDisposition.InvalidProof);
        await Assert.That(invalid.CanAcknowledge || stale.CanAcknowledge || malformed.CanAcknowledge).IsFalse();
        await Assert.That(ledger.Mutations).IsEqualTo(0);
        await Assert.That(objects.Values).IsEmpty();
    }

    [Test]
    public async Task PublisherRejectsAFalseJetStreamAcknowledgement()
    {
        var transport = new TestTransport { Stream = "OTHER", Sequence = 0 };

        await Assert.That(async () => await new RepositoryCiRuntimeObservationPublisher(transport)
                .PublishAsync(Runtime(signer)))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task RuntimeProofConsumerMetadataIsExactAndBounded()
    {
        var configuration = new GlobalNatsTopology(3).CiRuntimeProofConsumer;
        var valid = new RepositoryCiRuntimeObservationMessageMetadata(
            GlobalNatsTopology.CiRuntimeProofSubject,
            GlobalNatsTopology.CiStream,
            configuration.Name!,
            41,
            1,
            1,
            RepositoryCiRuntimeObservationWireCodec.MaximumWireBytes);

        await Assert.That(RepositoryCiRuntimeObservationNatsConsumer.ValidMetadata(valid, configuration)).IsTrue();
        await Assert.That(RepositoryCiRuntimeObservationNatsConsumer.ValidMetadata(
            valid with { Subject = GlobalNatsTopology.CiSubject }, configuration)).IsFalse();
        await Assert.That(RepositoryCiRuntimeObservationNatsConsumer.ValidMetadata(
            valid with { Stream = GlobalNatsTopology.CellSpecStream }, configuration)).IsFalse();
        await Assert.That(RepositoryCiRuntimeObservationNatsConsumer.ValidMetadata(
            valid with { Consumer = "other" }, configuration)).IsFalse();
        await Assert.That(RepositoryCiRuntimeObservationNatsConsumer.ValidMetadata(
            valid with { StreamSequence = 0 }, configuration)).IsFalse();
        await Assert.That(RepositoryCiRuntimeObservationNatsConsumer.ValidMetadata(
            valid with { DeliveryCount = 6 }, configuration)).IsFalse();
        await Assert.That(RepositoryCiRuntimeObservationNatsConsumer.ValidMetadata(
            valid with { MessageSize = RepositoryCiRuntimeObservationWireCodec.MaximumWireBytes + 1 },
            configuration)).IsFalse();
    }

    private static RepositoryCiSignedRuntimeObservation Runtime(HashSignature signer)
    {
        var subject = new RepositoryCiArtifactSubject(
            Digest('a'),
            new("candidate-job"),
            new("TerraScale/TerraScale.Orchestrator"),
            RepositoryCiArchitecture.LinuxX64,
            new(Digest('b')),
            RepositoryCiArtifactAttestation.EntrypointsDigest(
                RepositoryCiArchitecture.LinuxX64,
                ["orchestrator/terrascale-orchestrator"]));
        return RepositoryCiArtifactAttestation.ObserveRuntime(subject, subject.Digest, signer);
    }

    private static string Digest(char value) => new(value, 64);

    private sealed class TestTransport : IRepositoryCiRuntimeObservationTransport
    {
        internal string Stream { get; set; } = GlobalNatsTopology.CiStream;
        internal ulong Sequence { get; set; } = 41;
        internal string MessageId { get; private set; } = string.Empty;
        internal ReadOnlyMemory<byte> Payload { get; private set; }

        public Task<RepositoryCiRuntimeObservationTransportAck> PublishAsync(
            string messageId,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            MessageId = messageId;
            Payload = payload.ToArray();
            return Task.FromResult(new RepositoryCiRuntimeObservationTransportAck(
                Stream,
                Sequence));
        }
    }

    private sealed class HashSignature(byte domain) :
        IRepositoryCiArtifactAttestationSigner,
        IRepositoryCiArtifactSignatureVerifier
    {
        public string Identity => $"test-key-{domain}";

        public OpaqueSignature Sign(ReadOnlyMemory<byte> canonicalMaterial)
        {
            var bytes = new byte[canonicalMaterial.Length + 1];
            bytes[0] = domain;
            canonicalMaterial.Span.CopyTo(bytes.AsSpan(1));
            OpaqueSignature.TryCopyFrom(SHA256.HashData(bytes), out var signature);
            return signature!;
        }

        public VerificationOutcome Verify(
            string signingIdentity,
            ReadOnlyMemory<byte> canonicalMaterial,
            OpaqueSignature signature) => signingIdentity == Identity && Sign(canonicalMaterial).Equals(signature)
            ? VerificationOutcome.Valid
            : VerificationOutcome.Invalid;
    }

    private sealed class TestObjectStore : IDeliveryObjectStore
    {
        internal Dictionary<string, byte[]> Values { get; } = new(StringComparer.Ordinal);

        public Task PutAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Values[name] = content.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Values.TryGetValue(name, out var content)) throw new IOException("Missing test object.");
            return Task.FromResult(content.ToArray());
        }
    }
}
