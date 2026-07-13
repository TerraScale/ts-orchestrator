using System.Text;

namespace TerraScale.Orchestrator.Protocol.Tests;

public class CommandEnvelopeTests
{
    [Test]
    public async Task Envelope_carries_every_required_field()
    {
        var envelope = ProtocolTestData.ValidEnvelope();

        await Assert.That(envelope.ProtocolVersion).IsEqualTo(ProtocolTestData.Protocol(1));
        await Assert.That(envelope.Cell).IsEqualTo(ProtocolTestData.Cell("gru"));
        await Assert.That(envelope.AggregateId).IsEqualTo(ProtocolTestData.Aggregate("allocation/42"));
        await Assert.That(envelope.DesiredGeneration).IsEqualTo(ProtocolTestData.Generation(10));
        await Assert.That(envelope.WriterEpoch).IsEqualTo(ProtocolTestData.Epoch(7));
        await Assert.That(envelope.OperationId).IsEqualTo(ProtocolTestData.Operation("operation/abc"));
        await Assert.That(envelope.IdempotencyKey).IsEqualTo(ProtocolTestData.Idempotency("idempotency/abc"));
        await Assert.That(envelope.IssuedAt).IsEqualTo(ProtocolTestData.Now.AddMinutes(-1));
        await Assert.That(envelope.ExpiresAt).IsEqualTo(ProtocolTestData.Now.AddMinutes(1));
        await Assert.That(envelope.Attempt).IsEqualTo(ProtocolTestData.Attempt(1));
        await Assert.That(envelope.Payload.Bytes.SequenceEqual(ProtocolTestData.PayloadBytes)).IsTrue();
        await Assert.That(envelope.PayloadDigest.Bytes.SequenceEqual(ProtocolTestData.PayloadBytes)).IsTrue();
        await Assert.That(envelope.Signature.Bytes.SequenceEqual(ProtocolTestData.SignatureBytes)).IsTrue();
    }

    [Test]
    public async Task Envelope_formatting_never_renders_payload_digest_or_signature()
    {
        var payloadSecret = "payload-super-secret";
        var digestSecret = "digest-super-secret";
        var signatureSecret = "signature-super-secret";
        var envelope = ProtocolTestData.ValidEnvelope(
            payload: OpaquePayload.CopyFrom(Encoding.UTF8.GetBytes(payloadSecret)),
            digest: ProtocolTestData.Digest(Encoding.UTF8.GetBytes(digestSecret)),
            signature: ProtocolTestData.Signature(Encoding.UTF8.GetBytes(signatureSecret)));

        var rendered = envelope.ToString();

        await Assert.That(rendered).DoesNotContain(payloadSecret);
        await Assert.That(rendered).DoesNotContain(digestSecret);
        await Assert.That(rendered).DoesNotContain(signatureSecret);
        await Assert.That(rendered).Contains("Payload = <redacted>");
        await Assert.That(rendered).Contains("Signature = <redacted>");
    }
}
