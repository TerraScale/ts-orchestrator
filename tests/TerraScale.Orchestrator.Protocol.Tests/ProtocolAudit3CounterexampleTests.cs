using System.Reflection;
using System.Text;

namespace TerraScale.Orchestrator.Protocol.Tests;

public sealed class ProtocolAudit3CounterexampleTests
{
    [Test]
    public async Task Accepted_validation_receipt_distinguishes_the_exact_protocol_and_command()
    {
        var context = ProtocolTestData.ValidContext(
            acceptedProtocols: [ProtocolTestData.Protocol(1), ProtocolTestData.Protocol(2)]);
        var n = ProtocolTestData.ValidEnvelope(
            protocol: ProtocolTestData.Protocol(2),
            generation: ProtocolTestData.Generation(11),
            operation: ProtocolTestData.Operation("operation/n"),
            idempotency: ProtocolTestData.Idempotency("idempotency/n"));
        var nMinusOne = ProtocolTestData.ValidEnvelope(
            protocol: ProtocolTestData.Protocol(1),
            generation: ProtocolTestData.Generation(10),
            operation: ProtocolTestData.Operation("operation/n-minus-one"),
            idempotency: ProtocolTestData.Idempotency("idempotency/n-minus-one"));

        var acceptedN = CommandEnvelopeValidator.Validate(n, context, ProtocolTestData.Now);
        var acceptedNMinusOne = CommandEnvelopeValidator.Validate(nMinusOne, context, ProtocolTestData.Now);

        await Assert.That(acceptedN.IsValid).IsTrue();
        await Assert.That(acceptedNMinusOne.IsValid).IsTrue();
        await Assert.That(acceptedN).IsNotEqualTo(acceptedNMinusOne);
    }

    [Test]
    public async Task Acceptance_retains_every_approved_field_but_not_the_raw_payload()
    {
        var payloadSecret = Encoding.UTF8.GetBytes("payload-secret");
        var digestSecret = Encoding.UTF8.GetBytes("digest-secret");
        var signatureSecret = Encoding.UTF8.GetBytes("signature-secret");
        var validatedAt = ProtocolTestData.Now.AddSeconds(17);
        var envelope = ProtocolTestData.ValidEnvelope(
            protocol: ProtocolTestData.Protocol(2),
            generation: ProtocolTestData.Generation(11),
            epoch: ProtocolTestData.Epoch(8),
            operation: ProtocolTestData.Operation("operation/exact"),
            idempotency: ProtocolTestData.Idempotency("idempotency/exact"),
            issuedAt: ProtocolTestData.Now.AddMinutes(-2),
            expiresAt: ProtocolTestData.Now.AddMinutes(2),
            attempt: ProtocolTestData.Attempt(3),
            payload: OpaquePayload.CopyFrom(payloadSecret),
            digest: ProtocolTestData.Digest(digestSecret),
            signature: ProtocolTestData.Signature(signatureSecret));
        var context = ProtocolTestData.ValidContext(
            minimumGeneration: ProtocolTestData.Generation(11),
            minimumEpoch: ProtocolTestData.Epoch(8),
            acceptedProtocols: [ProtocolTestData.Protocol(1), ProtocolTestData.Protocol(2)],
            digestVerifier: new OutcomeDigestVerifier(VerificationOutcome.Valid));

        var result = CommandEnvelopeValidator.Validate(envelope, context, validatedAt);
        var receipt = result.Acceptance!;

        await Assert.That(result.IsValid).IsTrue();
        await Assert.That(receipt.ProtocolVersion).IsEqualTo(envelope.ProtocolVersion);
        await Assert.That(receipt.Cell).IsEqualTo(envelope.Cell);
        await Assert.That(receipt.AggregateId).IsEqualTo(envelope.AggregateId);
        await Assert.That(receipt.DesiredGeneration).IsEqualTo(envelope.DesiredGeneration);
        await Assert.That(receipt.WriterEpoch).IsEqualTo(envelope.WriterEpoch);
        await Assert.That(receipt.OperationId).IsEqualTo(envelope.OperationId);
        await Assert.That(receipt.IdempotencyKey).IsEqualTo(envelope.IdempotencyKey);
        await Assert.That(receipt.IssuedAt).IsEqualTo(envelope.IssuedAt);
        await Assert.That(receipt.ExpiresAt).IsEqualTo(envelope.ExpiresAt);
        await Assert.That(receipt.Attempt).IsEqualTo(envelope.Attempt);
        await Assert.That(receipt.PayloadDigest).IsEqualTo(envelope.PayloadDigest);
        await Assert.That(receipt.Signature).IsEqualTo(envelope.Signature);
        await Assert.That(receipt.ValidatedAt).IsEqualTo(validatedAt);
        await Assert.That(typeof(CommandAcceptance).GetProperty("Payload")).IsNull();
        await Assert.That(typeof(CommandAcceptance).GetProperty("SignedMaterial")).IsNull();

        var rendered = receipt.ToString();
        await Assert.That(rendered).DoesNotContain(Encoding.UTF8.GetString(payloadSecret));
        await Assert.That(rendered).DoesNotContain(Encoding.UTF8.GetString(digestSecret));
        await Assert.That(rendered).DoesNotContain(Encoding.UTF8.GetString(signatureSecret));
        await Assert.That(rendered).Contains("PayloadDigest = <redacted>");
        await Assert.That(rendered).Contains("Signature = <redacted>");
    }

    [Test]
    public async Task Identical_replay_is_equal_and_each_receipt_field_participates_in_equality()
    {
        var baselineEnvelope = ProtocolTestData.ValidEnvelope();
        var baseline = Accept(baselineEnvelope, ProtocolTestData.Now);
        await Assert.That(Accept(baselineEnvelope, ProtocolTestData.Now)).IsEqualTo(baseline);

        var variants = new (CommandEnvelope Envelope, DateTimeOffset Now)[]
        {
            (ProtocolTestData.ValidEnvelope(protocol: ProtocolTestData.Protocol(2)), ProtocolTestData.Now),
            (ProtocolTestData.ValidEnvelope(cell: ProtocolTestData.Cell("sfo")), ProtocolTestData.Now),
            (ProtocolTestData.ValidEnvelope(aggregate: ProtocolTestData.Aggregate("allocation/other")), ProtocolTestData.Now),
            (ProtocolTestData.ValidEnvelope(generation: ProtocolTestData.Generation(11)), ProtocolTestData.Now),
            (ProtocolTestData.ValidEnvelope(epoch: ProtocolTestData.Epoch(8)), ProtocolTestData.Now),
            (ProtocolTestData.ValidEnvelope(operation: ProtocolTestData.Operation("operation/other")), ProtocolTestData.Now),
            (ProtocolTestData.ValidEnvelope(idempotency: ProtocolTestData.Idempotency("idempotency/other")), ProtocolTestData.Now),
            (ProtocolTestData.ValidEnvelope(issuedAt: ProtocolTestData.Now.AddSeconds(-30)), ProtocolTestData.Now),
            (ProtocolTestData.ValidEnvelope(expiresAt: ProtocolTestData.Now.AddSeconds(30)), ProtocolTestData.Now),
            (ProtocolTestData.ValidEnvelope(attempt: ProtocolTestData.Attempt(2)), ProtocolTestData.Now),
            (ProtocolTestData.ValidEnvelope(digest: ProtocolTestData.Digest([4, 3, 2, 1])), ProtocolTestData.Now),
            (ProtocolTestData.ValidEnvelope(signature: ProtocolTestData.Signature([6, 7, 8, 9])), ProtocolTestData.Now),
            (baselineEnvelope, ProtocolTestData.Now.AddTicks(1)),
        };

        foreach (var variant in variants)
        {
            await Assert.That(Accept(variant.Envelope, variant.Now)).IsNotEqualTo(baseline);
        }
    }

    [Test]
    public async Task Rejections_and_default_never_carry_an_acceptance()
    {
        await Assert.That(default(CommandValidationResult).Acceptance).IsNull();
        foreach (var protocol in Enumerable.Range(2, 32))
        {
            var result = CommandEnvelopeValidator.Validate(
                ProtocolTestData.ValidEnvelope(protocol: ProtocolTestData.Protocol(protocol)),
                ProtocolTestData.ValidContext(),
                ProtocolTestData.Now);
            await Assert.That(result.IsValid).IsFalse();
            await Assert.That(result.Acceptance).IsNull();
        }
    }

    [Test]
    public async Task Acceptance_construction_surface_is_closed()
    {
        var type = typeof(CommandAcceptance);
        await Assert.That(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(static property => property.SetMethod?.IsPublic == true)).IsEmpty();
        await Assert.That(type.GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(static method => method.Name == "Deconstruct")).IsEmpty();
        await Assert.That(type.Assembly.GetExportedTypes()
            .SelectMany(static exported => exported.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(static method => !method.IsSpecialName && method.ReturnType == typeof(CommandAcceptance))).IsEmpty();
    }

    private static CommandValidationResult Accept(CommandEnvelope envelope, DateTimeOffset now)
    {
        var context = new CommandValidationContext(
            envelope.Cell,
            envelope.AggregateId,
            envelope.DesiredGeneration,
            envelope.WriterEpoch,
            [ProtocolTestData.Protocol(1), ProtocolTestData.Protocol(2)],
            TimeSpan.FromMinutes(2),
            new OutcomeDigestVerifier(VerificationOutcome.Valid),
            new OutcomeSignatureVerifier(VerificationOutcome.Valid));
        return CommandEnvelopeValidator.Validate(envelope, context, now);
    }

    private sealed class OutcomeDigestVerifier(VerificationOutcome outcome) : IPayloadDigestVerifier
    {
        public VerificationOutcome Verify(OpaquePayload payload, PayloadDigest expectedDigest) => outcome;
    }

    private sealed class OutcomeSignatureVerifier(VerificationOutcome outcome) : ICommandSignatureVerifier
    {
        public VerificationOutcome Verify(CommandSignedMaterial signedMaterial, OpaqueSignature signature) => outcome;
    }
}
