using TerraScale.Orchestrator.Contracts;

namespace TerraScale.Orchestrator.Protocol.Tests;

public class CommandEnvelopeValidatorTests
{
    [Test]
    public async Task Default_validation_result_is_not_accidentally_accepted()
    {
        var result = default(CommandValidationResult);

        await Assert.That(result.IsValid).IsFalse();
        await Assert.That(result.Error).IsEqualTo(CommandValidationError.Uninitialized);
    }

    [Test]
    public async Task Valid_envelope_is_accepted_and_identical_replay_is_idempotent()
    {
        var digestVerifier = new TestDigestVerifier();
        var signatureVerifier = new TestSignatureVerifier();
        var context = ProtocolTestData.ValidContext(
            digestVerifier: digestVerifier,
            signatureVerifier: signatureVerifier);
        var envelope = ProtocolTestData.ValidEnvelope();

        var first = CommandEnvelopeValidator.Validate(envelope, context, ProtocolTestData.Now);
        var replay = CommandEnvelopeValidator.Validate(envelope, context, ProtocolTestData.Now);

        await Assert.That(first.IsValid).IsTrue();
        await Assert.That(first.Error).IsEqualTo(CommandValidationError.None);
        await Assert.That(replay).IsEqualTo(first);
        await Assert.That(digestVerifier.Calls).IsEqualTo(2);
        await Assert.That(signatureVerifier.Calls).IsEqualTo(2);
    }

    [Test]
    public async Task Malformed_envelope_fields_fail_before_verifiers()
    {
        var digestVerifier = new TestDigestVerifier();
        var signatureVerifier = new TestSignatureVerifier();
        var context = ProtocolTestData.ValidContext(
            digestVerifier: digestVerifier,
            signatureVerifier: signatureVerifier);
        var malformed = new CommandEnvelope?[]
        {
            null,
            ProtocolTestData.ValidEnvelope(protocol: default(ProtocolRevision)),
            ProtocolTestData.ValidEnvelope(cell: default(CellId)),
            ProtocolTestData.ValidEnvelope(aggregate: default(AggregateId)),
            ProtocolTestData.ValidEnvelope(generation: default(DesiredGeneration)),
            ProtocolTestData.ValidEnvelope(epoch: default(WriterEpoch)),
            ProtocolTestData.ValidEnvelope(operation: default(OperationId)),
            ProtocolTestData.ValidEnvelope(idempotency: default(IdempotencyKey)),
            ProtocolTestData.ValidEnvelope(attempt: default(DeliveryAttempt)),
            EnvelopeWithNullableBytes(payload: null, digest: ProtocolTestData.Digest(ProtocolTestData.PayloadBytes), signature: ProtocolTestData.Signature(ProtocolTestData.SignatureBytes)),
            EnvelopeWithNullableBytes(payload: OpaquePayload.CopyFrom(ProtocolTestData.PayloadBytes), digest: null, signature: ProtocolTestData.Signature(ProtocolTestData.SignatureBytes)),
            EnvelopeWithNullableBytes(payload: OpaquePayload.CopyFrom(ProtocolTestData.PayloadBytes), digest: ProtocolTestData.Digest(ProtocolTestData.PayloadBytes), signature: null),
        };

        foreach (var envelope in malformed)
        {
            var result = CommandEnvelopeValidator.Validate(envelope, context, ProtocolTestData.Now);
            await Assert.That(result.Error).IsEqualTo(CommandValidationError.MalformedEnvelope);
        }

        await Assert.That(digestVerifier.Calls).IsEqualTo(0);
        await Assert.That(signatureVerifier.Calls).IsEqualTo(0);
    }

    [Test]
    public async Task Invalid_context_is_closed_and_precedes_envelope_validation()
    {
        var validEnvelope = ProtocolTestData.ValidEnvelope();
        var invalidContexts = new CommandValidationContext?[]
        {
            null,
            new(default, ProtocolTestData.Aggregate("allocation/42"), ProtocolTestData.Generation(10), ProtocolTestData.Epoch(7), [ProtocolTestData.Protocol(1)], TimeSpan.Zero, new TestDigestVerifier(), new TestSignatureVerifier()),
            new(ProtocolTestData.Cell("gru"), default, ProtocolTestData.Generation(10), ProtocolTestData.Epoch(7), [ProtocolTestData.Protocol(1)], TimeSpan.Zero, new TestDigestVerifier(), new TestSignatureVerifier()),
            new(ProtocolTestData.Cell("gru"), ProtocolTestData.Aggregate("allocation/42"), default, ProtocolTestData.Epoch(7), [ProtocolTestData.Protocol(1)], TimeSpan.Zero, new TestDigestVerifier(), new TestSignatureVerifier()),
            new(ProtocolTestData.Cell("gru"), ProtocolTestData.Aggregate("allocation/42"), ProtocolTestData.Generation(10), default, [ProtocolTestData.Protocol(1)], TimeSpan.Zero, new TestDigestVerifier(), new TestSignatureVerifier()),
            new(ProtocolTestData.Cell("gru"), ProtocolTestData.Aggregate("allocation/42"), ProtocolTestData.Generation(10), ProtocolTestData.Epoch(7), [], TimeSpan.Zero, new TestDigestVerifier(), new TestSignatureVerifier()),
            new(ProtocolTestData.Cell("gru"), ProtocolTestData.Aggregate("allocation/42"), ProtocolTestData.Generation(10), ProtocolTestData.Epoch(7), [default], TimeSpan.Zero, new TestDigestVerifier(), new TestSignatureVerifier()),
            new(ProtocolTestData.Cell("gru"), ProtocolTestData.Aggregate("allocation/42"), ProtocolTestData.Generation(10), ProtocolTestData.Epoch(7), [ProtocolTestData.Protocol(1)], TimeSpan.FromTicks(-1), new TestDigestVerifier(), new TestSignatureVerifier()),
            new(ProtocolTestData.Cell("gru"), ProtocolTestData.Aggregate("allocation/42"), ProtocolTestData.Generation(10), ProtocolTestData.Epoch(7), [ProtocolTestData.Protocol(1)], TimeSpan.Zero, null, new TestSignatureVerifier()),
            new(ProtocolTestData.Cell("gru"), ProtocolTestData.Aggregate("allocation/42"), ProtocolTestData.Generation(10), ProtocolTestData.Epoch(7), [ProtocolTestData.Protocol(1)], TimeSpan.Zero, new TestDigestVerifier(), null),
        };

        foreach (var context in invalidContexts)
        {
            var result = CommandEnvelopeValidator.Validate(validEnvelope, context, ProtocolTestData.Now);
            await Assert.That(result.Error).IsEqualTo(CommandValidationError.InvalidValidationContext);
        }
    }

    [Test]
    public async Task Accepted_protocol_versions_are_defensively_copied()
    {
        var accepted = new HashSet<ProtocolRevision> { ProtocolTestData.Protocol(1) };
        var context = ProtocolTestData.ValidContext(acceptedProtocols: accepted);
        accepted.Clear();
        accepted.Add(ProtocolTestData.Protocol(2));

        var result = CommandEnvelopeValidator.Validate(
            ProtocolTestData.ValidEnvelope(),
            context,
            ProtocolTestData.Now);

        await Assert.That(result.IsValid).IsTrue();
    }

    [Test]
    public async Task Unsupported_protocol_precedes_time_and_identity_checks()
    {
        var envelope = ProtocolTestData.ValidEnvelope(
            protocol: ProtocolTestData.Protocol(2),
            cell: ProtocolTestData.Cell("wrong"),
            issuedAt: ProtocolTestData.Now.AddHours(2),
            expiresAt: ProtocolTestData.Now.AddHours(1));

        var result = CommandEnvelopeValidator.Validate(
            envelope,
            ProtocolTestData.ValidContext(),
            ProtocolTestData.Now);

        await Assert.That(result.Error).IsEqualTo(CommandValidationError.UnsupportedProtocolVersion);
    }

    [Test]
    public async Task Equal_validity_endpoints_are_allowed_but_reversed_window_is_never_resurrected()
    {
        var equal = ProtocolTestData.ValidEnvelope(
            issuedAt: ProtocolTestData.Now,
            expiresAt: ProtocolTestData.Now);
        var reversed = ProtocolTestData.ValidEnvelope(
            issuedAt: ProtocolTestData.Now.AddDays(1),
            expiresAt: ProtocolTestData.Now.AddDays(-1));
        var context = ProtocolTestData.ValidContext(skew: TimeSpan.MaxValue);

        await Assert.That(CommandEnvelopeValidator.Validate(equal, context, ProtocolTestData.Now).IsValid).IsTrue();
        await Assert.That(CommandEnvelopeValidator.Validate(reversed, context, ProtocolTestData.Now).Error)
            .IsEqualTo(CommandValidationError.InvalidValidityWindow);
    }

    [Test]
    public async Task Clock_skew_boundaries_are_inclusive_and_one_tick_beyond_is_rejected()
    {
        var skew = TimeSpan.FromMinutes(2);
        var context = ProtocolTestData.ValidContext(skew: skew);
        var issueBoundary = ProtocolTestData.ValidEnvelope(
            issuedAt: ProtocolTestData.Now + skew,
            expiresAt: ProtocolTestData.Now.AddMinutes(3));
        var expiryBoundary = ProtocolTestData.ValidEnvelope(
            issuedAt: ProtocolTestData.Now.AddMinutes(-3),
            expiresAt: ProtocolTestData.Now - skew);
        var issueBeyond = ProtocolTestData.ValidEnvelope(
            issuedAt: ProtocolTestData.Now + skew + TimeSpan.FromTicks(1),
            expiresAt: ProtocolTestData.Now.AddMinutes(3));
        var expiryBeyond = ProtocolTestData.ValidEnvelope(
            issuedAt: ProtocolTestData.Now.AddMinutes(-3),
            expiresAt: ProtocolTestData.Now - skew - TimeSpan.FromTicks(1));

        await Assert.That(CommandEnvelopeValidator.Validate(issueBoundary, context, ProtocolTestData.Now).IsValid).IsTrue();
        await Assert.That(CommandEnvelopeValidator.Validate(expiryBoundary, context, ProtocolTestData.Now).IsValid).IsTrue();
        await Assert.That(CommandEnvelopeValidator.Validate(issueBeyond, context, ProtocolTestData.Now).Error)
            .IsEqualTo(CommandValidationError.NotYetValid);
        await Assert.That(CommandEnvelopeValidator.Validate(expiryBeyond, context, ProtocolTestData.Now).Error)
            .IsEqualTo(CommandValidationError.Expired);
    }

    [Test]
    public async Task Skew_comparisons_do_not_overflow_at_datetime_extremes()
    {
        var context = ProtocolTestData.ValidContext(skew: TimeSpan.Zero);
        var farFuture = ProtocolTestData.ValidEnvelope(
            issuedAt: DateTimeOffset.MaxValue.AddTicks(-1),
            expiresAt: DateTimeOffset.MaxValue);
        var farPast = ProtocolTestData.ValidEnvelope(
            issuedAt: DateTimeOffset.MinValue,
            expiresAt: DateTimeOffset.MinValue.AddTicks(1));

        await Assert.That(CommandEnvelopeValidator.Validate(farFuture, context, DateTimeOffset.MinValue).Error)
            .IsEqualTo(CommandValidationError.NotYetValid);
        await Assert.That(CommandEnvelopeValidator.Validate(farPast, context, DateTimeOffset.MaxValue).Error)
            .IsEqualTo(CommandValidationError.Expired);
    }

    [Test]
    public async Task Wrong_cell_precedes_invalid_signature_and_wrong_identity_is_typed()
    {
        var signatureVerifier = new TestSignatureVerifier(isValid: false);
        var context = ProtocolTestData.ValidContext(signatureVerifier: signatureVerifier);
        var wrongCell = ProtocolTestData.ValidEnvelope(cell: ProtocolTestData.Cell("sfo"));
        var wrongIdentity = ProtocolTestData.ValidEnvelope(aggregate: ProtocolTestData.Aggregate("allocation/other"));

        await Assert.That(CommandEnvelopeValidator.Validate(wrongCell, context, ProtocolTestData.Now).Error)
            .IsEqualTo(CommandValidationError.WrongCell);
        await Assert.That(signatureVerifier.Calls).IsEqualTo(0);
        await Assert.That(CommandEnvelopeValidator.Validate(wrongIdentity, context, ProtocolTestData.Now).Error)
            .IsEqualTo(CommandValidationError.WrongAggregateIdentity);
        await Assert.That(signatureVerifier.Calls).IsEqualTo(0);
    }

    [Test]
    public async Task Lower_generation_and_epoch_are_stale_while_equal_boundaries_pass()
    {
        var context = ProtocolTestData.ValidContext(
            minimumGeneration: ProtocolTestData.Generation(10),
            minimumEpoch: ProtocolTestData.Epoch(7));

        await Assert.That(CommandEnvelopeValidator.Validate(
            ProtocolTestData.ValidEnvelope(generation: ProtocolTestData.Generation(9)), context, ProtocolTestData.Now).Error)
            .IsEqualTo(CommandValidationError.StaleGeneration);
        await Assert.That(CommandEnvelopeValidator.Validate(
            ProtocolTestData.ValidEnvelope(generation: ProtocolTestData.Generation(10)), context, ProtocolTestData.Now).IsValid)
            .IsTrue();
        await Assert.That(CommandEnvelopeValidator.Validate(
            ProtocolTestData.ValidEnvelope(epoch: ProtocolTestData.Epoch(6)), context, ProtocolTestData.Now).Error)
            .IsEqualTo(CommandValidationError.StaleWriterEpoch);
        await Assert.That(CommandEnvelopeValidator.Validate(
            ProtocolTestData.ValidEnvelope(epoch: ProtocolTestData.Epoch(7)), context, ProtocolTestData.Now).IsValid)
            .IsTrue();
        await Assert.That(CommandEnvelopeValidator.Validate(
            ProtocolTestData.ValidEnvelope(
                generation: ProtocolTestData.Generation(9),
                epoch: ProtocolTestData.Epoch(6)), context, ProtocolTestData.Now).Error)
            .IsEqualTo(CommandValidationError.StaleGeneration);
    }

    [Test]
    public async Task Digest_mismatch_precedes_signature_and_invalid_signature_is_typed()
    {
        var signatureVerifier = new TestSignatureVerifier(isValid: false);
        var mismatchContext = ProtocolTestData.ValidContext(
            digestVerifier: new TestDigestVerifier(matches: false),
            signatureVerifier: signatureVerifier);

        await Assert.That(CommandEnvelopeValidator.Validate(
            ProtocolTestData.ValidEnvelope(), mismatchContext, ProtocolTestData.Now).Error)
            .IsEqualTo(CommandValidationError.PayloadDigestMismatch);
        await Assert.That(signatureVerifier.Calls).IsEqualTo(0);

        var invalidSignature = CommandEnvelopeValidator.Validate(
            ProtocolTestData.ValidEnvelope(),
            ProtocolTestData.ValidContext(signatureVerifier: new TestSignatureVerifier(isValid: false)),
            ProtocolTestData.Now);
        await Assert.That(invalidSignature.Error).IsEqualTo(CommandValidationError.InvalidSignature);
    }

    [Test]
    public async Task Verifier_exceptions_map_to_closed_errors_without_exception_text()
    {
        var digestFailure = CommandEnvelopeValidator.Validate(
            ProtocolTestData.ValidEnvelope(),
            ProtocolTestData.ValidContext(digestVerifier: new TestDigestVerifier(throws: true)),
            ProtocolTestData.Now);
        var signatureFailure = CommandEnvelopeValidator.Validate(
            ProtocolTestData.ValidEnvelope(),
            ProtocolTestData.ValidContext(signatureVerifier: new TestSignatureVerifier(throws: true)),
            ProtocolTestData.Now);

        await Assert.That(digestFailure.Error).IsEqualTo(CommandValidationError.PayloadDigestVerificationFailed);
        await Assert.That(signatureFailure.Error).IsEqualTo(CommandValidationError.SignatureVerificationFailed);
        await Assert.That(digestFailure.ToString()).DoesNotContain("synthetic verifier failure");
        await Assert.That(signatureFailure.ToString()).DoesNotContain("synthetic verifier failure");
    }

    [Test]
    public async Task Signature_verifier_receives_all_signed_fields_and_enforces_signer_policy()
    {
        var verifier = new TestSignatureVerifier(isValid: false);
        var envelope = ProtocolTestData.ValidEnvelope();

        var result = CommandEnvelopeValidator.Validate(
            envelope,
            ProtocolTestData.ValidContext(signatureVerifier: verifier),
            ProtocolTestData.Now);

        await Assert.That(result.Error).IsEqualTo(CommandValidationError.InvalidSignature);
        await Assert.That(verifier.LastMaterial).IsNotNull();
        await Assert.That(verifier.LastMaterial!.ProtocolVersion).IsEqualTo(envelope.ProtocolVersion);
        await Assert.That(verifier.LastMaterial.Cell).IsEqualTo(envelope.Cell);
        await Assert.That(verifier.LastMaterial.AggregateId).IsEqualTo(envelope.AggregateId);
        await Assert.That(verifier.LastMaterial.DesiredGeneration).IsEqualTo(envelope.DesiredGeneration);
        await Assert.That(verifier.LastMaterial.WriterEpoch).IsEqualTo(envelope.WriterEpoch);
        await Assert.That(verifier.LastMaterial.OperationId).IsEqualTo(envelope.OperationId);
        await Assert.That(verifier.LastMaterial.IdempotencyKey).IsEqualTo(envelope.IdempotencyKey);
        await Assert.That(verifier.LastMaterial.IssuedAt).IsEqualTo(envelope.IssuedAt);
        await Assert.That(verifier.LastMaterial.ExpiresAt).IsEqualTo(envelope.ExpiresAt);
        await Assert.That(verifier.LastMaterial.Attempt).IsEqualTo(envelope.Attempt);
        await Assert.That(verifier.LastMaterial.Payload).IsEqualTo(envelope.Payload);
        await Assert.That(verifier.LastMaterial.PayloadDigest).IsEqualTo(envelope.PayloadDigest);
        await Assert.That(verifier.LastSignature).IsEqualTo(envelope.Signature);
        await Assert.That(verifier.LastMaterial.ToString()).IsEqualTo("<command-signed-material>");
    }

    private static CommandEnvelope EnvelopeWithNullableBytes(
        OpaquePayload? payload,
        PayloadDigest? digest,
        OpaqueSignature? signature) =>
        new(
            ProtocolTestData.Protocol(1),
            ProtocolTestData.Cell("gru"),
            ProtocolTestData.Aggregate("allocation/42"),
            ProtocolTestData.Generation(10),
            ProtocolTestData.Epoch(7),
            ProtocolTestData.Operation("operation/abc"),
            ProtocolTestData.Idempotency("idempotency/abc"),
            ProtocolTestData.Now.AddMinutes(-1),
            ProtocolTestData.Now.AddMinutes(1),
            ProtocolTestData.Attempt(1),
            payload!,
            digest!,
            signature!);
}
