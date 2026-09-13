using TerraScale.Orchestrator.ControlPlane.Snapshots;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class SnapshotValidationTests
{
    [Test]
    public async Task Default_result_and_invalid_context_fail_closed()
    {
        await Assert.That(default(SnapshotValidationResult).IsValid).IsFalse();
        await Assert.That(default(SnapshotValidationResult).Error).IsEqualTo(SnapshotValidationError.Uninitialized);
        await Assert.That(SignedSnapshotValidator.Validate(SnapshotTestData.Snapshot(), null).Error)
            .IsEqualTo(SnapshotValidationError.InvalidContext);

        var invalid = new SnapshotValidationContext(
            default, SnapshotTestData.Stream(), SnapshotTestData.Key(), SnapshotTestData.Schema(),
            SnapshotTestData.Epoch(), SnapshotTestData.Sequence(100), SnapshotTestData.Generation(), SnapshotTestData.Digest(),
            new TestSchemaCompatibility(), new TestSnapshotSignatureVerifier());
        await Assert.That(SignedSnapshotValidator.Validate(SnapshotTestData.Snapshot(), invalid).Error)
            .IsEqualTo(SnapshotValidationError.InvalidContext);
        await Assert.That(SignedSnapshotValidator.Validate(
            new SignedSnapshot(null!, SnapshotTestData.Signature()), SnapshotTestData.Context()).Error)
            .IsEqualTo(SnapshotValidationError.MalformedSnapshot);
        await Assert.That(SignedSnapshotValidator.Validate(
            new SignedSnapshot(SnapshotTestData.Material(), null!), SnapshotTestData.Context()).Error)
            .IsEqualTo(SnapshotValidationError.MalformedSnapshot);
    }

    [Test]
    public async Task Wrong_scope_schema_epoch_position_digest_and_signature_are_typed()
    {
        await AssertError(SnapshotTestData.Material(authority: SnapshotTestData.Authority("other")), SnapshotValidationError.WrongAuthority);
        await AssertError(SnapshotTestData.Material(stream: SnapshotTestData.Stream("other")), SnapshotValidationError.WrongStream);
        await AssertError(SnapshotTestData.Material(key: SnapshotTestData.Key("other")), SnapshotValidationError.WrongSigningKey);
        await AssertError(SnapshotTestData.Material(), SnapshotValidationError.UnknownSchema,
            SnapshotTestData.Context(compatibility: new TestSchemaCompatibility(SnapshotSchemaCompatibilityOutcome.Unknown)));
        await AssertError(SnapshotTestData.Material(), SnapshotValidationError.IncompatibleSchema,
            SnapshotTestData.Context(compatibility: new TestSchemaCompatibility(SnapshotSchemaCompatibilityOutcome.Incompatible)));
        await AssertError(SnapshotTestData.Material(epoch: SnapshotTestData.Epoch(6)), SnapshotValidationError.StaleEpoch);
        await AssertError(SnapshotTestData.Material(sequence: SnapshotTestData.Sequence(100)), SnapshotValidationError.StreamRollback);
        await AssertError(SnapshotTestData.Material(sequence: SnapshotTestData.Sequence(99)), SnapshotValidationError.StreamRollback);
        await AssertError(SnapshotTestData.Material(digest: SnapshotTestData.Digest("tampered")), SnapshotValidationError.StateDigestMismatch);
        await AssertError(SnapshotTestData.Material(), SnapshotValidationError.InvalidSignature,
            SnapshotTestData.Context(signatureVerifier: new TestSnapshotSignatureVerifier(SnapshotSignatureVerificationOutcome.Invalid)));
    }

    [Test]
    public async Task Verifier_failures_and_unknown_outcomes_are_closed_and_secret_safe()
    {
        var compatibilityFailure = SignedSnapshotValidator.Validate(
            SnapshotTestData.Snapshot(),
            SnapshotTestData.Context(compatibility: new TestSchemaCompatibility(throws: true)));
        var signatureFailure = SignedSnapshotValidator.Validate(
            SnapshotTestData.Snapshot(),
            SnapshotTestData.Context(signatureVerifier: new TestSnapshotSignatureVerifier(throws: true)));
        var unknownCompatibility = SignedSnapshotValidator.Validate(
            SnapshotTestData.Snapshot(),
            SnapshotTestData.Context(compatibility: new TestSchemaCompatibility((SnapshotSchemaCompatibilityOutcome)99)));
        var unknownSignature = SignedSnapshotValidator.Validate(
            SnapshotTestData.Snapshot(),
            SnapshotTestData.Context(signatureVerifier: new TestSnapshotSignatureVerifier((SnapshotSignatureVerificationOutcome)99)));

        await Assert.That(compatibilityFailure.Error).IsEqualTo(SnapshotValidationError.SchemaCompatibilityFailed);
        await Assert.That(signatureFailure.Error).IsEqualTo(SnapshotValidationError.SignatureVerificationFailed);
        await Assert.That(unknownCompatibility.Error).IsEqualTo(SnapshotValidationError.SchemaCompatibilityFailed);
        await Assert.That(unknownSignature.Error).IsEqualTo(SnapshotValidationError.SignatureVerificationFailed);
        await Assert.That(compatibilityFailure.ToString()).DoesNotContain("schema-compatibility-secret");
        await Assert.That(signatureFailure.ToString()).DoesNotContain("signature-verifier-secret");
    }

    [Test]
    public async Task Tampering_each_signed_field_or_signature_is_detected()
    {
        var original = SnapshotTestData.Material();
        var signature = SnapshotTestData.Signature();
        var verifier = new TestSnapshotSignatureVerifier(expectedMaterial: original, expectedSignature: signature);
        var tampered = new[]
        {
            SnapshotTestData.Material(authority: SnapshotTestData.Authority("other-authority")),
            SnapshotTestData.Material(stream: SnapshotTestData.Stream("other-stream")),
            SnapshotTestData.Material(id: SnapshotTestData.Id("other-id")),
            SnapshotTestData.Material(schema: SnapshotTestData.Schema("other-schema")),
            SnapshotTestData.Material(key: SnapshotTestData.Key("other-key")),
            SnapshotTestData.Material(epoch: SnapshotTestData.Epoch(8)),
            SnapshotTestData.Material(sequence: SnapshotTestData.Sequence(102)),
            SnapshotTestData.Material(generation: SnapshotTestData.Generation(4)),
            SnapshotTestData.Material(digest: SnapshotTestData.Digest("other-digest")),
        };

        foreach (var material in tampered)
        {
            var tailored = SnapshotTestData.Context(
                authority: material.Authority,
                stream: material.Stream,
                key: material.SigningKey,
                currentSchema: material.Schema,
                currentEpoch: SnapshotTestData.Epoch(1),
                currentSequence: SnapshotTestData.Sequence(1),
                digest: material.StateDigest,
                signatureVerifier: verifier);
            await Assert.That(SignedSnapshotValidator.Validate(new SignedSnapshot(material, signature), tailored).Error)
                .IsEqualTo(SnapshotValidationError.InvalidSignature);
        }

        await Assert.That(SignedSnapshotValidator.Validate(
            new SignedSnapshot(original, SnapshotTestData.Signature("other-signature")),
            SnapshotTestData.Context(signatureVerifier: verifier)).Error)
            .IsEqualTo(SnapshotValidationError.InvalidSignature);
    }

    private static async Task AssertError(
        SnapshotSignedMaterial material,
        SnapshotValidationError expected,
        SnapshotValidationContext? context = null) =>
        await Assert.That(SignedSnapshotValidator.Validate(SnapshotTestData.Snapshot(material), context ?? SnapshotTestData.Context()).Error)
            .IsEqualTo(expected);
}

