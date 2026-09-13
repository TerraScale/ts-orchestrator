using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Snapshots;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class SnapshotPolicyCompletenessTests
{
    private const int Cases = 1_000;

    [Test]
    public async Task Epoch_position_generation_digest_schema_and_signature_match_independent_oracle_for_1000_cases()
    {
        var cultures = new[] { "en-US", "tr-TR", "ar-SA", "ja-JP" };
        var fingerprints = new HashSet<string>(StringComparer.Ordinal);
        for (var seed = 0; seed < Cases; seed++)
        {
            var mode = seed % 10;
            var currentEpoch = 100UL + (ulong)seed;
            var currentSequence = 10_000UL + (ulong)seed;
            var currentGeneration = 20_000UL + (ulong)seed;
            var candidateEpoch = mode == 2 ? currentEpoch - 1 : currentEpoch;
            var candidateSequence = mode switch
            {
                3 => currentSequence,
                4 => currentSequence - 1,
                _ => currentSequence + 1,
            };
            var candidateGeneration = mode switch
            {
                1 => currentGeneration + 1,
                5 => currentGeneration - 1,
                _ => currentGeneration,
            };
            var id = SnapshotTestData.Id($"snapshot-policy-{seed}");
            var material = SnapshotTestData.Material(
                id: id,
                epoch: SnapshotTestData.Epoch(candidateEpoch),
                sequence: SnapshotTestData.Sequence(candidateSequence),
                generation: SnapshotTestData.Generation(candidateGeneration));
            var compatibility = new TestSchemaCompatibility(mode switch
            {
                8 => SnapshotSchemaCompatibilityOutcome.Unknown,
                9 => (SnapshotSchemaCompatibilityOutcome)99,
                _ => SnapshotSchemaCompatibilityOutcome.Compatible,
            });
            var verifier = new TestSnapshotSignatureVerifier(
                mode == 7 ? SnapshotSignatureVerificationOutcome.Invalid : SnapshotSignatureVerificationOutcome.Valid);
            var context = SnapshotTestData.Context(
                currentEpoch: SnapshotTestData.Epoch(currentEpoch),
                currentSequence: SnapshotTestData.Sequence(currentSequence),
                currentGeneration: SnapshotTestData.Generation(currentGeneration),
                digest: mode == 6 ? SnapshotTestData.Digest($"wrong-{seed}") : material.StateDigest,
                compatibility: compatibility,
                signatureVerifier: verifier);
            var expected = mode switch
            {
                2 => SnapshotValidationError.StaleEpoch,
                3 or 4 => SnapshotValidationError.StreamRollback,
                5 => SnapshotValidationError.GenerationRollback,
                6 => SnapshotValidationError.StateDigestMismatch,
                7 => SnapshotValidationError.InvalidSignature,
                8 => SnapshotValidationError.UnknownSchema,
                9 => SnapshotValidationError.SchemaCompatibilityFailed,
                _ => SnapshotValidationError.None,
            };
            fingerprints.Add($"{seed}|{candidateEpoch}|{candidateSequence}|{candidateGeneration}|{mode}");

            var originalCulture = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultures[seed % cultures.Length]);
                var first = SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(material), context);
                var replay = SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(material), context);
                await Assert.That(first.ValidationError).IsEqualTo(expected);
                await Assert.That(first.IsPlanned).IsEqualTo(expected == SnapshotValidationError.None);
                await Assert.That(replay.ValidationError).IsEqualTo(first.ValidationError);
                await Assert.That(replay.IsPlanned).IsEqualTo(first.IsPlanned);
                if (expected == SnapshotValidationError.None)
                {
                    await AssertPlan(first.Plan!, material, candidateSequence + 1);
                    await AssertPlan(replay.Plan!, material, candidateSequence + 1);
                }
                else
                {
                    await Assert.That(first.Plan).IsNull();
                    await Assert.That(first.Error).IsEqualTo(SnapshotRestorePlanError.SnapshotRejected);
                }
            }
            finally
            {
                CultureInfo.CurrentCulture = originalCulture;
            }
        }

        await Assert.That(fingerprints.Count).IsEqualTo(Cases);
    }

    [Test]
    public async Task Validation_precedence_and_delegate_suppression_are_exact()
    {
        var compatibility = new TestSchemaCompatibility();
        var verifier = new TestSnapshotSignatureVerifier(SnapshotSignatureVerificationOutcome.Invalid);
        var wrongScope = SignedSnapshotValidator.Validate(
            SnapshotTestData.Snapshot(SnapshotTestData.Material(authority: SnapshotTestData.Authority("wrong"))),
            SnapshotTestData.Context(compatibility: compatibility, signatureVerifier: verifier));
        await Assert.That(wrongScope.Error).IsEqualTo(SnapshotValidationError.WrongAuthority);
        await Assert.That(compatibility.Calls).IsEqualTo(0);
        await Assert.That(verifier.Calls).IsEqualTo(0);

        var currentEpoch = SnapshotTestData.Epoch(8);
        var currentSequence = SnapshotTestData.Sequence(102);
        var currentGeneration = SnapshotTestData.Generation(4);
        var material = SnapshotTestData.Material(
            epoch: SnapshotTestData.Epoch(7),
            sequence: SnapshotTestData.Sequence(101),
            generation: SnapshotTestData.Generation(3),
            digest: SnapshotTestData.Digest("candidate"));
        compatibility = new TestSchemaCompatibility();
        verifier = new TestSnapshotSignatureVerifier(SnapshotSignatureVerificationOutcome.Invalid);
        var context = SnapshotTestData.Context(
            currentEpoch: currentEpoch,
            currentSequence: currentSequence,
            currentGeneration: currentGeneration,
            digest: SnapshotTestData.Digest("expected"),
            compatibility: compatibility,
            signatureVerifier: verifier);

        await Assert.That(SignedSnapshotValidator.Validate(SnapshotTestData.Snapshot(material), context).Error)
            .IsEqualTo(SnapshotValidationError.StaleEpoch);
        await Assert.That(compatibility.Calls).IsEqualTo(1);
        await Assert.That(compatibility.LastCurrent).IsEqualTo(context.CurrentSchema);
        await Assert.That(compatibility.LastCandidate).IsEqualTo(material.Schema);
        await Assert.That(verifier.Calls).IsEqualTo(0);

        material = SnapshotTestData.Material(
            epoch: currentEpoch,
            sequence: currentSequence,
            generation: SnapshotTestData.Generation(3),
            digest: SnapshotTestData.Digest("candidate"));
        await Assert.That(SignedSnapshotValidator.Validate(SnapshotTestData.Snapshot(material), context).Error)
            .IsEqualTo(SnapshotValidationError.StreamRollback);
        await Assert.That(verifier.Calls).IsEqualTo(0);

        material = SnapshotTestData.Material(
            epoch: currentEpoch,
            sequence: SnapshotTestData.Sequence(103),
            generation: SnapshotTestData.Generation(3),
            digest: SnapshotTestData.Digest("candidate"));
        await Assert.That(SignedSnapshotValidator.Validate(SnapshotTestData.Snapshot(material), context).Error)
            .IsEqualTo(SnapshotValidationError.GenerationRollback);
        await Assert.That(verifier.Calls).IsEqualTo(0);

        material = SnapshotTestData.Material(
            epoch: currentEpoch,
            sequence: SnapshotTestData.Sequence(103),
            generation: currentGeneration,
            digest: SnapshotTestData.Digest("candidate"));
        await Assert.That(SignedSnapshotValidator.Validate(SnapshotTestData.Snapshot(material), context).Error)
            .IsEqualTo(SnapshotValidationError.StateDigestMismatch);
        await Assert.That(verifier.Calls).IsEqualTo(0);

        material = SnapshotTestData.Material(
            epoch: currentEpoch,
            sequence: SnapshotTestData.Sequence(103),
            generation: currentGeneration,
            digest: SnapshotTestData.Digest("expected"));
        await Assert.That(SignedSnapshotValidator.Validate(SnapshotTestData.Snapshot(material), context).Error)
            .IsEqualTo(SnapshotValidationError.InvalidSignature);
        await Assert.That(verifier.Calls).IsEqualTo(1);
        await Assert.That(verifier.LastMaterial).IsSameReferenceAs(material);
    }

    [Test]
    public async Task Default_current_generation_invalidates_context_and_public_catalogs_are_complete()
    {
        var invalid = new SnapshotValidationContext(
            SnapshotTestData.Authority(), SnapshotTestData.Stream(), SnapshotTestData.Key(), SnapshotTestData.Schema(),
            SnapshotTestData.Epoch(), SnapshotTestData.Sequence(100), default, SnapshotTestData.Digest(),
            new TestSchemaCompatibility(), new TestSnapshotSignatureVerifier());
        await Assert.That(SignedSnapshotValidator.Validate(SnapshotTestData.Snapshot(), invalid).Error)
            .IsEqualTo(SnapshotValidationError.InvalidContext);

        await Assert.That(Enum.GetValues<SnapshotSchemaCompatibilityOutcome>())
            .IsEquivalentTo(new[] { SnapshotSchemaCompatibilityOutcome.Unknown, SnapshotSchemaCompatibilityOutcome.Compatible, SnapshotSchemaCompatibilityOutcome.Incompatible });
        await Assert.That(Enum.GetValues<SnapshotSignatureVerificationOutcome>())
            .IsEquivalentTo(new[] { SnapshotSignatureVerificationOutcome.Invalid, SnapshotSignatureVerificationOutcome.Valid });
        await Assert.That(Enum.GetValues<SnapshotValidationError>().Length).IsEqualTo(16);
        await Assert.That(Enum.GetValues<SnapshotValidationError>().Count(static value => value is SnapshotValidationError.Uninitialized)).IsEqualTo(1);
        await Assert.That(Enum.GetValues<SnapshotValidationError>().Count(static value => value is SnapshotValidationError.None)).IsEqualTo(1);
        var validationCodes = new Dictionary<SnapshotValidationError, int>
        {
            [SnapshotValidationError.Uninitialized] = 0,
            [SnapshotValidationError.None] = 1,
            [SnapshotValidationError.InvalidContext] = 2,
            [SnapshotValidationError.MalformedSnapshot] = 3,
            [SnapshotValidationError.WrongAuthority] = 4,
            [SnapshotValidationError.WrongStream] = 5,
            [SnapshotValidationError.WrongSigningKey] = 6,
            [SnapshotValidationError.UnknownSchema] = 7,
            [SnapshotValidationError.IncompatibleSchema] = 8,
            [SnapshotValidationError.SchemaCompatibilityFailed] = 9,
            [SnapshotValidationError.StaleEpoch] = 10,
            [SnapshotValidationError.StreamRollback] = 11,
            [SnapshotValidationError.StateDigestMismatch] = 12,
            [SnapshotValidationError.InvalidSignature] = 13,
            [SnapshotValidationError.SignatureVerificationFailed] = 14,
            [SnapshotValidationError.GenerationRollback] = 15,
        };
        await Assert.That(validationCodes.Count).IsEqualTo(Enum.GetValues<SnapshotValidationError>().Length);
        foreach (var (code, number) in validationCodes)
        {
            await Assert.That((int)code).IsEqualTo(number);
        }
        await Assert.That(Enum.GetValues<SnapshotRestorePlanError>())
            .IsEquivalentTo(new[] { SnapshotRestorePlanError.Uninitialized, SnapshotRestorePlanError.None, SnapshotRestorePlanError.SnapshotRejected, SnapshotRestorePlanError.ReplayStartOverflow });
        await Assert.That(Enum.GetValues<SnapshotMaterialError>().Length).IsEqualTo(11);
        await Assert.That(typeof(SnapshotValidationResult).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(SnapshotRestorePlanResult).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(SnapshotRestorePlan).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
    }

    private static async Task AssertPlan(
        SnapshotRestorePlan plan,
        SnapshotSignedMaterial material,
        ulong expectedReplayStart)
    {
        await Assert.That(plan.AcceptedSnapshot.SignedMaterial).IsSameReferenceAs(material);
        await Assert.That(plan.SnapshotId).IsEqualTo(material.SnapshotId);
        await Assert.That(plan.Generation).IsEqualTo(material.Generation);
        await Assert.That(plan.ExpectedRestoredEpoch).IsEqualTo(material.Epoch);
        await Assert.That(plan.ReplayStartSequence.Value).IsEqualTo(expectedReplayStart);
        await Assert.That(plan.ExpectedRestoredDigest).IsSameReferenceAs(material.StateDigest);
    }
}

