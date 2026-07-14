using System.Globalization;
using System.Reflection;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Snapshots;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class SnapshotAudit3CounterexampleTests
{
    [Test]
    public async Task Accepted_restore_plan_binds_exact_signed_snapshot_scope_and_signature()
    {
        var firstMaterial = SnapshotTestData.Material(
            authority: SnapshotTestData.Authority("authority-a"),
            stream: SnapshotTestData.Stream("stream-a"),
            schema: SnapshotTestData.Schema("schema-a"),
            key: SnapshotTestData.Key("key-a"));
        var secondMaterial = SnapshotTestData.Material(
            authority: SnapshotTestData.Authority("authority-b"),
            stream: SnapshotTestData.Stream("stream-b"),
            schema: SnapshotTestData.Schema("schema-b"),
            key: SnapshotTestData.Key("key-b"));
        var firstSnapshot = SnapshotTestData.Snapshot(firstMaterial, SnapshotTestData.Signature("signature-a"));
        var secondSnapshot = SnapshotTestData.Snapshot(secondMaterial, SnapshotTestData.Signature("signature-b"));
        var first = SnapshotRestorePlanner.Plan(
            firstSnapshot,
            SnapshotTestData.Context(authority: firstMaterial.Authority, stream: firstMaterial.Stream,
                key: firstMaterial.SigningKey, currentSchema: firstMaterial.Schema));
        var second = SnapshotRestorePlanner.Plan(
            secondSnapshot,
            SnapshotTestData.Context(authority: secondMaterial.Authority, stream: secondMaterial.Stream,
                key: secondMaterial.SigningKey, currentSchema: secondMaterial.Schema));

        await Assert.That(first.IsPlanned).IsTrue();
        await Assert.That(second.IsPlanned).IsTrue();
        await Assert.That(first.Plan!.AcceptedSnapshot).IsSameReferenceAs(firstSnapshot);
        await Assert.That(first.Plan.AcceptedSnapshot.SignedMaterial).IsSameReferenceAs(firstMaterial);
        await Assert.That(first.Plan.AcceptedSnapshot.Signature).IsSameReferenceAs(firstSnapshot.Signature);
        await Assert.That(first.Plan.ExpectedRestoredDigest).IsSameReferenceAs(firstMaterial.StateDigest);
        await Assert.That(SnapshotRestorePlanFingerprint.Create(first.Plan))
            .IsNotEqualTo(SnapshotRestorePlanFingerprint.Create(second.Plan!));
    }

    [Test]
    public async Task Complete_plan_fingerprint_is_sensitive_to_every_signed_field_and_signature()
    {
        var baselineMaterial = SnapshotTestData.Material();
        var baselineSignature = SnapshotTestData.Signature();
        var baseline = Plan(baselineMaterial, baselineSignature);
        var variants = new (SnapshotSignedMaterial Material, SnapshotSignature Signature)[]
        {
            (SnapshotTestData.Material(authority: SnapshotTestData.Authority("other-authority")), baselineSignature),
            (SnapshotTestData.Material(stream: SnapshotTestData.Stream("other-stream")), baselineSignature),
            (SnapshotTestData.Material(id: SnapshotTestData.Id("other-snapshot")), baselineSignature),
            (SnapshotTestData.Material(schema: SnapshotTestData.Schema("control-state/v2")), baselineSignature),
            (SnapshotTestData.Material(key: SnapshotTestData.Key("other-key")), baselineSignature),
            (SnapshotTestData.Material(epoch: SnapshotTestData.Epoch(8)), baselineSignature),
            (SnapshotTestData.Material(sequence: SnapshotTestData.Sequence(102)), baselineSignature),
            (SnapshotTestData.Material(generation: SnapshotTestData.Generation(4)), baselineSignature),
            (SnapshotTestData.Material(digest: SnapshotTestData.Digest("other-digest")), baselineSignature),
            (baselineMaterial, SnapshotTestData.Signature("other-signature")),
        };

        var fingerprint = SnapshotRestorePlanFingerprint.Create(baseline);
        foreach (var (material, signature) in variants)
        {
            await Assert.That(SnapshotRestorePlanFingerprint.Create(Plan(material, signature)))
                .IsNotEqualTo(fingerprint);
        }
    }

    [Test]
    public async Task Semantic_replay_is_culture_stable_without_claiming_structural_plan_equality()
    {
        var cultures = new[] { "en-US", "tr-TR", "ar-SA", "ja-JP" };
        string? expected = null;
        var original = CultureInfo.CurrentCulture;
        try
        {
            foreach (var culture in cultures)
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
                var actual = SnapshotRestorePlanFingerprint.Create(Plan(
                    SnapshotTestData.Material(), SnapshotTestData.Signature()));
                expected ??= actual;
                await Assert.That(actual).IsEqualTo(expected);
            }
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }

    [Test]
    public async Task Retained_digest_and_signature_are_safe_from_source_buffer_mutation()
    {
        var digestBytes = Encoding.UTF8.GetBytes("mutable-digest");
        var signatureBytes = Encoding.UTF8.GetBytes("mutable-signature");
        SnapshotStateDigest.TryCopyFrom(digestBytes, SnapshotTestData.ByteLimit, out var digest);
        SnapshotSignature.TryCopyFrom(signatureBytes, SnapshotTestData.ByteLimit, out var signature);
        var plan = Plan(SnapshotTestData.Material(digest: digest), signature!);
        var before = SnapshotRestorePlanFingerprint.Create(plan);

        Array.Fill<byte>(digestBytes, 0);
        Array.Fill<byte>(signatureBytes, 0);

        await Assert.That(SnapshotRestorePlanFingerprint.Create(plan)).IsEqualTo(before);
        await Assert.That(Convert.ToHexString(plan.AcceptedSnapshot.SignedMaterial.StateDigest.Bytes))
            .IsEqualTo(Convert.ToHexString(Encoding.UTF8.GetBytes("mutable-digest")));
        await Assert.That(Convert.ToHexString(plan.AcceptedSnapshot.Signature.Bytes))
            .IsEqualTo(Convert.ToHexString(Encoding.UTF8.GetBytes("mutable-signature")));
    }

    [Test]
    public async Task Accepted_schema_paths_retain_the_exact_envelope_and_equal_generation_later_position()
    {
        foreach (var currentSchema in new[] { SnapshotTestData.Schema(), SnapshotTestData.Schema("control-state/v0") })
        {
            var snapshot = SnapshotTestData.Snapshot();
            var result = SnapshotRestorePlanner.Plan(snapshot, SnapshotTestData.Context(
                currentSchema: currentSchema,
                currentGeneration: snapshot.SignedMaterial.Generation,
                currentSequence: SnapshotTestData.Sequence(snapshot.SignedMaterial.StreamSequence.Value - 1),
                compatibility: new TestSchemaCompatibility(SnapshotSchemaCompatibilityOutcome.Compatible)));

            await Assert.That(result.IsPlanned).IsTrue();
            await Assert.That(result.Plan!.AcceptedSnapshot).IsSameReferenceAs(snapshot);
            await Assert.That(result.Plan.ReplayStartSequence.Value)
                .IsEqualTo(snapshot.SignedMaterial.StreamSequence.Value + 1);
        }
    }

    [Test]
    public async Task Restore_plan_remains_construction_closed()
    {
        var type = typeof(SnapshotRestorePlan);
        await Assert.That(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(static property => property.SetMethod is not null)).IsEmpty();
        await Assert.That(type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)
            .Where(static method => method.Name is "Deconstruct" or "Clone" || method.ReturnType == typeof(SnapshotRestorePlan)))
            .IsEmpty();

        var planReturningMethods = type.Assembly.ExportedTypes
            .SelectMany(static exportedType => exportedType.GetMethods(
                BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            .Where(method => method.ReturnType == type)
            .ToArray();
        await Assert.That(planReturningMethods).HasSingleItem();
        await Assert.That(planReturningMethods[0].DeclaringType).IsEqualTo(typeof(SnapshotRestorePlanResult));
        await Assert.That(planReturningMethods[0].Name).IsEqualTo("get_Plan");
        await Assert.That(planReturningMethods[0].IsSpecialName).IsTrue();

        var uninitialized = default(SnapshotRestorePlanResult);
        await Assert.That(uninitialized.Plan).IsNull();
        await Assert.That(uninitialized.IsPlanned).IsFalse();
    }

    [Test]
    public async Task Every_validation_rejection_and_replay_overflow_has_no_plan()
    {
        var material = SnapshotTestData.Material();
        var rejected = new[]
        {
            SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(), null),
            SnapshotRestorePlanner.Plan(new SignedSnapshot(material, null!), SnapshotTestData.Context()),
            SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(SnapshotTestData.Material(authority: SnapshotTestData.Authority("wrong"))), SnapshotTestData.Context()),
            SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(SnapshotTestData.Material(stream: SnapshotTestData.Stream("wrong"))), SnapshotTestData.Context()),
            SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(SnapshotTestData.Material(key: SnapshotTestData.Key("wrong"))), SnapshotTestData.Context()),
            SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(), SnapshotTestData.Context(compatibility: new TestSchemaCompatibility(SnapshotSchemaCompatibilityOutcome.Unknown))),
            SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(), SnapshotTestData.Context(compatibility: new TestSchemaCompatibility(SnapshotSchemaCompatibilityOutcome.Incompatible))),
            SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(), SnapshotTestData.Context(compatibility: new TestSchemaCompatibility(throws: true))),
            SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(SnapshotTestData.Material(epoch: SnapshotTestData.Epoch(6))), SnapshotTestData.Context()),
            SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(SnapshotTestData.Material(sequence: SnapshotTestData.Sequence(100))), SnapshotTestData.Context()),
            SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(SnapshotTestData.Material(generation: SnapshotTestData.Generation(2))), SnapshotTestData.Context()),
            SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(), SnapshotTestData.Context(digest: SnapshotTestData.Digest("wrong"))),
            SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(), SnapshotTestData.Context(signatureVerifier: new TestSnapshotSignatureVerifier(SnapshotSignatureVerificationOutcome.Invalid))),
            SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(), SnapshotTestData.Context(signatureVerifier: new TestSnapshotSignatureVerifier(throws: true))),
        };
        var expected = Enum.GetValues<SnapshotValidationError>()
            .Where(static error => error is not SnapshotValidationError.Uninitialized and not SnapshotValidationError.None)
            .ToHashSet();

        await Assert.That(rejected.Select(static result => result.ValidationError).ToHashSet())
            .IsEquivalentTo(expected);
        foreach (var result in rejected)
        {
            await Assert.That(result.Error).IsEqualTo(SnapshotRestorePlanError.SnapshotRejected);
            await Assert.That(result.Plan).IsNull();
        }

        var overflow = SnapshotRestorePlanner.Plan(
            SnapshotTestData.Snapshot(SnapshotTestData.Material(sequence: SnapshotTestData.Sequence(ulong.MaxValue))),
            SnapshotTestData.Context(currentSequence: SnapshotTestData.Sequence(1)));
        await Assert.That(overflow.Error).IsEqualTo(SnapshotRestorePlanError.ReplayStartOverflow);
        await Assert.That(overflow.ValidationError).IsEqualTo(SnapshotValidationError.None);
        await Assert.That(overflow.Plan).IsNull();
    }

    private static SnapshotRestorePlan Plan(SnapshotSignedMaterial material, SnapshotSignature signature)
    {
        var result = SnapshotRestorePlanner.Plan(SnapshotTestData.Snapshot(material, signature), SnapshotTestData.Context(
            authority: material.Authority,
            stream: material.Stream,
            key: material.SigningKey,
            currentSchema: material.Schema,
            currentEpoch: SnapshotTestData.Epoch(1),
            currentSequence: SnapshotTestData.Sequence(1),
            currentGeneration: SnapshotTestData.Generation(1),
            digest: material.StateDigest));
        if (!result.IsPlanned)
        {
            throw new InvalidOperationException($"Fixture was unexpectedly rejected: {result.Error}/{result.ValidationError}.");
        }
        return result.Plan!;
    }
}
