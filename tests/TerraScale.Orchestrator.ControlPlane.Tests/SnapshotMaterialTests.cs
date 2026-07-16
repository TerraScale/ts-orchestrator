using TerraScale.Orchestrator.ControlPlane.Snapshots;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class SnapshotMaterialTests
{
    [Test]
    public async Task Complete_material_projects_every_field_in_invariant_order()
    {
        var material = SnapshotTestData.Material();
        var verifier = new TestSnapshotSignatureVerifier();
        var snapshot = SnapshotTestData.Snapshot(material);
        var result = SignedSnapshotValidator.Validate(snapshot, SnapshotTestData.Context(signatureVerifier: verifier));

        await Assert.That(result.IsValid).IsTrue();
        await Assert.That(verifier.LastMaterial).IsSameReferenceAs(material);
        await Assert.That(verifier.LastMaterial!.Authority).IsEqualTo(SnapshotTestData.Authority());
        await Assert.That(verifier.LastMaterial.Stream).IsEqualTo(SnapshotTestData.Stream());
        await Assert.That(verifier.LastMaterial.SnapshotId).IsEqualTo(SnapshotTestData.Id());
        await Assert.That(verifier.LastMaterial.Schema).IsEqualTo(SnapshotTestData.Schema());
        await Assert.That(verifier.LastMaterial.SigningKey).IsEqualTo(SnapshotTestData.Key());
        await Assert.That(verifier.LastMaterial.Epoch).IsEqualTo(SnapshotTestData.Epoch());
        await Assert.That(verifier.LastMaterial.StreamSequence).IsEqualTo(SnapshotTestData.Sequence());
        await Assert.That(verifier.LastMaterial.Generation).IsEqualTo(SnapshotTestData.Generation());
        await Assert.That(verifier.LastMaterial.StateDigest).IsEqualTo(SnapshotTestData.Digest());
        await Assert.That(material.ToString()).IsEqualTo("<snapshot-signed-material>");
        await Assert.That(snapshot.ToString()).IsEqualTo("<signed-snapshot>");
    }

    [Test]
    public async Task Material_creation_rejects_each_omitted_field_with_closed_error()
    {
        var cases = new[]
        {
            Create(default, SnapshotTestData.Stream(), SnapshotTestData.Id(), SnapshotTestData.Schema(), SnapshotTestData.Key(), SnapshotTestData.Epoch(), SnapshotTestData.Sequence(), SnapshotTestData.Generation(), SnapshotTestData.Digest()),
            Create(SnapshotTestData.Authority(), default, SnapshotTestData.Id(), SnapshotTestData.Schema(), SnapshotTestData.Key(), SnapshotTestData.Epoch(), SnapshotTestData.Sequence(), SnapshotTestData.Generation(), SnapshotTestData.Digest()),
            Create(SnapshotTestData.Authority(), SnapshotTestData.Stream(), default, SnapshotTestData.Schema(), SnapshotTestData.Key(), SnapshotTestData.Epoch(), SnapshotTestData.Sequence(), SnapshotTestData.Generation(), SnapshotTestData.Digest()),
            Create(SnapshotTestData.Authority(), SnapshotTestData.Stream(), SnapshotTestData.Id(), default, SnapshotTestData.Key(), SnapshotTestData.Epoch(), SnapshotTestData.Sequence(), SnapshotTestData.Generation(), SnapshotTestData.Digest()),
            Create(SnapshotTestData.Authority(), SnapshotTestData.Stream(), SnapshotTestData.Id(), SnapshotTestData.Schema(), default, SnapshotTestData.Epoch(), SnapshotTestData.Sequence(), SnapshotTestData.Generation(), SnapshotTestData.Digest()),
            Create(SnapshotTestData.Authority(), SnapshotTestData.Stream(), SnapshotTestData.Id(), SnapshotTestData.Schema(), SnapshotTestData.Key(), default, SnapshotTestData.Sequence(), SnapshotTestData.Generation(), SnapshotTestData.Digest()),
            Create(SnapshotTestData.Authority(), SnapshotTestData.Stream(), SnapshotTestData.Id(), SnapshotTestData.Schema(), SnapshotTestData.Key(), SnapshotTestData.Epoch(), default, SnapshotTestData.Generation(), SnapshotTestData.Digest()),
            Create(SnapshotTestData.Authority(), SnapshotTestData.Stream(), SnapshotTestData.Id(), SnapshotTestData.Schema(), SnapshotTestData.Key(), SnapshotTestData.Epoch(), SnapshotTestData.Sequence(), default, SnapshotTestData.Digest()),
            Create(SnapshotTestData.Authority(), SnapshotTestData.Stream(), SnapshotTestData.Id(), SnapshotTestData.Schema(), SnapshotTestData.Key(), SnapshotTestData.Epoch(), SnapshotTestData.Sequence(), SnapshotTestData.Generation(), null),
        };
        var expected = new[]
        {
            SnapshotMaterialError.InvalidAuthority, SnapshotMaterialError.InvalidStream,
            SnapshotMaterialError.InvalidSnapshotId, SnapshotMaterialError.InvalidSchema,
            SnapshotMaterialError.InvalidSigningKey, SnapshotMaterialError.InvalidEpoch,
            SnapshotMaterialError.InvalidStreamSequence, SnapshotMaterialError.InvalidGeneration,
            SnapshotMaterialError.MissingStateDigest,
        };

        for (var index = 0; index < cases.Length; index++)
        {
            await Assert.That(cases[index].Success).IsFalse();
            await Assert.That(cases[index].Material).IsNull();
            await Assert.That(cases[index].Error).IsEqualTo(expected[index]);
        }
    }

    private static (bool Success, SnapshotSignedMaterial? Material, SnapshotMaterialError Error) Create(
        SnapshotAuthorityId authority, SnapshotStreamId stream, SnapshotId id, SnapshotSchemaId schema,
        SnapshotSigningKeyId key, SnapshotEpoch epoch, SnapshotStreamSequence sequence,
        SnapshotGeneration generation, SnapshotStateDigest? digest)
    {
        var success = SnapshotSignedMaterial.TryCreate(
            authority, stream, id, schema, key, epoch, sequence, generation, digest, out var material, out var error);
        return (success, material, error);
    }
}
