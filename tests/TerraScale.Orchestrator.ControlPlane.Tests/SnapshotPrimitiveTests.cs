using System.Text;
using TerraScale.Orchestrator.ControlPlane.Snapshots;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class SnapshotPrimitiveTests
{
    [Test]
    public async Task Identities_require_explicit_positive_bounds_and_well_formed_values()
    {
        foreach (var value in new string?[] { null, "", "two words", "line\nfeed", "nul\0byte", "\uD800", "\uDC00" })
        {
            await Assert.That(SnapshotAuthorityId.TryCreate(value, 64, out var authority)).IsFalse();
            await Assert.That(authority.IsValid).IsFalse();
        }

        await Assert.That(SnapshotAuthorityId.TryCreate("a", 0, out _)).IsFalse();
        await Assert.That(SnapshotStreamId.TryCreate("ab", 1, out _)).IsFalse();
        await Assert.That(SnapshotId.TryCreate("snapshot", -1, out _)).IsFalse();
        await Assert.That(SnapshotSchemaId.TryCreate("schema/v1", 9, out var schema)).IsTrue();
        await Assert.That(schema.IsValid).IsTrue();
        await Assert.That(SnapshotSigningKeyId.TryCreate("key-\U0001F680", 8, out var key)).IsTrue();
        await Assert.That(key.IsValid).IsTrue();
    }

    [Test]
    public async Task Numeric_values_are_positive_and_allow_unsigned_maximum()
    {
        await Assert.That(SnapshotEpoch.TryCreate(0, out _)).IsFalse();
        await Assert.That(SnapshotStreamSequence.TryCreate(0, out _)).IsFalse();
        await Assert.That(SnapshotGeneration.TryCreate(0, out _)).IsFalse();
        await Assert.That(SnapshotEpoch.TryCreate(ulong.MaxValue, out var epoch)).IsTrue();
        await Assert.That(SnapshotStreamSequence.TryCreate(ulong.MaxValue, out var sequence)).IsTrue();
        await Assert.That(SnapshotGeneration.TryCreate(ulong.MaxValue, out var generation)).IsTrue();
        await Assert.That(epoch.Value).IsEqualTo(ulong.MaxValue);
        await Assert.That(sequence.Value).IsEqualTo(ulong.MaxValue);
        await Assert.That(generation.Value).IsEqualTo(ulong.MaxValue);
    }

    [Test]
    public async Task Opaque_bytes_are_bounded_copied_content_equal_and_secret_safe()
    {
        var source = Encoding.UTF8.GetBytes("credential-looking-secret");
        var expected = source.ToArray();
        await Assert.That(SnapshotStateDigest.TryCopyFrom(source, source.Length, out var digest)).IsTrue();
        await Assert.That(SnapshotSignature.TryCopyFrom(source, source.Length, out var signature)).IsTrue();
        if (digest is not { IsValid: true } validDigest || signature is not { IsValid: true } validSignature)
        {
            throw new InvalidOperationException("The bounded opaque values were not created.");
        }

        source.AsSpan().Fill(0);
        var exported = validDigest.Bytes.ToArray();
        exported.AsSpan().Fill(255);

        await Assert.That(validDigest.Bytes.SequenceEqual(expected)).IsTrue();
        await Assert.That(validSignature.Bytes.SequenceEqual(expected)).IsTrue();
        await Assert.That(validDigest).IsEqualTo(SnapshotTestData.Digest("credential-looking-secret"));
        await Assert.That(validDigest.ToString()).DoesNotContain("credential-looking-secret");
        await Assert.That(validSignature.ToString()).DoesNotContain("credential-looking-secret");
        await Assert.That(SnapshotStateDigest.TryCopyFrom([], 1, out _)).IsFalse();
        await Assert.That(SnapshotStateDigest.TryCopyFrom([1], 0, out _)).IsFalse();
        await Assert.That(SnapshotSignature.TryCopyFrom([1, 2], 1, out _)).IsFalse();
    }
}

