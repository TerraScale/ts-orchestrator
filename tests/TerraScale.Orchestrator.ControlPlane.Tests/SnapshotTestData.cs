using System.Text;
using TerraScale.Orchestrator.ControlPlane.Snapshots;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

internal static class SnapshotTestData
{
    public const int IdentityLimit = 64;
    public const int ByteLimit = 128;

    public static SnapshotAuthorityId Authority(string value = "regional-gru")
    {
        SnapshotAuthorityId.TryCreate(value, IdentityLimit, out var result);
        return result;
    }

    public static SnapshotStreamId Stream(string value = "regional-journal")
    {
        SnapshotStreamId.TryCreate(value, IdentityLimit, out var result);
        return result;
    }

    public static SnapshotId Id(string value = "snapshot-42")
    {
        SnapshotId.TryCreate(value, IdentityLimit, out var result);
        return result;
    }

    public static SnapshotSchemaId Schema(string value = "control-state/v1")
    {
        SnapshotSchemaId.TryCreate(value, IdentityLimit, out var result);
        return result;
    }

    public static SnapshotSigningKeyId Key(string value = "regional-snapshot-key/v1")
    {
        SnapshotSigningKeyId.TryCreate(value, IdentityLimit, out var result);
        return result;
    }

    public static SnapshotEpoch Epoch(ulong value = 7)
    {
        SnapshotEpoch.TryCreate(value, out var result);
        return result;
    }

    public static SnapshotStreamSequence Sequence(ulong value = 101)
    {
        SnapshotStreamSequence.TryCreate(value, out var result);
        return result;
    }

    public static SnapshotGeneration Generation(ulong value = 3)
    {
        SnapshotGeneration.TryCreate(value, out var result);
        return result;
    }

    public static SnapshotStateDigest Digest(string value = "state-digest-secret")
    {
        SnapshotStateDigest.TryCopyFrom(Encoding.UTF8.GetBytes(value), ByteLimit, out var result);
        return result!;
    }

    public static SnapshotSignature Signature(string value = "signature-secret")
    {
        SnapshotSignature.TryCopyFrom(Encoding.UTF8.GetBytes(value), ByteLimit, out var result);
        return result!;
    }

    public static SnapshotSignedMaterial Material(
        SnapshotAuthorityId? authority = null,
        SnapshotStreamId? stream = null,
        SnapshotId? id = null,
        SnapshotSchemaId? schema = null,
        SnapshotSigningKeyId? key = null,
        SnapshotEpoch? epoch = null,
        SnapshotStreamSequence? sequence = null,
        SnapshotGeneration? generation = null,
        SnapshotStateDigest? digest = null)
    {
        SnapshotSignedMaterial.TryCreate(
            authority ?? Authority(),
            stream ?? Stream(),
            id ?? Id(),
            schema ?? Schema(),
            key ?? Key(),
            epoch ?? Epoch(),
            sequence ?? Sequence(),
            generation ?? Generation(),
            digest ?? Digest(),
            out var result,
            out _);
        return result!;
    }

    public static SignedSnapshot Snapshot(SnapshotSignedMaterial? material = null, SnapshotSignature? signature = null) =>
        new(material ?? Material(), signature ?? Signature());

    public static SnapshotValidationContext Context(
        SnapshotAuthorityId? authority = null,
        SnapshotStreamId? stream = null,
        SnapshotSigningKeyId? key = null,
        SnapshotSchemaId? currentSchema = null,
        SnapshotEpoch? currentEpoch = null,
        SnapshotStreamSequence? currentSequence = null,
        SnapshotStateDigest? digest = null,
        ISnapshotSchemaCompatibility? compatibility = null,
        ISnapshotSignatureVerifier? signatureVerifier = null) =>
        new(
            authority ?? Authority(),
            stream ?? Stream(),
            key ?? Key(),
            currentSchema ?? Schema(),
            currentEpoch ?? Epoch(),
            currentSequence ?? Sequence(100),
            digest ?? Digest(),
            compatibility ?? new TestSchemaCompatibility(),
            signatureVerifier ?? new TestSnapshotSignatureVerifier());
}

internal sealed class TestSchemaCompatibility(
    SnapshotSchemaCompatibilityOutcome outcome = SnapshotSchemaCompatibilityOutcome.Compatible,
    bool throws = false) : ISnapshotSchemaCompatibility
{
    public int Calls { get; private set; }
    public SnapshotSchemaId LastCurrent { get; private set; }
    public SnapshotSchemaId LastCandidate { get; private set; }

    public SnapshotSchemaCompatibilityOutcome Evaluate(SnapshotSchemaId currentSchema, SnapshotSchemaId candidateSchema)
    {
        Calls++;
        LastCurrent = currentSchema;
        LastCandidate = candidateSchema;
        if (throws)
        {
            throw new InvalidOperationException("schema-compatibility-secret");
        }
        return outcome;
    }
}

internal sealed class TestSnapshotSignatureVerifier(
    SnapshotSignatureVerificationOutcome outcome = SnapshotSignatureVerificationOutcome.Valid,
    bool throws = false,
    SnapshotSignedMaterial? expectedMaterial = null,
    SnapshotSignature? expectedSignature = null) : ISnapshotSignatureVerifier
{
    public int Calls { get; private set; }
    public SnapshotSignedMaterial? LastMaterial { get; private set; }
    public SnapshotSignature? LastSignature { get; private set; }

    public SnapshotSignatureVerificationOutcome Verify(SnapshotSignedMaterial signedMaterial, SnapshotSignature signature)
    {
        Calls++;
        LastMaterial = signedMaterial;
        LastSignature = signature;
        if (throws)
        {
            throw new InvalidOperationException("signature-verifier-secret");
        }
        if (expectedMaterial is not null && !SameProjection(expectedMaterial, signedMaterial))
        {
            return SnapshotSignatureVerificationOutcome.Invalid;
        }
        if (expectedSignature is not null && !expectedSignature.Equals(signature))
        {
            return SnapshotSignatureVerificationOutcome.Invalid;
        }
        return outcome;
    }

    private static bool SameProjection(SnapshotSignedMaterial left, SnapshotSignedMaterial right) =>
        left.Authority == right.Authority
        && left.Stream == right.Stream
        && left.SnapshotId == right.SnapshotId
        && left.Schema == right.Schema
        && left.SigningKey == right.SigningKey
        && left.Epoch == right.Epoch
        && left.StreamSequence == right.StreamSequence
        && left.Generation == right.Generation
        && left.StateDigest.Equals(right.StateDigest);
}
