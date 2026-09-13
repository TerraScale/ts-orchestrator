namespace TerraScale.Orchestrator.ControlPlane.Snapshots;

public enum SnapshotMaterialError
{
    Uninitialized = 0,
    None,
    InvalidAuthority,
    InvalidStream,
    InvalidSnapshotId,
    InvalidSchema,
    InvalidSigningKey,
    InvalidEpoch,
    InvalidStreamSequence,
    InvalidGeneration,
    MissingStateDigest,
}

/// <summary>
/// Complete algorithm-neutral projection authenticated by a caller-supplied verifier.
/// The verifier owns canonical serialization and signing policy; no field may be omitted.
/// </summary>
public sealed class SnapshotSignedMaterial
{
    private SnapshotSignedMaterial(
        SnapshotAuthorityId authority,
        SnapshotStreamId stream,
        SnapshotId snapshotId,
        SnapshotSchemaId schema,
        SnapshotSigningKeyId signingKey,
        SnapshotEpoch epoch,
        SnapshotStreamSequence streamSequence,
        SnapshotGeneration generation,
        SnapshotStateDigest stateDigest)
    {
        Authority = authority;
        Stream = stream;
        SnapshotId = snapshotId;
        Schema = schema;
        SigningKey = signingKey;
        Epoch = epoch;
        StreamSequence = streamSequence;
        Generation = generation;
        StateDigest = stateDigest;
    }

    public SnapshotAuthorityId Authority { get; }
    public SnapshotStreamId Stream { get; }
    public SnapshotId SnapshotId { get; }
    public SnapshotSchemaId Schema { get; }
    public SnapshotSigningKeyId SigningKey { get; }
    public SnapshotEpoch Epoch { get; }
    public SnapshotStreamSequence StreamSequence { get; }
    public SnapshotGeneration Generation { get; }
    public SnapshotStateDigest StateDigest { get; }

    public static bool TryCreate(
        SnapshotAuthorityId authority,
        SnapshotStreamId stream,
        SnapshotId snapshotId,
        SnapshotSchemaId schema,
        SnapshotSigningKeyId signingKey,
        SnapshotEpoch epoch,
        SnapshotStreamSequence streamSequence,
        SnapshotGeneration generation,
        SnapshotStateDigest? stateDigest,
        out SnapshotSignedMaterial? result,
        out SnapshotMaterialError error)
    {
        error = !authority.IsValid ? SnapshotMaterialError.InvalidAuthority
            : !stream.IsValid ? SnapshotMaterialError.InvalidStream
            : !snapshotId.IsValid ? SnapshotMaterialError.InvalidSnapshotId
            : !schema.IsValid ? SnapshotMaterialError.InvalidSchema
            : !signingKey.IsValid ? SnapshotMaterialError.InvalidSigningKey
            : !epoch.IsValid ? SnapshotMaterialError.InvalidEpoch
            : !streamSequence.IsValid ? SnapshotMaterialError.InvalidStreamSequence
            : !generation.IsValid ? SnapshotMaterialError.InvalidGeneration
            : stateDigest is not { IsValid: true } ? SnapshotMaterialError.MissingStateDigest
            : SnapshotMaterialError.None;

        result = error == SnapshotMaterialError.None
            && stateDigest is { IsValid: true } validStateDigest
            ? new SnapshotSignedMaterial(authority, stream, snapshotId, schema, signingKey, epoch, streamSequence, generation, validStateDigest)
            : null;
        return result is not null;
    }

    public override string ToString() => "<snapshot-signed-material>";
}

public sealed class SignedSnapshot
{
    public SignedSnapshot(SnapshotSignedMaterial signedMaterial, SnapshotSignature signature)
    {
        SignedMaterial = signedMaterial;
        Signature = signature;
    }
    public SnapshotSignedMaterial SignedMaterial { get; }
    public SnapshotSignature Signature { get; }
    public override string ToString() => "<signed-snapshot>";
}

