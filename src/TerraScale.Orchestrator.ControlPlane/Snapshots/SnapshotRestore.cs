namespace TerraScale.Orchestrator.ControlPlane.Snapshots;

public enum SnapshotSchemaCompatibilityOutcome
{
    Unknown = 0,
    Compatible,
    Incompatible,
}

public enum SnapshotSignatureVerificationOutcome
{
    Invalid = 0,
    Valid,
}

public interface ISnapshotSchemaCompatibility
{
    SnapshotSchemaCompatibilityOutcome Evaluate(SnapshotSchemaId currentSchema, SnapshotSchemaId candidateSchema);
}

public interface ISnapshotSignatureVerifier
{
    SnapshotSignatureVerificationOutcome Verify(SnapshotSignedMaterial signedMaterial, SnapshotSignature signature);
}

public sealed class SnapshotValidationContext
{
    public SnapshotValidationContext(
        SnapshotAuthorityId expectedAuthority,
        SnapshotStreamId expectedStream,
        SnapshotSigningKeyId expectedSigningKey,
        SnapshotSchemaId currentSchema,
        SnapshotEpoch currentAcceptedEpoch,
        SnapshotStreamSequence currentAcceptedStreamSequence,
        SnapshotStateDigest expectedStateDigest,
        ISnapshotSchemaCompatibility schemaCompatibility,
        ISnapshotSignatureVerifier signatureVerifier)
    {
        ExpectedAuthority = expectedAuthority;
        ExpectedStream = expectedStream;
        ExpectedSigningKey = expectedSigningKey;
        CurrentSchema = currentSchema;
        CurrentAcceptedEpoch = currentAcceptedEpoch;
        CurrentAcceptedStreamSequence = currentAcceptedStreamSequence;
        ExpectedStateDigest = expectedStateDigest;
        SchemaCompatibility = schemaCompatibility;
        SignatureVerifier = signatureVerifier;
    }

    public SnapshotAuthorityId ExpectedAuthority { get; }
    public SnapshotStreamId ExpectedStream { get; }
    public SnapshotSigningKeyId ExpectedSigningKey { get; }
    public SnapshotSchemaId CurrentSchema { get; }
    public SnapshotEpoch CurrentAcceptedEpoch { get; }
    public SnapshotStreamSequence CurrentAcceptedStreamSequence { get; }
    public SnapshotStateDigest ExpectedStateDigest { get; }
    public ISnapshotSchemaCompatibility SchemaCompatibility { get; }
    public ISnapshotSignatureVerifier SignatureVerifier { get; }

    internal bool IsWellFormed =>
        ExpectedAuthority.IsValid
        && ExpectedStream.IsValid
        && ExpectedSigningKey.IsValid
        && CurrentSchema.IsValid
        && CurrentAcceptedEpoch.IsValid
        && CurrentAcceptedStreamSequence.IsValid
        && ExpectedStateDigest is { IsValid: true }
        && SchemaCompatibility is not null
        && SignatureVerifier is not null;
}

public enum SnapshotValidationError
{
    Uninitialized = 0,
    None,
    InvalidContext,
    MalformedSnapshot,
    WrongAuthority,
    WrongStream,
    WrongSigningKey,
    UnknownSchema,
    IncompatibleSchema,
    SchemaCompatibilityFailed,
    StaleEpoch,
    StreamRollback,
    StateDigestMismatch,
    InvalidSignature,
    SignatureVerificationFailed,
}

public readonly record struct SnapshotValidationResult
{
    private SnapshotValidationResult(SnapshotValidationError error) => Error = error;
    public SnapshotValidationError Error { get; }
    public bool IsValid => Error == SnapshotValidationError.None;
    internal static SnapshotValidationResult Accepted() => new(SnapshotValidationError.None);
    internal static SnapshotValidationResult Rejected(SnapshotValidationError error) => new(error);
}

public static class SignedSnapshotValidator
{
    public static SnapshotValidationResult Validate(SignedSnapshot? snapshot, SnapshotValidationContext? context)
    {
        if (context is null || !context.IsWellFormed)
        {
            return SnapshotValidationResult.Rejected(SnapshotValidationError.InvalidContext);
        }

        if (snapshot?.SignedMaterial is null || snapshot.Signature is not { IsValid: true })
        {
            return SnapshotValidationResult.Rejected(SnapshotValidationError.MalformedSnapshot);
        }

        var material = snapshot.SignedMaterial;
        if (material.Authority != context.ExpectedAuthority)
        {
            return SnapshotValidationResult.Rejected(SnapshotValidationError.WrongAuthority);
        }
        if (material.Stream != context.ExpectedStream)
        {
            return SnapshotValidationResult.Rejected(SnapshotValidationError.WrongStream);
        }
        if (material.SigningKey != context.ExpectedSigningKey)
        {
            return SnapshotValidationResult.Rejected(SnapshotValidationError.WrongSigningKey);
        }

        SnapshotSchemaCompatibilityOutcome compatibility;
        try
        {
            compatibility = context.SchemaCompatibility.Evaluate(context.CurrentSchema, material.Schema);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException)
        {
            return SnapshotValidationResult.Rejected(SnapshotValidationError.SchemaCompatibilityFailed);
        }

        if (compatibility == SnapshotSchemaCompatibilityOutcome.Unknown)
        {
            return SnapshotValidationResult.Rejected(SnapshotValidationError.UnknownSchema);
        }
        if (compatibility == SnapshotSchemaCompatibilityOutcome.Incompatible)
        {
            return SnapshotValidationResult.Rejected(SnapshotValidationError.IncompatibleSchema);
        }
        if (compatibility != SnapshotSchemaCompatibilityOutcome.Compatible)
        {
            return SnapshotValidationResult.Rejected(SnapshotValidationError.SchemaCompatibilityFailed);
        }
        if (material.Epoch.Value < context.CurrentAcceptedEpoch.Value)
        {
            return SnapshotValidationResult.Rejected(SnapshotValidationError.StaleEpoch);
        }
        if (material.StreamSequence.Value <= context.CurrentAcceptedStreamSequence.Value)
        {
            return SnapshotValidationResult.Rejected(SnapshotValidationError.StreamRollback);
        }
        if (!material.StateDigest.Equals(context.ExpectedStateDigest))
        {
            return SnapshotValidationResult.Rejected(SnapshotValidationError.StateDigestMismatch);
        }

        SnapshotSignatureVerificationOutcome signature;
        try
        {
            signature = context.SignatureVerifier.Verify(material, snapshot.Signature);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException)
        {
            return SnapshotValidationResult.Rejected(SnapshotValidationError.SignatureVerificationFailed);
        }

        return signature switch
        {
            SnapshotSignatureVerificationOutcome.Valid => SnapshotValidationResult.Accepted(),
            SnapshotSignatureVerificationOutcome.Invalid => SnapshotValidationResult.Rejected(SnapshotValidationError.InvalidSignature),
            _ => SnapshotValidationResult.Rejected(SnapshotValidationError.SignatureVerificationFailed),
        };
    }
}

public enum SnapshotRestorePlanError
{
    Uninitialized = 0,
    None,
    SnapshotRejected,
    ReplayStartOverflow,
}

public sealed class SnapshotRestorePlan
{
    internal SnapshotRestorePlan(
        SnapshotId snapshotId,
        SnapshotGeneration generation,
        SnapshotEpoch expectedRestoredEpoch,
        SnapshotStreamSequence replayStartSequence,
        SnapshotStateDigest expectedRestoredDigest)
    {
        SnapshotId = snapshotId;
        Generation = generation;
        ExpectedRestoredEpoch = expectedRestoredEpoch;
        ReplayStartSequence = replayStartSequence;
        ExpectedRestoredDigest = expectedRestoredDigest;
    }
    public SnapshotId SnapshotId { get; }
    public SnapshotGeneration Generation { get; }
    public SnapshotEpoch ExpectedRestoredEpoch { get; }
    public SnapshotStreamSequence ReplayStartSequence { get; }
    public SnapshotStateDigest ExpectedRestoredDigest { get; }
    public override string ToString() => "<snapshot-restore-plan>";
}

public readonly record struct SnapshotRestorePlanResult
{
    private SnapshotRestorePlanResult(SnapshotRestorePlanError error, SnapshotValidationError validationError, SnapshotRestorePlan? plan)
    {
        Error = error;
        ValidationError = validationError;
        Plan = plan;
    }
    public SnapshotRestorePlanError Error { get; }
    public SnapshotValidationError ValidationError { get; }
    public SnapshotRestorePlan? Plan { get; }
    public bool IsPlanned => Error == SnapshotRestorePlanError.None && Plan is not null;
    internal static SnapshotRestorePlanResult Rejected(SnapshotValidationError error) =>
        new(SnapshotRestorePlanError.SnapshotRejected, error, null);
    internal static SnapshotRestorePlanResult Overflow() =>
        new(SnapshotRestorePlanError.ReplayStartOverflow, SnapshotValidationError.None, null);
    internal static SnapshotRestorePlanResult Planned(SnapshotRestorePlan plan) =>
        new(SnapshotRestorePlanError.None, SnapshotValidationError.None, plan);
}

public static class SnapshotRestorePlanner
{
    public static SnapshotRestorePlanResult Plan(SignedSnapshot? snapshot, SnapshotValidationContext? context)
    {
        var validation = SignedSnapshotValidator.Validate(snapshot, context);
        if (!validation.IsValid)
        {
            return SnapshotRestorePlanResult.Rejected(validation.Error);
        }

        var material = snapshot!.SignedMaterial;
        if (material.StreamSequence.Value == ulong.MaxValue)
        {
            return SnapshotRestorePlanResult.Overflow();
        }

        SnapshotStreamSequence.TryCreate(material.StreamSequence.Value + 1, out var replayStart);
        return SnapshotRestorePlanResult.Planned(new SnapshotRestorePlan(
            material.SnapshotId,
            material.Generation,
            material.Epoch,
            replayStart,
            material.StateDigest));
    }
}
