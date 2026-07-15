using System.Runtime.ExceptionServices;
using TerraScale.Orchestrator.Contracts;

namespace TerraScale.Orchestrator.Protocol;

public enum VerificationOutcome
{
    Invalid = 0,
    Valid = 1,
}

public interface IPayloadDigestVerifier
{
    VerificationOutcome Verify(OpaquePayload payload, PayloadDigest expectedDigest);
}

public interface ICommandSignatureVerifier
{
    VerificationOutcome Verify(CommandSignedMaterial signedMaterial, OpaqueSignature signature);
}

public enum CommandValidationError
{
    Uninitialized = 0,
    None,
    InvalidValidationContext,
    MalformedEnvelope,
    UnsupportedProtocolVersion,
    InvalidValidityWindow,
    NotYetValid,
    Expired,
    WrongCell,
    WrongAggregateIdentity,
    StaleGeneration,
    StaleWriterEpoch,
    PayloadDigestMismatch,
    PayloadDigestVerificationFailed,
    InvalidSignature,
    SignatureVerificationFailed,
}

public readonly record struct CommandValidationResult
{
    private CommandValidationResult(CommandValidationError error, CommandAcceptance? acceptance)
    {
        Error = error;
        Acceptance = acceptance;
    }

    public CommandValidationError Error { get; }

    public CommandAcceptance? Acceptance { get; }

    public bool IsValid => Error == CommandValidationError.None;

    internal static CommandValidationResult Accepted(CommandEnvelope envelope, DateTimeOffset validatedAt) =>
        new(CommandValidationError.None, new CommandAcceptance(envelope, validatedAt));

    internal static CommandValidationResult Rejected(CommandValidationError error) => new(error, null);
}

/// <summary>
/// Exact secret-safe receipt for the signed command envelope accepted by validation.
/// It intentionally does not retain the opaque payload, verifier implementations, or
/// the complete validation-context policy.
/// </summary>
public sealed class CommandAcceptance : IEquatable<CommandAcceptance>
{
    internal CommandAcceptance(CommandEnvelope envelope, DateTimeOffset validatedAt)
    {
        ProtocolVersion = envelope.ProtocolVersion;
        Cell = envelope.Cell;
        AggregateId = envelope.AggregateId;
        DesiredGeneration = envelope.DesiredGeneration;
        WriterEpoch = envelope.WriterEpoch;
        OperationId = envelope.OperationId;
        IdempotencyKey = envelope.IdempotencyKey;
        IssuedAt = envelope.IssuedAt;
        ExpiresAt = envelope.ExpiresAt;
        Attempt = envelope.Attempt;
        PayloadDigest = envelope.PayloadDigest;
        Signature = envelope.Signature;
        ValidatedAt = validatedAt;
    }

    public ProtocolRevision ProtocolVersion { get; }
    public CellId Cell { get; }
    public AggregateId AggregateId { get; }
    public DesiredGeneration DesiredGeneration { get; }
    public WriterEpoch WriterEpoch { get; }
    public OperationId OperationId { get; }
    public IdempotencyKey IdempotencyKey { get; }
    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
    public DeliveryAttempt Attempt { get; }
    public PayloadDigest PayloadDigest { get; }
    public OpaqueSignature Signature { get; }
    public DateTimeOffset ValidatedAt { get; }

    public bool Equals(CommandAcceptance? other) =>
        other is not null
        && ProtocolVersion == other.ProtocolVersion
        && Cell == other.Cell
        && AggregateId == other.AggregateId
        && DesiredGeneration == other.DesiredGeneration
        && WriterEpoch == other.WriterEpoch
        && OperationId == other.OperationId
        && IdempotencyKey == other.IdempotencyKey
        && IssuedAt == other.IssuedAt
        && ExpiresAt == other.ExpiresAt
        && Attempt == other.Attempt
        && PayloadDigest.Equals(other.PayloadDigest)
        && Signature.Equals(other.Signature)
        && ValidatedAt == other.ValidatedAt;

    public override bool Equals(object? obj) => Equals(obj as CommandAcceptance);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(ProtocolVersion);
        hash.Add(Cell);
        hash.Add(AggregateId);
        hash.Add(DesiredGeneration);
        hash.Add(WriterEpoch);
        hash.Add(OperationId);
        hash.Add(IdempotencyKey);
        hash.Add(IssuedAt);
        hash.Add(ExpiresAt);
        hash.Add(Attempt);
        hash.Add(PayloadDigest);
        hash.Add(Signature);
        hash.Add(ValidatedAt);
        return hash.ToHashCode();
    }

    public override string ToString() =>
        $"CommandAcceptance {{ ProtocolVersion = {ProtocolVersion}, Cell = {Cell}, AggregateId = {AggregateId}, "
        + $"DesiredGeneration = {DesiredGeneration}, WriterEpoch = {WriterEpoch}, OperationId = {OperationId}, "
        + $"IdempotencyKey = {IdempotencyKey}, IssuedAt = {IssuedAt:O}, ExpiresAt = {ExpiresAt:O}, "
        + $"Attempt = {Attempt}, PayloadDigest = <redacted>, Signature = <redacted>, ValidatedAt = {ValidatedAt:O} }}";
}

public sealed class CommandValidationContext
{
    private readonly HashSet<ProtocolRevision> _acceptedProtocolVersions;

    public CommandValidationContext(
        CellId expectedCell,
        AggregateId expectedAggregateId,
        DesiredGeneration minimumDesiredGeneration,
        WriterEpoch minimumWriterEpoch,
        IEnumerable<ProtocolRevision>? acceptedProtocolVersions,
        TimeSpan allowedClockSkew,
        IPayloadDigestVerifier? payloadDigestVerifier,
        ICommandSignatureVerifier? signatureVerifier)
    {
        ExpectedCell = expectedCell;
        ExpectedAggregateId = expectedAggregateId;
        MinimumDesiredGeneration = minimumDesiredGeneration;
        MinimumWriterEpoch = minimumWriterEpoch;
        _acceptedProtocolVersions = CaptureAcceptedProtocolVersions(acceptedProtocolVersions);
        AllowedClockSkew = allowedClockSkew;
        PayloadDigestVerifier = payloadDigestVerifier;
        SignatureVerifier = signatureVerifier;
    }

    public CellId ExpectedCell { get; }

    public AggregateId ExpectedAggregateId { get; }

    public DesiredGeneration MinimumDesiredGeneration { get; }

    public WriterEpoch MinimumWriterEpoch { get; }

    public TimeSpan AllowedClockSkew { get; }

    public IPayloadDigestVerifier? PayloadDigestVerifier { get; }

    public ICommandSignatureVerifier? SignatureVerifier { get; }

    internal bool IsWellFormed =>
        ExpectedCell.IsValid
        && ExpectedAggregateId.IsValid
        && MinimumDesiredGeneration.IsValid
        && MinimumWriterEpoch.IsValid
        && _acceptedProtocolVersions.Count > 0
        && _acceptedProtocolVersions.All(static version => version.IsValid)
        && AllowedClockSkew >= TimeSpan.Zero
        && PayloadDigestVerifier is not null
        && SignatureVerifier is not null;

    internal bool Accepts(ProtocolRevision version) => _acceptedProtocolVersions.Contains(version);

    private static HashSet<ProtocolRevision> CaptureAcceptedProtocolVersions(
        IEnumerable<ProtocolRevision>? source)
    {
        if (source is null)
        {
            return [];
        }

        IEnumerator<ProtocolRevision> enumerator;
        try
        {
            enumerator = source.GetEnumerator();
        }
        catch (Exception exception) when (!ProtocolExceptionPolicy.IsFatal(exception))
        {
            throw CaptureFailure();
        }

        var captured = new HashSet<ProtocolRevision>();
        Exception? enumerationFailure = null;
        var exceeded = false;
        var observed = 0;
        try
        {
            while (enumerator.MoveNext())
            {
                if (observed == ProtocolTechnicalInputLimits.MaximumAcceptedProtocolVersionCount)
                {
                    exceeded = true;
                    break;
                }

                captured.Add(enumerator.Current);
                observed++;
            }
        }
        catch (Exception exception)
        {
            enumerationFailure = exception;
        }

        Exception? disposalFailure = null;
        try
        {
            enumerator.Dispose();
        }
        catch (Exception exception)
        {
            disposalFailure = exception;
        }

        var fatalFailure = ProtocolExceptionPolicy.IsFatal(enumerationFailure)
            ? enumerationFailure
            : ProtocolExceptionPolicy.IsFatal(disposalFailure)
                ? disposalFailure
                : null;
        if (fatalFailure is not null)
        {
            ExceptionDispatchInfo.Capture(fatalFailure).Throw();
        }

        if (enumerationFailure is not null || disposalFailure is not null || exceeded)
        {
            throw CaptureFailure();
        }

        return captured;
    }

    private static ArgumentException CaptureFailure() =>
        new("Accepted protocol versions could not be captured within the technical input bound.",
            "acceptedProtocolVersions");
}

/// <summary>
/// Pure, deterministic INV-005 command admission validation.
/// </summary>
public static class CommandEnvelopeValidator
{
    public static CommandValidationResult Validate(
        CommandEnvelope? envelope,
        CommandValidationContext? context,
        DateTimeOffset now)
    {
        if (context is null || !context.IsWellFormed)
        {
            return CommandValidationResult.Rejected(CommandValidationError.InvalidValidationContext);
        }

        if (!IsWellFormed(envelope))
        {
            return CommandValidationResult.Rejected(CommandValidationError.MalformedEnvelope);
        }

        if (!context.Accepts(envelope!.ProtocolVersion))
        {
            return CommandValidationResult.Rejected(CommandValidationError.UnsupportedProtocolVersion);
        }

        if (envelope.ExpiresAt < envelope.IssuedAt)
        {
            return CommandValidationResult.Rejected(CommandValidationError.InvalidValidityWindow);
        }

        if (envelope.IssuedAt - now > context.AllowedClockSkew)
        {
            return CommandValidationResult.Rejected(CommandValidationError.NotYetValid);
        }

        if (now - envelope.ExpiresAt > context.AllowedClockSkew)
        {
            return CommandValidationResult.Rejected(CommandValidationError.Expired);
        }

        if (envelope.Cell != context.ExpectedCell)
        {
            return CommandValidationResult.Rejected(CommandValidationError.WrongCell);
        }

        if (envelope.AggregateId != context.ExpectedAggregateId)
        {
            return CommandValidationResult.Rejected(CommandValidationError.WrongAggregateIdentity);
        }

        if (envelope.DesiredGeneration.Value < context.MinimumDesiredGeneration.Value)
        {
            return CommandValidationResult.Rejected(CommandValidationError.StaleGeneration);
        }

        if (envelope.WriterEpoch.Value < context.MinimumWriterEpoch.Value)
        {
            return CommandValidationResult.Rejected(CommandValidationError.StaleWriterEpoch);
        }

        VerificationOutcome digestOutcome;
        try
        {
            digestOutcome = context.PayloadDigestVerifier!.Verify(envelope.Payload, envelope.PayloadDigest);
        }
        catch (Exception exception) when (!ProtocolExceptionPolicy.IsFatal(exception))
        {
            return CommandValidationResult.Rejected(CommandValidationError.PayloadDigestVerificationFailed);
        }

        if (digestOutcome == VerificationOutcome.Invalid)
        {
            return CommandValidationResult.Rejected(CommandValidationError.PayloadDigestMismatch);
        }

        if (digestOutcome != VerificationOutcome.Valid)
        {
            return CommandValidationResult.Rejected(CommandValidationError.PayloadDigestVerificationFailed);
        }

        VerificationOutcome signatureOutcome;
        try
        {
            signatureOutcome = context.SignatureVerifier!.Verify(envelope.SignedMaterial, envelope.Signature);
        }
        catch (Exception exception) when (!ProtocolExceptionPolicy.IsFatal(exception))
        {
            return CommandValidationResult.Rejected(CommandValidationError.SignatureVerificationFailed);
        }

        return signatureOutcome switch
        {
            VerificationOutcome.Valid => CommandValidationResult.Accepted(envelope, now),
            VerificationOutcome.Invalid => CommandValidationResult.Rejected(CommandValidationError.InvalidSignature),
            _ => CommandValidationResult.Rejected(CommandValidationError.SignatureVerificationFailed),
        };
    }

    private static bool IsWellFormed(CommandEnvelope? envelope) =>
        envelope is not null
        && envelope.ProtocolVersion.IsValid
        && envelope.Cell.IsValid
        && envelope.AggregateId.IsValid
        && envelope.DesiredGeneration.IsValid
        && envelope.WriterEpoch.IsValid
        && envelope.OperationId.IsValid
        && envelope.IdempotencyKey.IsValid
        && envelope.Attempt.IsValid
        && envelope.Payload is not null
        && envelope.PayloadDigest is { IsValid: true }
        && envelope.Signature is { IsValid: true };
}
