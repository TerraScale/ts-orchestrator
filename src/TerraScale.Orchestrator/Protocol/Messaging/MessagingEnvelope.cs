using TerraScale.Orchestrator.Protocol.Subjects;

namespace TerraScale.Orchestrator.Protocol.Messaging;

/// <summary>Schema version of the messaging envelope contract: additive minor, breaking major.</summary>
public readonly record struct MessagingSchemaVersion(int Major, int Minor)
{
    public static MessagingSchemaVersion Current { get; } = new(1, 0);

    public bool IsWellFormed => Major > 0 && Minor >= 0;

    public override string ToString() => $"v{Major}.{Minor}";
}

/// <summary>
/// Bounded message identity tokens: message id, correlation id, and causation id.
/// Identical rules as the command identifiers: nonempty, no control characters, bounded.
/// </summary>
public readonly record struct MessageIdentityToken
{
    private readonly string? _value;

    private MessageIdentityToken(string value) => _value = value;

    public string Value => _value ?? string.Empty;

    public bool IsValid =>
        _value is { Length: >= 1 and <= 128 } &&
        _value.AsSpan().IndexOf('\0') < 0 &&
        !_value.Any(char.IsControl);

    public static bool TryCreate(string? value, out MessageIdentityToken result)
    {
        if (value is null || value.Length > 128 || value.AsSpan().IndexOf('\0') >= 0 || value.Any(char.IsControl))
        {
            result = default;
            return false;
        }

        result = new MessageIdentityToken(value);
        return true;
    }

    public override string ToString() => Value;
}

/// <summary>W3C-shaped trace context; both identifiers are bounded hex strings.</summary>
public sealed record MessagingTraceContext(string TraceId, string SpanId)
{
    public bool IsWellFormed =>
        TraceId is { Length: 32 } && TraceId.All(char.IsAsciiHexDigit) &&
        SpanId is { Length: 16 } && SpanId.All(char.IsAsciiHexDigit);
}

/// <summary>Where the message came from: the exact instance, session, cell, and cluster.</summary>
public sealed record MessagingSource(
    string Instance,
    string Session,
    string Cell,
    string Cluster)
{
    public bool IsWellFormed =>
        IsToken(Instance, 128) && IsToken(Session, 128) && IsToken(Cell, 63) && IsToken(Cluster, 128);

    private static bool IsToken(string? value, int maximumLength) =>
        value is { Length: >= 1 } && value.Length <= maximumLength &&
        value.All(static character =>
            char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
}

/// <summary>Where the message is addressed: taxonomy namespace, concrete subject, and optional cell scope. The namespace is validated against the subject's derived classification, so it can never drift into an ignored decorative field.</summary>
public sealed record MessagingTargetScope(
    NatsSubjectNamespace Namespace,
    string Subject,
    string? Cell)
{
    public bool IsWellFormed =>
        Subject is { Length: >= 1 and <= 512 } &&
        (Cell is null || Cell is { Length: >= 1 and <= 63 });
}

/// <summary>
/// The versioned messaging envelope. It does NOT duplicate the signed command contract: the
/// <see cref="Command"/> property carries the canonical <see cref="CommandEnvelope"/> (protocol
/// version, cell, aggregate, generation, writer epoch, operation id, idempotency key, issued/
/// expiry times, delivery attempt, payload, digest, signature). This envelope adds the
/// messaging-correlation, source/target, trace, payload-type, and observation metadata.
/// </summary>
public sealed class MessagingEnvelope
{
    public MessagingEnvelope(
        MessagingSchemaVersion schemaVersion,
        MessageIdentityToken messageId,
        MessageIdentityToken? correlationId,
        MessageIdentityToken? causationId,
        MessagingSource source,
        MessagingTargetScope target,
        string payloadType,
        CommandEnvelope command,
        MessagingTraceContext? traceContext,
        DateTimeOffset observedAt)
    {
        SchemaVersion = schemaVersion;
        MessageId = messageId;
        CorrelationId = correlationId;
        CausationId = causationId;
        Source = source;
        Target = target;
        PayloadType = payloadType;
        Command = command;
        TraceContext = traceContext;
        ObservedAt = observedAt;
    }

    public MessagingSchemaVersion SchemaVersion { get; }

    public MessageIdentityToken MessageId { get; }

    public MessageIdentityToken? CorrelationId { get; }

    public MessageIdentityToken? CausationId { get; }

    public MessagingSource Source { get; }

    public MessagingTargetScope Target { get; }

    /// <summary>The closed payload type discriminator (for example <c>cellspec-v1</c>).</summary>
    public string PayloadType { get; }

    public CommandEnvelope Command { get; }

    public MessagingTraceContext? TraceContext { get; }

    /// <summary>When the transport observed the message; used for staleness and duplicate windows.</summary>
    public DateTimeOffset ObservedAt { get; }

    public override string ToString() =>
        $"MessagingEnvelope {{ SchemaVersion = {SchemaVersion}, MessageId = <redacted>, Target = {Target.Subject}, "
        + $"PayloadType = {PayloadType}, Command = {Command} }}";
}

public enum MessagingEnvelopeError
{
    None = 0,
    NullEnvelope,
    UnknownMajorVersion,
    MalformedEnvelope,
    MalformedSubject,
    SubjectOutsideClosedTaxonomy,
    /// <summary>The declared target namespace disagrees with the subject's derived classification.</summary>
    DeclaredNamespaceMismatch,
    SubjectCellMismatch,
    SourceCellMismatch,
    PayloadTypeNotPermitted,
    InvalidTraceContext,
    /// <summary>The signed command contract rejected the envelope; the command error carries the exact reason.</summary>
    CommandRejected,
}

public readonly record struct MessagingEnvelopeResult
{
    private MessagingEnvelopeResult(MessagingEnvelopeError error, CommandValidationError commandError, MessagingEnvelope? envelope)
    {
        Error = error;
        CommandError = commandError;
        Envelope = envelope;
    }

    public MessagingEnvelopeError Error { get; }

    /// <summary>Exact signed-command rejection reason when <see cref="Error"/> is <see cref="MessagingEnvelopeError.CommandRejected"/>.</summary>
    public CommandValidationError CommandError { get; }

    public MessagingEnvelope? Envelope { get; }

    public bool IsAccepted => Error == MessagingEnvelopeError.None && Envelope is not null;

    internal static MessagingEnvelopeResult Accepted(MessagingEnvelope envelope) =>
        new(MessagingEnvelopeError.None, CommandValidationError.None, envelope);

    internal static MessagingEnvelopeResult Rejected(
        MessagingEnvelopeError error,
        CommandValidationError commandError = CommandValidationError.Uninitialized) =>
        new(error, commandError, null);
}

/// <summary>Frozen admission context: accepted schema majors, permitted payload types, and the signed-command context.</summary>
public sealed class MessagingValidationContext
{
    public MessagingValidationContext(
        IReadOnlySet<int> acceptedSchemaMajorVersions,
        IReadOnlySet<string> permittedPayloadTypes,
        CommandValidationContext commandContext)
    {
        AcceptedSchemaMajorVersions = acceptedSchemaMajorVersions;
        PermittedPayloadTypes = permittedPayloadTypes;
        CommandContext = commandContext;
    }

    public IReadOnlySet<int> AcceptedSchemaMajorVersions { get; }

    public IReadOnlySet<string> PermittedPayloadTypes { get; }

    public CommandValidationContext CommandContext { get; }

    internal bool IsWellFormed =>
        AcceptedSchemaMajorVersions.Count > 0 &&
        PermittedPayloadTypes.Count > 0 &&
        PermittedPayloadTypes.All(static type => type is { Length: >= 1 and <= 64 });
}

/// <summary>
/// Pure, fail-closed messaging-envelope admission. Every check is deterministic and
/// infrastructure-free: unknown major versions, malformed or off-taxonomy subjects,
/// declared-namespace disagreement with the derived classification, subject/cell
/// disagreement, unpermitted payload types, malformed trace context, and every
/// signed-command rejection (expiry, wrong cell, stale epoch, signature, digest) fail
/// closed with typed errors.
/// </summary>
public static class MessagingEnvelopeValidator
{
    public static MessagingEnvelopeResult Validate(MessagingEnvelope? envelope, MessagingValidationContext? context)
    {
        if (context is null || !context.IsWellFormed)
        {
            return MessagingEnvelopeResult.Rejected(MessagingEnvelopeError.MalformedEnvelope);
        }

        if (envelope is null)
        {
            return MessagingEnvelopeResult.Rejected(MessagingEnvelopeError.NullEnvelope);
        }

        if (!envelope.SchemaVersion.IsWellFormed ||
            !context.AcceptedSchemaMajorVersions.Contains(envelope.SchemaVersion.Major))
        {
            return MessagingEnvelopeResult.Rejected(MessagingEnvelopeError.UnknownMajorVersion);
        }

        if (!envelope.MessageId.IsValid ||
            (envelope.CorrelationId is { } correlation && !correlation.IsValid) ||
            (envelope.CausationId is { } causation && !causation.IsValid) ||
            !envelope.Source.IsWellFormed ||
            !envelope.Target.IsWellFormed ||
            string.IsNullOrWhiteSpace(envelope.PayloadType) ||
            envelope.PayloadType.Length > 64 ||
            envelope.Command is null)
        {
            return MessagingEnvelopeResult.Rejected(MessagingEnvelopeError.MalformedEnvelope);
        }

        if (envelope.TraceContext is { } trace && !trace.IsWellFormed)
        {
            return MessagingEnvelopeResult.Rejected(MessagingEnvelopeError.InvalidTraceContext);
        }

        // Source and signed command must agree on the cell before any subject coupling check.
        if (!string.Equals(envelope.Source.Cell, envelope.Command.Cell.Value, StringComparison.Ordinal))
        {
            return MessagingEnvelopeResult.Rejected(MessagingEnvelopeError.SourceCellMismatch);
        }

        if (!ConcreteSubject.TryParse(envelope.Target.Subject, NatsSubjectTaxonomy.GrammarLimits, out _, out _))
        {
            return MessagingEnvelopeResult.Rejected(MessagingEnvelopeError.MalformedSubject);
        }

        var ns = NatsSubjectTaxonomy.Classify(envelope.Target.Subject);
        if (!NatsSubjectTaxonomy.IsControlNamespace(ns))
        {
            return MessagingEnvelopeResult.Rejected(MessagingEnvelopeError.SubjectOutsideClosedTaxonomy);
        }

        // The declared namespace must equal the classification derived from the subject;
        // disagreement is a typed rejection rather than a silently ignored decorative field.
        if (envelope.Target.Namespace != ns)
        {
            return MessagingEnvelopeResult.Rejected(MessagingEnvelopeError.DeclaredNamespaceMismatch);
        }

        var subjectCell = ExtractCellScope(envelope.Target.Subject);
        if (subjectCell is { } scoped &&
            !string.Equals(scoped, envelope.Command.Cell.Value, StringComparison.Ordinal))
        {
            return MessagingEnvelopeResult.Rejected(MessagingEnvelopeError.SubjectCellMismatch);
        }

        if (envelope.Target.Cell is { } targetCell &&
            !string.Equals(targetCell, envelope.Command.Cell.Value, StringComparison.Ordinal))
        {
            return MessagingEnvelopeResult.Rejected(MessagingEnvelopeError.SubjectCellMismatch);
        }

        if (!context.PermittedPayloadTypes.Contains(envelope.PayloadType))
        {
            return MessagingEnvelopeResult.Rejected(MessagingEnvelopeError.PayloadTypeNotPermitted);
        }

        var commandResult = CommandEnvelopeValidator.Validate(envelope.Command, context.CommandContext, envelope.ObservedAt);
        if (!commandResult.IsValid)
        {
            return MessagingEnvelopeResult.Rejected(MessagingEnvelopeError.CommandRejected, commandResult.Error);
        }

        return MessagingEnvelopeResult.Accepted(envelope);
    }

    /// <summary>
    /// Extracts the cell token of a cell-scoped subject: the regional shape
    /// (<c>ts.orch.v2.&lt;cell&gt;…</c>, token 4) and, as defense in depth, the canonical
    /// global per-cell shape (<c>ts.orch.v2.global.desired.gitops.&lt;cell&gt;</c>). Any other
    /// global subject carries no cell scope and returns <c>null</c>.
    /// </summary>
    internal static string? ExtractCellScope(string subject)
    {
        var tokens = subject.Split('.');
        if (tokens.Length >= 4 &&
            subject.StartsWith(NatsSubjectTaxonomy.Root + ".", StringComparison.Ordinal))
        {
            if (string.Equals(tokens[3], "global", StringComparison.Ordinal))
            {
                return tokens.Length == 7 &&
                    string.Equals(tokens[4], "desired", StringComparison.Ordinal) &&
                    string.Equals(tokens[5], "gitops", StringComparison.Ordinal)
                        ? tokens[6]
                        : null;
            }

            return tokens[3];
        }

        return null;
    }
}
