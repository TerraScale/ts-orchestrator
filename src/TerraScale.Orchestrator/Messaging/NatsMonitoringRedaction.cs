using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.Messaging;

/// <summary>
/// Redacted correlation metadata for NATS monitoring logs and traces. A correlation
/// carries a bounded opaque correlation token and a redacted summary — never a JWT,
/// NKey seed, private key, credential, customer payload, or raw signed bundle.
/// Correlation tokens exist so operators can join a monitoring event to a trace
/// without the joined material itself being secret-bearing.
/// </summary>
internal sealed record NatsMonitoringCorrelation
{
    internal NatsMonitoringCorrelation(string correlationToken, string redactedSummary)
    {
        CorrelationToken = ValidateToken(correlationToken);
        RedactedSummary = NatsMonitoringRedaction.Sanitize(redactedSummary);
    }

    internal string CorrelationToken { get; }
    internal string RedactedSummary { get; }

    private static string ValidateToken(string token)
    {
        if (token is not { Length: >= 8 and <= 64 } ||
            !token.All(static character =>
                character is >= 'a' and <= 'z' or >= '0' and <= '9'))
            throw new ArgumentException("The correlation token must be a bounded lowercase alphanumeric token.");
        return token;
    }
}

/// <summary>
/// The single redaction boundary for NATS monitoring output. Everything that can
/// reach a log line, trace attribute, metric tag, test assertion, or Grafana fixture
/// passes through <see cref="Sanitize"/> first; <see cref="ContainsSecretMaterial"/>
/// is the detector both the sanitizer and the tests share, so the tests prove the
/// same predicate production code relies on.
/// </summary>
internal static partial class NatsMonitoringRedaction
{
    /// <summary>Bounded replacement for any detected secret-bearing span.</summary>
    internal const string RedactedPlaceholder = "[redacted]";

    private const int MaximumSummaryLength = 256;

    /// <summary>
    /// Removes secret-bearing spans and bounds the length. The result is safe for
    /// logs, traces, metrics tag values, and fixtures; if a span cannot be proven
    /// clean it is replaced, never passed through.
    /// </summary>
    internal static string Sanitize(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var sanitized = value;
        sanitized = PemBlockRegex().Replace(sanitized, RedactedPlaceholder);
        sanitized = JwtRegex().Replace(sanitized, RedactedPlaceholder);
        sanitized = NkeySeedRegex().Replace(sanitized, RedactedPlaceholder);
        sanitized = BearerRegex().Replace(sanitized, RedactedPlaceholder);
        sanitized = CredentialAssignmentRegex().Replace(sanitized, RedactedPlaceholder);
        return sanitized.Length <= MaximumSummaryLength
            ? sanitized
            : sanitized[..MaximumSummaryLength];
    }

    /// <summary>
    /// True when the value contains material the monitoring contract must never
    /// emit: PEM private-key blocks, JWTs, NKey seeds, bearer tokens, or explicit
    /// credential assignments. This is the predicate the redaction tests assert
    /// against production output shapes.
    /// </summary>
    internal static bool ContainsSecretMaterial(string value)
    {
        if (string.IsNullOrEmpty(value)) return false;
        return PemBlockRegex().IsMatch(value) ||
               JwtRegex().IsMatch(value) ||
               NkeySeedRegex().IsMatch(value) ||
               BearerRegex().IsMatch(value) ||
               CredentialAssignmentRegex().IsMatch(value);
    }

    // -----BEGIN <anything> KEY----- ... -----END <anything> KEY-----
    [GeneratedRegex(@"-----BEGIN [A-Z ]*KEY-----[\s\S]*?-----END [A-Z ]*KEY-----", RegexOptions.CultureInvariant)]
    private static partial Regex PemBlockRegex();

    // Compact JWS/JWT: three base64url segments, header at least 8 bytes, signature at least 16.
    [GeneratedRegex(@"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{16,}", RegexOptions.CultureInvariant)]
    private static partial Regex JwtRegex();

    // NKey/user seeds: S + role letter (U/A/O/P/S/C) + base32 payload, and the
    // seed form used in credentials files.
    [GeneratedRegex(@"\bS[UAOPSC][A-Z2-7]{40,}\b", RegexOptions.CultureInvariant)]
    private static partial Regex NkeySeedRegex();

    [GeneratedRegex(@"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BearerRegex();

    [GeneratedRegex(@"(?:password|secret|token|apikey|api_key|nkey|seed)[""']?\s*[:=]\s*[""']?[^\s,""'}]{4,}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CredentialAssignmentRegex();
}
