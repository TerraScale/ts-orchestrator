using System.Collections.ObjectModel;
using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.Security.SystemProjectBootstrap;

internal static partial class BootstrapValueRules
{
    public static string Token(string value, string name)
    {
        ArgumentNullException.ThrowIfNull(value, name);
        if (value.Length is < 1 or > 128 || !TokenPattern().IsMatch(value))
            throw new ArgumentException("Bootstrap value must be a bounded canonical token.", name);
        return value;
    }

    public static string Thumbprint(string value, string name)
    {
        ArgumentNullException.ThrowIfNull(value, name);
        if (value.Length != 64 || value.Any(static c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new ArgumentException("Certificate thumbprint must be a lowercase SHA-256 value.", name);
        return value;
    }

    [GeneratedRegex("^[a-z0-9][a-z0-9]*(?:[.-][a-z0-9]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex TokenPattern();
}

public abstract record BootstrapToken
{
    protected BootstrapToken(string value, string name) => Value = BootstrapValueRules.Token(value, name);
    public string Value { get; }
    public sealed override string ToString() => Value;
}

public sealed record BootstrapGrantId : BootstrapToken { public BootstrapGrantId(string value) : base(value, nameof(value)) { } }
public sealed record BootstrapNonce : BootstrapToken { public BootstrapNonce(string value) : base(value, nameof(value)) { } }
public sealed record BootstrapAudience : BootstrapToken { public BootstrapAudience(string value) : base(value, nameof(value)) { } }
public sealed record BootstrapOrganizationId : BootstrapToken { public BootstrapOrganizationId(string value) : base(value, nameof(value)) { } }
public sealed record BootstrapProjectId : BootstrapToken { public BootstrapProjectId(string value) : base(value, nameof(value)) { } }
public sealed record BootstrapDatabaseId : BootstrapToken { public BootstrapDatabaseId(string value) : base(value, nameof(value)) { } }
public sealed record BootstrapTrustBundleKeyId : BootstrapToken { public BootstrapTrustBundleKeyId(string value) : base(value, nameof(value)) { } }

public sealed record BootstrapCertificateThumbprint
{
    public BootstrapCertificateThumbprint(string value) => Value = BootstrapValueRules.Thumbprint(value, nameof(value));
    public string Value { get; }
    public sealed override string ToString() => "[redacted]";
}

public sealed record BootstrapTrustBundleVersion
{
    public BootstrapTrustBundleVersion(ulong value) => Value = value > 0 ? value : throw new ArgumentOutOfRangeException(nameof(value));
    public ulong Value { get; }
}

public enum BootstrapOperation
{
    EnsureSystemOrganization = 1,
    EnsureSystemProject = 2,
    EnsureSystemDatabase = 3,
    EnsureSystemProjectConfiguration = 4,
    ReadCustomerProject = 100,
}

public enum BootstrapGrantSignatureStatus
{
    Valid = 1,
    Invalid = 2,
    Unavailable = 3,
    Unknown = 4,
}

public enum BootstrapReplayConsumeResult
{
    Consumed = 1,
    AlreadyConsumed = 2,
    Rejected = 3,
    Unavailable = 4,
}

public enum BootstrapReplayAuditOutcome
{
    NotAttempted = 1,
    Consumed = 2,
    AlreadyConsumed = 3,
    Rejected = 4,
    Unavailable = 5,
}

public enum BootstrapGrantDecisionCode
{
    Authorized = 1,
    InvalidSignature = 2,
    SignatureKeyMismatch = 3,
    OperationMismatch = 4,
    OperationNotIdempotent = 5,
    AudienceMismatch = 6,
    CertificateMismatch = 7,
    CustomerProjectDenied = 8,
    SystemProjectMismatch = 9,
    TrustBundleKeyMismatch = 10,
    NotYetValid = 11,
    Expired = 12,
    InvalidValidityWindow = 13,
    LifetimeExceeded = 14,
    ReplayConsumerUnavailable = 15,
    ReplayDetected = 16,
    ReplayRejected = 17,
}

public sealed record BootstrapSystemProjectIdentity
{
    public BootstrapSystemProjectIdentity(BootstrapOrganizationId organizationId, BootstrapProjectId projectId, BootstrapDatabaseId databaseId)
    {
        OrganizationId = organizationId ?? throw new ArgumentNullException(nameof(organizationId));
        ProjectId = projectId ?? throw new ArgumentNullException(nameof(projectId));
        DatabaseId = databaseId ?? throw new ArgumentNullException(nameof(databaseId));
    }

    public BootstrapOrganizationId OrganizationId { get; }
    public BootstrapProjectId ProjectId { get; }
    public BootstrapDatabaseId DatabaseId { get; }
}

public sealed class BootstrapSystemProjectAllowlist
{
    private readonly IReadOnlyList<BootstrapSystemProjectIdentity> entries;

    public BootstrapSystemProjectAllowlist(IEnumerable<BootstrapSystemProjectIdentity> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var values = entries.ToArray();
        if (values.Length is < 1 or > 20 || values.Any(static value => value is null))
            throw new ArgumentException("The fixed system Project allowlist must be bounded and non-empty.", nameof(entries));
        if (values.Distinct().Count() != values.Length)
            throw new ArgumentException("The fixed system Project allowlist cannot contain duplicates.", nameof(entries));
        this.entries = new ReadOnlyCollection<BootstrapSystemProjectIdentity>(values);
    }

    public IReadOnlyList<BootstrapSystemProjectIdentity> Entries => entries;

    public bool Contains(BootstrapSystemProjectIdentity identity) => identity is not null && entries.Contains(identity);
}

public sealed record BootstrapTrustBundleKey
{
    public BootstrapTrustBundleKey(BootstrapTrustBundleKeyId keyId, BootstrapTrustBundleVersion version)
    {
        KeyId = keyId ?? throw new ArgumentNullException(nameof(keyId));
        Version = version ?? throw new ArgumentNullException(nameof(version));
    }

    public BootstrapTrustBundleKeyId KeyId { get; }
    public BootstrapTrustBundleVersion Version { get; }
}

public sealed class BootstrapTrustBundleRotation
{
    public BootstrapTrustBundleRotation(BootstrapTrustBundleKey current, BootstrapTrustBundleKey? overlap)
    {
        Current = current ?? throw new ArgumentNullException(nameof(current));
        if (overlap is not null && (overlap.KeyId == current.KeyId || overlap.Version.Value >= current.Version.Value))
            throw new ArgumentException("An overlap key must be distinct and older than the current key.", nameof(overlap));
        Overlap = overlap;
    }

    public BootstrapTrustBundleKey Current { get; }
    public BootstrapTrustBundleKey? Overlap { get; }

    public bool Accepts(BootstrapTrustBundleKey key) =>
        key is not null && (key == Current || key == Overlap);
}

public sealed record BootstrapGrant
{
    public BootstrapGrant(
        BootstrapGrantId grantId,
        BootstrapNonce nonce,
        BootstrapAudience audience,
        BootstrapCertificateThumbprint certificateThumbprint,
        BootstrapSystemProjectIdentity target,
        BootstrapOperation operation,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        BootstrapTrustBundleKey trustBundleKey)
    {
        GrantId = grantId ?? throw new ArgumentNullException(nameof(grantId));
        Nonce = nonce ?? throw new ArgumentNullException(nameof(nonce));
        Audience = audience ?? throw new ArgumentNullException(nameof(audience));
        CertificateThumbprint = certificateThumbprint ?? throw new ArgumentNullException(nameof(certificateThumbprint));
        Target = target ?? throw new ArgumentNullException(nameof(target));
        if (!Enum.IsDefined(operation)) throw new ArgumentOutOfRangeException(nameof(operation));
        Operation = operation;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
        TrustBundleKey = trustBundleKey ?? throw new ArgumentNullException(nameof(trustBundleKey));
    }

    public BootstrapGrantId GrantId { get; }
    public BootstrapNonce Nonce { get; }
    public BootstrapAudience Audience { get; }
    public BootstrapCertificateThumbprint CertificateThumbprint { get; }
    public BootstrapSystemProjectIdentity Target { get; }
    public BootstrapOperation Operation { get; }
    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
    public BootstrapTrustBundleKey TrustBundleKey { get; }
}

public sealed record BootstrapGrantSignatureEvidence
{
    public BootstrapGrantSignatureEvidence(BootstrapGrantSignatureStatus status, BootstrapTrustBundleKey? verifiedWith)
    {
        if (!Enum.IsDefined(status)) throw new ArgumentOutOfRangeException(nameof(status));
        Status = status;
        VerifiedWith = verifiedWith;
    }

    public BootstrapGrantSignatureStatus Status { get; }
    public BootstrapTrustBundleKey? VerifiedWith { get; }
}

public sealed record BootstrapGrantReplayKey
{
    public BootstrapGrantReplayKey(BootstrapGrantId grantId, BootstrapNonce nonce)
    {
        GrantId = grantId ?? throw new ArgumentNullException(nameof(grantId));
        Nonce = nonce ?? throw new ArgumentNullException(nameof(nonce));
    }

    public BootstrapGrantId GrantId { get; }
    public BootstrapNonce Nonce { get; }
}

public interface IBootstrapGrantReplayConsumer
{
    BootstrapReplayConsumeResult TryConsume(BootstrapGrantReplayKey key, DateTimeOffset expiresAt);
}

public sealed record BootstrapGrantVerificationContext
{
    public BootstrapGrantVerificationContext(
        BootstrapOperation requestedOperation,
        BootstrapAudience expectedAudience,
        BootstrapCertificateThumbprint expectedCertificateThumbprint,
        BootstrapSystemProjectIdentity expectedTarget,
        BootstrapSystemProjectAllowlist systemProjectAllowlist,
        BootstrapTrustBundleRotation trustBundle,
        DateTimeOffset now,
        TimeSpan maximumLifetime)
    {
        if (!Enum.IsDefined(requestedOperation)) throw new ArgumentOutOfRangeException(nameof(requestedOperation));
        if (maximumLifetime <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(maximumLifetime));
        RequestedOperation = requestedOperation;
        ExpectedAudience = expectedAudience ?? throw new ArgumentNullException(nameof(expectedAudience));
        ExpectedCertificateThumbprint = expectedCertificateThumbprint ?? throw new ArgumentNullException(nameof(expectedCertificateThumbprint));
        ExpectedTarget = expectedTarget ?? throw new ArgumentNullException(nameof(expectedTarget));
        SystemProjectAllowlist = systemProjectAllowlist ?? throw new ArgumentNullException(nameof(systemProjectAllowlist));
        TrustBundle = trustBundle ?? throw new ArgumentNullException(nameof(trustBundle));
        Now = now;
        MaximumLifetime = maximumLifetime;
    }

    public BootstrapOperation RequestedOperation { get; }
    public BootstrapAudience ExpectedAudience { get; }
    public BootstrapCertificateThumbprint ExpectedCertificateThumbprint { get; }
    public BootstrapSystemProjectIdentity ExpectedTarget { get; }
    public BootstrapSystemProjectAllowlist SystemProjectAllowlist { get; }
    public BootstrapTrustBundleRotation TrustBundle { get; }
    public DateTimeOffset Now { get; }
    public TimeSpan MaximumLifetime { get; }
}

public sealed record BootstrapGrantVerificationInput
{
    public BootstrapGrantVerificationInput(
        BootstrapGrant grant,
        BootstrapGrantVerificationContext context,
        BootstrapGrantSignatureEvidence? signatureEvidence,
        IBootstrapGrantReplayConsumer? replayConsumer)
    {
        Grant = grant ?? throw new ArgumentNullException(nameof(grant));
        Context = context ?? throw new ArgumentNullException(nameof(context));
        SignatureEvidence = signatureEvidence;
        ReplayConsumer = replayConsumer;
    }

    public BootstrapGrant Grant { get; }
    public BootstrapGrantVerificationContext Context { get; }
    public BootstrapGrantSignatureEvidence? SignatureEvidence { get; }
    public IBootstrapGrantReplayConsumer? ReplayConsumer { get; }
}

public sealed record BootstrapGrantAuditFacts
{
    internal BootstrapGrantAuditFacts(
        BootstrapGrantDecisionCode code,
        BootstrapOperation? operation,
        BootstrapTrustBundleKeyId? trustBundleKeyId,
        ulong? trustBundleVersion,
        bool targetAllowlisted,
        bool customerProjectDenied,
        bool audienceMatched,
        bool certificateMatched,
        bool timeWindowValid,
        BootstrapGrantSignatureStatus signatureStatus,
        BootstrapReplayAuditOutcome replayOutcome)
    {
        Code = code;
        Operation = operation;
        TrustBundleKeyId = trustBundleKeyId?.Value;
        TrustBundleVersion = trustBundleVersion;
        TargetAllowlisted = targetAllowlisted;
        CustomerProjectDenied = customerProjectDenied;
        AudienceMatched = audienceMatched;
        CertificateMatched = certificateMatched;
        TimeWindowValid = timeWindowValid;
        SignatureStatus = signatureStatus;
        ReplayOutcome = replayOutcome;
    }

    public BootstrapGrantDecisionCode Code { get; init; }
    public BootstrapOperation? Operation { get; init; }
    public string? TrustBundleKeyId { get; init; }
    public ulong? TrustBundleVersion { get; init; }
    public bool TargetAllowlisted { get; init; }
    public bool CustomerProjectDenied { get; init; }
    public bool AudienceMatched { get; init; }
    public bool CertificateMatched { get; init; }
    public bool TimeWindowValid { get; init; }
    public BootstrapGrantSignatureStatus SignatureStatus { get; init; }
    public BootstrapReplayAuditOutcome ReplayOutcome { get; init; }
}

public sealed record BootstrapGrantVerificationResult
{
    internal BootstrapGrantVerificationResult(bool authorized, BootstrapGrantDecisionCode code, BootstrapGrantAuditFacts audit)
    {
        Authorized = authorized;
        Code = code;
        Audit = audit ?? throw new ArgumentNullException(nameof(audit));
    }

    public bool Authorized { get; }
    public BootstrapGrantDecisionCode Code { get; }
    public BootstrapGrantAuditFacts Audit { get; }
}
