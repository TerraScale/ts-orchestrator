using System.Globalization;

namespace TerraScale.Orchestrator.Bootstrap;

/// <summary>
/// A canonical ULID identity value per ADR 0027: exactly 26 uppercase Crockford
/// base 32 characters. The bootstrap grant carries fixed system Organization,
/// Project, and database identities in this form.
/// </summary>
public sealed record BootstrapUlid
{
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    public BootstrapUlid(string value) =>
        Value = value.Length == 26 && value.All(Alphabet.Contains)
            ? value
            : throw new ArgumentException("A bootstrap ULID must be 26 uppercase Crockford base 32 characters.", nameof(value));

    public string Value { get; }

    public sealed override string ToString() => Value;
}

/// <summary>
/// The audience-bound workload certificate fingerprint: the lowercase SHA-256
/// hex digest of the bound X.509 certificate's SubjectPublicKeyInfo. Binding
/// the SPKI digest ties the grant to the exact workload key that must prove
/// possession during bootstrap.
/// </summary>
public sealed record BootstrapCertificateFingerprint
{
    public BootstrapCertificateFingerprint(string value) =>
        Value = BootstrapGrantCanonical.ValidateLowercaseHex(value, 64, nameof(value));

    public string Value { get; }

    public sealed override string ToString() => "[redacted]";
}

/// <summary>
/// Stable operation codes carried by a signed bootstrap grant. Persisted codes
/// are fixed strings; they are never derived from enum or source order. Only
/// the idempotent <c>ensure-*</c> set may appear in a grant.
/// </summary>
public static class BootstrapGrantOperation
{
    public const string EnsureSystemOrganization = "ensure-system-organization";
    public const string EnsureSystemProject = "ensure-system-project";
    public const string EnsureSystemDatabase = "ensure-system-database";
    public const string EnsureSystemProjectConfiguration = "ensure-system-project-configuration";

    /// <summary>A known non-idempotent sentinel used by tests to prove denial; it can never be admitted by a grant.</summary>
    public const string ReadCustomerProject = "read-customer-project";

    private static readonly string[] IdempotentOperations =
    [
        EnsureSystemDatabase,
        EnsureSystemOrganization,
        EnsureSystemProject,
        EnsureSystemProjectConfiguration,
    ];

    public static bool IsIdempotentBootstrapOperation(string code) => IdempotentOperations.Contains(code);
}

/// <summary>
/// Stable trust-bundle key purpose codes. Key purpose separation means a key
/// generated for one purpose is structurally unusable for another: the grant
/// signer refuses non-grant-signing keys and the verifier refuses grants whose
/// key resolves to any other purpose.
/// </summary>
public static class BootstrapKeyPurposeCodes
{
    public const string GrantSigning = "bootstrap-grant-signing-v1";
    public const string WorkloadAttestation = "bootstrap-workload-attestation-v1";

    public static bool IsKnown(string code) => code is GrantSigning or WorkloadAttestation;
}

/// <summary>The fixed system Project identities named by a bootstrap grant.</summary>
public sealed record BootstrapSystemProjectUlds
{
    public BootstrapSystemProjectUlds(BootstrapUlid organizationUlid, BootstrapUlid projectUlid, BootstrapUlid databaseUlid)
    {
        OrganizationUlid = organizationUlid ?? throw new ArgumentNullException(nameof(organizationUlid));
        ProjectUlid = projectUlid ?? throw new ArgumentNullException(nameof(projectUlid));
        DatabaseUlid = databaseUlid ?? throw new ArgumentNullException(nameof(databaseUlid));
    }

    public BootstrapUlid OrganizationUlid { get; }
    public BootstrapUlid ProjectUlid { get; }
    public BootstrapUlid DatabaseUlid { get; }
}

/// <summary>
/// The typed, canonically encodable cold-bootstrap grant payload. Everything
/// the verifier checks is signed: system Project ULIDs, audience, certificate
/// fingerprint, key identity and purpose, validity window, nonce, grant
/// identity, and the allowed idempotent operation list.
/// </summary>
public sealed record BootstrapGrantPayload
{
    public const string PayloadVersion = "terrascale-bootstrap-grant-v1";
    private const int FixedFieldCount = 13;
    private const int MaximumOperations = 16;

    public BootstrapGrantPayload(
        string grantId,
        string nonce,
        string keyId,
        ulong keyVersion,
        string keyPurposeCode,
        BootstrapSystemProjectUlds systemProject,
        string audience,
        BootstrapCertificateFingerprint certificateFingerprint,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        IReadOnlyList<string> allowedOperations)
    {
        GrantId = new BootstrapUlid(grantId);
        Nonce = BootstrapGrantCanonical.ValidateLowercaseHex(nonce, 64, nameof(nonce));
        KeyId = BootstrapGrantCanonical.ValidateToken(keyId, nameof(keyId));
        if (keyVersion == 0) throw new ArgumentOutOfRangeException(nameof(keyVersion), "A trust-bundle key version must be positive.");
        KeyVersion = keyVersion;
        if (!BootstrapKeyPurposeCodes.IsKnown(keyPurposeCode))
            throw new ArgumentException("A grant must name a known trust-bundle key purpose.", nameof(keyPurposeCode));
        KeyPurposeCode = keyPurposeCode;
        SystemProject = systemProject ?? throw new ArgumentNullException(nameof(systemProject));
        Audience = BootstrapGrantCanonical.ValidateToken(audience, nameof(audience));
        CertificateFingerprint = certificateFingerprint ?? throw new ArgumentNullException(nameof(certificateFingerprint));
        if (issuedAt == default || expiresAt == default) throw new ArgumentException("Grant timestamps must be explicit UTC instants.");
        if (expiresAt <= issuedAt) throw new ArgumentException("A grant must have a positive lifetime.", nameof(expiresAt));
        IssuedAt = issuedAt.ToUniversalTime();
        ExpiresAt = expiresAt.ToUniversalTime();
        AllowedOperations = ValidateOperations(allowedOperations);
    }

    public BootstrapUlid GrantId { get; }
    public string Nonce { get; }
    public string KeyId { get; }
    public ulong KeyVersion { get; }
    public string KeyPurposeCode { get; }
    public BootstrapSystemProjectUlds SystemProject { get; }
    public string Audience { get; }
    public BootstrapCertificateFingerprint CertificateFingerprint { get; }
    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }

    /// <summary>Distinct allowed operation codes in canonical ordinal order.</summary>
    public IReadOnlyList<string> AllowedOperations { get; }

    public string Encode() => BootstrapGrantCanonical.EncodeFields(
        [PayloadVersion, GrantId.Value, Nonce, KeyId, KeyVersion.ToString(CultureInfo.InvariantCulture), KeyPurposeCode,
            SystemProject.OrganizationUlid.Value, SystemProject.ProjectUlid.Value, SystemProject.DatabaseUlid.Value,
            Audience, CertificateFingerprint.Value,
            IssuedAt.UtcTicks.ToString(CultureInfo.InvariantCulture), ExpiresAt.UtcTicks.ToString(CultureInfo.InvariantCulture),
            AllowedOperations.Count.ToString(CultureInfo.InvariantCulture), .. AllowedOperations]);

    /// <summary>Strictly parses one canonical payload. Throws <see cref="FormatException"/> on any deviation.</summary>
    public static BootstrapGrantPayload Parse(string text)
    {
        ArgumentException.ThrowIfNullOrEmpty(text);
        var records = BootstrapGrantCanonical.Parse(text);
        if (records.Count < FixedFieldCount + 1) throw new FormatException("A bootstrap grant payload has a fixed minimum record count.");
        if (records[0] != PayloadVersion) throw new FormatException("The bootstrap grant payload version is unknown.");
        if (!ulong.TryParse(records[4], CultureInfo.InvariantCulture, out var keyVersion))
            throw new FormatException("The trust-bundle key version must be a decimal integer.");
        if (!long.TryParse(records[11], CultureInfo.InvariantCulture, out var issuedTicks) ||
            !long.TryParse(records[12], CultureInfo.InvariantCulture, out var expiresTicks))
            throw new FormatException("Grant timestamps must be decimal UTC ticks.");
        if (!int.TryParse(records[13], CultureInfo.InvariantCulture, out var operationCount) ||
            operationCount is < 1 or > MaximumOperations || records.Count != FixedFieldCount + 1 + operationCount)
            throw new FormatException("The allowed operation count must match the remaining records.");
        var operations = records.Skip(FixedFieldCount + 1).ToArray();
        if (operations.Distinct(StringComparer.Ordinal).Count() != operations.Length)
            throw new FormatException("Allowed operations must be distinct.");
        return new BootstrapGrantPayload(
            records[1], records[2], records[3], keyVersion, records[5],
            new BootstrapSystemProjectUlds(new BootstrapUlid(records[6]), new BootstrapUlid(records[7]), new BootstrapUlid(records[8])),
            records[9],
            new BootstrapCertificateFingerprint(records[10]),
            new DateTimeOffset(issuedTicks, TimeSpan.Zero),
            new DateTimeOffset(expiresTicks, TimeSpan.Zero),
            operations);
    }

    private static IReadOnlyList<string> ValidateOperations(IReadOnlyList<string> allowedOperations)
    {
        ArgumentNullException.ThrowIfNull(allowedOperations);
        var values = allowedOperations.ToArray();
        if (values.Length is < 1 or > MaximumOperations || values.Any(string.IsNullOrEmpty))
            throw new ArgumentException("A grant must allow between one and sixteen named operations.", nameof(allowedOperations));
        if (values.Distinct(StringComparer.Ordinal).Count() != values.Length)
            throw new ArgumentException("A grant cannot repeat an operation.", nameof(allowedOperations));
        Array.Sort(values, StringComparer.Ordinal);
        return values;
    }
}

