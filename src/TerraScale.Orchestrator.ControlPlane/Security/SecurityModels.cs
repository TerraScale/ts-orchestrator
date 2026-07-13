using System.Collections.ObjectModel;
using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.ControlPlane.Security;

internal static partial class SecurityIdentity
{
    public static string Token(string value, string name)
    {
        ArgumentNullException.ThrowIfNull(value, name);
        if (value.Length is < 1 or > 128 || !TokenPattern().IsMatch(value))
            throw new ArgumentException("Security identity must be a bounded canonical token.", name);
        return value;
    }

    public static string Digest(string value, string name)
    {
        ArgumentNullException.ThrowIfNull(value, name);
        if (value.Length != 64 || value.Any(c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new ArgumentException("Digest must be canonical SHA-256.", name);
        return value;
    }

    [GeneratedRegex("^[a-z0-9][a-z0-9]*(?:[.-][a-z0-9]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex TokenPattern();
}

public abstract record SecurityToken
{
    internal SecurityToken(string value, string name) => Value = SecurityIdentity.Token(value, name);
    public string Value { get; }
    public sealed override string ToString() => Value;
}

public sealed record SecurityCellId : SecurityToken { public SecurityCellId(string value) : base(value, nameof(value)) { } }
public sealed record SecurityNodeId : SecurityToken { public SecurityNodeId(string value) : base(value, nameof(value)) { } }
public sealed record SecurityWorkloadId : SecurityToken { public SecurityWorkloadId(string value) : base(value, nameof(value)) { } }
public sealed record SecurityPrincipalId : SecurityToken { public SecurityPrincipalId(string value) : base(value, nameof(value)) { } }
public sealed record SecurityIssuerId : SecurityToken { public SecurityIssuerId(string value) : base(value, nameof(value)) { } }
public sealed record SecurityKeyId : SecurityToken { public SecurityKeyId(string value) : base(value, nameof(value)) { } }
public sealed record SecurityCertificateId : SecurityToken { public SecurityCertificateId(string value) : base(value, nameof(value)) { } }
public sealed record SecuritySecretId : SecurityToken { public SecuritySecretId(string value) : base(value, nameof(value)) { } }
public sealed record SecurityLeaseId : SecurityToken { public SecurityLeaseId(string value) : base(value, nameof(value)) { } }
public sealed record SecurityOperationId : SecurityToken { public SecurityOperationId(string value) : base(value, nameof(value)) { } }
public sealed record SecurityAttestationId : SecurityToken { public SecurityAttestationId(string value) : base(value, nameof(value)) { } }
public sealed record SecurityBootstrapId : SecurityToken { public SecurityBootstrapId(string value) : base(value, nameof(value)) { } }

public abstract record PositiveSecurityNumber
{
    internal PositiveSecurityNumber(ulong value, string name) => Value = value > 0 ? value : throw new ArgumentOutOfRangeException(name);
    public ulong Value { get; }
}
public sealed record SecurityEpoch : PositiveSecurityNumber { public SecurityEpoch(ulong value) : base(value, nameof(value)) { } }
public sealed record SecurityGeneration : PositiveSecurityNumber { public SecurityGeneration(ulong value) : base(value, nameof(value)) { } }
public sealed record SecuritySequence : PositiveSecurityNumber { public SecuritySequence(ulong value) : base(value, nameof(value)) { } }
public sealed record SecretVersion : PositiveSecurityNumber { public SecretVersion(ulong value) : base(value, nameof(value)) { } }
public sealed record SecurityDurationSeconds : PositiveSecurityNumber { public SecurityDurationSeconds(ulong value) : base(value, nameof(value)) { } }

public sealed record SecurityDigest
{
    public SecurityDigest(string sha256) => Sha256 = SecurityIdentity.Digest(sha256, nameof(sha256));
    public string Sha256 { get; }
}

public enum SecurityPrincipalKind { Node = 1, Workload = 2, Operator = 3, Controller = 4, CiWorker = 5, Service = 6 }
public enum SecurityRole { Agent = 1, RegionalController = 2, NatsServer = 3, TerraBase = 4, TelemetryForwarder = 5, Operator = 6, TrustedCi = 7, UntrustedCi = 8, WorkloadService = 9 }
public enum CertificateUsage { NodeTransport = 1, WorkloadTransport = 2, NatsServer = 3, NatsRoute = 4, NatsGateway = 5, TerraBase = 6, Telemetry = 7, OperatorClient = 8 }
public enum TrustScope { Cell = 1, GlobalAdministration = 2 }
public enum IssuerCapabilityKind { RegionalIntermediate = 1, GlobalAdministrativeIntermediate = 2 }
public enum EvidenceStatus { Valid = 1, Stale = 2, Consumed = 3, Missing = 4, Conflicting = 5, Unknown = 6 }
public enum RevocationStatus { Current = 1, Revoked = 2, Unknown = 3 }
public enum ValidityStatus { Valid = 1, RenewalDue = 2, Expired = 3, Unknown = 4 }
public enum CertificateAction { Issue = 1, Renew = 2, Rotate = 3, Revoke = 4 }
public enum AuthorizationCapability { EnrollNode = 1, EnrollWorkload = 2, IssueCellIdentity = 3, RenewIdentity = 4, RevokeIdentity = 5, ReadEncryptedSecret = 6, GrantSecretLease = 7, RenewOwnLease = 8, RevokeLease = 9, AdministerGlobalTrust = 10 }
public enum SecurityResourceKind { Enrollment = 1, Certificate = 2, TrustBundle = 3, EncryptedSecret = 4, SecretLease = 5 }
public enum SecurityEnvironment { Development = 1, Staging = 2, Production = 3, Recovery = 4 }
public enum SecretPurpose { Database = 1, Messaging = 2, Telemetry = 3, Deployment = 4, OperatorAccess = 5, Recovery = 6 }
public enum SecretAvailability { Available = 1, Missing = 2, Conflicting = 3, Unknown = 4 }
public enum LeaseAction { Grant = 1, Renew = 2, Revoke = 3 }
public enum LeaseStatus { Active = 1, Revoked = 2, Unknown = 3 }

internal static class SecurityEnums
{
    public static T Defined<T>(T value, string name) where T : struct, Enum =>
        Enum.IsDefined(value) ? value : throw new ArgumentOutOfRangeException(name);

    public static IReadOnlyList<T> CopyDistinct<T>(IEnumerable<T> source, string name) where T : struct, Enum
    {
        ArgumentNullException.ThrowIfNull(source, name);
        var values = source.ToArray();
        if (values.Any(v => !Enum.IsDefined(v))) throw new ArgumentOutOfRangeException(name);
        if (values.Length != values.Distinct().Count()) throw new ArgumentException("Duplicate catalog values are invalid.", name);
        return new ReadOnlyCollection<T>(values.Order().ToArray());
    }
}

public sealed record SecurityPrincipal
{
    public SecurityPrincipal(SecurityPrincipalId id, SecurityPrincipalKind kind, SecurityRole role, SecurityCellId cellId, SecurityGeneration generation)
    {
        Id = id ?? throw new ArgumentNullException(nameof(id));
        Kind = SecurityEnums.Defined(kind, nameof(kind));
        Role = SecurityEnums.Defined(role, nameof(role));
        CellId = cellId ?? throw new ArgumentNullException(nameof(cellId));
        Generation = generation ?? throw new ArgumentNullException(nameof(generation));
    }
    public SecurityPrincipalId Id { get; }
    public SecurityPrincipalKind Kind { get; }
    public SecurityRole Role { get; }
    public SecurityCellId CellId { get; }
    public SecurityGeneration Generation { get; }
}

public sealed record IssuerSigningCapability
{
    public IssuerSigningCapability(SecurityIssuerId issuerId, IssuerCapabilityKind kind, SecurityCellId cellId, TrustScope scope, SecurityGeneration generation, SecurityGeneration revocationGeneration)
    {
        IssuerId = issuerId ?? throw new ArgumentNullException(nameof(issuerId));
        Kind = SecurityEnums.Defined(kind, nameof(kind));
        CellId = cellId ?? throw new ArgumentNullException(nameof(cellId));
        Scope = SecurityEnums.Defined(scope, nameof(scope));
        Generation = generation ?? throw new ArgumentNullException(nameof(generation));
        RevocationGeneration = revocationGeneration ?? throw new ArgumentNullException(nameof(revocationGeneration));
        if (kind == IssuerCapabilityKind.RegionalIntermediate && scope != TrustScope.Cell)
            throw new ArgumentException("Regional issuers are cell scoped.", nameof(scope));
    }
    public SecurityIssuerId IssuerId { get; }
    public IssuerCapabilityKind Kind { get; }
    public SecurityCellId CellId { get; }
    public TrustScope Scope { get; }
    public SecurityGeneration Generation { get; }
    public SecurityGeneration RevocationGeneration { get; }
}

public sealed record BootstrapEnrollmentEvidence
{
    public BootstrapEnrollmentEvidence(SecurityBootstrapId id, SecurityOperationId operationId, SecurityPrincipalId principalId, SecurityPrincipalKind audience, SecurityCellId cellId, SecurityRole role, SecurityGeneration nodeGeneration, EvidenceStatus status)
    {
        Id = id ?? throw new ArgumentNullException(nameof(id));
        OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId));
        PrincipalId = principalId ?? throw new ArgumentNullException(nameof(principalId));
        Audience = SecurityEnums.Defined(audience, nameof(audience));
        CellId = cellId ?? throw new ArgumentNullException(nameof(cellId));
        Role = SecurityEnums.Defined(role, nameof(role));
        NodeGeneration = nodeGeneration ?? throw new ArgumentNullException(nameof(nodeGeneration));
        Status = SecurityEnums.Defined(status, nameof(status));
    }
    public SecurityBootstrapId Id { get; }
    public SecurityOperationId OperationId { get; }
    public SecurityPrincipalId PrincipalId { get; }
    public SecurityPrincipalKind Audience { get; }
    public SecurityCellId CellId { get; }
    public SecurityRole Role { get; }
    public SecurityGeneration NodeGeneration { get; }
    public EvidenceStatus Status { get; }
}

public sealed record SecurityAttestationEvidence
{
    public SecurityAttestationEvidence(SecurityAttestationId id, SecurityDigest measurement, SecurityPrincipalId principalId, SecurityPrincipalKind kind, SecurityCellId cellId, SecurityRole role, SecurityGeneration generation, SecurityGeneration policyGeneration, EvidenceStatus status)
    {
        Id = id ?? throw new ArgumentNullException(nameof(id));
        Measurement = measurement ?? throw new ArgumentNullException(nameof(measurement));
        PrincipalId = principalId ?? throw new ArgumentNullException(nameof(principalId));
        Kind = SecurityEnums.Defined(kind, nameof(kind));
        CellId = cellId ?? throw new ArgumentNullException(nameof(cellId));
        Role = SecurityEnums.Defined(role, nameof(role));
        Generation = generation ?? throw new ArgumentNullException(nameof(generation));
        PolicyGeneration = policyGeneration ?? throw new ArgumentNullException(nameof(policyGeneration));
        Status = SecurityEnums.Defined(status, nameof(status));
    }
    public SecurityAttestationId Id { get; }
    public SecurityDigest Measurement { get; }
    public SecurityPrincipalId PrincipalId { get; }
    public SecurityPrincipalKind Kind { get; }
    public SecurityCellId CellId { get; }
    public SecurityRole Role { get; }
    public SecurityGeneration Generation { get; }
    public SecurityGeneration PolicyGeneration { get; }
    public EvidenceStatus Status { get; }
}

public sealed record EnrollmentRequest
{
    public EnrollmentRequest(SecurityOperationId operationId, SecurityPrincipal expectedPrincipal, SecurityKeyId subjectKeyId, SecurityGeneration attestationPolicyGeneration, IssuerSigningCapability issuer, SecurityGeneration currentIssuerGeneration, SecurityGeneration currentRevocationGeneration, IEnumerable<BootstrapEnrollmentEvidence> bootstrapEvidence, IEnumerable<SecurityAttestationEvidence> attestations)
    {
        OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId));
        ExpectedPrincipal = expectedPrincipal ?? throw new ArgumentNullException(nameof(expectedPrincipal));
        SubjectKeyId = subjectKeyId ?? throw new ArgumentNullException(nameof(subjectKeyId));
        AttestationPolicyGeneration = attestationPolicyGeneration ?? throw new ArgumentNullException(nameof(attestationPolicyGeneration));
        Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        CurrentIssuerGeneration = currentIssuerGeneration ?? throw new ArgumentNullException(nameof(currentIssuerGeneration));
        CurrentRevocationGeneration = currentRevocationGeneration ?? throw new ArgumentNullException(nameof(currentRevocationGeneration));
        BootstrapEvidence = Copy(bootstrapEvidence, nameof(bootstrapEvidence));
        Attestations = Copy(attestations, nameof(attestations));
    }
    public SecurityOperationId OperationId { get; }
    public SecurityPrincipal ExpectedPrincipal { get; }
    public SecurityKeyId SubjectKeyId { get; }
    public SecurityGeneration AttestationPolicyGeneration { get; }
    public IssuerSigningCapability Issuer { get; }
    public SecurityGeneration CurrentIssuerGeneration { get; }
    public SecurityGeneration CurrentRevocationGeneration { get; }
    public IReadOnlyList<BootstrapEnrollmentEvidence> BootstrapEvidence { get; }
    public IReadOnlyList<SecurityAttestationEvidence> Attestations { get; }
    internal static IReadOnlyList<T> Copy<T>(IEnumerable<T> source, string name) where T : notnull
    {
        ArgumentNullException.ThrowIfNull(source, name);
        var values = source.ToArray();
        if (values.Any(v => v is null)) throw new ArgumentException("Null evidence is invalid.", name);
        return new ReadOnlyCollection<T>(values);
    }
}

public sealed record CertificateLifecyclePolicy
{
    public CertificateLifecyclePolicy(SecurityGeneration generation, SecurityDurationSeconds lifetime, SecurityDurationSeconds renewalWindow, SecurityDurationSeconds overlap, IEnumerable<CertificateUsage> usages, TrustScope scope)
    {
        Generation = generation ?? throw new ArgumentNullException(nameof(generation));
        Lifetime = lifetime ?? throw new ArgumentNullException(nameof(lifetime));
        RenewalWindow = renewalWindow ?? throw new ArgumentNullException(nameof(renewalWindow));
        Overlap = overlap ?? throw new ArgumentNullException(nameof(overlap));
        if (renewalWindow.Value >= lifetime.Value || overlap.Value >= lifetime.Value) throw new ArgumentException("Renewal and overlap must be shorter than lifetime.");
        Usages = SecurityEnums.CopyDistinct(usages, nameof(usages));
        Scope = SecurityEnums.Defined(scope, nameof(scope));
    }
    public SecurityGeneration Generation { get; }
    public SecurityDurationSeconds Lifetime { get; }
    public SecurityDurationSeconds RenewalWindow { get; }
    public SecurityDurationSeconds Overlap { get; }
    public IReadOnlyList<CertificateUsage> Usages { get; }
    public TrustScope Scope { get; }
}

public sealed record CertificateValidityEvidence
{
    public CertificateValidityEvidence(SecurityCertificateId certificateId, SecurityOperationId operationId, SecurityPrincipalId principalId, SecurityCellId cellId, SecurityKeyId subjectKeyId, CertificateUsage usage, TrustScope scope, SecurityIssuerId issuerId, SecurityGeneration issuerGeneration, SecurityGeneration certificateGeneration, SecurityGeneration policyGeneration, SecurityGeneration revocationGeneration, ValidityStatus validity, RevocationStatus revocation)
    {
        CertificateId = certificateId ?? throw new ArgumentNullException(nameof(certificateId));
        OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId));
        PrincipalId = principalId ?? throw new ArgumentNullException(nameof(principalId));
        CellId = cellId ?? throw new ArgumentNullException(nameof(cellId));
        SubjectKeyId = subjectKeyId ?? throw new ArgumentNullException(nameof(subjectKeyId));
        Usage = SecurityEnums.Defined(usage, nameof(usage));
        Scope = SecurityEnums.Defined(scope, nameof(scope));
        IssuerId = issuerId ?? throw new ArgumentNullException(nameof(issuerId));
        IssuerGeneration = issuerGeneration ?? throw new ArgumentNullException(nameof(issuerGeneration));
        CertificateGeneration = certificateGeneration ?? throw new ArgumentNullException(nameof(certificateGeneration));
        PolicyGeneration = policyGeneration ?? throw new ArgumentNullException(nameof(policyGeneration));
        RevocationGeneration = revocationGeneration ?? throw new ArgumentNullException(nameof(revocationGeneration));
        Validity = SecurityEnums.Defined(validity, nameof(validity));
        Revocation = SecurityEnums.Defined(revocation, nameof(revocation));
    }
    public SecurityCertificateId CertificateId { get; }
    public SecurityOperationId OperationId { get; }
    public SecurityPrincipalId PrincipalId { get; }
    public SecurityCellId CellId { get; }
    public SecurityKeyId SubjectKeyId { get; }
    public CertificateUsage Usage { get; }
    public TrustScope Scope { get; }
    public SecurityIssuerId IssuerId { get; }
    public SecurityGeneration IssuerGeneration { get; }
    public SecurityGeneration CertificateGeneration { get; }
    public SecurityGeneration PolicyGeneration { get; }
    public SecurityGeneration RevocationGeneration { get; }
    public ValidityStatus Validity { get; }
    public RevocationStatus Revocation { get; }
}

public sealed record CertificateCompromiseEvidence
{
    public CertificateCompromiseEvidence(SecurityCertificateId certificateId, SecurityPrincipalId principalId, SecurityCellId cellId, SecurityGeneration certificateGeneration, SecurityGeneration revocationGeneration, EvidenceStatus status)
    {
        CertificateId = certificateId ?? throw new ArgumentNullException(nameof(certificateId));
        PrincipalId = principalId ?? throw new ArgumentNullException(nameof(principalId));
        CellId = cellId ?? throw new ArgumentNullException(nameof(cellId));
        CertificateGeneration = certificateGeneration ?? throw new ArgumentNullException(nameof(certificateGeneration));
        RevocationGeneration = revocationGeneration ?? throw new ArgumentNullException(nameof(revocationGeneration));
        Status = SecurityEnums.Defined(status, nameof(status));
    }
    public SecurityCertificateId CertificateId { get; }
    public SecurityPrincipalId PrincipalId { get; }
    public SecurityCellId CellId { get; }
    public SecurityGeneration CertificateGeneration { get; }
    public SecurityGeneration RevocationGeneration { get; }
    public EvidenceStatus Status { get; }
}

public sealed record CertificateLifecycleRequest
{
    public CertificateLifecycleRequest(CertificateAction action, SecurityOperationId operationId, SecurityPrincipal principal, SecurityGeneration currentPrincipalGeneration, SecurityKeyId subjectKeyId, CertificateUsage usage, TrustScope requestedScope, SecurityGeneration requestedGeneration, IssuerSigningCapability issuer, SecurityGeneration currentIssuerGeneration, CertificateLifecyclePolicy policy, CertificateValidityEvidence validityEvidence, SecurityGeneration currentRevocationGeneration, CertificateCompromiseEvidence compromiseEvidence)
    {
        Action = SecurityEnums.Defined(action, nameof(action));
        OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId));
        Principal = principal ?? throw new ArgumentNullException(nameof(principal));
        CurrentPrincipalGeneration = currentPrincipalGeneration ?? throw new ArgumentNullException(nameof(currentPrincipalGeneration));
        SubjectKeyId = subjectKeyId ?? throw new ArgumentNullException(nameof(subjectKeyId));
        Usage = SecurityEnums.Defined(usage, nameof(usage));
        RequestedScope = SecurityEnums.Defined(requestedScope, nameof(requestedScope));
        RequestedGeneration = requestedGeneration ?? throw new ArgumentNullException(nameof(requestedGeneration));
        Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        CurrentIssuerGeneration = currentIssuerGeneration ?? throw new ArgumentNullException(nameof(currentIssuerGeneration));
        Policy = policy ?? throw new ArgumentNullException(nameof(policy));
        ValidityEvidence = validityEvidence ?? throw new ArgumentNullException(nameof(validityEvidence));
        CurrentRevocationGeneration = currentRevocationGeneration ?? throw new ArgumentNullException(nameof(currentRevocationGeneration));
        CompromiseEvidence = compromiseEvidence ?? throw new ArgumentNullException(nameof(compromiseEvidence));
    }
    public CertificateAction Action { get; }
    public SecurityOperationId OperationId { get; }
    public SecurityPrincipal Principal { get; }
    public SecurityGeneration CurrentPrincipalGeneration { get; }
    public SecurityKeyId SubjectKeyId { get; }
    public CertificateUsage Usage { get; }
    public TrustScope RequestedScope { get; }
    public SecurityGeneration RequestedGeneration { get; }
    public IssuerSigningCapability Issuer { get; }
    public SecurityGeneration CurrentIssuerGeneration { get; }
    public CertificateLifecyclePolicy Policy { get; }
    public CertificateValidityEvidence ValidityEvidence { get; }
    public SecurityGeneration CurrentRevocationGeneration { get; }
    public CertificateCompromiseEvidence CompromiseEvidence { get; }
}

public sealed record SecurityResourceScope
{
    public SecurityResourceScope(SecurityResourceKind kind, SecurityCellId cellId, SecurityEnvironment environment, SecretPurpose? purpose)
    {
        Kind = SecurityEnums.Defined(kind, nameof(kind));
        CellId = cellId ?? throw new ArgumentNullException(nameof(cellId));
        Environment = SecurityEnums.Defined(environment, nameof(environment));
        if (purpose is not null && !Enum.IsDefined(purpose.Value)) throw new ArgumentOutOfRangeException(nameof(purpose));
        if ((kind is SecurityResourceKind.EncryptedSecret or SecurityResourceKind.SecretLease) != (purpose is not null))
            throw new ArgumentException("Secret resources require an exact purpose and other resources forbid it.", nameof(purpose));
        Purpose = purpose;
    }
    public SecurityResourceKind Kind { get; }
    public SecurityCellId CellId { get; }
    public SecurityEnvironment Environment { get; }
    public SecretPurpose? Purpose { get; }
}

public sealed record PrincipalAuthorizationEvidence
{
    public PrincipalAuthorizationEvidence(SecurityPrincipal principal, SecurityGeneration revocationGeneration, RevocationStatus revocation, EvidenceStatus status)
    {
        Principal = principal ?? throw new ArgumentNullException(nameof(principal));
        RevocationGeneration = revocationGeneration ?? throw new ArgumentNullException(nameof(revocationGeneration));
        Revocation = SecurityEnums.Defined(revocation, nameof(revocation));
        Status = SecurityEnums.Defined(status, nameof(status));
    }
    public SecurityPrincipal Principal { get; }
    public SecurityGeneration RevocationGeneration { get; }
    public RevocationStatus Revocation { get; }
    public EvidenceStatus Status { get; }
}

public sealed record AuthorizationGrant
{
    public AuthorizationGrant(SecurityGeneration policyGeneration, SecurityPrincipalKind principalKind, SecurityRole role, AuthorizationCapability capability, SecurityResourceScope resourceScope)
    {
        PolicyGeneration = policyGeneration ?? throw new ArgumentNullException(nameof(policyGeneration));
        PrincipalKind = SecurityEnums.Defined(principalKind, nameof(principalKind));
        Role = SecurityEnums.Defined(role, nameof(role));
        Capability = SecurityEnums.Defined(capability, nameof(capability));
        ResourceScope = resourceScope ?? throw new ArgumentNullException(nameof(resourceScope));
    }
    public SecurityGeneration PolicyGeneration { get; }
    public SecurityPrincipalKind PrincipalKind { get; }
    public SecurityRole Role { get; }
    public AuthorizationCapability Capability { get; }
    public SecurityResourceScope ResourceScope { get; }
}

public sealed record AuthorizationRequest
{
    public AuthorizationRequest(SecurityOperationId operationId, SecurityPrincipalId principalId, SecurityGeneration expectedPrincipalGeneration, SecurityGeneration currentPrincipalGeneration, AuthorizationCapability capability, SecurityResourceScope resourceScope, SecurityGeneration policyGeneration, SecurityGeneration currentPolicyGeneration, SecurityGeneration currentRevocationGeneration, IEnumerable<PrincipalAuthorizationEvidence> principalEvidence, IEnumerable<AuthorizationGrant> grants, EvidenceStatus evidenceCompleteness)
    {
        OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId));
        PrincipalId = principalId ?? throw new ArgumentNullException(nameof(principalId));
        ExpectedPrincipalGeneration = expectedPrincipalGeneration ?? throw new ArgumentNullException(nameof(expectedPrincipalGeneration));
        CurrentPrincipalGeneration = currentPrincipalGeneration ?? throw new ArgumentNullException(nameof(currentPrincipalGeneration));
        Capability = SecurityEnums.Defined(capability, nameof(capability));
        ResourceScope = resourceScope ?? throw new ArgumentNullException(nameof(resourceScope));
        PolicyGeneration = policyGeneration ?? throw new ArgumentNullException(nameof(policyGeneration));
        CurrentPolicyGeneration = currentPolicyGeneration ?? throw new ArgumentNullException(nameof(currentPolicyGeneration));
        CurrentRevocationGeneration = currentRevocationGeneration ?? throw new ArgumentNullException(nameof(currentRevocationGeneration));
        PrincipalEvidence = EnrollmentRequest.Copy(principalEvidence, nameof(principalEvidence));
        Grants = EnrollmentRequest.Copy(grants, nameof(grants));
        EvidenceCompleteness = SecurityEnums.Defined(evidenceCompleteness, nameof(evidenceCompleteness));
    }
    public SecurityOperationId OperationId { get; }
    public SecurityPrincipalId PrincipalId { get; }
    public SecurityGeneration ExpectedPrincipalGeneration { get; }
    public SecurityGeneration CurrentPrincipalGeneration { get; }
    public AuthorizationCapability Capability { get; }
    public SecurityResourceScope ResourceScope { get; }
    public SecurityGeneration PolicyGeneration { get; }
    public SecurityGeneration CurrentPolicyGeneration { get; }
    public SecurityGeneration CurrentRevocationGeneration { get; }
    public IReadOnlyList<PrincipalAuthorizationEvidence> PrincipalEvidence { get; }
    public IReadOnlyList<AuthorizationGrant> Grants { get; }
    public EvidenceStatus EvidenceCompleteness { get; }
}

public sealed record EncryptedSecretMetadata
{
    public EncryptedSecretMetadata(SecuritySecretId secretId, SecretVersion version, SecurityCellId cellId, SecurityEnvironment environment, SecretPurpose purpose, SecurityKeyId wrappingKeyId, SecurityDigest ciphertextDigest, SecretAvailability availability)
    {
        SecretId = secretId ?? throw new ArgumentNullException(nameof(secretId));
        Version = version ?? throw new ArgumentNullException(nameof(version));
        CellId = cellId ?? throw new ArgumentNullException(nameof(cellId));
        Environment = SecurityEnums.Defined(environment, nameof(environment));
        Purpose = SecurityEnums.Defined(purpose, nameof(purpose));
        WrappingKeyId = wrappingKeyId ?? throw new ArgumentNullException(nameof(wrappingKeyId));
        CiphertextDigest = ciphertextDigest ?? throw new ArgumentNullException(nameof(ciphertextDigest));
        Availability = SecurityEnums.Defined(availability, nameof(availability));
    }
    public SecuritySecretId SecretId { get; }
    public SecretVersion Version { get; }
    public SecurityCellId CellId { get; }
    public SecurityEnvironment Environment { get; }
    public SecretPurpose Purpose { get; }
    public SecurityKeyId WrappingKeyId { get; }
    public SecurityDigest CiphertextDigest { get; }
    public SecretAvailability Availability { get; }
}

public sealed record SecretRetentionPolicy
{
    public SecretRetentionPolicy(SecurityGeneration generation, SecuritySecretId secretId, SecurityCellId cellId, SecurityEnvironment environment, SecretPurpose purpose, IEnumerable<SecretVersion> retainedVersions, SecurityDurationSeconds maximumLeaseDuration, EvidenceStatus expiryEvidence)
    {
        Generation = generation ?? throw new ArgumentNullException(nameof(generation));
        SecretId = secretId ?? throw new ArgumentNullException(nameof(secretId));
        CellId = cellId ?? throw new ArgumentNullException(nameof(cellId));
        Environment = SecurityEnums.Defined(environment, nameof(environment));
        Purpose = SecurityEnums.Defined(purpose, nameof(purpose));
        ArgumentNullException.ThrowIfNull(retainedVersions);
        var versions = retainedVersions.ToArray();
        if (versions.Any(v => v is null)) throw new ArgumentException("Null secret version.", nameof(retainedVersions));
        if (versions.Length == 0 || versions.Length != versions.Distinct().Count()) throw new ArgumentException("Retention versions must be non-empty and unique.", nameof(retainedVersions));
        RetainedVersions = new ReadOnlyCollection<SecretVersion>(versions.OrderBy(v => v.Value).ToArray());
        MaximumLeaseDuration = maximumLeaseDuration ?? throw new ArgumentNullException(nameof(maximumLeaseDuration));
        ExpiryEvidence = SecurityEnums.Defined(expiryEvidence, nameof(expiryEvidence));
    }
    public SecurityGeneration Generation { get; }
    public SecuritySecretId SecretId { get; }
    public SecurityCellId CellId { get; }
    public SecurityEnvironment Environment { get; }
    public SecretPurpose Purpose { get; }
    public IReadOnlyList<SecretVersion> RetainedVersions { get; }
    public SecurityDurationSeconds MaximumLeaseDuration { get; }
    public EvidenceStatus ExpiryEvidence { get; }
}

public sealed record SecretLeaseEvidence
{
    public SecretLeaseEvidence(SecurityLeaseId leaseId, SecurityPrincipalId principalId, SecuritySecretId secretId, SecretVersion version, SecurityCellId cellId, SecurityEnvironment environment, SecretPurpose purpose, SecurityKeyId wrappingKeyId, SecurityDigest ciphertextDigest, SecurityGeneration generation, SecurityGeneration policyGeneration, LeaseStatus status, ValidityStatus validity)
    {
        LeaseId = leaseId ?? throw new ArgumentNullException(nameof(leaseId));
        PrincipalId = principalId ?? throw new ArgumentNullException(nameof(principalId));
        SecretId = secretId ?? throw new ArgumentNullException(nameof(secretId));
        Version = version ?? throw new ArgumentNullException(nameof(version));
        CellId = cellId ?? throw new ArgumentNullException(nameof(cellId));
        Environment = SecurityEnums.Defined(environment, nameof(environment));
        Purpose = SecurityEnums.Defined(purpose, nameof(purpose));
        WrappingKeyId = wrappingKeyId ?? throw new ArgumentNullException(nameof(wrappingKeyId));
        CiphertextDigest = ciphertextDigest ?? throw new ArgumentNullException(nameof(ciphertextDigest));
        Generation = generation ?? throw new ArgumentNullException(nameof(generation));
        PolicyGeneration = policyGeneration ?? throw new ArgumentNullException(nameof(policyGeneration));
        Status = SecurityEnums.Defined(status, nameof(status));
        Validity = SecurityEnums.Defined(validity, nameof(validity));
    }
    public SecurityLeaseId LeaseId { get; }
    public SecurityPrincipalId PrincipalId { get; }
    public SecuritySecretId SecretId { get; }
    public SecretVersion Version { get; }
    public SecurityCellId CellId { get; }
    public SecurityEnvironment Environment { get; }
    public SecretPurpose Purpose { get; }
    public SecurityKeyId WrappingKeyId { get; }
    public SecurityDigest CiphertextDigest { get; }
    public SecurityGeneration Generation { get; }
    public SecurityGeneration PolicyGeneration { get; }
    public LeaseStatus Status { get; }
    public ValidityStatus Validity { get; }
}

public sealed record SecretLeaseRequest
{
    public SecretLeaseRequest(LeaseAction action, SecurityOperationId operationId, SecurityLeaseId requestedLeaseId, PrincipalAuthorizationEvidence principalEvidence, SecurityGeneration expectedPrincipalGeneration, SecurityGeneration currentPrincipalGeneration, EncryptedSecretMetadata secret, SecretRetentionPolicy policy, SecurityGeneration currentPolicyGeneration, IEnumerable<AuthorizationGrant> grants, SecurityGeneration requestedLeaseGeneration, SecurityDurationSeconds requestedDuration, SecurityGeneration currentRevocationGeneration, SecretLeaseEvidence? existingLease)
    {
        Action = SecurityEnums.Defined(action, nameof(action));
        OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId));
        RequestedLeaseId = requestedLeaseId ?? throw new ArgumentNullException(nameof(requestedLeaseId));
        PrincipalEvidence = principalEvidence ?? throw new ArgumentNullException(nameof(principalEvidence));
        ExpectedPrincipalGeneration = expectedPrincipalGeneration ?? throw new ArgumentNullException(nameof(expectedPrincipalGeneration));
        CurrentPrincipalGeneration = currentPrincipalGeneration ?? throw new ArgumentNullException(nameof(currentPrincipalGeneration));
        Secret = secret ?? throw new ArgumentNullException(nameof(secret));
        Policy = policy ?? throw new ArgumentNullException(nameof(policy));
        CurrentPolicyGeneration = currentPolicyGeneration ?? throw new ArgumentNullException(nameof(currentPolicyGeneration));
        Grants = EnrollmentRequest.Copy(grants, nameof(grants));
        RequestedLeaseGeneration = requestedLeaseGeneration ?? throw new ArgumentNullException(nameof(requestedLeaseGeneration));
        RequestedDuration = requestedDuration ?? throw new ArgumentNullException(nameof(requestedDuration));
        CurrentRevocationGeneration = currentRevocationGeneration ?? throw new ArgumentNullException(nameof(currentRevocationGeneration));
        ExistingLease = existingLease;
        if ((action == LeaseAction.Grant) == (existingLease is not null))
            throw new ArgumentException("Grant forbids an existing lease; renew/revoke require one.", nameof(existingLease));
    }
    public LeaseAction Action { get; }
    public SecurityOperationId OperationId { get; }
    public SecurityLeaseId RequestedLeaseId { get; }
    public PrincipalAuthorizationEvidence PrincipalEvidence { get; }
    public SecurityGeneration ExpectedPrincipalGeneration { get; }
    public SecurityGeneration CurrentPrincipalGeneration { get; }
    public EncryptedSecretMetadata Secret { get; }
    public SecretRetentionPolicy Policy { get; }
    public SecurityGeneration CurrentPolicyGeneration { get; }
    public IReadOnlyList<AuthorizationGrant> Grants { get; }
    public SecurityGeneration RequestedLeaseGeneration { get; }
    public SecurityDurationSeconds RequestedDuration { get; }
    public SecurityGeneration CurrentRevocationGeneration { get; }
    public SecretLeaseEvidence? ExistingLease { get; }
}

public sealed record SurvivalSecretReference
{
    public SurvivalSecretReference(SecuritySecretId secretId, SecretVersion version, SecurityCellId cellId, SecurityEnvironment environment, SecretPurpose purpose, SecurityDigest ciphertextDigest)
    {
        SecretId = secretId ?? throw new ArgumentNullException(nameof(secretId));
        Version = version ?? throw new ArgumentNullException(nameof(version));
        CellId = cellId ?? throw new ArgumentNullException(nameof(cellId));
        Environment = SecurityEnums.Defined(environment, nameof(environment));
        Purpose = SecurityEnums.Defined(purpose, nameof(purpose));
        CiphertextDigest = ciphertextDigest ?? throw new ArgumentNullException(nameof(ciphertextDigest));
    }
    public SecuritySecretId SecretId { get; }
    public SecretVersion Version { get; }
    public SecurityCellId CellId { get; }
    public SecurityEnvironment Environment { get; }
    public SecretPurpose Purpose { get; }
    public SecurityDigest CiphertextDigest { get; }
}

public sealed record SurvivalSecretRequest
{
    public SurvivalSecretRequest(SecurityOperationId operationId, SecurityCellId cellId, SecurityGeneration bundleGeneration, SecurityGeneration currentPolicyGeneration, IEnumerable<SurvivalSecretReference> references, IEnumerable<EncryptedSecretMetadata> availableVersions, IEnumerable<SecretRetentionPolicy> policies)
    {
        OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId));
        CellId = cellId ?? throw new ArgumentNullException(nameof(cellId));
        BundleGeneration = bundleGeneration ?? throw new ArgumentNullException(nameof(bundleGeneration));
        CurrentPolicyGeneration = currentPolicyGeneration ?? throw new ArgumentNullException(nameof(currentPolicyGeneration));
        References = new ReadOnlyCollection<SurvivalSecretReference>(EnrollmentRequest.Copy(references, nameof(references))
            .OrderBy(item => item.SecretId.Value, StringComparer.Ordinal).ThenBy(item => item.Version.Value).ToArray());
        AvailableVersions = new ReadOnlyCollection<EncryptedSecretMetadata>(EnrollmentRequest.Copy(availableVersions, nameof(availableVersions))
            .OrderBy(item => item.SecretId.Value, StringComparer.Ordinal).ThenBy(item => item.Version.Value).ToArray());
        Policies = new ReadOnlyCollection<SecretRetentionPolicy>(EnrollmentRequest.Copy(policies, nameof(policies))
            .OrderBy(item => item.SecretId.Value, StringComparer.Ordinal).ThenBy(item => item.Generation.Value).ToArray());
    }
    public SecurityOperationId OperationId { get; }
    public SecurityCellId CellId { get; }
    public SecurityGeneration BundleGeneration { get; }
    public SecurityGeneration CurrentPolicyGeneration { get; }
    public IReadOnlyList<SurvivalSecretReference> References { get; }
    public IReadOnlyList<EncryptedSecretMetadata> AvailableVersions { get; }
    public IReadOnlyList<SecretRetentionPolicy> Policies { get; }
}

public enum SecurityDecisionCode
{
    EvidenceComplete = 1, EvidenceUnique = 2, EvidenceConsistent = 3, OperationMatches = 4,
    PrincipalMatches = 5, CellMatches = 6, RoleMatches = 7, GenerationCurrent = 8,
    AttestationCurrent = 9, BootstrapUnused = 10, IssuerScopeValid = 11, IssuerCurrent = 12,
    RevocationCurrent = 13, PolicyCurrent = 14, UsageAllowed = 15, ValidityAllowsAction = 16,
    CompromiseProven = 17, ExactGrantPresent = 18, PrivilegeBounded = 19,
    SecretMetadataExact = 20, SecretVersionRetained = 21, SecretAvailable = 22,
    LeaseExact = 23, LeaseValidityAllowsAction = 24, SurvivalReferencesExact = 25,
    ValidityEvidenceExact = 26,
}
public enum SecurityDecisionOutcome { Passed = 1, Rejected = 2, Held = 3, NotApplicable = 4 }
public sealed record SecurityDecisionReason
{
    internal SecurityDecisionReason(SecurityDecisionCode code, SecurityDecisionOutcome outcome, ulong observed, ulong required)
    { Code = code; Outcome = outcome; Observed = observed; Required = required; }
    public SecurityDecisionCode Code { get; }
    public SecurityDecisionOutcome Outcome { get; }
    public ulong Observed { get; }
    public ulong Required { get; }
}

public abstract record SecurityIntent { internal SecurityIntent(SecurityOperationId operationId) => OperationId = operationId; public SecurityOperationId OperationId { get; } }
public sealed record AttestIdentityIntent : SecurityIntent { internal AttestIdentityIntent(EnrollmentRequest request, SecurityAttestationId attestationId) : base(request.OperationId) { Request = request; AttestationId = attestationId; } public EnrollmentRequest Request { get; } public SecurityAttestationId AttestationId { get; } }
public sealed record IssueIdentityIntent : SecurityIntent { internal IssueIdentityIntent(EnrollmentRequest request) : base(request.OperationId) => Request = request; public EnrollmentRequest Request { get; } public SecurityPrincipal Principal => Request.ExpectedPrincipal; public IssuerSigningCapability Issuer => Request.Issuer; }
public sealed record IssueCertificateIntent : SecurityIntent { internal IssueCertificateIntent(CertificateLifecycleRequest request) : base(request.OperationId) => Request = request; public CertificateLifecycleRequest Request { get; } }
public sealed record RenewCertificateIntent : SecurityIntent { internal RenewCertificateIntent(CertificateLifecycleRequest request) : base(request.OperationId) => Request = request; public CertificateLifecycleRequest Request { get; } }
public sealed record RotateCertificateIntent : SecurityIntent { internal RotateCertificateIntent(CertificateLifecycleRequest request) : base(request.OperationId) => Request = request; public CertificateLifecycleRequest Request { get; } }
public sealed record RevokeCertificateIntent : SecurityIntent { internal RevokeCertificateIntent(CertificateLifecycleRequest request) : base(request.OperationId) => Request = request; public CertificateLifecycleRequest Request { get; } }
public sealed record AuthorizeCapabilityIntent : SecurityIntent { internal AuthorizeCapabilityIntent(AuthorizationRequest request) : base(request.OperationId) { Capability = request.Capability; ResourceScope = request.ResourceScope; PrincipalId = request.PrincipalId; } public AuthorizationCapability Capability { get; } public SecurityResourceScope ResourceScope { get; } public SecurityPrincipalId PrincipalId { get; } }
public sealed record GrantSecretLeaseIntent : SecurityIntent { internal GrantSecretLeaseIntent(SecretLeaseRequest request) : base(request.OperationId) => Request = request; public SecretLeaseRequest Request { get; } }
public sealed record RenewSecretLeaseIntent : SecurityIntent { internal RenewSecretLeaseIntent(SecretLeaseRequest request) : base(request.OperationId) => Request = request; public SecretLeaseRequest Request { get; } }
public sealed record RevokeSecretLeaseIntent : SecurityIntent { internal RevokeSecretLeaseIntent(SecretLeaseRequest request) : base(request.OperationId) => Request = request; public SecretLeaseRequest Request { get; } }
public sealed record AcceptSurvivalSecretReferencesIntent : SecurityIntent { internal AcceptSurvivalSecretReferencesIntent(SurvivalSecretRequest request) : base(request.OperationId) => Request = request; public SurvivalSecretRequest Request { get; } }
public sealed record HoldSecurityOperationIntent : SecurityIntent { internal HoldSecurityOperationIntent(SecurityOperationId operationId) : base(operationId) { } }

public sealed record SecurityDecision
{
    internal SecurityDecision(bool authorized, IReadOnlyList<SecurityDecisionReason> trace, SecurityIntent intent)
    { Authorized = authorized; Trace = trace; Intent = intent; }
    public bool Authorized { get; }
    public IReadOnlyList<SecurityDecisionReason> Trace { get; }
    public SecurityIntent Intent { get; }
}
