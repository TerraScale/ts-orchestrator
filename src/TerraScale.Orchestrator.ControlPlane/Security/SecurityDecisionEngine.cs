using System.Collections.ObjectModel;
using System.Globalization;

namespace TerraScale.Orchestrator.ControlPlane.Security;

public static class SecurityDecisionEngine
{
    public static SecurityDecision EvaluateEnrollment(EnrollmentRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var bootstrapGroups = request.BootstrapEvidence.GroupBy(e => e.Id.Value, StringComparer.Ordinal).ToArray();
        var attestationGroups = request.Attestations.GroupBy(e => e.Id.Value, StringComparer.Ordinal).ToArray();
        var duplicates = Duplicates(bootstrapGroups.Select(g => g.Count()).Concat(attestationGroups.Select(g => g.Count())));
        var conflicts = bootstrapGroups.Count(g => g.Select(BootstrapProjection).Distinct(StringComparer.Ordinal).Skip(1).Any()) +
                        attestationGroups.Count(g => g.Select(AttestationProjection).Distinct(StringComparer.Ordinal).Skip(1).Any());
        var bootstrap = request.BootstrapEvidence.Count == 1 ? request.BootstrapEvidence[0] : null;
        var attestation = request.Attestations.Count == 1 ? request.Attestations[0] : null;
        var complete = bootstrap is not null && attestation is not null;
        var trace = new List<SecurityDecisionReason>
        {
            Hold(SecurityDecisionCode.EvidenceComplete, complete, complete ? 2UL : 0UL, 2),
            Hold(SecurityDecisionCode.EvidenceUnique, duplicates == 0, checked((ulong)duplicates), 0),
            Hold(SecurityDecisionCode.EvidenceConsistent, conflicts == 0, checked((ulong)conflicts), 0),
        };
        if (trace.Any(r => r.Outcome == SecurityDecisionOutcome.Held)) return Deny(request.OperationId, trace);

        var principal = request.ExpectedPrincipal;
        var exactBootstrap = bootstrap!;
        var exactAttestation = attestation!;
        trace.Add(Reject(SecurityDecisionCode.OperationMatches, exactBootstrap.OperationId == request.OperationId, exactBootstrap.OperationId == request.OperationId ? 1UL : 0UL, 1));
        var principalMatches = exactBootstrap.PrincipalId == principal.Id && exactAttestation.PrincipalId == principal.Id &&
                               exactBootstrap.Audience == principal.Kind && exactAttestation.Kind == principal.Kind &&
                               principal.Kind is SecurityPrincipalKind.Node or SecurityPrincipalKind.Workload;
        trace.Add(Reject(SecurityDecisionCode.PrincipalMatches, principalMatches, principalMatches ? 1UL : 0UL, 1));
        var cellMatches = exactBootstrap.CellId == principal.CellId && exactAttestation.CellId == principal.CellId && request.Issuer.CellId == principal.CellId;
        trace.Add(Reject(SecurityDecisionCode.CellMatches, cellMatches, cellMatches ? 1UL : 0UL, 1));
        var roleMatches = exactBootstrap.Role == principal.Role && exactAttestation.Role == principal.Role;
        trace.Add(Reject(SecurityDecisionCode.RoleMatches, roleMatches, roleMatches ? 1UL : 0UL, 1));
        var generationMatches = exactBootstrap.NodeGeneration == principal.Generation && exactAttestation.Generation == principal.Generation;
        trace.Add(Reject(SecurityDecisionCode.GenerationCurrent, generationMatches, generationMatches ? principal.Generation.Value : 0UL, principal.Generation.Value));
        var attestationCurrent = exactAttestation.PolicyGeneration == request.AttestationPolicyGeneration && exactAttestation.Status == EvidenceStatus.Valid;
        trace.Add(exactAttestation.Status == EvidenceStatus.Missing
            ? Hold(SecurityDecisionCode.AttestationCurrent, false, 0, request.AttestationPolicyGeneration.Value)
            : Reject(SecurityDecisionCode.AttestationCurrent, attestationCurrent, exactAttestation.PolicyGeneration.Value, request.AttestationPolicyGeneration.Value));
        trace.Add(Reject(SecurityDecisionCode.BootstrapUnused, exactBootstrap.Status == EvidenceStatus.Valid, exactBootstrap.Status == EvidenceStatus.Valid ? 1UL : 0UL, 1));
        var issuerScope = request.Issuer.Kind == IssuerCapabilityKind.RegionalIntermediate && request.Issuer.Scope == TrustScope.Cell;
        trace.Add(Reject(SecurityDecisionCode.IssuerScopeValid, issuerScope, issuerScope ? 1UL : 0UL, 1));
        trace.Add(Reject(SecurityDecisionCode.IssuerCurrent, request.Issuer.Generation == request.CurrentIssuerGeneration,
            request.Issuer.Generation.Value, request.CurrentIssuerGeneration.Value));
        trace.Add(Reject(SecurityDecisionCode.RevocationCurrent, request.Issuer.RevocationGeneration == request.CurrentRevocationGeneration,
            request.Issuer.RevocationGeneration.Value, request.CurrentRevocationGeneration.Value));

        if (trace.Any(r => r.Outcome is SecurityDecisionOutcome.Rejected or SecurityDecisionOutcome.Held))
        {
            var onlyAttestationMissing = trace.Where(r => r.Outcome is SecurityDecisionOutcome.Rejected or SecurityDecisionOutcome.Held)
                .All(r => r.Code == SecurityDecisionCode.AttestationCurrent) && exactAttestation.Status == EvidenceStatus.Missing;
            return onlyAttestationMissing
                ? Decision(true, trace, new AttestIdentityIntent(request, exactAttestation.Id))
                : Deny(request.OperationId, trace);
        }
        return Decision(true, trace, new IssueIdentityIntent(request));
    }

    public static SecurityDecision EvaluateCertificate(CertificateLifecycleRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var trace = new List<SecurityDecisionReason>();
        var principalCurrent = request.Principal.Generation == request.CurrentPrincipalGeneration;
        trace.Add(Reject(SecurityDecisionCode.GenerationCurrent, principalCurrent,
            request.Principal.Generation.Value, request.CurrentPrincipalGeneration.Value));
        var cellMatches = request.Issuer.CellId == request.Principal.CellId;
        trace.Add(Reject(SecurityDecisionCode.CellMatches, cellMatches, cellMatches ? 1UL : 0UL, 1));
        var validity = request.ValidityEvidence;
        var validityExact = validity.OperationId == request.OperationId && validity.PrincipalId == request.Principal.Id &&
                            validity.CellId == request.Principal.CellId && validity.SubjectKeyId == request.SubjectKeyId &&
                            validity.Usage == request.Usage && validity.Scope == request.RequestedScope &&
                            validity.IssuerId == request.Issuer.IssuerId && validity.IssuerGeneration == request.Issuer.Generation;
        trace.Add(Reject(SecurityDecisionCode.ValidityEvidenceExact, validityExact, validityExact ? 1UL : 0UL, 1));
        var issuerScope = request.Issuer.Kind switch
        {
            IssuerCapabilityKind.RegionalIntermediate => request.Issuer.Scope == TrustScope.Cell && request.RequestedScope == TrustScope.Cell,
            IssuerCapabilityKind.GlobalAdministrativeIntermediate => request.Issuer.Scope == TrustScope.GlobalAdministration &&
                                                                      request.RequestedScope == TrustScope.GlobalAdministration,
            _ => false,
        };
        trace.Add(Reject(SecurityDecisionCode.IssuerScopeValid, issuerScope, issuerScope ? 1UL : 0UL, 1));
        trace.Add(Reject(SecurityDecisionCode.IssuerCurrent, request.Issuer.Generation == request.CurrentIssuerGeneration,
            request.Issuer.Generation.Value, request.CurrentIssuerGeneration.Value));
        var revocationCurrent = request.Issuer.RevocationGeneration == request.CurrentRevocationGeneration &&
                                request.ValidityEvidence.RevocationGeneration == request.CurrentRevocationGeneration &&
                                request.ValidityEvidence.Revocation != RevocationStatus.Unknown;
        trace.Add(Reject(SecurityDecisionCode.RevocationCurrent, revocationCurrent,
            request.ValidityEvidence.RevocationGeneration.Value, request.CurrentRevocationGeneration.Value));
        var policyCurrent = request.ValidityEvidence.PolicyGeneration == request.Policy.Generation && request.Policy.Scope == request.RequestedScope;
        trace.Add(Reject(SecurityDecisionCode.PolicyCurrent, policyCurrent, request.ValidityEvidence.PolicyGeneration.Value, request.Policy.Generation.Value));
        var usageAllowed = request.Policy.Usages.Contains(request.Usage);
        trace.Add(Reject(SecurityDecisionCode.UsageAllowed, usageAllowed, usageAllowed ? 1UL : 0UL, 1));

        var nextGeneration = IsNext(request.ValidityEvidence.CertificateGeneration, request.RequestedGeneration);
        var validityAllows = request.Action switch
        {
            CertificateAction.Issue => request.ValidityEvidence.Validity == ValidityStatus.Valid &&
                                       request.ValidityEvidence.Revocation == RevocationStatus.Current &&
                                       request.ValidityEvidence.CertificateGeneration == request.RequestedGeneration,
            CertificateAction.Renew => request.ValidityEvidence.Validity == ValidityStatus.RenewalDue && request.ValidityEvidence.Revocation == RevocationStatus.Current && nextGeneration,
            CertificateAction.Rotate => request.ValidityEvidence.Validity is ValidityStatus.Valid or ValidityStatus.RenewalDue && request.ValidityEvidence.Revocation == RevocationStatus.Current && nextGeneration,
            CertificateAction.Revoke => request.ValidityEvidence.Revocation == RevocationStatus.Current &&
                                        request.RequestedGeneration == request.ValidityEvidence.CertificateGeneration,
            _ => false,
        };
        trace.Add(Reject(SecurityDecisionCode.ValidityAllowsAction, validityAllows, validityAllows ? 1UL : 0UL, 1));
        var compromiseProof = request.CompromiseEvidence;
        var compromise = request.Action != CertificateAction.Revoke ||
            compromiseProof.Status == EvidenceStatus.Valid &&
            compromiseProof.CertificateId == request.ValidityEvidence.CertificateId &&
            compromiseProof.PrincipalId == request.Principal.Id && compromiseProof.CellId == request.Principal.CellId &&
            compromiseProof.CertificateGeneration == request.ValidityEvidence.CertificateGeneration &&
            compromiseProof.RevocationGeneration == request.CurrentRevocationGeneration;
        trace.Add(request.Action == CertificateAction.Revoke
            ? Reject(SecurityDecisionCode.CompromiseProven, compromise, compromise ? 1UL : 0UL, 1)
            : NotApplicable(SecurityDecisionCode.CompromiseProven));

        if (trace.Any(r => r.Outcome is SecurityDecisionOutcome.Rejected or SecurityDecisionOutcome.Held)) return Deny(request.OperationId, trace);
        SecurityIntent intent = request.Action switch
        {
            CertificateAction.Issue => new IssueCertificateIntent(request),
            CertificateAction.Renew => new RenewCertificateIntent(request),
            CertificateAction.Rotate => new RotateCertificateIntent(request),
            CertificateAction.Revoke => new RevokeCertificateIntent(request),
            _ => throw new ArgumentOutOfRangeException(),
        };
        return Decision(true, trace, intent);
    }

    public static SecurityDecision Authorize(AuthorizationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var groups = request.PrincipalEvidence.GroupBy(e => e.Principal.Id.Value, StringComparer.Ordinal).ToArray();
        var duplicates = Duplicates(groups.Select(g => g.Count()));
        var conflicts = groups.Count(g => g.Select(PrincipalProjection).Distinct(StringComparer.Ordinal).Skip(1).Any());
        var complete = request.EvidenceCompleteness == EvidenceStatus.Valid && request.PrincipalEvidence.Count == 1;
        var trace = new List<SecurityDecisionReason>
        {
            Hold(SecurityDecisionCode.EvidenceComplete, complete, complete ? 1UL : 0UL, 1),
            Hold(SecurityDecisionCode.EvidenceUnique, duplicates == 0, checked((ulong)duplicates), 0),
            Hold(SecurityDecisionCode.EvidenceConsistent, conflicts == 0, checked((ulong)conflicts), 0),
        };
        if (trace.Any(r => r.Outcome == SecurityDecisionOutcome.Held)) return Deny(request.OperationId, trace);
        var evidence = request.PrincipalEvidence[0];
        var principalMatches = evidence.Principal.Id == request.PrincipalId && evidence.Status == EvidenceStatus.Valid;
        trace.Add(Reject(SecurityDecisionCode.PrincipalMatches, principalMatches, principalMatches ? 1UL : 0UL, 1));
        var generationCurrent = evidence.Principal.Generation == request.ExpectedPrincipalGeneration &&
                                request.ExpectedPrincipalGeneration == request.CurrentPrincipalGeneration;
        trace.Add(Reject(SecurityDecisionCode.GenerationCurrent, generationCurrent,
            evidence.Principal.Generation.Value, request.CurrentPrincipalGeneration.Value));
        var revocation = evidence.Revocation == RevocationStatus.Current && evidence.RevocationGeneration == request.CurrentRevocationGeneration;
        trace.Add(Reject(SecurityDecisionCode.RevocationCurrent, revocation, evidence.RevocationGeneration.Value, request.CurrentRevocationGeneration.Value));
        var policyCurrent = request.PolicyGeneration == request.CurrentPolicyGeneration;
        trace.Add(Reject(SecurityDecisionCode.PolicyCurrent, policyCurrent, request.PolicyGeneration.Value, request.CurrentPolicyGeneration.Value));
        var grants = request.Grants.Where(g => g.PolicyGeneration == request.PolicyGeneration &&
            g.PrincipalKind == evidence.Principal.Kind && g.Role == evidence.Principal.Role &&
            g.Capability == request.Capability && g.ResourceScope == request.ResourceScope).ToArray();
        trace.Add(Reject(SecurityDecisionCode.ExactGrantPresent, grants.Length == 1, checked((ulong)grants.Length), 1));
        var bounded = PrivilegeBounded(evidence.Principal, request.Capability, request.ResourceScope);
        trace.Add(Reject(SecurityDecisionCode.PrivilegeBounded, bounded, bounded ? 1UL : 0UL, 1));
        if (trace.Any(r => r.Outcome is SecurityDecisionOutcome.Rejected or SecurityDecisionOutcome.Held)) return Deny(request.OperationId, trace);
        return Decision(true, trace, new AuthorizeCapabilityIntent(request));
    }

    public static SecurityDecision EvaluateLease(SecretLeaseRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var principal = request.PrincipalEvidence;
        var trace = new List<SecurityDecisionReason>();
        var principalExact = principal.Principal.Generation == request.ExpectedPrincipalGeneration;
        trace.Add(Reject(SecurityDecisionCode.PrincipalMatches, principalExact, principalExact ? 1UL : 0UL, 1));
        var principalCurrent = request.ExpectedPrincipalGeneration == request.CurrentPrincipalGeneration;
        trace.Add(Reject(SecurityDecisionCode.GenerationCurrent, principalCurrent,
            request.ExpectedPrincipalGeneration.Value, request.CurrentPrincipalGeneration.Value));
        var revocation = principal.Status == EvidenceStatus.Valid && principal.Revocation == RevocationStatus.Current &&
                         principal.RevocationGeneration == request.CurrentRevocationGeneration;
        trace.Add(Reject(SecurityDecisionCode.RevocationCurrent, revocation, principal.RevocationGeneration.Value, request.CurrentRevocationGeneration.Value));
        var revoking = request.Action == LeaseAction.Revoke;
        var metadata = revoking
            ? ExistingLeaseCoreExact(request)
            : request.Secret.SecretId == request.Policy.SecretId && request.Secret.CellId == request.Policy.CellId &&
              request.Secret.Environment == request.Policy.Environment && request.Secret.Purpose == request.Policy.Purpose;
        trace.Add(Reject(SecurityDecisionCode.SecretMetadataExact, metadata, metadata ? 1UL : 0UL, 1));
        var retained = request.Policy.RetainedVersions.Contains(request.Secret.Version) && request.Policy.ExpiryEvidence == EvidenceStatus.Valid;
        trace.Add(revoking
            ? NotApplicable(SecurityDecisionCode.SecretVersionRetained)
            : Reject(SecurityDecisionCode.SecretVersionRetained, retained, retained ? 1UL : 0UL, 1));
        var available = request.Secret.Availability == SecretAvailability.Available;
        trace.Add(revoking
            ? NotApplicable(SecurityDecisionCode.SecretAvailable)
            : available ? Pass(SecurityDecisionCode.SecretAvailable) : Hold(SecurityDecisionCode.SecretAvailable, false, 0, 1));
        var policyCurrent = request.Policy.Generation == request.CurrentPolicyGeneration &&
                            request.RequestedDuration.Value <= request.Policy.MaximumLeaseDuration.Value;
        trace.Add(revoking
            ? NotApplicable(SecurityDecisionCode.PolicyCurrent)
            : Reject(SecurityDecisionCode.PolicyCurrent, policyCurrent, request.Policy.Generation.Value, request.CurrentPolicyGeneration.Value));
        var capability = request.Action switch
        {
            LeaseAction.Grant => AuthorizationCapability.GrantSecretLease,
            LeaseAction.Renew => AuthorizationCapability.RenewOwnLease,
            LeaseAction.Revoke => AuthorizationCapability.RevokeLease,
            _ => throw new ArgumentOutOfRangeException(),
        };
        var resourceScope = new SecurityResourceScope(SecurityResourceKind.SecretLease, request.Secret.CellId,
            request.Secret.Environment, request.Secret.Purpose);
        var exactGrants = request.Grants.Where(g => g.PolicyGeneration == request.CurrentPolicyGeneration &&
            g.PrincipalKind == principal.Principal.Kind && g.Role == principal.Principal.Role &&
            g.Capability == capability && g.ResourceScope == resourceScope).ToArray();
        trace.Add(Reject(SecurityDecisionCode.ExactGrantPresent, exactGrants.Length == 1 && request.Grants.Count == 1, checked((ulong)exactGrants.Length), 1));
        var privilege = PrivilegeBounded(principal.Principal, capability, resourceScope);
        trace.Add(Reject(SecurityDecisionCode.PrivilegeBounded, privilege, privilege ? 1UL : 0UL, 1));
        var exactLease = request.Action == LeaseAction.Grant ||
                         ExistingLeaseCoreExact(request) &&
                         (revoking || request.ExistingLease!.PolicyGeneration == request.Policy.Generation);
        trace.Add(request.Action == LeaseAction.Grant ? NotApplicable(SecurityDecisionCode.LeaseExact) : Reject(SecurityDecisionCode.LeaseExact, exactLease, exactLease ? 1UL : 0UL, 1));
        var actionValidity = request.Action switch
        {
            LeaseAction.Grant => request.RequestedLeaseGeneration.Value == 1,
            LeaseAction.Renew => request.ExistingLease!.Status == LeaseStatus.Active &&
                                 request.ExistingLease.Validity is ValidityStatus.Valid or ValidityStatus.RenewalDue &&
                                 IsNext(request.ExistingLease.Generation, request.RequestedLeaseGeneration),
            LeaseAction.Revoke => request.ExistingLease!.Status == LeaseStatus.Active &&
                                  request.RequestedLeaseGeneration == request.ExistingLease.Generation,
            _ => false,
        };
        trace.Add(Reject(SecurityDecisionCode.LeaseValidityAllowsAction, actionValidity, actionValidity ? 1UL : 0UL, 1));
        if (trace.Any(r => r.Outcome is SecurityDecisionOutcome.Rejected or SecurityDecisionOutcome.Held)) return Deny(request.OperationId, trace);
        SecurityIntent intent = request.Action switch
        {
            LeaseAction.Grant => new GrantSecretLeaseIntent(request),
            LeaseAction.Renew => new RenewSecretLeaseIntent(request),
            LeaseAction.Revoke => new RevokeSecretLeaseIntent(request),
            _ => throw new ArgumentOutOfRangeException(),
        };
        return Decision(true, trace, intent);
    }

    public static SecurityDecision EvaluateSurvivalSecrets(SurvivalSecretRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var referenceDuplicates = Duplicates(request.References.GroupBy(ReferenceKey, StringComparer.Ordinal).Select(g => g.Count()));
        var availableDuplicates = Duplicates(request.AvailableVersions.GroupBy(MetadataKey, StringComparer.Ordinal).Select(g => g.Count()));
        var policyDuplicates = Duplicates(request.Policies.GroupBy(p => p.SecretId.Value, StringComparer.Ordinal).Select(g => g.Count()));
        var duplicates = checked(referenceDuplicates + availableDuplicates + policyDuplicates);
        var exact = request.References.Count > 0 && request.References.All(reference =>
        {
            var metadata = request.AvailableVersions.Where(m => MetadataKey(m) == ReferenceKey(reference)).ToArray();
            var policies = request.Policies.Where(p => p.SecretId == reference.SecretId).ToArray();
            return reference.CellId == request.CellId && metadata is [var item] && policies is [var policy] &&
                   item.CellId == request.CellId && item.Environment == reference.Environment && item.Purpose == reference.Purpose &&
                   item.CiphertextDigest == reference.CiphertextDigest && item.Availability == SecretAvailability.Available &&
                   policy.CellId == request.CellId && policy.Environment == reference.Environment && policy.Purpose == reference.Purpose &&
                   policy.Generation == request.CurrentPolicyGeneration &&
                   policy.RetainedVersions.Contains(reference.Version) && policy.ExpiryEvidence == EvidenceStatus.Valid;
        });
        var trace = new List<SecurityDecisionReason>
        {
            Hold(SecurityDecisionCode.EvidenceUnique, duplicates == 0, checked((ulong)duplicates), 0),
            Reject(SecurityDecisionCode.SurvivalReferencesExact, exact, exact ? checked((ulong)request.References.Count) : 0UL, checked((ulong)request.References.Count)),
        };
        return trace.All(r => r.Outcome == SecurityDecisionOutcome.Passed)
            ? Decision(true, trace, new AcceptSurvivalSecretReferencesIntent(request))
            : Deny(request.OperationId, trace);
    }

    private static bool ExistingLeaseCoreExact(SecretLeaseRequest request)
    {
        var lease = request.ExistingLease!;
        return lease.LeaseId == request.RequestedLeaseId &&
               lease.PrincipalId == request.PrincipalEvidence.Principal.Id && lease.SecretId == request.Secret.SecretId &&
               lease.Version == request.Secret.Version && lease.CellId == request.Secret.CellId &&
               lease.Environment == request.Secret.Environment && lease.Purpose == request.Secret.Purpose &&
               lease.WrappingKeyId == request.Secret.WrappingKeyId && lease.CiphertextDigest == request.Secret.CiphertextDigest;
    }

    private static bool PrivilegeBounded(SecurityPrincipal principal, AuthorizationCapability capability, SecurityResourceScope scope)
    {
        if (capability == AuthorizationCapability.AdministerGlobalTrust)
            return principal.Kind == SecurityPrincipalKind.Operator && principal.Role == SecurityRole.Operator;
        if (principal.CellId != scope.CellId) return false;
        if (principal.Role == SecurityRole.UntrustedCi && capability is AuthorizationCapability.ReadEncryptedSecret or AuthorizationCapability.GrantSecretLease)
            return false;
        return true;
    }

    private static bool IsNext(PositiveSecurityNumber current, PositiveSecurityNumber requested) =>
        current.Value < ulong.MaxValue && requested.Value == current.Value + 1;
    private static int Duplicates(IEnumerable<int> counts) => counts.Aggregate(0, (sum, count) => checked(sum + Math.Max(0, count - 1)));
    private static string BootstrapProjection(BootstrapEnrollmentEvidence e) => string.Join('|', e.OperationId.Value, e.PrincipalId.Value, e.Audience, e.CellId.Value, e.Role, Invariant(e.NodeGeneration.Value), e.Status);
    private static string AttestationProjection(SecurityAttestationEvidence e) => string.Join('|', e.Measurement.Sha256, e.PrincipalId.Value, e.Kind, e.CellId.Value, e.Role, Invariant(e.Generation.Value), Invariant(e.PolicyGeneration.Value), e.Status);
    private static string PrincipalProjection(PrincipalAuthorizationEvidence e) => string.Join('|', e.Principal.Kind, e.Principal.Role, e.Principal.CellId.Value, Invariant(e.Principal.Generation.Value), Invariant(e.RevocationGeneration.Value), e.Revocation, e.Status);
    private static string ReferenceKey(SurvivalSecretReference r) => $"{r.SecretId.Value}|{Invariant(r.Version.Value)}";
    private static string MetadataKey(EncryptedSecretMetadata m) => $"{m.SecretId.Value}|{Invariant(m.Version.Value)}";
    private static string Invariant(ulong value) => value.ToString(CultureInfo.InvariantCulture);
    private static SecurityDecisionReason Pass(SecurityDecisionCode code) => new(code, SecurityDecisionOutcome.Passed, 1, 1);
    private static SecurityDecisionReason Hold(SecurityDecisionCode code, bool pass, ulong observed, ulong required) => new(code, pass ? SecurityDecisionOutcome.Passed : SecurityDecisionOutcome.Held, observed, required);
    private static SecurityDecisionReason Reject(SecurityDecisionCode code, bool pass, ulong observed, ulong required) => new(code, pass ? SecurityDecisionOutcome.Passed : SecurityDecisionOutcome.Rejected, observed, required);
    private static SecurityDecisionReason NotApplicable(SecurityDecisionCode code) => new(code, SecurityDecisionOutcome.NotApplicable, 0, 0);
    private static SecurityDecision Decision(bool authorized, List<SecurityDecisionReason> trace, SecurityIntent intent) => new(authorized, new ReadOnlyCollection<SecurityDecisionReason>(trace.ToArray()), intent);
    private static SecurityDecision Deny(SecurityOperationId operationId, List<SecurityDecisionReason> trace) => Decision(false, trace, new HoldSecurityOperationIntent(operationId));
}
