using TerraScale.Orchestrator.ControlPlane.Security;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties;

public sealed class SecurityAcceptedOutputGapTests
{
    [Test]
    public async Task Enrollment_attestation_cannot_be_replayed_onto_a_different_subject_key()
    {
        var original = Enrollment(EvidenceStatus.Valid);
        var substituted = new EnrollmentRequest(
            original.OperationId,
            original.ExpectedPrincipal,
            original.CurrentPrincipalGeneration,
            new SecurityKeyId("attacker-subject-key"),
            original.AttestationPolicyGeneration,
            original.Issuer,
            original.CurrentIssuerGeneration,
            original.CurrentRevocationGeneration,
            original.BootstrapEvidence,
            original.Attestations);

        var decision = SecurityDecisionEngine.EvaluateEnrollment(substituted);

        await Assert.That(decision.Authorized).IsFalse();
        await Assert.That(decision.Intent).IsTypeOf<HoldSecurityOperationIntent>();
        await Assert.That(decision.Trace.Single(reason => reason.Code == SecurityDecisionCode.SubjectKeyMatches).Outcome)
            .IsEqualTo(SecurityDecisionOutcome.Rejected);
    }

    [Test]
    public async Task Missing_attestation_cannot_be_requested_for_a_substituted_subject_key()
    {
        var original = Enrollment(EvidenceStatus.Missing);
        var substituted = new EnrollmentRequest(
            original.OperationId,
            original.ExpectedPrincipal,
            original.CurrentPrincipalGeneration,
            new SecurityKeyId("attacker-subject-key"),
            original.AttestationPolicyGeneration,
            original.Issuer,
            original.CurrentIssuerGeneration,
            original.CurrentRevocationGeneration,
            original.BootstrapEvidence,
            original.Attestations);

        var decision = SecurityDecisionEngine.EvaluateEnrollment(substituted);

        await Assert.That(decision.Authorized).IsFalse();
        await Assert.That(decision.Intent).IsTypeOf<HoldSecurityOperationIntent>();
        await Assert.That(decision.Trace.Single(reason => reason.Code == SecurityDecisionCode.SubjectKeyMatches).Outcome)
            .IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(decision.Trace.Single(reason => reason.Code == SecurityDecisionCode.AttestationCurrent).Outcome)
            .IsEqualTo(SecurityDecisionOutcome.Held);
    }

    [Test]
    public async Task Authorization_rejects_a_capability_granted_for_the_wrong_resource_kind()
    {
        var principal = Principal();
        var certificateScope = new SecurityResourceScope(
            SecurityResourceKind.Certificate,
            Cell,
            SecurityEnvironment.Production,
            purpose: null);
        var request = new AuthorizationRequest(
            Operation,
            principal.Id,
            Generation,
            Generation,
            AuthorizationCapability.ReadEncryptedSecret,
            certificateScope,
            PolicyGeneration,
            PolicyGeneration,
            RevocationGeneration,
            [new PrincipalAuthorizationEvidence(principal, RevocationGeneration, RevocationStatus.Current, EvidenceStatus.Valid)],
            [new AuthorizationGrant(PolicyGeneration, principal.Kind, principal.Role, AuthorizationCapability.ReadEncryptedSecret, certificateScope)],
            EvidenceStatus.Valid);

        var decision = SecurityDecisionEngine.Authorize(request);

        await Assert.That(decision.Authorized).IsFalse();
        await Assert.That(decision.Intent).IsTypeOf<HoldSecurityOperationIntent>();
    }

    [Test]
    public async Task Capability_resource_map_is_closed_for_1000_deterministic_cases()
    {
        var capabilities = Enum.GetValues<AuthorizationCapability>();
        var resourceKinds = Enum.GetValues<SecurityResourceKind>();
        var executed = 0;
        for (var seed = 0; seed < 1000; seed++)
        {
            var capability = capabilities[seed % capabilities.Length];
            var resourceKind = resourceKinds[(seed / capabilities.Length) % resourceKinds.Length];
            var principal = capability == AuthorizationCapability.AdministerGlobalTrust
                ? new SecurityPrincipal(new SecurityPrincipalId($"operator-{seed}"), SecurityPrincipalKind.Operator, SecurityRole.Operator, Cell, Generation)
                : new SecurityPrincipal(new SecurityPrincipalId($"principal-{seed}"), SecurityPrincipalKind.Node, SecurityRole.Agent, Cell, Generation);
            var scope = new SecurityResourceScope(
                resourceKind,
                Cell,
                SecurityEnvironment.Production,
                resourceKind is SecurityResourceKind.EncryptedSecret or SecurityResourceKind.SecretLease
                    ? SecretPurpose.Database
                    : null);
            var request = new AuthorizationRequest(
                new SecurityOperationId($"authorization-{seed}"),
                principal.Id,
                Generation,
                Generation,
                capability,
                scope,
                PolicyGeneration,
                PolicyGeneration,
                RevocationGeneration,
                [new PrincipalAuthorizationEvidence(principal, RevocationGeneration, RevocationStatus.Current, EvidenceStatus.Valid)],
                [new AuthorizationGrant(PolicyGeneration, principal.Kind, principal.Role, capability, scope)],
                EvidenceStatus.Valid);

            var decision = SecurityDecisionEngine.Authorize(request);
            var expected = ExpectedResourceKind(capability) == resourceKind;

            if (decision.Authorized != expected)
                throw new InvalidOperationException($"Capability/resource closure failed at seed {seed}: {capability}/{resourceKind}.");
            var bounded = decision.Trace.Single(reason => reason.Code == SecurityDecisionCode.PrivilegeBounded);
            await Assert.That(bounded.Outcome).IsEqualTo(expected
                ? SecurityDecisionOutcome.Passed
                : SecurityDecisionOutcome.Rejected);
            executed++;
        }

        await Assert.That(executed).IsEqualTo(1000);
    }

    private static EnrollmentRequest Enrollment(EvidenceStatus status)
    {
        var principal = Principal();
        var issuer = new IssuerSigningCapability(
            new SecurityIssuerId("issuer-gru"),
            IssuerCapabilityKind.RegionalIntermediate,
            Cell,
            TrustScope.Cell,
            IssuerGeneration,
            RevocationGeneration);
        return new EnrollmentRequest(
            Operation,
            principal,
            principal.Generation,
            new SecurityKeyId("subject-key"),
            PolicyGeneration,
            issuer,
            IssuerGeneration,
            RevocationGeneration,
            [new BootstrapEnrollmentEvidence(
                new SecurityBootstrapId("bootstrap"),
                Operation,
                principal.Id,
                principal.Kind,
                Cell,
                principal.Role,
                Generation,
                EvidenceStatus.Valid)],
            [new SecurityAttestationEvidence(
                new SecurityAttestationId("attestation"),
                new SecurityDigest(new string('a', 64)),
                principal.Id,
                new SecurityKeyId("subject-key"),
                principal.Kind,
                Cell,
                principal.Role,
                Generation,
                PolicyGeneration,
                status)]);
    }

    private static SecurityPrincipal Principal() => new(
        new SecurityPrincipalId("principal"),
        SecurityPrincipalKind.Node,
        SecurityRole.Agent,
        Cell,
        Generation);

    private static SecurityResourceKind ExpectedResourceKind(AuthorizationCapability capability) => capability switch
    {
        AuthorizationCapability.EnrollNode or AuthorizationCapability.EnrollWorkload => SecurityResourceKind.Enrollment,
        AuthorizationCapability.IssueCellIdentity or AuthorizationCapability.RenewIdentity or AuthorizationCapability.RevokeIdentity => SecurityResourceKind.Certificate,
        AuthorizationCapability.ReadEncryptedSecret => SecurityResourceKind.EncryptedSecret,
        AuthorizationCapability.GrantSecretLease or AuthorizationCapability.RenewOwnLease or AuthorizationCapability.RevokeLease => SecurityResourceKind.SecretLease,
        AuthorizationCapability.AdministerGlobalTrust => SecurityResourceKind.TrustBundle,
        _ => throw new ArgumentOutOfRangeException(nameof(capability)),
    };

    private static SecurityCellId Cell { get; } = new("gru");
    private static SecurityOperationId Operation { get; } = new("security-operation");
    private static SecurityGeneration Generation { get; } = new(5);
    private static SecurityGeneration PolicyGeneration { get; } = new(2);
    private static SecurityGeneration IssuerGeneration { get; } = new(1);
    private static SecurityGeneration RevocationGeneration { get; } = new(3);
}

