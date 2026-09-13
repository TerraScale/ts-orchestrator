using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Security;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class SecurityDecisionTests
{
    [Test]
    public async Task ExactSingleUseEnrollmentIssuesOnlyScopedIdentity()
    {
        var decision = SecurityDecisionEngine.EvaluateEnrollment(Enrollment());
        await Assert.That(decision.Authorized).IsTrue();
        var intent = (IssueIdentityIntent)decision.Intent;
        await Assert.That(intent.Principal.CellId).IsEqualTo(Cell);
        await Assert.That(intent.Issuer.Kind).IsEqualTo(IssuerCapabilityKind.RegionalIntermediate);
    }

    [Test]
    public async Task ConsumedReplayWrongScopeRoleGenerationAndStaleAttestationDeny()
    {
        var replay = SecurityDecisionEngine.EvaluateEnrollment(Enrollment(bootstrapStatus: EvidenceStatus.Consumed));
        var wrongCell = SecurityDecisionEngine.EvaluateEnrollment(Enrollment(attestationCell: new("sfo")));
        var wrongRole = SecurityDecisionEngine.EvaluateEnrollment(Enrollment(attestationRole: SecurityRole.TerraBase));
        var wrongGeneration = SecurityDecisionEngine.EvaluateEnrollment(Enrollment(attestationGeneration: new(6)));
        var stale = SecurityDecisionEngine.EvaluateEnrollment(Enrollment(attestationStatus: EvidenceStatus.Stale));
        await Assert.That(replay.Authorized).IsFalse();
        await Assert.That(Reason(replay, SecurityDecisionCode.BootstrapUnused).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(Reason(wrongCell, SecurityDecisionCode.CellMatches).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(Reason(wrongRole, SecurityDecisionCode.RoleMatches).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(Reason(wrongGeneration, SecurityDecisionCode.GenerationCurrent).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(Reason(stale, SecurityDecisionCode.AttestationCurrent).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
    }

    [Test]
    public async Task MissingAttestationEmitsOnlyBoundAttestationIntent()
    {
        var decision = SecurityDecisionEngine.EvaluateEnrollment(Enrollment(attestationStatus: EvidenceStatus.Missing));
        await Assert.That(decision.Authorized).IsTrue();
        await Assert.That(((AttestIdentityIntent)decision.Intent).AttestationId).IsEqualTo(new SecurityAttestationId("attestation-1"));
    }

    [Test]
    public async Task EnrollmentEvidenceCannotReplayForAnotherPrincipalOrStaleIssuer()
    {
        var exact = Enrollment();
        var wrongPrincipalBootstrap = new BootstrapEnrollmentEvidence(
            new("bootstrap-1"), Operation, new("other-principal"), SecurityPrincipalKind.Node,
            Cell, SecurityRole.Agent, Generation, EvidenceStatus.Valid);
        var replay = SecurityDecisionEngine.EvaluateEnrollment(new(
            exact.OperationId, exact.ExpectedPrincipal, exact.CurrentPrincipalGeneration, exact.SubjectKeyId, exact.AttestationPolicyGeneration,
            exact.Issuer, exact.CurrentIssuerGeneration, exact.CurrentRevocationGeneration,
            [wrongPrincipalBootstrap], exact.Attestations));
        var staleIssuer = SecurityDecisionEngine.EvaluateEnrollment(Enrollment(currentIssuerGeneration: new(2)));
        await Assert.That(Reason(replay, SecurityDecisionCode.PrincipalMatches).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(Reason(staleIssuer, SecurityDecisionCode.IssuerCurrent).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
    }

    [Test]
    public async Task DuplicateOrConflictingEnrollmentEvidenceHoldsBeforeIssue()
    {
        var exact = Enrollment();
        var duplicate = new EnrollmentRequest(exact.OperationId, exact.ExpectedPrincipal, exact.CurrentPrincipalGeneration, exact.SubjectKeyId, exact.AttestationPolicyGeneration,
            exact.Issuer, exact.CurrentIssuerGeneration, exact.CurrentRevocationGeneration, [exact.BootstrapEvidence[0], exact.BootstrapEvidence[0]], exact.Attestations);
        var conflictBootstrap = new BootstrapEnrollmentEvidence(new("bootstrap-1"), Operation, new("principal-1"), SecurityPrincipalKind.Node,
            Cell, SecurityRole.TerraBase, Generation, EvidenceStatus.Valid);
        var conflict = new EnrollmentRequest(exact.OperationId, exact.ExpectedPrincipal, exact.CurrentPrincipalGeneration, exact.SubjectKeyId, exact.AttestationPolicyGeneration,
            exact.Issuer, exact.CurrentIssuerGeneration, exact.CurrentRevocationGeneration, [exact.BootstrapEvidence[0], conflictBootstrap], exact.Attestations);
        var duplicateDecision = SecurityDecisionEngine.EvaluateEnrollment(duplicate);
        var conflictDecision = SecurityDecisionEngine.EvaluateEnrollment(conflict);
        await Assert.That(Reason(duplicateDecision, SecurityDecisionCode.EvidenceUnique).Outcome).IsEqualTo(SecurityDecisionOutcome.Held);
        await Assert.That(Reason(conflictDecision, SecurityDecisionCode.EvidenceConsistent).Outcome).IsEqualTo(SecurityDecisionOutcome.Held);
        await Assert.That(duplicateDecision.Intent is HoldSecurityOperationIntent).IsTrue();
    }

    [Test]
    public async Task RegionalIssuerCannotCrossCellOrGlobalScopeAndStaleRevocationRejects()
    {
        var crossCell = SecurityDecisionEngine.EvaluateCertificate(Certificate(principalCell: new("sfo")));
        var global = SecurityDecisionEngine.EvaluateCertificate(Certificate(scope: TrustScope.GlobalAdministration));
        var stale = SecurityDecisionEngine.EvaluateCertificate(Certificate(validityRevocationGeneration: new(2)));
        await Assert.That(Reason(crossCell, SecurityDecisionCode.CellMatches).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(Reason(global, SecurityDecisionCode.IssuerScopeValid).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(Reason(stale, SecurityDecisionCode.RevocationCurrent).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
    }

    [Test]
    public async Task RenewRotateOverlapAndCompromiseRevocationUseExplicitEvidence()
    {
        var renew = SecurityDecisionEngine.EvaluateCertificate(Certificate());
        var rotate = SecurityDecisionEngine.EvaluateCertificate(Certificate(action: CertificateAction.Rotate));
        var unprovenRevoke = SecurityDecisionEngine.EvaluateCertificate(Certificate(action: CertificateAction.Revoke, compromise: EvidenceStatus.Unknown));
        var provenRevoke = SecurityDecisionEngine.EvaluateCertificate(Certificate(action: CertificateAction.Revoke, compromise: EvidenceStatus.Valid));
        await Assert.That(renew.Intent is RenewCertificateIntent).IsTrue();
        await Assert.That(rotate.Intent is RotateCertificateIntent).IsTrue();
        await Assert.That(unprovenRevoke.Authorized).IsFalse();
        await Assert.That(provenRevoke.Intent is RevokeCertificateIntent).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => Policy(overlap: 900))).IsTrue();
    }

    [Test]
    public async Task CertificateRejectsStalePrincipalIssuerAndCrossScopedCompromiseProof()
    {
        var stalePrincipal = SecurityDecisionEngine.EvaluateCertificate(Certificate(currentPrincipalGeneration: new(6)));
        var staleIssuer = SecurityDecisionEngine.EvaluateCertificate(Certificate(currentIssuerGeneration: new(2)));
        var wrongCompromiseCell = SecurityDecisionEngine.EvaluateCertificate(Certificate(
            action: CertificateAction.Revoke, compromiseCell: new("sfo")));
        await Assert.That(Reason(stalePrincipal, SecurityDecisionCode.GenerationCurrent).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(Reason(staleIssuer, SecurityDecisionCode.IssuerCurrent).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(Reason(wrongCompromiseCell, SecurityDecisionCode.CompromiseProven).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
    }

    [Test]
    public async Task CertificateValidityProofCannotReplayAcrossPrincipalKeyScopeIssuerOrOperation()
    {
        var wrongPrincipal = SecurityDecisionEngine.EvaluateCertificate(Certificate(validityPrincipalId: new("other-principal")));
        var wrongKey = SecurityDecisionEngine.EvaluateCertificate(Certificate(validitySubjectKeyId: new("other-key")));
        var wrongScope = SecurityDecisionEngine.EvaluateCertificate(Certificate(validityScope: TrustScope.GlobalAdministration));
        var wrongIssuer = SecurityDecisionEngine.EvaluateCertificate(Certificate(validityIssuerId: new("other-issuer")));
        var wrongOperation = SecurityDecisionEngine.EvaluateCertificate(Certificate(validityOperationId: new("other-operation")));
        foreach (var decision in new[] { wrongPrincipal, wrongKey, wrongScope, wrongIssuer, wrongOperation })
            await Assert.That(Reason(decision, SecurityDecisionCode.ValidityEvidenceExact).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
    }

    [Test]
    public async Task AuthorizationIsExactDefaultDenyAndCrossCellOrEscalationRejects()
    {
        var allowed = SecurityDecisionEngine.Authorize(Authorization());
        var noGrant = SecurityDecisionEngine.Authorize(Authorization(grants: []));
        var crossCell = SecurityDecisionEngine.Authorize(Authorization(scopeCell: new("sfo"), grantCell: new("sfo")));
        var escalation = SecurityDecisionEngine.Authorize(Authorization(
            capability: AuthorizationCapability.AdministerGlobalTrust,
            grants: [Grant(AuthorizationCapability.AdministerGlobalTrust)]));
        await Assert.That(allowed.Intent is AuthorizeCapabilityIntent).IsTrue();
        await Assert.That(Reason(noGrant, SecurityDecisionCode.ExactGrantPresent).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(Reason(crossCell, SecurityDecisionCode.PrivilegeBounded).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(Reason(escalation, SecurityDecisionCode.PrivilegeBounded).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
    }

    [Test]
    public async Task RevokedStaleDuplicateOrConflictingPrincipalEvidenceNeverAuthorizes()
    {
        var revoked = SecurityDecisionEngine.Authorize(Authorization(revocation: RevocationStatus.Revoked));
        var stale = SecurityDecisionEngine.Authorize(Authorization(revocationGeneration: new(2)));
        var evidence = PrincipalEvidence();
        var duplicate = SecurityDecisionEngine.Authorize(Authorization(principalEvidence: [evidence, evidence]));
        var conflicting = SecurityDecisionEngine.Authorize(Authorization(principalEvidence:
            [evidence, PrincipalEvidence(role: SecurityRole.TerraBase)]));
        await Assert.That(revoked.Authorized).IsFalse();
        await Assert.That(stale.Authorized).IsFalse();
        await Assert.That(Reason(duplicate, SecurityDecisionCode.EvidenceUnique).Outcome).IsEqualTo(SecurityDecisionOutcome.Held);
        await Assert.That(Reason(conflicting, SecurityDecisionCode.EvidenceConsistent).Outcome).IsEqualTo(SecurityDecisionOutcome.Held);
    }

    [Test]
    public async Task AuthorizationRejectsEvidenceAndExpectationThatAgreeOnOldGeneration()
    {
        var oldPrincipal = new SecurityPrincipal(new("principal-1"), SecurityPrincipalKind.Node, SecurityRole.Agent, Cell, new(4));
        var oldEvidence = new PrincipalAuthorizationEvidence(oldPrincipal, RevocationGeneration, RevocationStatus.Current, EvidenceStatus.Valid);
        var decision = SecurityDecisionEngine.Authorize(Authorization(
            expectedPrincipalGeneration: new(4), currentPrincipalGeneration: Generation,
            principalEvidence: [oldEvidence]));
        await Assert.That(Reason(decision, SecurityDecisionCode.GenerationCurrent).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
    }

    [Test]
    public async Task AuthorizationRejectsGrantAndRequestThatAgreeOnStalePolicyGeneration()
    {
        var staleGrant = new AuthorizationGrant(new(1), SecurityPrincipalKind.Node, SecurityRole.Agent,
            AuthorizationCapability.ReadEncryptedSecret, Scope());
        var decision = SecurityDecisionEngine.Authorize(Authorization(
            policyGeneration: new(1), currentPolicyGeneration: new(2), grants: [staleGrant]));
        await Assert.That(Reason(decision, SecurityDecisionCode.PolicyCurrent).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
    }

    [Test]
    public async Task SecretLeaseGrantBindsEncryptedMetadataRetentionDurationAndPrincipal()
    {
        var granted = SecurityDecisionEngine.EvaluateLease(Lease());
        var unavailable = SecurityDecisionEngine.EvaluateLease(Lease(secret: Secret(availability: SecretAvailability.Missing)));
        var unretained = SecurityDecisionEngine.EvaluateLease(Lease(secret: Secret(version: 3)));
        var tooLong = SecurityDecisionEngine.EvaluateLease(Lease(duration: 301));
        var crossCell = SecurityDecisionEngine.EvaluateLease(Lease(secret: Secret(cell: new("sfo"))));
        await Assert.That(granted.Intent is GrantSecretLeaseIntent).IsTrue();
        await Assert.That(Reason(unavailable, SecurityDecisionCode.SecretAvailable).Outcome).IsEqualTo(SecurityDecisionOutcome.Held);
        await Assert.That(Reason(unretained, SecurityDecisionCode.SecretVersionRetained).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(tooLong.Authorized).IsFalse();
        await Assert.That(crossCell.Authorized).IsFalse();
    }

    [Test]
    public async Task LeaseDefaultDeniesWithoutExactGrantOrCurrentGenerations()
    {
        var noGrant = SecurityDecisionEngine.EvaluateLease(Lease(grants: []));
        var oldPrincipal = new SecurityPrincipal(new("principal-1"), SecurityPrincipalKind.Node, SecurityRole.Agent, Cell, new(4));
        var oldEvidence = new PrincipalAuthorizationEvidence(oldPrincipal, RevocationGeneration, RevocationStatus.Current, EvidenceStatus.Valid);
        var stalePrincipal = SecurityDecisionEngine.EvaluateLease(Lease(
            principalEvidence: oldEvidence, expectedPrincipalGeneration: new(4), currentPrincipalGeneration: Generation));
        var stalePolicy = SecurityDecisionEngine.EvaluateLease(Lease(currentPolicyGeneration: new(3)));
        await Assert.That(Reason(noGrant, SecurityDecisionCode.ExactGrantPresent).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(Reason(stalePrincipal, SecurityDecisionCode.GenerationCurrent).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(Reason(stalePolicy, SecurityDecisionCode.PolicyCurrent).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
    }

    [Test]
    public async Task LeaseRenewAndRevokeRequireExactLeaseAndCallerValidityEvidence()
    {
        var existing = ExistingLease();
        var renew = SecurityDecisionEngine.EvaluateLease(Lease(action: LeaseAction.Renew, existing: existing, requestedGeneration: 2));
        var expired = SecurityDecisionEngine.EvaluateLease(Lease(action: LeaseAction.Renew,
            existing: ExistingLease(validity: ValidityStatus.Expired), requestedGeneration: 2));
        var wrongPrincipal = SecurityDecisionEngine.EvaluateLease(Lease(action: LeaseAction.Renew,
            existing: ExistingLease(principalId: new("other-principal")), requestedGeneration: 2));
        var changedCiphertext = SecurityDecisionEngine.EvaluateLease(Lease(action: LeaseAction.Renew,
            existing: ExistingLease(ciphertextDigest: new(new string('b', 64))), requestedGeneration: 2));
        var wrongLease = SecurityDecisionEngine.EvaluateLease(Lease(action: LeaseAction.Renew,
            requestedLeaseId: new("lease-2"), existing: ExistingLease(), requestedGeneration: 2));
        var revoke = SecurityDecisionEngine.EvaluateLease(Lease(action: LeaseAction.Revoke, existing: existing));
        await Assert.That(renew.Intent is RenewSecretLeaseIntent).IsTrue();
        await Assert.That(expired.Authorized).IsFalse();
        await Assert.That(Reason(wrongPrincipal, SecurityDecisionCode.LeaseExact).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(Reason(changedCiphertext, SecurityDecisionCode.LeaseExact).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(Reason(wrongLease, SecurityDecisionCode.LeaseExact).Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
        await Assert.That(revoke.Intent is RevokeSecretLeaseIntent).IsTrue();
    }

    [Test]
    public async Task LeaseRenewAndRevokeWithMissingLeaseEvidenceDenyWithoutThrowing()
    {
        var renew = SecurityDecisionEngine.EvaluateLease(Lease(action: LeaseAction.Renew));
        var revoke = SecurityDecisionEngine.EvaluateLease(Lease(action: LeaseAction.Revoke));

        foreach (var decision in new[] { renew, revoke })
        {
            await Assert.That(decision.Authorized).IsFalse();
            await Assert.That(decision.Intent).IsTypeOf<HoldSecurityOperationIntent>();
            await Assert.That(Reason(decision, SecurityDecisionCode.LeaseExact).Outcome)
                .IsEqualTo(SecurityDecisionOutcome.Rejected);
            await Assert.That(Reason(decision, SecurityDecisionCode.LeaseValidityAllowsAction).Outcome)
                .IsEqualTo(SecurityDecisionOutcome.Rejected);
        }
    }

    [Test]
    public async Task LeaseRevokeDoesNotDependOnSecretAvailabilityRetentionExpiryOrDuration()
    {
        var missingSecret = SecurityDecisionEngine.EvaluateLease(Lease(
            action: LeaseAction.Revoke, secret: Secret(availability: SecretAvailability.Missing),
            existing: ExistingLease()));
        var stalePolicy = SecurityDecisionEngine.EvaluateLease(Lease(
            action: LeaseAction.Revoke, policy: Retention(generation: 1, expiry: EvidenceStatus.Stale),
            existing: ExistingLease(), duration: 999));
        var unretainedSecret = Secret(version: 3);
        var unretained = SecurityDecisionEngine.EvaluateLease(Lease(
            action: LeaseAction.Revoke, secret: unretainedSecret,
            policy: Retention(), existing: ExistingLease(version: 3)));

        foreach (var decision in new[] { missingSecret, stalePolicy, unretained })
        {
            await Assert.That(decision.Authorized).IsTrue();
            await Assert.That(decision.Intent is RevokeSecretLeaseIntent).IsTrue();
            await Assert.That(Reason(decision, SecurityDecisionCode.SecretAvailable).Outcome).IsEqualTo(SecurityDecisionOutcome.NotApplicable);
            await Assert.That(Reason(decision, SecurityDecisionCode.SecretVersionRetained).Outcome).IsEqualTo(SecurityDecisionOutcome.NotApplicable);
            await Assert.That(Reason(decision, SecurityDecisionCode.PolicyCurrent).Outcome).IsEqualTo(SecurityDecisionOutcome.NotApplicable);
        }
    }

    [Test]
    public async Task RetainedRollbackVersionIsAllowedButUnretainedOrExpiredPolicyIsNot()
    {
        var rollbackSecret = Secret(version: 1);
        var retained = SecurityDecisionEngine.EvaluateLease(Lease(secret: rollbackSecret));
        var expiredPolicy = SecurityDecisionEngine.EvaluateLease(Lease(secret: rollbackSecret, policy: Retention(expiry: EvidenceStatus.Stale)));
        await Assert.That(retained.Authorized).IsTrue();
        await Assert.That(expiredPolicy.Authorized).IsFalse();
    }

    [Test]
    public async Task SurvivalReferencesRequireExactScopedCiphertextVersionAndPolicy()
    {
        var exact = Survival();
        var accepted = SecurityDecisionEngine.EvaluateSurvivalSecrets(exact);
        var wrongCellReference = new SurvivalSecretReference(SecretId, new(2), new("sfo"), SecurityEnvironment.Production, SecretPurpose.Database, Digest());
        var crossCell = SecurityDecisionEngine.EvaluateSurvivalSecrets(new(Operation, Cell, Generation, Generation, new(2),
            [wrongCellReference], exact.AvailableVersions, exact.Policies));
        var wrongDigest = new SurvivalSecretReference(SecretId, new(2), Cell, SecurityEnvironment.Production, SecretPurpose.Database, new(new string('b', 64)));
        var mismatch = SecurityDecisionEngine.EvaluateSurvivalSecrets(new(Operation, Cell, Generation, Generation, new(2),
            [wrongDigest], exact.AvailableVersions, exact.Policies));
        await Assert.That(accepted.Intent is AcceptSurvivalSecretReferencesIntent).IsTrue();
        await Assert.That(crossCell.Authorized).IsFalse();
        await Assert.That(mismatch.Authorized).IsFalse();
    }

    [Test]
    public async Task InputsAreDefensivelyCopiedAndDecisionsAreCulturePermutationStable()
    {
        var references = new List<SurvivalSecretReference> { Reference() };
        var request = new SurvivalSecretRequest(Operation, Cell, Generation, Generation, new(2), references, [Secret()], [Retention()]);
        references.Clear();
        await Assert.That(request.References.Count).IsEqualTo(1);
        string? baseline = null;
        foreach (var cultureName in new[] { "en-US", "tr-TR", "ar-SA" })
        {
            var original = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultureName);
                var value = Serialize(SecurityDecisionEngine.EvaluateSurvivalSecrets(Survival()));
                baseline ??= value;
                await Assert.That(value).IsEqualTo(baseline);
            }
            finally { CultureInfo.CurrentCulture = original; }
        }
        var exact = PrincipalEvidence();
        var conflict = PrincipalEvidence(role: SecurityRole.TerraBase);
        var forward = Serialize(SecurityDecisionEngine.Authorize(Authorization(principalEvidence: [exact, conflict])));
        var reverse = Serialize(SecurityDecisionEngine.Authorize(Authorization(principalEvidence: [conflict, exact])));
        await Assert.That(reverse).IsEqualTo(forward);
    }

    [Test]
    public async Task OfflineRootsPlaintextAndPrivateKeysAreStructurallyUnrepresentable()
    {
        var types = typeof(SecurityDecisionEngine).Assembly.GetTypes()
            .Where(type => type.Namespace == "TerraScale.Orchestrator.ControlPlane.Security").ToArray();
        var forbiddenNames = new[] { "OfflineRoot", "PrivateKey", "Plaintext", "SecretValue", "CredentialValue", "Reveal" };
        await Assert.That(types.Any(type => forbiddenNames.Any(name => type.Name.Contains(name, StringComparison.OrdinalIgnoreCase)))).IsFalse();
        await Assert.That(types.SelectMany(type => type.GetProperties()).Any(property =>
            forbiddenNames.Any(name => property.Name.Contains(name, StringComparison.OrdinalIgnoreCase)))).IsFalse();
        var forbiddenTypes = new[] { typeof(byte[]), typeof(Stream), typeof(Delegate), typeof(DateTime), typeof(DateTimeOffset) };
        await Assert.That(types.SelectMany(type => type.GetProperties()).Any(property => forbiddenTypes.Contains(property.PropertyType))).IsFalse();
        await Assert.That(Enum.GetNames<IssuerCapabilityKind>().Any(name => name.Contains("Root", StringComparison.OrdinalIgnoreCase))).IsFalse();
        await Assert.That(Serialize(SecurityDecisionEngine.EvaluateEnrollment(Enrollment()))).DoesNotContain("secret");
    }

    [Test]
    public async Task UnknownZeroDuplicateAndMalformedValuesFailClosed()
    {
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new SecurityGeneration(0))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new SecurityPrincipalId("bad/value"))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new SecurityDigest("not-a-digest"))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new PrincipalAuthorizationEvidence(Principal(), RevocationGeneration, (RevocationStatus)0, EvidenceStatus.Valid))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new CertificateLifecyclePolicy(new(1), new(900), new(300), new(100), [CertificateUsage.NodeTransport, CertificateUsage.NodeTransport], TrustScope.Cell))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new IssuerSigningCapability(
            new("issuer-global"),
            IssuerCapabilityKind.GlobalAdministrativeIntermediate,
            Cell,
            TrustScope.Cell,
            new(1),
            RevocationGeneration))).IsTrue();
    }

    private static SecurityCellId Cell { get; } = new("gru");
    private static SecurityGeneration Generation { get; } = new(5);
    private static SecurityGeneration RevocationGeneration { get; } = new(3);
    private static SecurityOperationId Operation { get; } = new("operation-1");
    private static SecuritySecretId SecretId { get; } = new("database-password");
    private static SecurityDigest Digest() => new(new string('a', 64));
    private static SecurityPrincipal Principal(SecurityCellId? cell = null, SecurityRole role = SecurityRole.Agent) =>
        new(new("principal-1"), SecurityPrincipalKind.Node, role, cell ?? Cell, Generation);
    private static IssuerSigningCapability Issuer() => new(new("issuer-gru"), IssuerCapabilityKind.RegionalIntermediate, Cell, TrustScope.Cell, new(1), RevocationGeneration);

    private static EnrollmentRequest Enrollment(
        EvidenceStatus bootstrapStatus = EvidenceStatus.Valid, EvidenceStatus attestationStatus = EvidenceStatus.Valid,
        SecurityCellId? attestationCell = null, SecurityRole attestationRole = SecurityRole.Agent,
        SecurityGeneration? attestationGeneration = null,
        SecurityGeneration? currentIssuerGeneration = null)
    {
        var principal = Principal();
        return new(Operation, principal, principal.Generation, new("subject-key-1"), new(2), Issuer(), currentIssuerGeneration ?? new(1), RevocationGeneration,
            [new(new("bootstrap-1"), Operation, principal.Id, SecurityPrincipalKind.Node, Cell, SecurityRole.Agent, Generation, bootstrapStatus)],
            [new(new("attestation-1"), Digest(), principal.Id, new("subject-key-1"), SecurityPrincipalKind.Node, attestationCell ?? Cell,
                attestationRole, attestationGeneration ?? Generation, new(2), attestationStatus)]);
    }

    private static CertificateLifecyclePolicy Policy(ulong overlap = 100) => new(
        new(2), new(900), new(300), new(overlap), [CertificateUsage.NodeTransport], TrustScope.Cell);
    private static CertificateLifecycleRequest Certificate(
        CertificateAction action = CertificateAction.Renew, SecurityCellId? principalCell = null,
        TrustScope scope = TrustScope.Cell, SecurityGeneration? validityRevocationGeneration = null,
        EvidenceStatus compromise = EvidenceStatus.Valid, SecurityGeneration? currentPrincipalGeneration = null,
        SecurityGeneration? currentIssuerGeneration = null, SecurityCellId? compromiseCell = null,
        SecurityPrincipalId? validityPrincipalId = null, SecurityKeyId? validitySubjectKeyId = null,
        TrustScope? validityScope = null, SecurityIssuerId? validityIssuerId = null,
        SecurityOperationId? validityOperationId = null) => new(
        action, Operation, Principal(principalCell), currentPrincipalGeneration ?? Generation, new("subject-key-1"), CertificateUsage.NodeTransport, scope, action == CertificateAction.Revoke ? new(4) : new(5), Issuer(), currentIssuerGeneration ?? new(1), Policy(),
        new(new("certificate-1"), validityOperationId ?? Operation, validityPrincipalId ?? new("principal-1"), principalCell ?? Cell,
            validitySubjectKeyId ?? new("subject-key-1"), CertificateUsage.NodeTransport, validityScope ?? scope,
            validityIssuerId ?? new("issuer-gru"), new(1), new(4), new(2), validityRevocationGeneration ?? RevocationGeneration,
            ValidityStatus.RenewalDue, RevocationStatus.Current), RevocationGeneration,
        new(new("certificate-1"), new("principal-1"), compromiseCell ?? principalCell ?? Cell, new(4), RevocationGeneration, compromise));

    private static SecurityResourceScope Scope(SecurityCellId? cell = null) => new(
        SecurityResourceKind.EncryptedSecret, cell ?? Cell, SecurityEnvironment.Production, SecretPurpose.Database);
    private static AuthorizationGrant Grant(AuthorizationCapability capability = AuthorizationCapability.ReadEncryptedSecret, SecurityCellId? cell = null) =>
        new(new(2), SecurityPrincipalKind.Node, SecurityRole.Agent, capability, Scope(cell));
    private static PrincipalAuthorizationEvidence PrincipalEvidence(
        SecurityRole role = SecurityRole.Agent, RevocationStatus revocation = RevocationStatus.Current,
        SecurityGeneration? revocationGeneration = null) => new(Principal(role: role), revocationGeneration ?? RevocationGeneration, revocation, EvidenceStatus.Valid);
    private static AuthorizationRequest Authorization(
        AuthorizationCapability capability = AuthorizationCapability.ReadEncryptedSecret,
        SecurityCellId? scopeCell = null, SecurityCellId? grantCell = null,
        IEnumerable<AuthorizationGrant>? grants = null,
        IEnumerable<PrincipalAuthorizationEvidence>? principalEvidence = null,
        RevocationStatus revocation = RevocationStatus.Current,
        SecurityGeneration? revocationGeneration = null,
        SecurityGeneration? expectedPrincipalGeneration = null,
        SecurityGeneration? currentPrincipalGeneration = null,
        SecurityGeneration? policyGeneration = null,
        SecurityGeneration? currentPolicyGeneration = null) => new(
        Operation, new("principal-1"), expectedPrincipalGeneration ?? Generation, currentPrincipalGeneration ?? Generation,
        capability, Scope(scopeCell), policyGeneration ?? new(2), currentPolicyGeneration ?? new(2), RevocationGeneration,
        principalEvidence ?? [PrincipalEvidence(revocation: revocation, revocationGeneration: revocationGeneration)],
        grants ?? [Grant(capability, grantCell ?? scopeCell)], EvidenceStatus.Valid);

    private static EncryptedSecretMetadata Secret(
        ulong version = 2, SecurityCellId? cell = null,
        SecretAvailability availability = SecretAvailability.Available) => new(
        SecretId, new(version), cell ?? Cell, SecurityEnvironment.Production, SecretPurpose.Database,
        new("wrapping-key-1"), Digest(), availability);
    private static SecretRetentionPolicy Retention(EvidenceStatus expiry = EvidenceStatus.Valid, ulong generation = 2) => new(
        new(generation), SecretId, Cell, SecurityEnvironment.Production, SecretPurpose.Database,
        [new SecretVersion(1), new SecretVersion(2)], new(300), expiry);
    private static SecretLeaseEvidence ExistingLease(
        SecurityPrincipalId? principalId = null, ValidityStatus validity = ValidityStatus.RenewalDue,
        SecurityDigest? ciphertextDigest = null, ulong version = 2) => new(
        new("lease-1"), principalId ?? new("principal-1"), SecretId, new(version), Cell,
        SecurityEnvironment.Production, SecretPurpose.Database, new("wrapping-key-1"), ciphertextDigest ?? Digest(), new(1), new(2),
        LeaseStatus.Active, validity);
    private static AuthorizationGrant LeaseGrant(LeaseAction action)
    {
        var capability = action switch
        {
            LeaseAction.Grant => AuthorizationCapability.GrantSecretLease,
            LeaseAction.Renew => AuthorizationCapability.RenewOwnLease,
            LeaseAction.Revoke => AuthorizationCapability.RevokeLease,
            _ => throw new ArgumentOutOfRangeException(nameof(action)),
        };
        return new(new(2), SecurityPrincipalKind.Node, SecurityRole.Agent, capability,
            new(SecurityResourceKind.SecretLease, Cell, SecurityEnvironment.Production, SecretPurpose.Database));
    }
    private static SecretLeaseRequest Lease(
        LeaseAction action = LeaseAction.Grant, EncryptedSecretMetadata? secret = null,
        SecretRetentionPolicy? policy = null, SecretLeaseEvidence? existing = null,
        ulong? requestedGeneration = null, ulong duration = 100,
        SecurityGeneration? expectedPrincipalGeneration = null, SecurityGeneration? currentPolicyGeneration = null,
        SecurityGeneration? currentPrincipalGeneration = null, PrincipalAuthorizationEvidence? principalEvidence = null,
        IEnumerable<AuthorizationGrant>? grants = null, SecurityLeaseId? requestedLeaseId = null) => new(
        action, Operation, requestedLeaseId ?? new("lease-1"), principalEvidence ?? PrincipalEvidence(), expectedPrincipalGeneration ?? Generation,
        currentPrincipalGeneration ?? Generation, secret ?? Secret(), policy ?? Retention(), currentPolicyGeneration ?? new(2),
        grants ?? [LeaseGrant(action)], new(requestedGeneration ?? (action == LeaseAction.Revoke ? 1UL : 1UL)), new(duration), RevocationGeneration, existing);
    private static SurvivalSecretReference Reference() => new(
        SecretId, new(2), Cell, SecurityEnvironment.Production, SecretPurpose.Database, Digest());
    private static SurvivalSecretRequest Survival() => new(
        Operation, Cell, Generation, Generation, new(2), [Reference()], [Secret()], [Retention()]);
    private static SecurityDecisionReason Reason(SecurityDecision decision, SecurityDecisionCode code) =>
        decision.Trace.Single(reason => reason.Code == code);
    private static string Serialize(SecurityDecision decision) =>
        $"{decision.Authorized}|{decision.Intent.GetType().Name}|{string.Join(';', decision.Trace.Select(reason => $"{reason.Code}:{reason.Outcome}:{reason.Observed}:{reason.Required}"))}";
    private static bool Throws<T>(Action action) where T : Exception { try { action(); return false; } catch (T) { return true; } }
}
