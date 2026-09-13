using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Security;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class SecurityFourthAuditRegressionTests
{
    [Test]
    public async Task Exact_issue_and_attestation_intents_retain_current_principal_high_water()
    {
        var issueRequest = Request(5, 5, EvidenceStatus.Valid);
        var issue = SecurityDecisionEngine.EvaluateEnrollment(issueRequest);
        await Assert.That(issue.Authorized).IsTrue();
        var issueIntent = (IssueIdentityIntent)issue.Intent;
        await Assert.That(ReferenceEquals(issueIntent.Request, issueRequest)).IsTrue();
        await Assert.That(ReferenceEquals(issueIntent.Request.CurrentPrincipalGeneration,
            issueRequest.CurrentPrincipalGeneration)).IsTrue();

        var attestRequest = Request(5, 5, EvidenceStatus.Missing);
        var attest = SecurityDecisionEngine.EvaluateEnrollment(attestRequest);
        await Assert.That(attest.Authorized).IsTrue();
        var attestIntent = (AttestIdentityIntent)attest.Intent;
        await Assert.That(ReferenceEquals(attestIntent.Request, attestRequest)).IsTrue();
        await Assert.That(ReferenceEquals(attestIntent.Request.CurrentPrincipalGeneration,
            attestRequest.CurrentPrincipalGeneration)).IsTrue();
    }

    [Test]
    public async Task Coherent_lower_future_and_missing_attestation_replays_are_denied()
    {
        foreach (var (principal, status) in new[]
                 {
                     (4UL, EvidenceStatus.Valid),
                     (6UL, EvidenceStatus.Valid),
                     (4UL, EvidenceStatus.Missing),
                 })
        {
            var decision = SecurityDecisionEngine.EvaluateEnrollment(Request(principal, 5, status));
            var generation = decision.Trace.Single(reason =>
                reason.Code == SecurityDecisionCode.GenerationCurrent);

            await Assert.That(decision.Authorized).IsFalse();
            await Assert.That(decision.Intent).IsTypeOf<HoldSecurityOperationIntent>();
            await Assert.That(decision.Intent is not IssueIdentityIntent and not AttestIdentityIntent).IsTrue();
            await Assert.That(generation.Outcome).IsEqualTo(SecurityDecisionOutcome.Rejected);
            await Assert.That(generation.Observed).IsEqualTo(principal);
            await Assert.That(generation.Required).IsEqualTo(5UL);
        }
    }

    [Test]
    public async Task Current_principal_high_water_is_mandatory_get_only_and_max_safe()
    {
        var exact = Request(5, 5, EvidenceStatus.Valid);
        await Assert.That(Throws<ArgumentNullException>(() => new EnrollmentRequest(
            exact.OperationId,
            exact.ExpectedPrincipal,
            null!,
            exact.SubjectKeyId,
            exact.AttestationPolicyGeneration,
            exact.Issuer,
            exact.CurrentIssuerGeneration,
            exact.CurrentRevocationGeneration,
            exact.BootstrapEvidence,
            exact.Attestations))).IsTrue();

        var property = typeof(EnrollmentRequest).GetProperty(nameof(EnrollmentRequest.CurrentPrincipalGeneration));
        await Assert.That(property).IsNotNull();
        await Assert.That(property!.SetMethod).IsNull();
        var generationCurrentCode = Convert.ToInt32(
            Enum.Parse<SecurityDecisionCode>(nameof(SecurityDecisionCode.GenerationCurrent)));
        await Assert.That(generationCurrentCode).IsEqualTo(8);

        var maximum = SecurityDecisionEngine.EvaluateEnrollment(Request(ulong.MaxValue, ulong.MaxValue,
            EvidenceStatus.Valid));
        await Assert.That(maximum.Authorized).IsTrue();
        await Assert.That(maximum.Intent).IsTypeOf<IssueIdentityIntent>();
        var reason = maximum.Trace.Single(value => value.Code == SecurityDecisionCode.GenerationCurrent);
        await Assert.That(reason.Observed).IsEqualTo(ulong.MaxValue);
        await Assert.That(reason.Required).IsEqualTo(ulong.MaxValue);
    }

    [Test]
    public async Task Enrollment_request_has_one_closed_non_optional_construction_surface()
    {
        var constructors = typeof(EnrollmentRequest).GetConstructors();
        await Assert.That(constructors).HasSingleItem();
        var parameters = constructors.Single().GetParameters();
        var expected = new[]
        {
            typeof(SecurityOperationId),
            typeof(SecurityPrincipal),
            typeof(SecurityGeneration),
            typeof(SecurityKeyId),
            typeof(SecurityGeneration),
            typeof(IssuerSigningCapability),
            typeof(SecurityGeneration),
            typeof(SecurityGeneration),
            typeof(IEnumerable<BootstrapEnrollmentEvidence>),
            typeof(IEnumerable<SecurityAttestationEvidence>),
        };
        var signatureMatches = parameters.Select(parameter => parameter.ParameterType).SequenceEqual(expected);
        await Assert.That(signatureMatches).IsTrue();
        await Assert.That(parameters.All(parameter => !parameter.IsOptional && !parameter.HasDefaultValue)).IsTrue();

        var factories = typeof(EnrollmentRequest).GetMethods(
                System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Where(method => method.ReturnType == typeof(EnrollmentRequest));
        await Assert.That(factories).IsEmpty();
    }

    [Test]
    public async Task Coherent_replay_trace_is_culture_stable_and_preserves_reason_order()
    {
        string? baseline = null;
        foreach (var cultureName in new[] { "en-US", "tr-TR", "ar-SA", "ja-JP" })
        {
            var original = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultureName);
                var decision = SecurityDecisionEngine.EvaluateEnrollment(Request(4, 5, EvidenceStatus.Valid));
                var fingerprint = string.Join(';', decision.Trace.Select(reason =>
                    $"{reason.Code}:{reason.Outcome}:{reason.Observed}:{reason.Required}"));
                baseline ??= fingerprint;
                await Assert.That(fingerprint).IsEqualTo(baseline);
                await Assert.That(decision.Trace[8].Code).IsEqualTo(SecurityDecisionCode.GenerationCurrent);
            }
            finally
            {
                CultureInfo.CurrentCulture = original;
            }
        }
    }

    private static EnrollmentRequest Request(ulong principalGeneration, ulong currentGeneration,
        EvidenceStatus attestationStatus)
    {
        var operation = new SecurityOperationId("enrollment-operation");
        var cell = new SecurityCellId("gru");
        var generation = new SecurityGeneration(principalGeneration);
        var principal = new SecurityPrincipal(new("principal"), SecurityPrincipalKind.Node,
            SecurityRole.Agent, cell, generation);
        var subjectKey = new SecurityKeyId("subject-key");
        return new EnrollmentRequest(
            operation,
            principal,
            new SecurityGeneration(currentGeneration),
            subjectKey,
            new SecurityGeneration(2),
            new IssuerSigningCapability(new("issuer-gru"), IssuerCapabilityKind.RegionalIntermediate,
                cell, TrustScope.Cell, new(1), new(3)),
            new SecurityGeneration(1),
            new SecurityGeneration(3),
            [new BootstrapEnrollmentEvidence(new("bootstrap"), operation, principal.Id, principal.Kind,
                cell, principal.Role, generation, EvidenceStatus.Valid)],
            [new SecurityAttestationEvidence(new("attestation"), new(new string('a', 64)), principal.Id,
                subjectKey, principal.Kind, cell, principal.Role, generation, new(2), attestationStatus)]);
    }

    private static bool Throws<T>(Action action) where T : Exception
    {
        try { action(); return false; }
        catch (T) { return true; }
    }
}

