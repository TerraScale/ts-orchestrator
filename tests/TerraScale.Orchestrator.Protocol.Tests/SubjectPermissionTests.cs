using TerraScale.Orchestrator.Protocol.Subjects;

namespace TerraScale.Orchestrator.Protocol.Tests;

public class SubjectPermissionTests
{
    [Test]
    public async Task Deny_wins_before_allow_and_reason_never_echoes_subject()
    {
        const string untrusted = "synthetic.private.payload-marker";
        var policy = CreatePolicy(
            [SubjectTestData.Pattern("synthetic.>")],
            [SubjectTestData.Pattern("synthetic.private.>")]);

        var decision = policy.Authorize(SubjectTestData.Subject(untrusted));

        await Assert.That(decision.IsAllowed).IsFalse();
        await Assert.That(decision.Reason).IsEqualTo(SubjectPermissionReason.DeniedByPattern);
        await Assert.That(decision.ToString()).DoesNotContain(untrusted); // SEC-NO-SECRET-OUTPUT
    }

    [Test]
    public async Task Denial_decision_never_echoes_credential_looking_subject_or_pattern()
    {
        const string credentialLooking = "credentials.sk_live_SUPERSECRET";
        var deniedPattern = SubjectTestData.Pattern(credentialLooking);
        var policy = CreatePolicy([SubjectTestData.Pattern("credentials.>")], [deniedPattern]);

        var decision = policy.Authorize(SubjectTestData.Subject(credentialLooking));
        var rendered = decision.ToString();

        await Assert.That(decision.Reason).IsEqualTo(SubjectPermissionReason.DeniedByPattern);
        await Assert.That(rendered).DoesNotContain(credentialLooking); // SEC-NO-SECRET-OUTPUT
        await Assert.That(rendered).DoesNotContain(deniedPattern.Value); // SEC-NO-SECRET-OUTPUT
        await Assert.That(rendered).DoesNotContain("SUPERSECRET"); // SEC-NO-SECRET-OUTPUT
    }

    [Test]
    public async Task Empty_allow_and_no_match_deny_by_default()
    {
        var empty = CreatePolicy([], []);
        var unmatched = CreatePolicy([SubjectTestData.Pattern("alpha.*")], []);

        var emptyDecision = empty.Authorize(SubjectTestData.Subject("alpha.beta"));
        var unmatchedDecision = unmatched.Authorize(SubjectTestData.Subject("other.beta"));
        var invalidDecision = unmatched.Authorize(null);

        await Assert.That(emptyDecision.IsAllowed).IsFalse();
        await Assert.That(emptyDecision.Reason).IsEqualTo(SubjectPermissionReason.DeniedEmptyAllowSet);
        await Assert.That(unmatchedDecision.Reason).IsEqualTo(SubjectPermissionReason.DeniedNoAllowMatch);
        await Assert.That(invalidDecision.Reason).IsEqualTo(SubjectPermissionReason.DeniedInvalidSubject);
        await Assert.That(default(SubjectPermissionDecision).IsAllowed).IsFalse();
        await Assert.That(default(SubjectPermissionDecision).Reason).IsEqualTo(SubjectPermissionReason.Uninitialized);
    }

    [Test]
    public async Task Matching_allow_returns_typed_success()
    {
        var policy = CreatePolicy([SubjectTestData.Pattern("alpha.*")], []);

        var decision = policy.Authorize(SubjectTestData.Subject("alpha.beta"));

        await Assert.That(decision.IsAllowed).IsTrue();
        await Assert.That(decision.Reason).IsEqualTo(SubjectPermissionReason.AllowedByPattern);
    }

    [Test]
    public async Task Policy_rejects_null_duplicate_cross_set_and_excess_patterns()
    {
        var limits = SubjectTestData.Limits(maximumPermissionPatternCount: 2);
        var alpha = SubjectTestData.Pattern("alpha.*");
        var beta = SubjectTestData.Pattern("beta.*");

        await Assert.That(SubjectPermissionPolicy.TryCreate(
            [alpha, null], [], limits, out _, out var nullError)).IsFalse();
        await Assert.That(nullError).IsEqualTo(SubjectPermissionPolicyError.NullPattern);
        await Assert.That(SubjectPermissionPolicy.TryCreate(
            [alpha, alpha], [], limits, out _, out var duplicateError)).IsFalse();
        await Assert.That(duplicateError).IsEqualTo(SubjectPermissionPolicyError.DuplicatePattern);
        await Assert.That(SubjectPermissionPolicy.TryCreate(
            [alpha], [alpha], limits, out _, out var crossError)).IsFalse();
        await Assert.That(crossError).IsEqualTo(SubjectPermissionPolicyError.PatternInAllowAndDeny);
        await Assert.That(SubjectPermissionPolicy.TryCreate(
            [alpha, beta], [SubjectTestData.Pattern("gamma.*")], limits, out _, out var countError)).IsFalse();
        await Assert.That(countError).IsEqualTo(SubjectPermissionPolicyError.TooManyPatterns);
        await Assert.That(SubjectPermissionPolicy.TryCreate(
            [alpha], [], null, out _, out var limitsError)).IsFalse();
        await Assert.That(limitsError).IsEqualTo(SubjectPermissionPolicyError.InvalidLimits);
    }

    [Test]
    public async Task Policy_count_budget_is_combined_without_overflow_and_invalid_limits_fail_closed()
    {
        var alpha = SubjectTestData.Pattern("alpha.*");
        var beta = SubjectTestData.Pattern("beta.*");
        var gamma = SubjectTestData.Pattern("gamma.*");
        var exactBudget = SubjectTestData.Limits(maximumPermissionPatternCount: 2);
        var maximumBudget = SubjectTestData.Limits(maximumPermissionPatternCount: int.MaxValue);

        await Assert.That(SubjectPermissionPolicy.TryCreate(
            [alpha], [beta], exactBudget, out var exactPolicy, out var exactError)).IsTrue();
        await Assert.That(exactError).IsEqualTo(SubjectPermissionPolicyError.None);
        await Assert.That(exactPolicy).IsNotNull();

        await Assert.That(SubjectPermissionPolicy.TryCreate(
            [alpha, beta], [gamma], exactBudget, out var excessPolicy, out var excessError)).IsFalse();
        await Assert.That(excessPolicy).IsNull();
        await Assert.That(excessError).IsEqualTo(SubjectPermissionPolicyError.TooManyPatterns);

        await Assert.That(SubjectPermissionPolicy.TryCreate(
            [alpha], [beta], maximumBudget, out var maximumPolicy, out var maximumError)).IsTrue();
        await Assert.That(maximumError).IsEqualTo(SubjectPermissionPolicyError.None);
        await Assert.That(maximumPolicy).IsNotNull();

        foreach (var invalid in new[] { 0, -1, int.MinValue })
        {
            await Assert.That(SubjectGrammarLimits.TryCreate(1, 1, 1, invalid, out var limits)).IsFalse();
            await Assert.That(limits).IsNull();
            await Assert.That(SubjectPermissionPolicy.TryCreate(
                [alpha], [], limits, out var policy, out var error)).IsFalse();
            await Assert.That(policy).IsNull();
            await Assert.That(error).IsEqualTo(SubjectPermissionPolicyError.InvalidLimits);
        }
    }

    [Test]
    public async Task Policy_defensively_copies_and_orders_patterns_canonically()
    {
        var allow = new List<SubjectPermissionPattern?>
        {
            SubjectTestData.Pattern("zeta.*"),
            SubjectTestData.Pattern("Alpha.*"),
            SubjectTestData.Pattern("alpha.*"),
        };
        var deny = new List<SubjectPermissionPattern?> { SubjectTestData.Pattern("blocked.>") };
        await Assert.That(SubjectPermissionPolicy.TryCreate(
            allow, deny, SubjectTestData.Limits(), out var policy, out var error)).IsTrue();

        allow.Clear();
        deny.Clear();

        await Assert.That(error).IsEqualTo(SubjectPermissionPolicyError.None);
        await Assert.That(policy!.AllowPatterns.Select(static pattern => pattern.Value).ToArray())
            .IsEquivalentTo(new[] { "Alpha.*", "alpha.*", "zeta.*" });
        await Assert.That(policy.AllowPatterns[0].Value).IsEqualTo("Alpha.*");
        await Assert.That(policy.AllowPatterns[1].Value).IsEqualTo("alpha.*");
        await Assert.That(policy.AllowPatterns[2].Value).IsEqualTo("zeta.*");
        await Assert.That(policy.DenyPatterns.Count).IsEqualTo(1);
        await Assert.That(policy.Authorize(SubjectTestData.Subject("alpha.one")).IsAllowed).IsTrue();
        await Assert.That(policy.Authorize(SubjectTestData.Subject("blocked.one")).Reason)
            .IsEqualTo(SubjectPermissionReason.DeniedByPattern);
    }

    [Test]
    public async Task Duplicate_detection_is_case_sensitive()
    {
        await Assert.That(SubjectPermissionPolicy.TryCreate(
            [SubjectTestData.Pattern("Alpha.*"), SubjectTestData.Pattern("alpha.*")],
            [],
            SubjectTestData.Limits(),
            out var policy,
            out var error)).IsTrue();

        await Assert.That(error).IsEqualTo(SubjectPermissionPolicyError.None);
        await Assert.That(policy!.AllowPatterns.Count).IsEqualTo(2);
    }

    private static SubjectPermissionPolicy CreatePolicy(
        IEnumerable<SubjectPermissionPattern?> allow,
        IEnumerable<SubjectPermissionPattern?> deny)
    {
        SubjectPermissionPolicy.TryCreate(
            allow,
            deny,
            SubjectTestData.Limits(),
            out var result,
            out _);
        return result!;
    }
}
