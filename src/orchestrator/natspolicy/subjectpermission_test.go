package natspolicy

import (
	"strings"
	"testing"
)

func createTestPolicy(allow, deny []*SubjectPermissionPattern) *SubjectPermissionPolicy {
	policy, _ := SubjectPermissionPolicyTryCreate(allow, deny, defaultTestLimits())
	return policy
}

func TestDenyWinsBeforeAllowAndReasonNeverEchoesSubject(t *testing.T) {
	untrusted := "synthetic.private.payload-marker"
	policy := createTestPolicy(
		[]*SubjectPermissionPattern{testPattern("synthetic.>", defaultTestLimits())},
		[]*SubjectPermissionPattern{testPattern("synthetic.private.>", defaultTestLimits())})

	decision := policy.Authorize(testConcreteSubject(untrusted, defaultTestLimits()))

	if decision.IsAllowed() {
		t.Fatal("deny must win before allow")
	}

	if decision.Reason != SubjectPermissionReasonDeniedByPattern {
		t.Fatalf("reason = %v", decision.Reason)
	}

	if strings.Contains(decision.String(), untrusted) { // SEC-NO-SECRET-OUTPUT
		t.Fatal("decision must not echo the subject")
	}
}

func TestDenialDecisionNeverEchoesCredentialLookingSubjectOrPattern(t *testing.T) {
	credentialLooking := "credentials.sk_live_SUPERSECRET"
	deniedPattern := testPattern(credentialLooking, defaultTestLimits())
	policy := createTestPolicy(
		[]*SubjectPermissionPattern{testPattern("credentials.>", defaultTestLimits())},
		[]*SubjectPermissionPattern{deniedPattern})

	decision := policy.Authorize(testConcreteSubject(credentialLooking, defaultTestLimits()))
	rendered := decision.String()

	if decision.Reason != SubjectPermissionReasonDeniedByPattern {
		t.Fatalf("reason = %v", decision.Reason)
	}

	for _, forbidden := range []string{credentialLooking, deniedPattern.Value(), "SUPERSECRET"} { // SEC-NO-SECRET-OUTPUT
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("decision rendered %q", forbidden)
		}
	}
}

func TestEmptyAllowAndNoMatchDenyByDefault(t *testing.T) {
	empty := createTestPolicy(nil, nil)
	unmatched := createTestPolicy([]*SubjectPermissionPattern{testPattern("alpha.*", defaultTestLimits())}, nil)

	emptyDecision := empty.Authorize(testConcreteSubject("alpha.beta", defaultTestLimits()))
	unmatchedDecision := unmatched.Authorize(testConcreteSubject("other.beta", defaultTestLimits()))
	invalidDecision := unmatched.Authorize(nil)

	if emptyDecision.IsAllowed() || emptyDecision.Reason != SubjectPermissionReasonDeniedEmptyAllowSet {
		t.Fatalf("empty allow decision = %v", emptyDecision.Reason)
	}

	if unmatchedDecision.Reason != SubjectPermissionReasonDeniedNoAllowMatch {
		t.Fatalf("unmatched decision = %v", unmatchedDecision.Reason)
	}

	if invalidDecision.Reason != SubjectPermissionReasonDeniedInvalidSubject {
		t.Fatalf("invalid subject decision = %v", invalidDecision.Reason)
	}

	var zero SubjectPermissionDecision
	if zero.IsAllowed() || zero.Reason != SubjectPermissionReasonUninitialized {
		t.Fatal("default decision must be uninitialized and denied")
	}
}

func TestMatchingAllowReturnsTypedSuccess(t *testing.T) {
	policy := createTestPolicy([]*SubjectPermissionPattern{testPattern("alpha.*", defaultTestLimits())}, nil)

	decision := policy.Authorize(testConcreteSubject("alpha.beta", defaultTestLimits()))

	if !decision.IsAllowed() || decision.Reason != SubjectPermissionReasonAllowedByPattern {
		t.Fatalf("decision = %v", decision.Reason)
	}
}

func TestPolicyRejectsNullDuplicateCrossSetAndExcessPatterns(t *testing.T) {
	limits := testLimits(128, 16, 32, 2)
	alpha := testPattern("alpha.*", limits)
	beta := testPattern("beta.*", limits)

	if _, err := SubjectPermissionPolicyTryCreate([]*SubjectPermissionPattern{alpha, nil}, nil, limits); err != SubjectPermissionPolicyErrorNullPattern {
		t.Fatalf("error = %v", err)
	}

	if _, err := SubjectPermissionPolicyTryCreate([]*SubjectPermissionPattern{alpha, alpha}, nil, limits); err != SubjectPermissionPolicyErrorDuplicatePattern {
		t.Fatalf("error = %v", err)
	}

	if _, err := SubjectPermissionPolicyTryCreate([]*SubjectPermissionPattern{alpha}, []*SubjectPermissionPattern{alpha}, limits); err != SubjectPermissionPolicyErrorPatternInAllowAndDeny {
		t.Fatalf("error = %v", err)
	}

	if _, err := SubjectPermissionPolicyTryCreate([]*SubjectPermissionPattern{alpha, beta},
		[]*SubjectPermissionPattern{testPattern("gamma.*", limits)}, limits); err != SubjectPermissionPolicyErrorTooManyPatterns {
		t.Fatalf("error = %v", err)
	}

	if _, err := SubjectPermissionPolicyTryCreate([]*SubjectPermissionPattern{alpha}, nil, nil); err != SubjectPermissionPolicyErrorInvalidLimits {
		t.Fatalf("error = %v", err)
	}
}

func TestPolicyCountBudgetIsCombinedWithoutOverflowAndInvalidLimitsFailClosed(t *testing.T) {
	alpha := testPattern("alpha.*", defaultTestLimits())
	beta := testPattern("beta.*", defaultTestLimits())
	gamma := testPattern("gamma.*", defaultTestLimits())
	exactBudget := testLimits(128, 16, 32, 2)
	maximumBudget := testLimits(128, 16, 32, 1<<31-1)

	if policy, err := SubjectPermissionPolicyTryCreate([]*SubjectPermissionPattern{alpha},
		[]*SubjectPermissionPattern{beta}, exactBudget); err != SubjectPermissionPolicyErrorNone || policy == nil {
		t.Fatalf("exact budget rejected: %v", err)
	}

	if policy, err := SubjectPermissionPolicyTryCreate([]*SubjectPermissionPattern{alpha, beta},
		[]*SubjectPermissionPattern{gamma}, exactBudget); err != SubjectPermissionPolicyErrorTooManyPatterns || policy != nil {
		t.Fatalf("excess budget error = %v", err)
	}

	if policy, err := SubjectPermissionPolicyTryCreate([]*SubjectPermissionPattern{alpha},
		[]*SubjectPermissionPattern{beta}, maximumBudget); err != SubjectPermissionPolicyErrorNone || policy == nil {
		t.Fatalf("maximum budget rejected: %v", err)
	}

	for _, invalid := range []int{0, -1, -1 << 31} {
		limits, ok := SubjectGrammarLimitsTryCreate(1, 1, 1, invalid)
		if ok || limits != nil {
			t.Fatalf("limits accepted %d", invalid)
		}

		if policy, err := SubjectPermissionPolicyTryCreate([]*SubjectPermissionPattern{alpha}, nil, limits); err != SubjectPermissionPolicyErrorInvalidLimits || policy != nil {
			t.Fatalf("invalid limits error = %v", err)
		}
	}
}

func TestPolicyDefensivelyCopiesAndOrdersPatternsCanonically(t *testing.T) {
	allow := []*SubjectPermissionPattern{
		testPattern("zeta.*", defaultTestLimits()),
		testPattern("Alpha.*", defaultTestLimits()),
		testPattern("alpha.*", defaultTestLimits()),
	}
	deny := []*SubjectPermissionPattern{testPattern("blocked.>", defaultTestLimits())}
	policy, err := SubjectPermissionPolicyTryCreate(allow, deny, defaultTestLimits())
	if err != SubjectPermissionPolicyErrorNone {
		t.Fatalf("error = %v", err)
	}

	// Mutate every source element; the policy must hold its own copies.
	for index := range allow {
		allow[index] = nil
	}

	deny[0] = nil

	values := []string{}
	for _, pattern := range policy.AllowPatterns() {
		values = append(values, pattern.Value())
	}

	if len(values) != 3 || values[0] != "Alpha.*" || values[1] != "alpha.*" || values[2] != "zeta.*" {
		t.Fatalf("allow order = %v", values)
	}

	if len(policy.DenyPatterns()) != 1 {
		t.Fatal("deny list must be copied")
	}

	if !policy.Authorize(testConcreteSubject("alpha.one", defaultTestLimits())).IsAllowed() {
		t.Fatal("policy must allow alpha.one")
	}

	if policy.Authorize(testConcreteSubject("blocked.one", defaultTestLimits())).Reason != SubjectPermissionReasonDeniedByPattern {
		t.Fatal("policy must deny blocked.one")
	}
}

func TestDuplicateDetectionIsCaseSensitive(t *testing.T) {
	policy, err := SubjectPermissionPolicyTryCreate([]*SubjectPermissionPattern{
		testPattern("Alpha.*", defaultTestLimits()),
		testPattern("alpha.*", defaultTestLimits()),
	}, nil, defaultTestLimits())

	if err != SubjectPermissionPolicyErrorNone {
		t.Fatalf("error = %v", err)
	}

	if len(policy.AllowPatterns()) != 2 {
		t.Fatal("case-distinct patterns must both be kept")
	}
}
