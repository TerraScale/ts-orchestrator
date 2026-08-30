// This file ports tests/TerraScale.Orchestrator.Tests/
// McpWorkloadReconciliationTests.cs.
package runtime

import (
	"errors"
	"strings"
	"testing"
)

const mcpFirstDomain = "fault-domain-a"
const mcpSecondDomain = "fault-domain-b"
const mcpDeployedDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const mcpUpgradedDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var mcpOtherProductRoutes = []string{"platform-api", "authentication", "dashboard"}

var mcpOpenIngress = McpIngressEvidence{
	AuthenticationVerified:  true,
	ScopeDenialVerified:     true,
	TenantIsolationVerified: true,
	HealthVerified:          true,
	RollbackVerified:        true,
}

func mcpDesired(
	t *testing.T,
	changeKind McpChangeKind,
	digest string,
	generation int64,
) McpDesiredWorkload {
	t.Helper()
	desired, err := NewMcpDesiredWorkload(
		generation,
		mcpTestManifest(t, digest, HostArchitectureArm64),
		[]string{mcpFirstDomain, mcpSecondDomain},
		changeKind)
	if err != nil {
		t.Fatalf("desired: %v", err)
	}
	return desired
}

func mcpRoutesOpen(t *testing.T) McpProductRouteTable {
	t.Helper()
	return McpProductRouteTableWithRoutesOpen(
		append([]string{McpProductRouteTableMcpRouteName}, mcpOtherProductRoutes...))
}

func mcpReady(domain string, generation int64, digest string) McpInstanceObservation {
	return McpInstanceObservation{
		FailureDomain:  domain,
		Generation:     generation,
		ArtifactDigest: digest,
		Condition:      McpInstanceConditionReady,
	}
}

func mcpPlan(
	t *testing.T,
	desired McpDesiredWorkload,
	observations []McpInstanceObservation,
	routeTable McpProductRouteTable,
	ingressEvidence *McpIngressEvidence,
) McpReconciliationPlan {
	t.Helper()
	plan, err := McpWorkloadReconciler.Plan(desired, observations, routeTable, ingressEvidence)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return plan
}

func distinct(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func equivalentSets(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := map[string]int{}
	for _, value := range left {
		counts[value]++
	}
	for _, value := range right {
		counts[value]--
		if counts[value] < 0 {
			return false
		}
	}
	return true
}

func TestCreatePlansOneInstancePerFailureDomain(t *testing.T) {
	plan := mcpPlan(t, mcpDesired(t, McpChangeKindInitialCreation, mcpDeployedDigest, 1), nil, mcpRoutesOpen(t), &mcpOpenIngress)

	var kinds []McpInstanceActionKind
	var domains []string
	for _, action := range plan.InstanceActions {
		kinds = append(kinds, action.Kind)
		domains = append(domains, action.FailureDomain)
	}
	if !equivalentSets(toStrings(kinds, func(v McpInstanceActionKind) string { return v.String() }),
		[]string{"Create", "Create"}) {
		t.Fatalf("unexpected kinds %v", kinds)
	}
	if !equivalentSets(domains, []string{mcpFirstDomain, mcpSecondDomain}) {
		t.Fatalf("unexpected domains %v", domains)
	}
	if plan.Route != McpRouteDecisionCodeClosedNoHealthyBackend {
		t.Fatalf("unexpected route %v", plan.Route)
	}
}

func toStrings[T any](values []T, format func(T) string) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = format(value)
	}
	return result
}

func TestIdempotentRestartOfAConvergedWorkloadIsANoOp(t *testing.T) {
	plan := mcpPlan(t, mcpDesired(t, McpChangeKindInitialCreation, mcpDeployedDigest, 1),
		[]McpInstanceObservation{
			mcpReady(mcpFirstDomain, 1, mcpDeployedDigest),
			mcpReady(mcpSecondDomain, 1, mcpDeployedDigest),
		}, mcpRoutesOpen(t), &mcpOpenIngress)

	if len(plan.InstanceActions) != 0 {
		t.Fatalf("expected no actions, got %d", len(plan.InstanceActions))
	}
	if !equivalentSets(plan.HealthyFailureDomains, []string{mcpFirstDomain, mcpSecondDomain}) {
		t.Fatalf("unexpected healthy domains %v", plan.HealthyFailureDomains)
	}
	if plan.Route != McpRouteDecisionCodeOpen {
		t.Fatalf("unexpected route %v", plan.Route)
	}
}

func TestALostInstanceRestartsOnTheSameArtifactWithoutChangingTheRoute(t *testing.T) {
	plan := mcpPlan(t, mcpDesired(t, McpChangeKindInitialCreation, mcpDeployedDigest, 1),
		[]McpInstanceObservation{
			mcpReady(mcpFirstDomain, 1, mcpDeployedDigest),
			{FailureDomain: mcpSecondDomain, Generation: 1, ArtifactDigest: mcpDeployedDigest, Condition: McpInstanceConditionAbsent},
		}, mcpRoutesOpen(t), &mcpOpenIngress)

	if len(plan.InstanceActions) != 1 {
		t.Fatalf("expected one action, got %d", len(plan.InstanceActions))
	}
	restart := plan.InstanceActions[0]
	if restart.Kind != McpInstanceActionKindRestart || restart.FailureDomain != mcpSecondDomain {
		t.Fatalf("unexpected action %+v", restart)
	}
	if plan.Route != McpRouteDecisionCodeOpenDegraded {
		t.Fatalf("unexpected route %v", plan.Route)
	}
}

func TestTwoInstancesRouteStatelesslyWithNoStickySessions(t *testing.T) {
	plan := mcpPlan(t, mcpDesired(t, McpChangeKindInitialCreation, mcpDeployedDigest, 1),
		[]McpInstanceObservation{
			mcpReady(mcpFirstDomain, 1, mcpDeployedDigest),
			mcpReady(mcpSecondDomain, 1, mcpDeployedDigest),
		}, mcpRoutesOpen(t), &mcpOpenIngress)

	if plan.StickySessions() {
		t.Fatal("the stateless contract forbids sticky sessions")
	}
	first, err := plan.SelectBackend(0)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	second, err := plan.SelectBackend(1)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if first.FailureDomain != mcpFirstDomain || second.FailureDomain != mcpSecondDomain {
		t.Fatalf("unexpected selections %v %v", first, second)
	}
	// The same request sequence always selects the same backend: there is no
	// session state to pin, so selection is a pure function of the sequence
	// over the healthy set.
	again, err := plan.SelectBackend(0)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if again != first {
		t.Fatal("selection must be deterministic per sequence")
	}
}

func TestPartialFailureKeepsTheRouteServingAndReplacesTheFailedInstance(t *testing.T) {
	plan := mcpPlan(t, mcpDesired(t, McpChangeKindInitialCreation, mcpDeployedDigest, 1),
		[]McpInstanceObservation{
			mcpReady(mcpFirstDomain, 1, mcpDeployedDigest),
			{FailureDomain: mcpSecondDomain, Generation: 1, ArtifactDigest: mcpDeployedDigest, Condition: McpInstanceConditionFailed},
		}, mcpRoutesOpen(t), &mcpOpenIngress)

	if len(plan.InstanceActions) != 1 {
		t.Fatalf("expected one action, got %d", len(plan.InstanceActions))
	}
	replacement := plan.InstanceActions[0]
	if replacement.Kind != McpInstanceActionKindReplace {
		t.Fatalf("unexpected kind %v", replacement.Kind)
	}
	if replacement.ChangeKind != McpChangeKindRestart {
		t.Fatalf("unexpected change kind %v", replacement.ChangeKind)
	}
	if plan.Route != McpRouteDecisionCodeOpenDegraded {
		t.Fatalf("unexpected route %v", plan.Route)
	}
	backend, err := plan.SelectBackend(0)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if backend.FailureDomain != mcpFirstDomain {
		t.Fatalf("unexpected backend %v", backend)
	}
}

func TestAStaleGenerationIsHeldAndCannotOpenTheRoute(t *testing.T) {
	plan := mcpPlan(t, mcpDesired(t, McpChangeKindInitialCreation, mcpDeployedDigest, 1),
		[]McpInstanceObservation{
			mcpReady(mcpFirstDomain, 2, mcpDeployedDigest),
			mcpReady(mcpSecondDomain, 2, mcpDeployedDigest),
		}, mcpRoutesOpen(t), &mcpOpenIngress)

	if len(plan.InstanceActions) != 0 {
		t.Fatal("a stale writer must not act")
	}
	if len(plan.HealthyFailureDomains) != 0 {
		t.Fatal("a held domain is not healthy")
	}
	if plan.Route != McpRouteDecisionCodeClosedDesiredStale {
		t.Fatalf("unexpected route %v", plan.Route)
	}
	for _, hold := range plan.Holds {
		if !strings.Contains(hold, "exceeds-desired") {
			t.Fatalf("unexpected hold %q", hold)
		}
	}
}

func TestCrashRemovedDomainsAtANewerGenerationAreHeldNotRestarted(t *testing.T) {
	// Both failure domains lost their instances (Absent) after a NEWER fenced
	// writer advanced them to generation 2. A stale writer at desired
	// generation 1 must not restart either domain onto its older artifact: the
	// generation fence runs before the Absent branch, so the plan holds and the
	// route stays closed.
	plan := mcpPlan(t, mcpDesired(t, McpChangeKindInitialCreation, mcpDeployedDigest, 1),
		[]McpInstanceObservation{
			{FailureDomain: mcpFirstDomain, Generation: 2, ArtifactDigest: mcpDeployedDigest, Condition: McpInstanceConditionAbsent},
			{FailureDomain: mcpSecondDomain, Generation: 2, ArtifactDigest: mcpDeployedDigest, Condition: McpInstanceConditionAbsent},
		}, mcpRoutesOpen(t), &mcpOpenIngress)

	if len(plan.InstanceActions) != 0 {
		t.Fatal("a stale writer must not restart crash-removed domains")
	}
	if len(plan.HealthyFailureDomains) != 0 {
		t.Fatal("held domains are not healthy")
	}
	if plan.Route != McpRouteDecisionCodeClosedDesiredStale {
		t.Fatalf("unexpected route %v", plan.Route)
	}
	if len(plan.Holds) != 2 {
		t.Fatalf("expected two holds, got %d", len(plan.Holds))
	}
}

func TestOneHeldStaleDomainStillClosesTheRouteAndNeverActsOnIt(t *testing.T) {
	plan := mcpPlan(t, mcpDesired(t, McpChangeKindInitialCreation, mcpDeployedDigest, 1),
		[]McpInstanceObservation{
			mcpReady(mcpFirstDomain, 1, mcpDeployedDigest),
			mcpReady(mcpSecondDomain, 2, mcpDeployedDigest),
		}, mcpRoutesOpen(t), &mcpOpenIngress)

	if len(plan.InstanceActions) != 0 {
		t.Fatal("held domains must not be acted on")
	}
	if !equivalentSets(plan.HealthyFailureDomains, []string{mcpFirstDomain}) {
		t.Fatalf("unexpected healthy domains %v", plan.HealthyFailureDomains)
	}
	if plan.Route != McpRouteDecisionCodeClosedDesiredStale {
		t.Fatalf("unexpected route %v", plan.Route)
	}
}

func TestAnUpgradeConvergesEveryDomainOntoTheNewQualifiedDigest(t *testing.T) {
	desired := mcpDesired(t, McpChangeKindUpgrade, mcpUpgradedDigest, 2)
	plan := mcpPlan(t, desired,
		[]McpInstanceObservation{
			mcpReady(mcpFirstDomain, 1, mcpDeployedDigest),
			mcpReady(mcpSecondDomain, 1, mcpDeployedDigest),
		}, mcpRoutesOpen(t), &mcpOpenIngress)

	var kinds, digests, changeKinds []string
	for _, action := range plan.InstanceActions {
		kinds = append(kinds, action.Kind.String())
		digests = append(digests, action.ArtifactDigest)
		changeKinds = append(changeKinds, action.ChangeKind.String())
	}
	if !equivalentSets(kinds, []string{"Converge", "Converge"}) {
		t.Fatalf("unexpected kinds %v", kinds)
	}
	if !equivalentSets(distinct(digests), []string{mcpUpgradedDigest}) {
		t.Fatalf("unexpected digests %v", digests)
	}
	if !equivalentSets(distinct(changeKinds), []string{"Upgrade"}) {
		t.Fatalf("unexpected change kinds %v", changeKinds)
	}
	if len(plan.HealthyFailureDomains) != 0 {
		t.Fatal("upgrading domains are not yet healthy")
	}
	if plan.Route != McpRouteDecisionCodeClosedNoHealthyBackend {
		t.Fatalf("unexpected route %v", plan.Route)
	}
}

func TestARollbackConvergesBackToThePreviousQualifiedDigest(t *testing.T) {
	afterUpgrade := mcpPlan(t, mcpDesired(t, McpChangeKindUpgrade, mcpUpgradedDigest, 2),
		[]McpInstanceObservation{
			mcpReady(mcpFirstDomain, 2, mcpUpgradedDigest),
			mcpReady(mcpSecondDomain, 2, mcpUpgradedDigest),
		}, mcpRoutesOpen(t), &mcpOpenIngress)
	if !equivalentSets(afterUpgrade.HealthyFailureDomains, []string{mcpFirstDomain, mcpSecondDomain}) {
		t.Fatalf("unexpected healthy domains %v", afterUpgrade.HealthyFailureDomains)
	}

	rollback := mcpPlan(t, mcpDesired(t, McpChangeKindRollback, mcpDeployedDigest, 3),
		[]McpInstanceObservation{
			mcpReady(mcpFirstDomain, 2, mcpUpgradedDigest),
			mcpReady(mcpSecondDomain, 2, mcpUpgradedDigest),
		}, mcpRoutesOpen(t), &mcpOpenIngress)

	var kinds, digests, changeKinds []string
	for _, action := range rollback.InstanceActions {
		kinds = append(kinds, action.Kind.String())
		digests = append(digests, action.ArtifactDigest)
		changeKinds = append(changeKinds, action.ChangeKind.String())
	}
	if !equivalentSets(kinds, []string{"Converge", "Converge"}) {
		t.Fatalf("unexpected kinds %v", kinds)
	}
	if !equivalentSets(distinct(digests), []string{mcpDeployedDigest}) {
		t.Fatalf("unexpected digests %v", digests)
	}
	if !equivalentSets(distinct(changeKinds), []string{"Rollback"}) {
		t.Fatalf("unexpected change kinds %v", changeKinds)
	}
}

func TestDriftAtTheSameGenerationIsRepairedByConvergence(t *testing.T) {
	plan := mcpPlan(t, mcpDesired(t, McpChangeKindInitialCreation, mcpDeployedDigest, 1),
		[]McpInstanceObservation{
			mcpReady(mcpFirstDomain, 1, mcpDeployedDigest),
			mcpReady(mcpSecondDomain, 1, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
		}, mcpRoutesOpen(t), &mcpOpenIngress)

	if len(plan.InstanceActions) != 1 {
		t.Fatalf("expected one action, got %d", len(plan.InstanceActions))
	}
	repair := plan.InstanceActions[0]
	if repair.Kind != McpInstanceActionKindConverge {
		t.Fatalf("unexpected kind %v", repair.Kind)
	}
	if !strings.Contains(repair.Reason, "drifted") {
		t.Fatalf("unexpected reason %q", repair.Reason)
	}
}

func TestIngressStaysClosedUntilTheLiveEvidenceBundlePasses(t *testing.T) {
	plan := mcpPlan(t, mcpDesired(t, McpChangeKindInitialCreation, mcpDeployedDigest, 1),
		[]McpInstanceObservation{
			mcpReady(mcpFirstDomain, 1, mcpDeployedDigest),
			mcpReady(mcpSecondDomain, 1, mcpDeployedDigest),
		}, mcpRoutesOpen(t), &McpIngressEvidenceNone)

	if plan.Route != McpRouteDecisionCodeClosedIngressNotProven {
		t.Fatalf("unexpected route %v", plan.Route)
	}
}

func TestEmergencyWithdrawalClosesOnlyTheMcpRoute(t *testing.T) {
	table := mcpRoutesOpen(t)
	withdrawal := McpEmergencyRouteControl.Withdraw(table)

	if !equivalentSets(withdrawal.ClosedRoutes, []string{McpProductRouteTableMcpRouteName}) {
		t.Fatalf("unexpected closed routes %v", withdrawal.ClosedRoutes)
	}
	if !equivalentSets(withdrawal.UntouchedRoutes, mcpOtherProductRoutes) {
		t.Fatalf("unexpected untouched routes %v", withdrawal.UntouchedRoutes)
	}
	if !equivalentSets(withdrawal.UntouchedDistributionChannels, []string{"stdio"}) {
		t.Fatalf("unexpected channels %v", withdrawal.UntouchedDistributionChannels)
	}
	if !equivalentSets(withdrawal.RemainingRoutes.OpenRouteNames(), mcpOtherProductRoutes) {
		t.Fatalf("unexpected remaining open routes %v", withdrawal.RemainingRoutes.OpenRouteNames())
	}

	plan := mcpPlan(t, mcpDesired(t, McpChangeKindInitialCreation, mcpDeployedDigest, 1),
		[]McpInstanceObservation{
			mcpReady(mcpFirstDomain, 1, mcpDeployedDigest),
			mcpReady(mcpSecondDomain, 1, mcpDeployedDigest),
		}, withdrawal.RemainingRoutes, &mcpOpenIngress)

	if plan.Route != McpRouteDecisionCodeClosedByEmergencyWithdrawal {
		t.Fatalf("unexpected route %v", plan.Route)
	}
	// Withdrawal is a route action: the instances stay ready and untouched.
	if !equivalentSets(plan.HealthyFailureDomains, []string{mcpFirstDomain, mcpSecondDomain}) {
		t.Fatalf("unexpected healthy domains %v", plan.HealthyFailureDomains)
	}
	if len(plan.InstanceActions) != 0 {
		t.Fatal("withdrawal must not touch instances")
	}
}

func TestTheDesiredPlacementRequiresTwoIndependentFailureDomains(t *testing.T) {
	if _, err := NewMcpDesiredWorkload(1, mcpTestManifest(t, mcpDeployedDigest, HostArchitectureArm64),
		[]string{"same-domain", "same-domain"}, McpChangeKindInitialCreation); err == nil {
		t.Fatal("duplicate failure domains must be rejected")
	}
	if _, err := NewMcpDesiredWorkload(1, mcpTestManifest(t, mcpDeployedDigest, HostArchitectureArm64),
		[]string{"only-one"}, McpChangeKindInitialCreation); err == nil {
		t.Fatal("a single failure domain must be rejected")
	}
	var rangeError *ArgumentOutOfRangeError
	_, err := NewMcpDesiredWorkload(0, mcpTestManifest(t, mcpDeployedDigest, HostArchitectureArm64),
		[]string{mcpFirstDomain, mcpSecondDomain}, McpChangeKindInitialCreation)
	if !errors.As(err, &rangeError) {
		t.Fatalf("expected ArgumentOutOfRangeError, got %v", err)
	}
}

func TestRoutingWithoutAHealthyBackendFailsClosed(t *testing.T) {
	plan := mcpPlan(t, mcpDesired(t, McpChangeKindInitialCreation, mcpDeployedDigest, 1), nil, mcpRoutesOpen(t), &mcpOpenIngress)

	var operationError *InvalidOperationError
	if _, err := plan.SelectBackend(0); !errors.As(err, &operationError) {
		t.Fatalf("expected InvalidOperationError, got %v", err)
	}
}

func TestBackendSelectionRejectsNegativeRequestSequences(t *testing.T) {
	plan := mcpPlan(t, mcpDesired(t, McpChangeKindInitialCreation, mcpDeployedDigest, 1),
		[]McpInstanceObservation{
			mcpReady(mcpFirstDomain, 1, mcpDeployedDigest),
			mcpReady(mcpSecondDomain, 1, mcpDeployedDigest),
		}, mcpRoutesOpen(t), &mcpOpenIngress)

	var rangeError *ArgumentOutOfRangeError
	if _, err := plan.SelectBackend(-1); !errors.As(err, &rangeError) {
		t.Fatalf("expected ArgumentOutOfRangeError, got %v", err)
	}
	// The guard is the first check: even a plan without healthy backends
	// refuses a negative sequence with the argument guard rather than the
	// routing failure.
	empty := mcpPlan(t, mcpDesired(t, McpChangeKindInitialCreation, mcpDeployedDigest, 1), nil, mcpRoutesOpen(t), &mcpOpenIngress)
	if _, err := empty.SelectBackend(-1); !errors.As(err, &rangeError) {
		t.Fatalf("expected ArgumentOutOfRangeError, got %v", err)
	}
}
