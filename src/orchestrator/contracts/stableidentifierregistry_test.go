// Port of tests/TerraScale.Orchestrator.ModelTests/StableIdentifierRegistryTests.cs.
// Registry completeness against the GOAL.md tables, verbatim canonical-text
// equality for every entry, identifier format validation, closed-set
// construction, the typed identifier surface, and supersession rules for the
// stable contract identifier registries. The C# static-property coverage
// checks use reflection; the Go port lists the typed surface explicitly.
package contracts

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var numericIdentifierPattern = regexp.MustCompile(`^(?:REQ|INV|SEC)-ORCH-\d{3}$`)
var namedIdentifierPattern = regexp.MustCompile(`^(?:SM|ERR)-ORCH-[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*$`)

var malformedNumericValues = []string{
	"REQ-ORCH-", "REQ-ORCH-1", "REQ-ORCH-01", "REQ-ORCH-0001", "REQ-ORCH-00A",
	"req-orch-001", "REQ-orch-001", " REQ-ORCH-001", "REQ-ORCH-001 ", "REQ-ORCH-001;", "SM-ORCH-BOOTSTRAP",
}

var malformedNamedValues = []string{
	"SM-ORCH-", "SM-ORCH-bootstrap", "SM-ORCH-Bootstrap", "SM-ORCH--BOOTSTRAP", "SM-ORCH-BOOTSTRAP-",
	"SM-ORCH-BOOT STRAP", "ERR-ORCH-", "ERR-ORCH-outcome-unknown", "REQ-ORCH-001",
}

var unregisteredValues = []string{
	"", " ", "REQ-ORCH-999", "REQ-ORCH-000", "REQ-ORCH-1", "REQ-ORCH-0001", "REQ-ORCH-00A",
	"req-orch-001", "REQ-orch-001", " REQ-ORCH-001", "REQ-ORCH-001 ", "REQ-ORCH-001;",
	"INV-ORCH-029", "SEC-ORCH-015", "SM-ORCH-bootstrap", "SM-ORCH-UNKNOWN-MACHINE",
	"ERR-ORCH-lowercase", "ERR-ORCH-UNKNOWN-ERROR",
}

func assertMatchesExactly(t *testing.T, actual, expected map[string]string) {
	t.Helper()
	missing := []string{}
	extra := []string{}
	changed := []string{}
	for id, text := range expected {
		if _, present := actual[id]; !present {
			missing = append(missing, id)
			continue
		}

		if actual[id] != text {
			changed = append(changed, id)
		}
	}

	for id := range actual {
		if _, present := expected[id]; !present {
			extra = append(extra, id)
		}
	}

	if len(missing) != 0 || len(extra) != 0 || len(changed) != 0 || len(actual) != len(expected) {
		t.Fatalf("registry mismatch: missing=%v extra=%v changed=%v", missing, extra, changed)
	}
}

func TestRegistryTranscribesEveryGoalRequirementExactly(t *testing.T) {
	registry := map[string]string{}
	for id, text := range StableIdentifierRegistry.Requirements() {
		registry[id.Value] = text
	}

	if len(registry) != 28 {
		t.Fatalf("requirement count = %d", len(registry))
	}

	assertMatchesExactly(t, registry, expectedRequirements())
}

func TestRegistryTranscribesEveryGoalInvariantExactly(t *testing.T) {
	registry := map[string]string{}
	for id, text := range StableIdentifierRegistry.Invariants() {
		registry[id.Value] = text
	}

	if len(registry) != 28 {
		t.Fatalf("invariant count = %d", len(registry))
	}

	assertMatchesExactly(t, registry, expectedInvariants())
}

func TestRegistryTranscribesEveryGoalSecurityRuleExactly(t *testing.T) {
	registry := map[string]string{}
	for id, text := range StableIdentifierRegistry.SecurityRules() {
		registry[id.Value] = text
	}

	if len(registry) != 14 {
		t.Fatalf("security rule count = %d", len(registry))
	}

	assertMatchesExactly(t, registry, expectedSecurityRules())
}

func TestRegistryTranscribesEveryGoalStateMachineExactly(t *testing.T) {
	registry := map[string]string{}
	for id, text := range StableIdentifierRegistry.StateMachines() {
		registry[id.Value] = text
	}

	if len(registry) != 18 {
		t.Fatalf("state machine count = %d", len(registry))
	}

	assertMatchesExactly(t, registry, expectedStateMachines())
}

func TestRegistryTranscribesEveryGoalStableErrorExactly(t *testing.T) {
	registry := map[string]string{}
	for id, text := range StableIdentifierRegistry.StableErrors() {
		registry[id.Value] = text
	}

	if len(registry) != 18 {
		t.Fatalf("stable error count = %d", len(registry))
	}

	assertMatchesExactly(t, registry, expectedStableErrors())
}

func findRepositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory unavailable: %v", err)
	}

	for hops := 0; hops < 12; hops++ {
		if _, err := os.Stat(filepath.Join(directory, "GOAL.md")); err == nil {
			return directory
		}

		directory = filepath.Dir(directory)
	}

	t.Fatal("the stable identifier tests could not locate GOAL.md within 12 parent directories.")
	return ""
}

func parseGoalTable(t *testing.T, lines []string, heading string) map[string]string {
	t.Helper()
	headingIndex := -1
	for index, line := range lines {
		if strings.TrimSpace(line) == heading {
			headingIndex = index
			break
		}
	}

	if headingIndex < 0 {
		t.Fatalf("GOAL.md does not contain the %s table.", heading)
	}

	rows := map[string]string{}
	for index := headingIndex + 1; index < len(lines); index++ {
		line := lines[index]
		if strings.HasPrefix(line, "#") {
			break
		}

		if !strings.HasPrefix(line, "|") {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) != 4 {
			continue
		}

		id := strings.TrimSpace(parts[1])
		if id == "ID" || !strings.HasPrefix(id, "`") {
			continue
		}

		rows[strings.Trim(id, "`")] = strings.TrimSpace(parts[2])
	}

	return rows
}

func TestRegistryMatchesTheGoalMarkdownSourceTables(t *testing.T) {
	goalBytes, err := os.ReadFile(filepath.Join(findRepositoryRoot(t), "GOAL.md"))
	if err != nil {
		t.Fatalf("GOAL.md unavailable: %v", err)
	}

	goal := strings.Split(string(goalBytes), "\n")
	assertMatchesExactly(t, parseGoalTable(t, goal, "### Requirements"), expectedRequirements())
	assertMatchesExactly(t, parseGoalTable(t, goal, "### Invariants"), expectedInvariants())
	assertMatchesExactly(t, parseGoalTable(t, goal, "### Security rules"), expectedSecurityRules())
	assertMatchesExactly(t, parseGoalTable(t, goal, "### State machines"), expectedStateMachines())
	assertMatchesExactly(t, parseGoalTable(t, goal, "### Stable errors"), expectedStableErrors())

	revised := ""
	for _, line := range goal {
		if strings.HasPrefix(line, "Last revised:") {
			revised = line
			break
		}
	}

	if revised == "" {
		t.Fatal("GOAL.md does not state a last-revised date.")
	}

	revision := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(revised, "Last revised:")), ".")
	if revision != RegistryRevision {
		t.Fatalf("GOAL.md revision %q != registry revision %q", revision, RegistryRevision)
	}
}

func assertNumericKind(t *testing.T, registry map[string]string, prefix string) {
	t.Helper()
	numbers := []int{}
	for identifier := range registry {
		if !numericIdentifierPattern.MatchString(identifier) {
			t.Fatalf("identifier %q is not numeric-shaped", identifier)
		}

		if !StableIdentifierFormat.IsNumericSuffixId(identifier, prefix) {
			t.Fatalf("identifier %q fails the numeric suffix rule", identifier)
		}

		if StableIdentifierFormat.IsNamedSuffixId(identifier, prefix) {
			t.Fatalf("identifier %q must not be named-shaped", identifier)
		}

		value, err := strconv.Atoi(identifier[len(prefix):])
		if err != nil {
			t.Fatalf("identifier %q suffix is not numeric", identifier)
		}

		numbers = append(numbers, value)
	}

	sort.Ints(numbers)
	if len(numbers) != len(registry) {
		t.Fatalf("number count %d != registry count %d", len(numbers), len(registry))
	}

	for expected := 1; expected <= len(numbers); expected++ {
		if numbers[expected-1] != expected {
			t.Fatalf("numeric suffixes must be contiguous from 1: %v", numbers)
		}
	}
}

func assertNamedKind(t *testing.T, registry map[string]string, prefix string) {
	t.Helper()
	for identifier := range registry {
		if !namedIdentifierPattern.MatchString(identifier) {
			t.Fatalf("identifier %q is not named-shaped", identifier)
		}

		if !StableIdentifierFormat.IsNamedSuffixId(identifier, prefix) {
			t.Fatalf("identifier %q fails the named suffix rule", identifier)
		}

		if StableIdentifierFormat.IsNumericSuffixId(identifier, prefix) {
			t.Fatalf("identifier %q must not be numeric-shaped", identifier)
		}
	}
}

func registryTexts[V interface{ ~struct{ Value string } }](registry map[V]string) map[string]string {
	result := map[string]string{}
	for id, text := range registry {
		result[id.Value] = text
	}

	return result
}

func TestNumericIdentifiersUsePrefixAndZeroPaddedContiguousSuffixes(t *testing.T) {
	assertNumericKind(t, registryTexts(StableIdentifierRegistry.Requirements()), StableIdentifierFormat.RequirementPrefix())
	assertNumericKind(t, registryTexts(StableIdentifierRegistry.Invariants()), StableIdentifierFormat.InvariantPrefix())
	assertNumericKind(t, registryTexts(StableIdentifierRegistry.SecurityRules()), StableIdentifierFormat.SecurityRulePrefix())

	for _, malformed := range malformedNumericValues {
		if StableIdentifierFormat.IsNumericSuffixId(malformed, StableIdentifierFormat.RequirementPrefix()) {
			t.Fatalf("value %q must fail the numeric suffix rule", malformed)
		}

		if numericIdentifierPattern.MatchString(malformed) {
			t.Fatalf("value %q must fail the numeric pattern", malformed)
		}
	}
}

func TestNamedIdentifiersUseUppercaseWordSuffixes(t *testing.T) {
	assertNamedKind(t, registryTexts(StableIdentifierRegistry.StateMachines()), StableIdentifierFormat.StateMachinePrefix())
	assertNamedKind(t, registryTexts(StableIdentifierRegistry.StableErrors()), StableIdentifierFormat.StableErrorPrefix())

	for _, malformed := range malformedNamedValues {
		if StableIdentifierFormat.IsNamedSuffixId(malformed, StableIdentifierFormat.StateMachinePrefix()) {
			t.Fatalf("value %q must fail the named suffix rule", malformed)
		}

		if namedIdentifierPattern.MatchString(malformed) {
			t.Fatalf("value %q must fail the named pattern", malformed)
		}
	}
}

func TestTryCreateAcceptsEveryRegisteredIdentifierAndRejectsEverythingElse(t *testing.T) {
	for id := range StableIdentifierRegistry.Requirements() {
		requirement, ok := RequirementIdTryCreate(id.Value)
		if !ok || requirement.Value != id.Value {
			t.Fatalf("requirement %q rejected", id.Value)
		}
	}

	for id := range StableIdentifierRegistry.Invariants() {
		invariant, ok := InvariantIdTryCreate(id.Value)
		if !ok || invariant.Value != id.Value {
			t.Fatalf("invariant %q rejected", id.Value)
		}
	}

	for id := range StableIdentifierRegistry.SecurityRules() {
		rule, ok := SecurityRuleIdTryCreate(id.Value)
		if !ok || rule.Value != id.Value {
			t.Fatalf("security rule %q rejected", id.Value)
		}
	}

	for id := range StableIdentifierRegistry.StateMachines() {
		machine, ok := StateMachineIdTryCreate(id.Value)
		if !ok || machine.Value != id.Value {
			t.Fatalf("state machine %q rejected", id.Value)
		}
	}

	for id := range StableIdentifierRegistry.StableErrors() {
		stableError, ok := StableErrorIdTryCreate(id.Value)
		if !ok || stableError.Value != id.Value {
			t.Fatalf("stable error %q rejected", id.Value)
		}
	}

	for _, rejected := range unregisteredValues {
		if requirement, ok := RequirementIdTryCreate(rejected); ok || requirement.IsRegistered() || requirement.Value != "" {
			t.Fatalf("requirement %q accepted", rejected)
		}

		if invariant, ok := InvariantIdTryCreate(rejected); ok || invariant.IsRegistered() {
			t.Fatalf("invariant %q accepted", rejected)
		}

		if rule, ok := SecurityRuleIdTryCreate(rejected); ok || rule.IsRegistered() {
			t.Fatalf("security rule %q accepted", rejected)
		}

		if machine, ok := StateMachineIdTryCreate(rejected); ok || machine.IsRegistered() {
			t.Fatalf("state machine %q accepted", rejected)
		}

		if stableError, ok := StableErrorIdTryCreate(rejected); ok || stableError.IsRegistered() {
			t.Fatalf("stable error %q accepted", rejected)
		}

		if fromCode, ok := StableErrorIdTryCreateFromCode(rejected); ok || fromCode.Code() != "" {
			t.Fatalf("error code %q accepted", rejected)
		}
	}

	assertPanics(t, func() { _ = RequirementId{}.CanonicalText() })
	assertPanics(t, func() { _ = StableErrorId{}.CanonicalText() })
}

func assertPanics(t *testing.T, action func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic for an unregistered identifier")
		}
	}()

	action()
}

// The typed identifier surface mirrors the C# static-property coverage via
// explicit lists of the exported well-known identifiers.
func typedRequirementSurface() []RequirementId {
	return []RequirementId{
		RequirementIdGlobalAuthority, RequirementIdThreeReplicaControllerGroups,
		RequirementIdJetStreamFileStorageR3, RequirementIdRegionalAutonomyDuringAuthorityLoss,
		RequirementIdRegionalJournalCompletenessAfterReconnect, RequirementIdGreenfieldOciEstateOwnership,
		RequirementIdTypedRegionScopedProviderActuators, RequirementIdAdmittedImmutableWorkloadPlacement,
		RequirementIdTerraBaseTwoMemberPlacement, RequirementIdProductServicesTwoInstancesPerRegion,
		RequirementIdWorkloadIdentityTrustAndBootstrapGrants, RequirementIdCloudflareRoutingTwentyRegionCeiling,
		RequirementIdExactArtifactDeliveryAdmission, RequirementIdSustainedCapacityAutoscaling,
		RequirementIdDurableProgressAndTerminalReceipts, RequirementIdControlStateBackupAndRestoreEvidence,
		RequirementIdTypedOperatorInterface, RequirementIdProductionReleaseQualification,
		RequirementIdTwentyRegionSimulation, RequirementIdNoControlPlaneLookupOnCustomerPath,
		RequirementIdNoEmbeddedDevelopmentComposition, RequirementIdParallelRegionalCandidateBeforeCutover,
		RequirementIdHostCapacityPublication, RequirementIdClosedWorkloadExecutionContract,
		RequirementIdResourceApiListWatchSurface, RequirementIdDependencyAwareDeletion,
		RequirementIdBoundedCoalescingWorkQueues, RequirementIdDisruptionSafeRebalancing,
	}
}

func typedInvariantSurface() []InvariantId {
	return []InvariantId{
		InvariantIdSingleAuthorityTermPerScope, InvariantIdGlobalPolicySingleWriter,
		InvariantIdRegionalMutationNeedsLocalTermAndQuorum, InvariantIdIsolatedRegionCannotCreateGlobalGeneration,
		InvariantIdObservationsAreNeverErased, InvariantIdDurableIntentBeforeExternalMutation,
		InvariantIdUnknownOutcomeReconciledBeforeRetry, InvariantIdSingleActiveLifecycleOwner,
		InvariantIdTagsNeverGrantAuthority, InvariantIdStaleLeaderCannotCompleteMutation,
		InvariantIdCommittedTargetFixedAcrossLeadership, InvariantIdNoCustomerDataInNats,
		InvariantIdTerraBaseAloneAcceptsMembership, InvariantIdScaleInPreservesDurabilityHeadroom,
		InvariantIdNoSecretsInStateOrTelemetry, InvariantIdExactQualifiedDigestActivation,
		InvariantIdDiscoveryAndPublicationAreSeparate, InvariantIdNoUnsafeIdentityReuse,
		InvariantIdAdmissionPrecedesCapacity, InvariantIdTelemetryNeverAuthorizesDestruction,
		InvariantIdNoInPlaceReleaseMutation, InvariantIdNoDevelopmentCompositionInProduction,
		InvariantIdCandidateTrafficGates, InvariantIdUniqueDurableEndpointLeases,
		InvariantIdDeletionBlockersHoldResources, InvariantIdObservedGenerationGate,
		InvariantIdPressureStopsPlacementBeforeEviction, InvariantIdBoundedQueueOverload,
	}
}

func typedSecurityRuleSurface() []SecurityRuleId {
	return []SecurityRuleId{
		SecurityRuleIdTls13MutualWorkloadIdentity, SecurityRuleIdNatsMutualTlsScopedIdentities,
		SecurityRuleIdDisjointIdentityPermissions, SecurityRuleIdRegionalCredentialScope,
		SecurityRuleIdGlobalControllersHoldNoRegionalCredentials, SecurityRuleIdSecretReferencesOnly,
		SecurityRuleIdNonExportablePrivateKeys, SecurityRuleIdBootstrapCredentialExpiry,
		SecurityRuleIdArtifactSupplyChainEvidence, SecurityRuleIdNoInboundSsh,
		SecurityRuleIdBoundedBreakGlassAccess, SecurityRuleIdSecretRedactionBeforeEmission,
		SecurityRuleIdNoDevelopmentTrustInProduction, SecurityRuleIdAccessThroughAllocationContract,
	}
}

func typedStateMachineSurface() []StateMachineId {
	return []StateMachineId{
		StateMachineIdBootstrap, StateMachineIdGlobalAuthority, StateMachineIdRegionalAuthority,
		StateMachineIdRegionAdmission, StateMachineIdRegionRemoval, StateMachineIdProviderOperation,
		StateMachineIdHostLifecycle, StateMachineIdWorkloadLifecycle, StateMachineIdMemberAdd,
		StateMachineIdMemberReplace, StateMachineIdCapacity, StateMachineIdRelease,
		StateMachineIdReconnect, StateMachineIdTrustRotation, StateMachineIdControlRestore,
		StateMachineIdNodePressure, StateMachineIdWorkloadRestart, StateMachineIdResourceDeletion,
	}
}

func typedStableErrorSurface() []StableErrorId {
	return []StableErrorId{
		StableErrorIdAuthorityUnavailable, StableErrorIdStaleTerm, StableErrorIdGenerationConflict,
		StableErrorIdRegionIsolated, StableErrorIdOutcomeUnknown, StableErrorIdOwnershipMismatch,
		StableErrorIdEvidenceIncomplete, StableErrorIdCapacityUnavailable, StableErrorIdBudgetApprovalRequired,
		StableErrorIdProviderLimit, StableErrorIdTerraBaseHold, StableErrorIdArtifactDenied,
		StableErrorIdRegionNotQualified, StableErrorIdRestoreGenerationConflict, StableErrorIdCandidateNotReady,
		StableErrorIdWorkloadQuarantined, StableErrorIdDeletionBlocked, StableErrorIdWatchExpired,
	}
}

func assertSurfaceCoversRegistry[V interface{ ~struct{ Value string } }](t *testing.T, surface []V, registry map[V]string) {
	t.Helper()
	surfaceValues := map[string]struct{}{}
	for _, identifier := range surface {
		surfaceValues[identifier.Value] = struct{}{}
	}

	registryValues := map[string]struct{}{}
	for id := range registry {
		registryValues[id.Value] = struct{}{}
	}

	if len(surfaceValues) != len(registryValues) {
		t.Fatalf("surface size %d != registry size %d", len(surfaceValues), len(registryValues))
	}

	for value := range surfaceValues {
		if _, present := registryValues[value]; !present {
			t.Fatalf("surface value %q is not registered", value)
		}
	}
}

func TestTypedIdentifierPropertiesCoverTheRegistryExactly(t *testing.T) {
	assertSurfaceCoversRegistry(t, typedRequirementSurface(), StableIdentifierRegistry.Requirements())
	assertSurfaceCoversRegistry(t, typedInvariantSurface(), StableIdentifierRegistry.Invariants())
	assertSurfaceCoversRegistry(t, typedSecurityRuleSurface(), StableIdentifierRegistry.SecurityRules())
	assertSurfaceCoversRegistry(t, typedStateMachineSurface(), StableIdentifierRegistry.StateMachines())
	assertSurfaceCoversRegistry(t, typedStableErrorSurface(), StableIdentifierRegistry.StableErrors())
}

func TestCanonicalTextMatchesRegistryTextForEveryIdentifier(t *testing.T) {
	for id, text := range StableIdentifierRegistry.Requirements() {
		if id.CanonicalText() != text {
			t.Fatalf("requirement %q canonical text differs", id.Value)
		}
	}

	for id, text := range StableIdentifierRegistry.Invariants() {
		if id.CanonicalText() != text {
			t.Fatalf("invariant %q canonical text differs", id.Value)
		}
	}

	for id, text := range StableIdentifierRegistry.SecurityRules() {
		if id.CanonicalText() != text {
			t.Fatalf("security rule %q canonical text differs", id.Value)
		}
	}

	for id, text := range StableIdentifierRegistry.StateMachines() {
		if id.CanonicalText() != text {
			t.Fatalf("state machine %q canonical text differs", id.Value)
		}
	}

	for id, text := range StableIdentifierRegistry.StableErrors() {
		if id.CanonicalText() != text {
			t.Fatalf("stable error %q canonical text differs", id.Value)
		}
	}

	if _, ok := (RequirementId{}).TryGetText(); ok {
		t.Fatal("default requirement must not resolve")
	}

	if _, ok := (StableErrorId{}).TryGetText(); ok {
		t.Fatal("default stable error must not resolve")
	}
}

func TestSupersessionsStartEmptyAndObeyTheReplacementRules(t *testing.T) {
	if len(StableIdentifierRegistry.Supersessions()) != 0 {
		t.Fatal("supersessions must start empty")
	}

	if violations := StableIdentifierRegistry.SupersessionViolations(); len(violations) != 0 {
		t.Fatalf("violations = %v", violations)
	}

	for id := range StableIdentifierRegistry.Requirements() {
		if _, superseded := id.SupersededBy(); superseded {
			t.Fatalf("requirement %q must not be superseded", id.Value)
		}
	}

	for id := range StableIdentifierRegistry.Invariants() {
		if _, superseded := id.SupersededBy(); superseded {
			t.Fatalf("invariant %q must not be superseded", id.Value)
		}
	}

	for id := range StableIdentifierRegistry.SecurityRules() {
		if _, superseded := id.SupersededBy(); superseded {
			t.Fatalf("security rule %q must not be superseded", id.Value)
		}
	}

	for id := range StableIdentifierRegistry.StateMachines() {
		if _, superseded := id.SupersededBy(); superseded {
			t.Fatalf("state machine %q must not be superseded", id.Value)
		}
	}

	for id := range StableIdentifierRegistry.StableErrors() {
		if _, superseded := id.SupersededBy(); superseded {
			t.Fatalf("stable error %q must not be superseded", id.Value)
		}
	}

	for retired := range StableIdentifierRegistry.Supersessions() {
		visited := map[string]struct{}{}
		current := retired
		for {
			next, present := StableIdentifierRegistry.Supersessions()[current]
			if !present {
				break
			}

			if _, cycle := visited[current]; cycle {
				t.Fatalf("supersession cycle at %q", current)
			}

			visited[current] = struct{}{}
			current = next
		}
	}
}

func TestStableErrorIdentifiersExposeTheErrorCodeStringSurface(t *testing.T) {
	if StableErrorIdOutcomeUnknown.Code() != "ERR-ORCH-OUTCOME-UNKNOWN" ||
		StableErrorIdOutcomeUnknown.Value != "ERR-ORCH-OUTCOME-UNKNOWN" ||
		StableErrorIdWatchExpired.String() != "ERR-ORCH-WATCH-EXPIRED" {
		t.Fatal("stable error code surface mismatch")
	}

	deletionBlocked, ok := StableErrorIdTryCreateFromCode("ERR-ORCH-DELETION-BLOCKED")
	if !ok || deletionBlocked != StableErrorIdDeletionBlocked {
		t.Fatal("error code round trip failed")
	}

	codes := map[string]struct{}{}
	for id := range StableIdentifierRegistry.StableErrors() {
		codes[id.Code()] = struct{}{}
	}

	if len(codes) != len(StableIdentifierRegistry.StableErrors()) {
		t.Fatal("error codes must be distinct")
	}

	for id := range StableIdentifierRegistry.StableErrors() {
		roundTrip, ok := StableErrorIdTryCreateFromCode(id.Code())
		if !ok || roundTrip != id {
			t.Fatalf("error code %q does not round trip", id.Code())
		}
	}
}
