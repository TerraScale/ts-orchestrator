// Registry completeness against the GOAL.md tables, verbatim canonical-text
// equality for every entry, identifier format validation, closed-set
// construction, the typed identifier surface, and supersession rules for the
// stable contract identifier registries. The C# static-property coverage
// checks use reflection; the Go port lists the typed surface explicitly.
package contracts

import (
	"fmt"
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

func registryTexts[V interface {
	comparable
	fmt.Stringer
}](registry map[V]string) map[string]string {
	result := map[string]string{}
	for id, text := range registry {
		result[id.String()] = text
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

	invalidCanonicalText := []struct {
		name    string
		resolve func() (string, error)
	}{
		{"requirement", func() (string, error) { return (RequirementId{}).CanonicalText() }},
		{"invariant", func() (string, error) { return (InvariantId{}).CanonicalText() }},
		{"security rule", func() (string, error) { return (SecurityRuleId{}).CanonicalText() }},
		{"state machine", func() (string, error) { return (StateMachineId{}).CanonicalText() }},
		{"stable error", func() (string, error) { return (StableErrorId{}).CanonicalText() }},
	}
	for _, test := range invalidCanonicalText {
		if _, err := test.resolve(); err == nil {
			t.Fatalf("default %s canonical text must return an error", test.name)
		}
	}
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

func assertSurfaceCoversRegistry[V interface {
	comparable
	fmt.Stringer
}](t *testing.T, surface []V, registry map[V]string) {
	t.Helper()
	surfaceValues := map[string]struct{}{}
	for _, identifier := range surface {
		surfaceValues[identifier.String()] = struct{}{}
	}

	registryValues := map[string]struct{}{}
	for id := range registry {
		registryValues[id.String()] = struct{}{}
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
		if got, err := id.CanonicalText(); err != nil || got != text {
			t.Fatalf("requirement %q canonical text differs", id.Value)
		}
	}

	for id, text := range StableIdentifierRegistry.Invariants() {
		if got, err := id.CanonicalText(); err != nil || got != text {
			t.Fatalf("invariant %q canonical text differs", id.Value)
		}
	}

	for id, text := range StableIdentifierRegistry.SecurityRules() {
		if got, err := id.CanonicalText(); err != nil || got != text {
			t.Fatalf("security rule %q canonical text differs", id.Value)
		}
	}

	for id, text := range StableIdentifierRegistry.StateMachines() {
		if got, err := id.CanonicalText(); err != nil || got != text {
			t.Fatalf("state machine %q canonical text differs", id.Value)
		}
	}

	for id, text := range StableIdentifierRegistry.StableErrors() {
		if got, err := id.CanonicalText(); err != nil || got != text {
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

func expectedRequirements() map[string]string {
	return map[string]string{
		"REQ-ORCH-001": "GRU runs the permanent global authority.",
		"REQ-ORCH-002": "Every global and regional controller group has three replicas and one active leader.",
		"REQ-ORCH-003": "Every NATS control domain uses JetStream file storage with three replicas.",
		"REQ-ORCH-004": "Every active Region operates safely during GRU or WAN loss from its last accepted policy.",
		"REQ-ORCH-005": "GRU receives the complete regional journal after connectivity returns.",
		"REQ-ORCH-006": "The Orchestrator bootstraps and owns the greenfield OCI estate without Pulumi or OpenTofu.",
		"REQ-ORCH-007": "OCI mutations use typed, region-scoped provider actuators and durable journals.",
		"REQ-ORCH-008": "The scheduler places only admitted immutable workloads on eligible hosts.",
		"REQ-ORCH-009": "TerraBase placement follows database-selected Regions and RF=2 active Members per Region and Partition.",
		"REQ-ORCH-010": "Dashboard and Database API run at least two instances per qualified Region.",
		"REQ-ORCH-011": "Orchestrator provisions workload identity, trust bundles, rotation, and bootstrap grants.",
		"REQ-ORCH-012": "Orchestrator operates Cloudflare global and strict regional routing for no more than twenty active Regions.",
		"REQ-ORCH-013": "Delivery admits exact artifacts, provenance, configuration, migrations, and rollback anchors.",
		"REQ-ORCH-014": "Autoscaling uses sustained typed capacity reports and preserves hard safety ceilings.",
		"REQ-ORCH-015": "Every long-running action exposes durable exact progress and a terminal receipt.",
		"REQ-ORCH-016": "Regional and global control state has backup, restore, corruption, and total-rebuild evidence.",
		"REQ-ORCH-017": "Operators receive typed plans, holds, approvals, progress, and redacted evidence.",
		"REQ-ORCH-018": "The production release qualifies GRU, SFO, FRA, ARM64 control hosts, ARM64 and x86_64 TerraBase workload hosts, OCI, NATS, systemd, containerd, Block Volume, Vault, Object Storage, and Cloudflare.",
		"REQ-ORCH-019": "The architecture supports a deterministic twenty-Region simulation before the fourth Region is published.",
		"REQ-ORCH-020": "No customer-serving request requires a live Orchestrator or NATS lookup.",
		"REQ-ORCH-021": "The production repository, solution, runtime, and artifact contain no embedded development-host composition or DevHost dependency.",
		"REQ-ORCH-022": "Every production upgrade creates and qualifies a parallel regional candidate before cutover.",
		"REQ-ORCH-023": "Every host publishes admitted capacity, reserved capacity, allocatable capacity, pressure, shutdown, and reclamation state.",
		"REQ-ORCH-024": "Every workload uses a closed execution mode, restart policy, priority class, preemption policy, network lease, and filesystem-reclamation contract.",
		"REQ-ORCH-025": "Resource status, list, and watch APIs expose conditions, `observedGeneration`, stable pagination, resumable progress, compaction recovery, and bounded overload behavior.",
		"REQ-ORCH-026": "Dependency-aware deletion uses durable typed blockers and verified absence before final removal.",
		"REQ-ORCH-027": "Reconcile, reconnect, health, and provider work queues are bounded, fair, coalesced by resource, and safe under retry storms.",
		"REQ-ORCH-028": "Rebalancing and consolidation preserve disruption budgets, failure headroom, surge capacity, storage safety, and a measured net benefit.",
	}
}

func expectedInvariants() map[string]string {
	return map[string]string{
		"INV-ORCH-001": "One exact authority term may mutate one control scope.",
		"INV-ORCH-002": "Global policy has one writer in GRU.",
		"INV-ORCH-003": "Regional mutation requires the current local term and local NATS quorum.",
		"INV-ORCH-004": "An isolated Region cannot create a new global generation.",
		"INV-ORCH-005": "Desired state never erases a provider or TerraBase observation.",
		"INV-ORCH-006": "Every external mutation is preceded by durable authorized intent.",
		"INV-ORCH-007": "Unknown provider outcome is reconciled before retry or compensation.",
		"INV-ORCH-008": "One provider resource has one active lifecycle owner.",
		"INV-ORCH-009": "Tags and discovery never grant mutation authority.",
		"INV-ORCH-010": "A stale leader cannot complete a new accepted mutation.",
		"INV-ORCH-011": "A committed provider target remains fixed across leadership change.",
		"INV-ORCH-012": "NATS never carries customer data or TerraBase correctness state.",
		"INV-ORCH-013": "TerraBase alone accepts membership and retirement.",
		"INV-ORCH-014": "Scale-in cannot reduce required durability or recovery headroom.",
		"INV-ORCH-015": "Secrets and private keys never enter desired state, NATS, telemetry, receipts, or Git.",
		"INV-ORCH-016": "A release activates only the exact qualified digest and configuration.",
		"INV-ORCH-017": "Catalog discovery and catalog publication are separate transitions.",
		"INV-ORCH-018": "A retired `RegionCode`, Member identity, replica epoch, volume identity, or bootstrap generation is never reused unsafely.",
		"INV-ORCH-019": "Admission and backpressure protect workloads before capacity arrives.",
		"INV-ORCH-020": "Telemetry cannot authorize a destructive operation.",
		"INV-ORCH-021": "An active allocation is never mutated in place during release.",
		"INV-ORCH-022": "Development composition, credentials, trust roots, and authority paths cannot enter a production artifact or state store.",
		"INV-ORCH-023": "Production traffic cannot reach a candidate before its exact generation satisfies minimum healthy time and every required gate.",
		"INV-ORCH-024": "One active allocation owns one unique, durable IP and port lease for each bound endpoint.",
		"INV-ORCH-025": "A resource cannot disappear while a current typed deletion blocker, live dependent, or unverified external resource remains.",
		"INV-ORCH-026": "Status cannot claim a desired generation applied until `observedGeneration` equals that generation.",
		"INV-ORCH-027": "Host pressure stops new placement before eviction, and planned shutdown drains admitted work before poweroff.",
		"INV-ORCH-028": "Queue overload sheds, delays, or coalesces work without dropping durable intent or creating unbounded memory use.",
	}
}

func expectedSecurityRules() map[string]string {
	return map[string]string{
		"SEC-ORCH-001": "Every privileged network boundary uses TLS 1.3 and mutual workload identity.",
		"SEC-ORCH-002": "NATS servers use mTLS; clients also use scoped NKey and JWT identities.",
		"SEC-ORCH-003": "Global, regional, host-agent, CI, monitoring, and infrastructure identities have disjoint permissions.",
		"SEC-ORCH-004": "Regional OCI credentials cannot mutate another Region or the tenancy root.",
		"SEC-ORCH-005": "GRU global controllers do not hold ordinary regional OCI mutation credentials.",
		"SEC-ORCH-006": "Secret configuration contains references and version identities only.",
		"SEC-ORCH-007": "Private keys are non-exportable where OCI Vault supports the required operation.",
		"SEC-ORCH-008": "Bootstrap credentials expire or are revoked after handoff.",
		"SEC-ORCH-009": "Artifacts require immutable digest, signature, provenance, SBOM, and vulnerability disposition.",
		"SEC-ORCH-010": "No ordinary operation requires inbound SSH.",
		"SEC-ORCH-011": "Break-glass access is time-bound, approved, recorded, and automatically revoked.",
		"SEC-ORCH-012": "Logs, traces, metrics, errors, fixtures, and receipts redact secret and customer content before emission.",
		"SEC-ORCH-013": "Development trust roots, certificates, credentials, tokens, and secret defaults never enter production state, images, packages, or deployments.",
		"SEC-ORCH-014": "A workload receives network, port, filesystem, device, secret, and peer access only through its admitted allocation contract.",
	}
}

func expectedStateMachines() map[string]string {
	return map[string]string{
		"SM-ORCH-BOOTSTRAP":          "Empty tenancy to accepted GRU authority",
		"SM-ORCH-GLOBAL-AUTHORITY":   "Global leader election, renewal, fencing, and replacement",
		"SM-ORCH-REGIONAL-AUTHORITY": "Regional leader election, renewal, fencing, and replacement",
		"SM-ORCH-REGION-ADMISSION":   "Planned Region to owner-approved catalog publication",
		"SM-ORCH-REGION-REMOVAL":     "Routing fence through final retention and deletion receipts",
		"SM-ORCH-PROVIDER-OPERATION": "Prepared intent through exact provider terminal outcome",
		"SM-ORCH-HOST-LIFECYCLE":     "Host request, creation, enrollment, admission, drain, and retirement",
		"SM-ORCH-WORKLOAD-LIFECYCLE": "Artifact admission through allocation, minimum health, service, drain, and verified stop",
		"SM-ORCH-MEMBER-ADD":         "TerraBase identity allocation through membership acceptance",
		"SM-ORCH-MEMBER-REPLACE":     "Failed seat through verified replacement and safe retirement",
		"SM-ORCH-CAPACITY":           "Pressure observation through scale, rebalance, or admission refusal",
		"SM-ORCH-RELEASE":            "Immutable blue through parallel green creation, qualification, atomic cutover, rollback window, and blue retirement",
		"SM-ORCH-RECONNECT":          "Regional isolation through journal upload and reconciled generation",
		"SM-ORCH-TRUST-ROTATION":     "New trust generation through overlap and old-generation retirement",
		"SM-ORCH-CONTROL-RESTORE":    "Backup selection through new fenced recovery generation",
		"SM-ORCH-NODE-PRESSURE":      "Pressure detection through cordon, reclaim, drain, recovery, or failed-host replacement",
		"SM-ORCH-WORKLOAD-RESTART":   "Failure through bounded backoff, stable recovery, rollback, or digest quarantine",
		"SM-ORCH-RESOURCE-DELETION":  "Deletion request through dependent drain, blocker release, external absence, and tombstone retention",
	}
}

func expectedStableErrors() map[string]string {
	return map[string]string{
		"ERR-ORCH-AUTHORITY-UNAVAILABLE":       "The required authority quorum or current term is unavailable.",
		"ERR-ORCH-STALE-TERM":                  "A command, executor, or observation belongs to an older authority term.",
		"ERR-ORCH-GENERATION-CONFLICT":         "Desired, applied, or observed generations cannot be reconciled automatically.",
		"ERR-ORCH-REGION-ISOLATED":             "The requested action is outside the Region's admitted survival policy.",
		"ERR-ORCH-OUTCOME-UNKNOWN":             "An external mutation may have occurred and needs observation.",
		"ERR-ORCH-OWNERSHIP-MISMATCH":          "Positive resource ownership does not match the requested operation.",
		"ERR-ORCH-EVIDENCE-INCOMPLETE":         "Required current and complete evidence is missing.",
		"ERR-ORCH-CAPACITY-UNAVAILABLE":        "No eligible placement satisfies resources and safety reserves.",
		"ERR-ORCH-BUDGET-APPROVAL-REQUIRED":    "A safe operation exceeds the automatic budget but not the hard ceiling.",
		"ERR-ORCH-PROVIDER-LIMIT":              "A provider quota, capacity, or account ceiling blocks the action.",
		"ERR-ORCH-TERRABASE-HOLD":              "TerraBase has not accepted the required membership, frontier, or retirement state.",
		"ERR-ORCH-ARTIFACT-DENIED":             "Artifact identity, signature, provenance, architecture, or rollback evidence failed.",
		"ERR-ORCH-REGION-NOT-QUALIFIED":        "A Region cannot receive customer traffic or placement.",
		"ERR-ORCH-RESTORE-GENERATION-CONFLICT": "A restore might overlap a live control generation.",
		"ERR-ORCH-CANDIDATE-NOT-READY":         "The exact candidate has not passed minimum health, compatibility, routing, or required tests.",
		"ERR-ORCH-WORKLOAD-QUARANTINED":        "The artifact and configuration pair exceeded its restart or health-failure budget.",
		"ERR-ORCH-DELETION-BLOCKED":            "A current dependent, safety hold, or external resource prevents deletion.",
		"ERR-ORCH-WATCH-EXPIRED":               "The resume point is below retained journal history and the client must relist.",
	}
}
