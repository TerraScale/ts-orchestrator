package protocol

import (
	"slices"
	"strings"
	"testing"
)

func TestConnectedCellsMayPerformEveryOperationClass(t *testing.T) {
	classes := []RegionalAutonomyOperationClass{
		RegionalAutonomyOperationClassPreAuthorizedRegionalOperation,
		RegionalAutonomyOperationClassNewGlobalGeneration,
		RegionalAutonomyOperationClassNewGlobalPolicy,
		RegionalAutonomyOperationClassNewGlobalRelease,
		RegionalAutonomyOperationClassGlobalAuthorityClaim,
		RegionalAutonomyOperationClassRegionalObservation,
	}

	for _, operationClass := range classes {
		if RegionalAutonomyRules.Decide(MessagingConnectivityConnected, operationClass) !=
			RegionalAutonomyDecisionPermitted {
			t.Fatalf("connected cells may perform %v", operationClass)
		}
	}
}

func TestGloballyIsolatedCellsKeepPreAuthorizedRegionalWork(t *testing.T) {
	if RegionalAutonomyRules.Decide(
		MessagingConnectivityGlobalIsolated,
		RegionalAutonomyOperationClassPreAuthorizedRegionalOperation) != RegionalAutonomyDecisionPermitted {
		t.Fatal("pre-authorized regional work must stay permitted under global isolation")
	}

	if RegionalAutonomyRules.Decide(
		MessagingConnectivityGlobalIsolated,
		RegionalAutonomyOperationClassRegionalObservation) != RegionalAutonomyDecisionPermitted {
		t.Fatal("regional observation must stay permitted under global isolation")
	}
}

func TestGloballyIsolatedCellsFreezeNewGlobalGenerationsPolicyAndReleases(t *testing.T) {
	frozen := []RegionalAutonomyOperationClass{
		RegionalAutonomyOperationClassNewGlobalGeneration,
		RegionalAutonomyOperationClassNewGlobalPolicy,
		RegionalAutonomyOperationClassNewGlobalRelease,
	}

	for _, operationClass := range frozen {
		if RegionalAutonomyRules.Decide(MessagingConnectivityGlobalIsolated, operationClass) !=
			RegionalAutonomyDecisionFrozenGlobalMutation {
			t.Fatalf("global isolation must freeze %v", operationClass)
		}
	}

	if RegionalAutonomyRules.Decide(
		MessagingConnectivityGlobalIsolated,
		RegionalAutonomyOperationClassGlobalAuthorityClaim) !=
		RegionalAutonomyDecisionFrozenGlobalAuthorityClaim {
		t.Fatal("an isolated cell may never claim global authority")
	}
}

func TestRegionsThatLostTheirOwnQuorumHoldAllMutationsButKeepObservation(t *testing.T) {
	if RegionalAutonomyRules.Decide(
		MessagingConnectivityRegionalQuorumLost,
		RegionalAutonomyOperationClassPreAuthorizedRegionalOperation) !=
		RegionalAutonomyDecisionHeldUntilRegionalQuorum {
		t.Fatal("quorum loss must hold pre-authorized regional work")
	}

	if RegionalAutonomyRules.Decide(
		MessagingConnectivityRegionalQuorumLost,
		RegionalAutonomyOperationClassNewGlobalRelease) !=
		RegionalAutonomyDecisionHeldUntilRegionalQuorum {
		t.Fatal("quorum loss must hold new global releases")
	}

	if RegionalAutonomyRules.Decide(
		MessagingConnectivityRegionalQuorumLost,
		RegionalAutonomyOperationClassRegionalObservation) !=
		RegionalAutonomyDecisionPermitted {
		t.Fatal("quorum loss must keep observation permitted")
	}
}

func TestUnknownInputsDecideNothingRatherThanDefaultingToPermit(t *testing.T) {
	if RegionalAutonomyRules.Decide(
		MessagingConnectivityUnspecified,
		RegionalAutonomyOperationClassNewGlobalRelease) != RegionalAutonomyDecisionUnspecified {
		t.Fatal("unknown connectivity must be unspecified")
	}

	if RegionalAutonomyRules.Decide(
		MessagingConnectivityConnected,
		RegionalAutonomyOperationClassUnspecified) != RegionalAutonomyDecisionUnspecified {
		t.Fatal("unknown operation class must be unspecified")
	}
}

func TestExactVersionsAreAcceptedAndKnownOlderVersionsMigrateForward(t *testing.T) {
	current := MessagingSchemaVersion{Major: 1, Minor: 0}
	migratable := map[MessagingSchemaVersion]struct{}{{Major: 1, Minor: 0}: {}}

	if MessagingSchemaNegotiation.Decide(MessagingSchemaVersion{Major: 1, Minor: 0}, current, migratable) !=
		SchemaNegotiationOutcomeAcceptExact {
		t.Fatal("exact versions must be accepted")
	}

	if MessagingSchemaNegotiation.Decide(
		MessagingSchemaVersion{Major: 1, Minor: 0},
		MessagingSchemaVersion{Major: 1, Minor: 1},
		map[MessagingSchemaVersion]struct{}{{Major: 1, Minor: 0}: {}}) != SchemaNegotiationOutcomeMigrateForward {
		t.Fatal("registered older minors must migrate forward")
	}
}

func TestUnknownMajorsFailClosed(t *testing.T) {
	current := MessagingSchemaVersion{Major: 1, Minor: 0}
	migratable := map[MessagingSchemaVersion]struct{}{{Major: 1, Minor: 0}: {}}

	for _, offered := range []MessagingSchemaVersion{{Major: 2, Minor: 0}, {Major: 99, Minor: 4}} {
		if MessagingSchemaNegotiation.Decide(offered, current, migratable) != SchemaNegotiationOutcomeRejectMajorMismatch {
			t.Fatalf("offered %v must be a major mismatch", offered)
		}
	}
}

func TestMalformedVersionsFailClosedWithADistinctMalformedOutcome(t *testing.T) {
	current := MessagingSchemaVersion{Major: 1, Minor: 0}
	migratable := map[MessagingSchemaVersion]struct{}{{Major: 1, Minor: 0}: {}}

	// A malformed offered version is not a major mismatch: it never got far
	// enough to compare majors, and reporting a mismatch would mislead the operator.
	for _, offered := range []MessagingSchemaVersion{{Major: 0, Minor: 1}, {Major: -1, Minor: 0}, {Major: 1, Minor: -1}} {
		if MessagingSchemaNegotiation.Decide(offered, current, migratable) != SchemaNegotiationOutcomeRejectMalformed {
			t.Fatalf("offered %v must be malformed", offered)
		}
	}

	// A malformed CURRENT version is equally undecidable and fails closed the same way.
	if MessagingSchemaNegotiation.Decide(
		MessagingSchemaVersion{Major: 1, Minor: 0},
		MessagingSchemaVersion{Major: 0, Minor: 0},
		migratable) != SchemaNegotiationOutcomeRejectMalformed {
		t.Fatal("malformed current version must be malformed")
	}
}

func TestNewerVersionsFailClosedSoAnNMinusOneNodeNeverGuesses(t *testing.T) {
	current := MessagingSchemaVersion{Major: 1, Minor: 0}
	migratable := map[MessagingSchemaVersion]struct{}{{Major: 1, Minor: 0}: {}}

	if MessagingSchemaNegotiation.Decide(MessagingSchemaVersion{Major: 1, Minor: 1}, current, migratable) !=
		SchemaNegotiationOutcomeRejectNewerVersion {
		t.Fatal("newer minor must fail closed")
	}

	if MessagingSchemaNegotiation.Decide(MessagingSchemaVersion{Major: 2, Minor: 0}, current, migratable) !=
		SchemaNegotiationOutcomeRejectMajorMismatch {
		t.Fatal("newer major must fail closed as a major mismatch")
	}
}

func TestOlderVersionsWithoutARegisteredMigrationFailClosed(t *testing.T) {
	if MessagingSchemaNegotiation.Decide(
		MessagingSchemaVersion{Major: 1, Minor: 0},
		MessagingSchemaVersion{Major: 1, Minor: 2},
		map[MessagingSchemaVersion]struct{}{}) != SchemaNegotiationOutcomeRejectUnmigratableOlderVersion {
		t.Fatal("unregistered older minor must fail closed")
	}
}

func TestCompatibilityRulesCoverEveryNamedArea(t *testing.T) {
	if !MessagingCompatibilityRules.IsComplete() {
		t.Fatal("compatibility rules must cover every area")
	}

	areas := map[MessagingCompatibilityRulesArea]struct{}{}
	for _, rule := range MessagingCompatibilityRules.Rules() {
		areas[rule.RuleArea] = struct{}{}
	}

	for _, expected := range []MessagingCompatibilityRulesArea{
		MessagingCompatibilityRulesAreaClients,
		MessagingCompatibilityRulesAreaServers,
		MessagingCompatibilityRulesAreaStreams,
		MessagingCompatibilityRulesAreaConsumers,
		MessagingCompatibilityRulesAreaKeyValueValues,
		MessagingCompatibilityRulesAreaObjectStoreMetadata,
		MessagingCompatibilityRulesAreaRollingUpgrades,
	} {
		if _, present := areas[expected]; !present {
			t.Fatalf("area %v has no rule", expected)
		}
	}
}

func TestRollingUpgradesRequireForwardAndRollbackArtifactsAndCannotBreakQuorumFloors(t *testing.T) {
	rolling := []CompatibilityRule{}
	for _, rule := range MessagingCompatibilityRules.Rules() {
		if rule.RuleArea == MessagingCompatibilityRulesAreaRollingUpgrades {
			rolling = append(rolling, rule)
		}
	}

	if len(rolling) < 2 {
		t.Fatalf("rolling upgrade rules = %d", len(rolling))
	}

	if !slices.ContainsFunc(rolling, func(rule CompatibilityRule) bool { return strings.Contains(rule.Rule, "rollback") }) {
		t.Fatal("a rolling upgrade rule must mention rollback")
	}

	for _, rule := range MessagingCompatibilityRules.Rules() {
		if rule.RuleArea == MessagingCompatibilityRulesAreaServers &&
			strings.Contains(rule.Rule, "disruption budget") {
			return
		}
	}

	t.Fatal("a server rule must pin the disruption budget")
}
