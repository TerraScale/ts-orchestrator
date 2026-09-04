package protocol

import (
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
