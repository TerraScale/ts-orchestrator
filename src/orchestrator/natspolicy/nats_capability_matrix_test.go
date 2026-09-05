package natspolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// expectedDispositions are the exact dispositions frozen by the contract; a
// change is an owner decision, not a refactor.
var expectedDispositions = []struct {
	capability  NatsCapability
	disposition NatsCapabilityDisposition
}{
	{NatsCapabilityCorePubSub, NatsCapabilityDispositionAccept},
	{NatsCapabilityRequestReply, NatsCapabilityDispositionAccept},
	{NatsCapabilityServicesAndDiscovery, NatsCapabilityDispositionAccept},
	{NatsCapabilityQueueGroups, NatsCapabilityDispositionAccept},
	{NatsCapabilityHeaders, NatsCapabilityDispositionAccept},
	{NatsCapabilityMessageIds, NatsCapabilityDispositionAccept},
	{NatsCapabilityJetStreamStreams, NatsCapabilityDispositionAccept},
	{NatsCapabilityDurableConsumers, NatsCapabilityDispositionAccept},
	{NatsCapabilityAcknowledgement, NatsCapabilityDispositionAccept},
	{NatsCapabilityRedeliveryAndBackoff, NatsCapabilityDispositionAccept},
	{NatsCapabilityFlowControl, NatsCapabilityDispositionAccept},
	{NatsCapabilityKeyValueCasAndWatch, NatsCapabilityDispositionAccept},
	{NatsCapabilityObjectStore, NatsCapabilityDispositionAccept},
	{NatsCapabilityAccounts, NatsCapabilityDispositionAccept},
	{NatsCapabilityJwts, NatsCapabilityDispositionDefer},
	{NatsCapabilityNKeys, NatsCapabilityDispositionAccept},
	{NatsCapabilityMtls, NatsCapabilityDispositionAccept},
	{NatsCapabilityImportsAndExports, NatsCapabilityDispositionAccept},
	{NatsCapabilityGateways, NatsCapabilityDispositionAccept},
	{NatsCapabilityAdvisories, NatsCapabilityDispositionAccept},
	{NatsCapabilitySystemMonitoring, NatsCapabilityDispositionAccept},
	{NatsCapabilitySnapshots, NatsCapabilityDispositionAccept},
	{NatsCapabilityRollingCompatibility, NatsCapabilityDispositionAccept},
}

func TestMatrixIsCompleteAndEveryEntryIsWellFormed(t *testing.T) {
	if !NatsCapabilityMatrix.IsComplete() {
		t.Fatal("the capability matrix must be complete")
	}

	if violations := NatsCapabilityMatrix.CompletenessViolations(); len(violations) != 0 {
		t.Fatalf("violations = %v", violations)
	}

	if len(NatsCapabilityMatrix.Entries()) != 23 {
		t.Fatalf("entry count = %d", len(NatsCapabilityMatrix.Entries()))
	}
}

func TestEveryCapabilityNamedByTheContractHasTheFrozenDisposition(t *testing.T) {
	for _, expected := range expectedDispositions {
		entry := NatsCapabilityMatrix.Find(expected.capability)
		if entry == nil {
			t.Fatalf("capability %v missing", expected.capability)
		}

		if entry.Disposition != expected.disposition {
			t.Fatalf("capability %v disposition = %v", expected.capability, entry.Disposition)
		}
	}
}

func TestAcceptedEntriesCarryOwnerDataClassDurabilityOrderingBoundaryFailureAndObservability(t *testing.T) {
	for _, entry := range NatsCapabilityMatrix.Entries() {
		if entry.Disposition != NatsCapabilityDispositionAccept {
			continue
		}

		if entry.Owner == NatsCapabilityOwnerUnspecified ||
			entry.DataClass == NatsDataClassUnspecified ||
			entry.Durability == NatsDurabilityClassUnspecified ||
			entry.Ordering == NatsOrderingClassUnspecified ||
			strings.TrimSpace(entry.SecurityBoundary) == "" ||
			strings.TrimSpace(entry.FailureMode) == "" ||
			strings.TrimSpace(entry.ObservabilityRequirement) == "" ||
			strings.TrimSpace(entry.LandedEvidence) == "" {
			t.Fatalf("accepted entry %v is missing required attributes", entry.Capability)
		}
	}
}

func TestDeferredAndRejectedEntriesRecordATriggerOrRationaleAndNoAttributes(t *testing.T) {
	for _, entry := range NatsCapabilityMatrix.Entries() {
		if entry.Disposition == NatsCapabilityDispositionAccept {
			continue
		}

		if strings.TrimSpace(entry.RevisitTriggerOrRejectionRationale) == "" ||
			entry.Owner == NatsCapabilityOwnerUnspecified ||
			entry.DataClass != NatsDataClassUnspecified {
			t.Fatalf("deferred/rejected entry %v is malformed", entry.Capability)
		}
	}
}

func TestEveryOwnerIsOneOfTheKnownResponsibilityRoles(t *testing.T) {
	owners := map[NatsCapabilityOwner]struct{}{}
	for _, entry := range NatsCapabilityMatrix.Entries() {
		owners[entry.Owner] = struct{}{}
	}

	if len(owners) <= 1 {
		t.Fatal("the matrix must exercise more than one owner")
	}

	knownOwners := []NatsCapabilityOwner{
		NatsCapabilityOwnerRegionalControlRuntime,
		NatsCapabilityOwnerGlobalAuthorityRuntime,
		NatsCapabilityOwnerGlobalDirectoryRuntime,
		NatsCapabilityOwnerMessagingContracts,
		NatsCapabilityOwnerDeliveryContracts,
		NatsCapabilityOwnerSecurityAndIdentity,
		NatsCapabilityOwnerInfrastructureBootstrap,
		NatsCapabilityOwnerObservability,
		NatsCapabilityOwnerStorageAndSnapshots,
	}

	for owner := range owners {
		found := false
		for _, known := range knownOwners {
			if owner == known {
				found = true
				break
			}
		}

		if !found {
			t.Fatalf("unknown owner %v", owner)
		}
	}
}

func findRepositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory unavailable: %v", err)
	}

	for hops := 0; hops < 12; hops++ {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}

		directory = filepath.Dir(directory)
	}

	t.Fatal("the Go module root was not found; the contract drift test must run from the repository")
	return ""
}

func TestCanonicalContractDocumentDispositionsEveryCapabilityIdentically(t *testing.T) {
	document, err := os.ReadFile(filepath.Join(findRepositoryRoot(t), "docs", "contracts", "nats-capability-matrix.md"))
	if err != nil {
		t.Fatalf("canonical document unavailable: %v", err)
	}

	text := string(document)
	for _, expected := range expectedDispositions {
		row := "| `" + expected.capability.String() + "` | " +
			strings.ToUpper(expected.disposition.String()) + " |"
		if !strings.Contains(text, row) {
			t.Fatalf("the canonical document must carry the row '%s'", row)
		}
	}
}
