package protocol

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var inventoryNow = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func TestTheInventoryIsCompleteAndWellFormed(t *testing.T) {
	if !DurableWorkInventory.IsComplete() {
		t.Fatal("the durable work inventory must be complete")
	}

	if violations := DurableWorkInventory.CompletenessViolations(); len(violations) != 0 {
		t.Fatalf("violations = %v", violations)
	}
}

func findInventoryEntry(t *testing.T, name string) DurableStreamPlan {
	t.Helper()
	for _, stream := range DurableWorkInventory.Streams() {
		if stream.Stream == name {
			return stream
		}
	}

	t.Fatalf("stream %q missing", name)
	return DurableStreamPlan{}
}

func findInventoryConsumer(t *testing.T, name string) DurableConsumerPlan {
	t.Helper()
	for _, consumer := range DurableWorkInventory.Consumers() {
		if consumer.Consumer == name {
			return consumer
		}
	}

	t.Fatalf("consumer %q missing", name)
	return DurableConsumerPlan{}
}

func TestEveryDurableStreamDeclaresTheFullPolicySurface(t *testing.T) {
	names := []string{}
	for _, stream := range DurableWorkInventory.Streams() {
		names = append(names, stream.Stream)
	}

	slices.Sort(names)
	if !slices.Equal(names, []string{"CELL_EVENTS", "CELL_OPERATIONS", "CELL_SPEC", "GLOBAL_CI", "GLOBAL_SPEC"}) {
		t.Fatalf("stream names = %v", names)
	}

	for _, stream := range DurableWorkInventory.Streams() {
		if stream.Retention != DurableStreamRetentionLimits ||
			stream.Discard != DurableStreamDiscardOld ||
			stream.Replicas != 3 ||
			stream.MaximumAge != 30*24*time.Hour ||
			!stream.DuplicateWindow.IsWellFormed() {
			t.Fatalf("stream %q violates the frozen policy surface", stream.Stream)
		}
	}

	global := findInventoryEntry(t, "GLOBAL_CI")
	if !strings.Contains(global.TerminalEvidenceBehavior, "terminate") ||
		global.Domain != DurableWorkDomainGlobalControl ||
		global.SemanticClass != MessagingSemanticClassWorkQueue ||
		global.DuplicateWindow.Window != 24*time.Hour ||
		global.MaximumBytes != int64(1024*1024*1024) {
		t.Fatal("GLOBAL_CI stream policy mismatch")
	}

	regional := findInventoryEntry(t, "CELL_SPEC")
	if !strings.Contains(regional.TerminalEvidenceBehavior, "terminate") ||
		regional.Domain != DurableWorkDomainRegionalCell ||
		regional.DuplicateWindow.Window != 2*time.Minute {
		t.Fatal("CELL_SPEC stream policy mismatch")
	}
}

func TestRegionalStreamTemplatesInstantiateOnlyValidCellTokens(t *testing.T) {
	regional := findInventoryEntry(t, "CELL_EVENTS")

	pattern, err := NatsSubjectTaxonomy.RegionalFamilyPattern("gru", NatsSubjectTaxonomy.ObservationFamilySegment())
	if err != nil {
		t.Fatalf("family pattern failed: %v", err)
	}

	subjects, err := regional.SubjectFor("gru")
	if err != nil || len(subjects) != 1 || subjects[0] != pattern {
		t.Fatalf("subjects = %v, err = %v", subjects, err)
	}

	if _, err := regional.SubjectFor("GRU"); err == nil {
		t.Fatal("uppercase cell must be refused")
	}

	if _, err := regional.SubjectFor("bad cell"); err == nil {
		t.Fatal("cell with space must be refused")
	}

	consumer := findInventoryConsumer(t, "gitops_cell_spec_{instance}")
	filter, err := consumer.FilterSubjectFor("sfo")
	cellSpec, cellSpecErr := NatsSubjectTaxonomy.CellSpecSubject("sfo")
	if err != nil || cellSpecErr != nil || filter != cellSpec {
		t.Fatalf("filter subject = %q, err = %v", filter, err)
	}
}

func TestEveryDurableConsumerSatisfiesTheBoundedRedeliveryContract(t *testing.T) {
	for _, consumer := range DurableWorkInventory.Consumers() {
		if !BoundedRedeliveryContract.BoundedBy(DurableWorkInventory.Redelivery(), consumer) {
			t.Fatalf("consumer %q violates the bounded redelivery contract", consumer.Consumer)
		}

		if consumer.Acknowledgement != DurableAcknowledgementExplicit {
			t.Fatalf("consumer %q must ack explicitly", consumer.Consumer)
		}

		ackWait, err := consumer.AckWait()
		if err != nil || ackWait != time.Second {
			t.Fatalf("consumer %q ack wait = %v", consumer.Consumer, ackWait)
		}

		if consumer.MaximumDeliveries != 5 || consumer.MaximumAckPending < 1 {
			t.Fatalf("consumer %q delivery policy mismatch", consumer.Consumer)
		}
	}

	runners := findInventoryConsumer(t, "ci_runner_{zone}_{runner}")
	if runners.Ownership != DurableWorkOwnershipReconciledRunnerIdentity ||
		runners.MaximumAckPending != 1 ||
		runners.MaximumBatch == nil || *runners.MaximumBatch != 1 ||
		runners.MaximumExpires == nil || *runners.MaximumExpires != 30*time.Second ||
		runners.MaximumWaiting == nil || *runners.MaximumWaiting != 4 {
		t.Fatal("runner inbox profile mismatch")
	}

	trigger := findInventoryConsumer(t, "global_ci_trigger")
	if trigger.Ownership != DurableWorkOwnershipGlobalFencedAuthority {
		t.Fatal("trigger ownership mismatch")
	}

	startup := findInventoryConsumer(t, "runtime_startup")
	if startup.Ownership != DurableWorkOwnershipRegionalEquivalentWorkers || startup.MaximumAckPending != 32 {
		t.Fatal("startup consumer profile mismatch")
	}
}

func TestQueueGroupsStayRegionalAndEquivalentWorkerOnly(t *testing.T) {
	names := []string{}
	for _, group := range DurableWorkInventory.QueueGroups() {
		names = append(names, group.Group)
	}

	slices.Sort(names)
	if !slices.Equal(names, []string{"orchestrator_{cell}", "terrascale_orchestrator_journal_writer_{cell}"}) {
		t.Fatalf("queue group names = %v", names)
	}

	for _, group := range DurableWorkInventory.QueueGroups() {
		if group.Domain != DurableWorkDomainRegionalCell || group.FencingBasis == "" {
			t.Fatalf("queue group %q must stay regional and fenced", group.Group)
		}
	}

	writer := findInventoryGroup(t, "terrascale_orchestrator_journal_writer_{cell}")
	if !strings.Contains(writer.FencingBasis, "epoch") {
		t.Fatal("the journal writer group must fence by epoch")
	}
}

func findInventoryGroup(t *testing.T, name string) QueueGroupPlan {
	t.Helper()
	for _, group := range DurableWorkInventory.QueueGroups() {
		if group.Group == name {
			return group
		}
	}

	t.Fatalf("queue group %q missing", name)
	return QueueGroupPlan{}
}

func TestTheDuplicateWindowInspectionNeverRecordsObservations(t *testing.T) {
	window := mustWindow(t, 2*time.Minute, 4)

	if window.Inspect("m1", "d1", inventoryNow) != DuplicateWindowDecisionAdmit {
		t.Fatal("unobserved id must inspect as admitted")
	}

	if window.Count() != 0 {
		t.Fatalf("inspect recorded an observation: %d", window.Count())
	}

	if window.Observe("m1", "d1", inventoryNow) != DuplicateWindowDecisionAdmit {
		t.Fatal("first observation must be admitted")
	}

	if window.Count() != 1 {
		t.Fatalf("count = %d", window.Count())
	}

	if window.Inspect("m1", "d1", inventoryNow) != DuplicateWindowDecisionSuppress {
		t.Fatal("resident id with the same digest must inspect as suppressed")
	}

	if window.Inspect("m1", "d2", inventoryNow) != DuplicateWindowDecisionConflict {
		t.Fatal("resident id with a different digest must inspect as conflict")
	}

	if window.Inspect("m1", "d1", inventoryNow.Add(3*time.Minute)) != DuplicateWindowDecisionAdmitBeyondWindow {
		t.Fatal("beyond-window id must inspect as admitted")
	}

	if window.Count() != 1 {
		t.Fatalf("inspect must not record: %d", window.Count())
	}

	if window.Inspect("", "d1", inventoryNow) != DuplicateWindowDecisionAdmit {
		t.Fatal("empty ids must inspect as admitted")
	}
}

func TestDuplicateWindowDecisionsMapToDeliveryActionsFailClosed(t *testing.T) {
	if DuplicateWindowDelivery.Decide(DuplicateWindowDecisionAdmit) != DuplicateWindowDeliveryActionProcess {
		t.Fatal("admit must map to process")
	}

	if DuplicateWindowDelivery.Decide(DuplicateWindowDecisionAdmitBeyondWindow) != DuplicateWindowDeliveryActionProcess {
		t.Fatal("admit-beyond-window must map to process")
	}

	if DuplicateWindowDelivery.Decide(DuplicateWindowDecisionSuppress) != DuplicateWindowDeliveryActionAcknowledgeSuppressedReplay {
		t.Fatal("suppress must map to acknowledge-suppressed-replay")
	}

	if DuplicateWindowDelivery.Decide(DuplicateWindowDecisionConflict) != DuplicateWindowDeliveryActionTerminateConflictingIdentity {
		t.Fatal("conflict must map to terminate-conflicting-identity")
	}

	if DuplicateWindowDelivery.Decide(DuplicateWindowDecisionUnspecified) != DuplicateWindowDeliveryActionUnspecified {
		t.Fatal("unspecified must map to unspecified")
	}
}

func TestTheCanonicalInventoryDocumentCarriesEveryDeclaredRow(t *testing.T) {
	document, err := os.ReadFile(filepath.Join(findRepositoryRoot(t), "docs", "contracts", "durable-work-inventory.md"))
	if err != nil {
		t.Fatalf("canonical document unavailable: %v", err)
	}

	text := string(document)
	for _, stream := range DurableWorkInventory.Streams() {
		if !strings.Contains(text, "| `"+stream.Stream+"` |") {
			t.Fatalf("the canonical inventory must carry the stream %s", stream.Stream)
		}
	}

	for _, consumer := range DurableWorkInventory.Consumers() {
		if !strings.Contains(text, "| `"+consumer.Consumer+"` |") {
			t.Fatalf("the canonical inventory must carry the consumer %s", consumer.Consumer)
		}
	}

	for _, group := range DurableWorkInventory.QueueGroups() {
		if !strings.Contains(text, "| `"+group.Group+"` |") {
			t.Fatalf("the canonical inventory must carry the queue group %s", group.Group)
		}
	}

	// The document must not weaken the delivery claim: effectively-once only.
	if !strings.Contains(text, "never exactly-once delivery") {
		t.Fatal("the canonical inventory must keep the never-exactly-once delivery claim")
	}
}
