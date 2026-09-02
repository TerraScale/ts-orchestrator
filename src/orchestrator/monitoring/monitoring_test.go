package monitoring

import (
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/membership"
)

func TestParsersRejectMalformedAndOversizedReplies(t *testing.T) {
	now := time.Unix(100, 0)
	if NatsMonitoringParsers.Connections("{", "cell-a", NatsMonitoringPlaneControl, now) != nil {
		t.Fatal("malformed reply was accepted")
	}
	if NatsMonitoringParsers.Connections(strings.Repeat("x", NatsMonitoringParsersMaximumReplyBytes+1), "cell-a", NatsMonitoringPlaneControl, now) != nil {
		t.Fatal("oversized reply was accepted")
	}
	got := NatsMonitoringParsers.Connections(`{"data":{"total":2,"connections":[{"num_reconnects":3}]}}`, "cell-a", NatsMonitoringPlaneControl, now)
	if got == nil || got.Connections != 2 || got.Reconnects != 3 {
		t.Fatalf("valid reply was not parsed: %#v", got)
	}
}

func TestSnapshotEntryBoundsMetricLabels(t *testing.T) {
	instrument := "terrascale.orchestrator.nats.connections"
	if _, err := NewNatsMonitoringSnapshotEntry(instrument, "{connections}", map[string]string{"stream_name": "CELL_SPEC"}, 1); err == nil {
		t.Fatal("forbidden label key was accepted")
	}
	if _, err := NewNatsMonitoringSnapshotEntry(instrument, "{connections}", map[string]string{"state": strings.Repeat("a", NatsMonitoringSnapshotEntryMaximumLabelValueLength+1)}, 1); err == nil {
		t.Fatal("oversized label value was accepted")
	}
	if _, err := NewNatsMonitoringSnapshotEntry(instrument, "{connections}", map[string]string{"state": "connected"}, 1); err != nil {
		t.Fatalf("allowed label was rejected: %v", err)
	}
}

func TestClassifierUsesBoundedClasses(t *testing.T) {
	checks := []struct {
		name string
		got  NatsStreamClass
		want NatsStreamClass
	}{
		{"cell", NatsMonitoringClassifier.ClassifyStream("CELL_SPEC"), NatsStreamClassCellSpec},
		{"kv", NatsMonitoringClassifier.ClassifyStream("KV_runtime"), NatsStreamClassKeyValue},
		{"unknown", NatsMonitoringClassifier.ClassifyStream("customer-secret-stream"), NatsStreamClassUnknown},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s stream class = %v, want %v", check.name, check.got, check.want)
		}
	}
	if got := NatsMonitoringClassifier.ClassifyConsumer("gitops_cell_spec_42"); got != NatsConsumerClassCellSpec {
		t.Fatalf("consumer class = %v", got)
	}
	if got := NatsMonitoringClassifier.ClassifyConsumer("abcdefghijklmnopqrstuv"); got != NatsConsumerClassEphemeralWatch {
		t.Fatalf("ephemeral consumer class = %v", got)
	}
	if got := NatsMonitoringClassifier.ClassifyConsumer("consumer-name"); got != NatsConsumerClassUnknown {
		t.Fatalf("unknown consumer class = %v", got)
	}
}

func TestSupervisionReconcilesAfterObservationRecovery(t *testing.T) {
	now := time.Unix(1000, 0)
	last := now.Add(-time.Second)
	if got := NatsMonitoringSupervision.Evaluate(&last, 1, now); got != NatsMonitoringSupervisionActionMarkDegraded {
		t.Fatalf("failed round action = %v", got)
	}
	if got := NatsMonitoringSupervision.Evaluate(&now, 0, now); got != NatsMonitoringSupervisionActionContinue {
		t.Fatalf("reconciled action = %v", got)
	}
	if got := NatsMonitoringSupervision.Availability(nil, 1, now); got != NatsMonitoringAvailabilityUnavailable {
		t.Fatalf("no-observation availability = %v", got)
	}
	if !NatsMonitoringSupervision.RegionalControlContinues(NatsMonitoringSupervisionActionMarkUnavailable) {
		t.Fatal("monitoring supervision stopped regional control")
	}
}

func TestMeshHealthStatePrecedence(t *testing.T) {
	now := time.Unix(2000, 0)
	state := func(gateways map[string]NatsGatewaysObservation, directory MeshDirectorySnapshot, memberships map[string]membership.RegionalRuntimeMembershipHealth) NatsMeshCellState {
		result, err := NatsMeshHealthEvaluate([]string{"cell-a"}, memberships, directory, gateways, now)
		if err != nil {
			t.Fatal(err)
		}
		return result.Cells[0].State
	}
	entry := MeshDirectoryEntry{Cell: "cell-a", LeaseExpiresAt: now.Add(time.Minute), MembershipCondition: membership.RegionalRuntimeMembershipConditionHealthy}
	healthy := membership.RegionalRuntimeMembershipHealth{Condition: membership.RegionalRuntimeMembershipConditionHealthy}
	if got := state(map[string]NatsGatewaysObservation{"cell-a": NatsGatewaysObserve("cell-a", 0, 1, now)}, MeshDirectorySnapshot{}, nil); got != NatsMeshCellStateDisconnected {
		t.Fatalf("disconnected state = %v", got)
	}
	if got := state(nil, MeshDirectorySnapshot{}, nil); got != NatsMeshCellStateMissing {
		t.Fatalf("missing state = %v", got)
	}
	if got := state(nil, MeshDirectorySnapshot{Cells: []MeshDirectoryEntry{{Cell: "cell-a", LeaseExpiresAt: now.Add(-time.Second)}}}, nil); got != NatsMeshCellStateStale {
		t.Fatalf("stale state = %v", got)
	}
	conflicting := healthy
	conflicting.ConflictingControllers = 1
	if got := state(nil, MeshDirectorySnapshot{Cells: []MeshDirectoryEntry{entry}}, map[string]membership.RegionalRuntimeMembershipHealth{"cell-a": conflicting}); got != NatsMeshCellStateConflicting {
		t.Fatalf("conflicting state = %v", got)
	}
	if got := state(nil, MeshDirectorySnapshot{Cells: []MeshDirectoryEntry{entry}}, map[string]membership.RegionalRuntimeMembershipHealth{"cell-a": healthy}); got != NatsMeshCellStateHealthy {
		t.Fatalf("healthy state = %v", got)
	}
	if got := state(map[string]NatsGatewaysObservation{"cell-a": NatsGatewaysObserve("cell-a", 1, 0, now)}, MeshDirectorySnapshot{Cells: []MeshDirectoryEntry{entry}}, map[string]membership.RegionalRuntimeMembershipHealth{"cell-a": healthy}); got != NatsMeshCellStateHealthy {
		t.Fatalf("reconnected state = %v", got)
	}
}
