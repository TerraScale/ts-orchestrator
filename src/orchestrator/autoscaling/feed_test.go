package autoscaling

import (
	"encoding/json"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/stateful"
)

func TestAutoscalerObservationFeedRoundTripsDemandAndPlacement(t *testing.T) {
	resources, err := NewNodeResources(1024, 20, 2)
	if err != nil {
		t.Fatal(err)
	}
	demand, err := NewAllocationDemand("dashboard-a", "dashboard", false, resources)
	if err != nil {
		t.Fatal(err)
	}
	replica, err := stateful.NewReplicaHealth("terrabase", "member-a", true, 1, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	original, err := NewAutoscalerObservationFeed(AutoscalerFeedSchemaVersion, 1770000000,
		[]AllocationDemand{demand}, true,
		[]AutoscalerNodePlacement{{NodeId: "node-a", Replicas: []stateful.ReplicaHealth{replica}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"demandComplete":true`) ||
		!strings.Contains(string(encoded), `"placementComplete":true`) {
		t.Fatalf("feed omitted completeness flags: %s", encoded)
	}
	var decoded AutoscalerObservationFeed
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Demand) != 1 || decoded.Demand[0].Resources != resources ||
		len(decoded.Placements) != 1 || len(decoded.Placements[0].Replicas) != 1 ||
		decoded.Placements[0].Replicas[0] != replica {
		t.Fatalf("decoded feed differs: %+v", decoded)
	}
}

func TestAutoscalerObservationFeedRejectsUnknownAndDuplicateInput(t *testing.T) {
	if _, err := NewAutoscalerObservationFeed(99, 1, nil, true, nil, true); err == nil {
		t.Fatal("unknown schema version must be rejected")
	}
	if _, err := NewAutoscalerObservationFeed(AutoscalerFeedSchemaVersion, 1, nil, true,
		[]AutoscalerNodePlacement{{NodeId: "node-a"}, {NodeId: "node-a"}}, true); err == nil {
		t.Fatal("duplicate placement nodes must be rejected")
	}
	var feed AutoscalerObservationFeed
	if err := json.Unmarshal([]byte(`{"schemaVersion":1,"unixSeconds":1,"demand":[],"demandComplete":true,"placements":[],"placementComplete":true,"extra":1}`), &feed); err == nil {
		t.Fatal("unknown feed fields must be rejected")
	}
	if err := json.Unmarshal([]byte(`{"schemaVersion":1,"unixSeconds":1,"demand":[],"demandComplete":true,"placements":[],"placementComplete":true} {}`), &feed); err == nil {
		t.Fatal("trailing JSON values must be rejected")
	}
}
