package swarmruntime

import (
	"slices"
	"testing"

	"github.com/moby/swarmkit/v2/api"
)

func TestTSAuthControllerPlacement(t *testing.T) {
	intent := serviceIntent()
	intent.Role = "ts-auth"
	for replicas := range uint64(4) {
		intent.Replicas = replicas
		spec, err := intent.serviceSpec()
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"node.labels." + LabelRegion + "==" + intent.Region, "node.labels." + LabelExecutionScope + "==platform", "node.role==manager"}
		if !slices.Equal(spec.Task.Placement.Constraints, want) || spec.Task.Placement.MaxReplicas != 1 || spec.GetReplicated().Replicas != replicas {
			t.Fatalf("TSAuth placement escaped controller domains: %+v", spec.Task.Placement)
		}
		if spec.Update.Order != api.UpdateConfig_STOP_FIRST || spec.Rollback.Order != api.UpdateConfig_STOP_FIRST {
			t.Fatal("TSAuth update requires an additional occupied controller slot")
		}
	}
	intent.Replicas = 4
	if _, err := intent.serviceSpec(); err == nil {
		t.Fatal("TSAuth admitted more replicas than controller domains")
	}
	intent.Role = "api"
	spec, err := intent.serviceSpec()
	if err != nil || spec.Task.Placement.MaxReplicas != 0 || slices.Contains(spec.Task.Placement.Constraints, "node.role==manager") {
		t.Fatalf("generic service inherited controller placement: %+v %v", spec, err)
	}
}
