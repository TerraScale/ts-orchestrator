package mesh

import (
	"errors"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

// sjc's dashboard bake failed only on a slow TerraBase (2026-10-28 16:53Z),
// which kept gru and fra from rolling. An excused region no longer blocks;
// a failed one still does.
func TestTurnPassesAnEarlierRegionExcusedOnADependency(t *testing.T) {
	spec := &swarmruntime.ServiceSpec{Name: "ts-dashboard", Regions: []string{"sjc", "fra", "gru"}}
	n := &Node{cfg: config{region: "fra"}}
	excused := map[string]stateReply{"sjc": {Region: "sjc", Excused: map[string]int64{"ts-dashboard": 7}}}
	if err := n.turn("ts-dashboard", spec, 7, excused); err != nil {
		t.Fatalf("excused sjc blocked fra: %v", err)
	}
	failed := map[string]stateReply{"sjc": {Region: "sjc", Failed: map[string]int64{"ts-dashboard": 7}}}
	if err := n.turn("ts-dashboard", spec, 7, failed); !errors.Is(err, errEarlierFailed) {
		t.Fatalf("failed sjc: %v, want errEarlierFailed", err)
	}
	if err := n.turn("ts-dashboard", spec, 8, excused); err == nil {
		t.Fatal("an older excused generation released a newer one")
	}
}
