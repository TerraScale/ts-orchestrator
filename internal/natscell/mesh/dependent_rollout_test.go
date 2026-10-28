package mesh

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

// A TerraBase restart under a local ts-dashboard bake failed its sjc rollback
// (E18): TerraBase waits; the dashboard and unrelated services never do.
func TestTerraBaseWaitsForLocalDependentRollout(t *testing.T) {
	dir := t.TempDir()
	node := &Node{cfg: config{dir: dir, region: "sjc", server: "sjc-1", applier: &fakeApplier{running: map[string]int64{}}},
		desired: map[string]desiredState{}, peers: &peers{root: t.TempDir(), region: "sjc", node: "sjc-1", address: func() (string, error) { return "10.200.0.1", nil }}}
	done := make(chan struct{})
	node.baking = map[string]chan struct{}{node.bakePath("ts-dashboard", 7): done}
	spec := swarmruntime.ServiceSpec{Name: "terrabase", Image: "ghcr.io/terrascale/terrabase@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1, Regions: []string{"sjc"}}
	request := ApplyRequest{Name: spec.Name, Entry: Entry{Generation: 10, Spec: &spec}}
	if _, err := node.apply(t.Context(), request); !errors.Is(err, errDependentRolling) || len(node.desired) != 0 {
		t.Fatalf("TerraBase applied under a dashboard rollout: %v", err)
	}
	for _, name := range []string{"ts-dashboard", "ts-auth", "whoami"} {
		if node.dependentRolling(name) {
			t.Fatalf("%s waits for a dependent rollout", name)
		}
	}
	short, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err := node.awaitDependents(short, "terrabase"); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errDependentRolling) {
		t.Fatalf("wait did not end with its context: %v", err)
	}
	node.mu.Lock()
	delete(node.baking, node.bakePath("ts-dashboard", 7))
	node.mu.Unlock()
	close(done)
	if err := node.awaitDependents(t.Context(), "terrabase"); err != nil {
		t.Fatal(err)
	}
	if applied, err := node.apply(t.Context(), request); err != nil || applied.result != "applied" {
		t.Fatalf("TerraBase did not apply after the dashboard rollout: %+v %v", applied, err)
	}
}
