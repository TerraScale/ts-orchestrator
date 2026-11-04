package insights

import (
	"context"
	"errors"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// These pin the fixes for the review findings on PR #121.

// A pass that cannot read an input keeps that input's insights open: a
// missing observation is not a recovery.
func TestUnavailableInputDoesNotResolveInsights(t *testing.T) {
	snapshot := healthy()
	snapshot.Members[2].System = &observability.SystemView{MemTotalBytes: 100, MemAvailBytes: 2}
	cluster := &fakeCluster{snapshot: snapshot}
	local := localSource{snapshot: controller("c1", true)}
	var changes []Change
	engine := NewEngine(Config{Region: "gru", Cluster: cluster, Local: local})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stream := engine.Subscribe(ctx, 16)
	if find(engine.Evaluate(t.Context()).Insights, "memory_pressure") == nil {
		t.Fatal("no memory insight for c3")
	}
	cluster.mu.Lock()
	cluster.err = errors.New("no responders")
	cluster.mu.Unlock()
	evaluation := engine.Evaluate(t.Context())
	if find(evaluation.Insights, "memory_pressure") == nil {
		t.Fatalf("a failed cluster read resolved c3's memory insight: %+v", evaluation)
	}
	for drained := false; !drained; {
		select {
		case change := <-stream:
			changes = append(changes, change)
		default:
			drained = true
		}
	}
	for _, change := range changes {
		if change.Type == ChangeResolved {
			t.Fatalf("a failed read emitted a resolution: %+v", change)
		}
	}
	// A successful read that no longer shows the problem resolves it.
	cluster.mu.Lock()
	cluster.err, cluster.snapshot = nil, healthy()
	cluster.mu.Unlock()
	if find(engine.Evaluate(t.Context()).Insights, "memory_pressure") != nil {
		t.Fatal("a recovered member stays open")
	}
}

// These pin the fixes for the review findings on PRs #127 and #130.
