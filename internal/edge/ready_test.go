package edge

import (
	"context"
	"slices"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

func TestManagerRestartInventory(t *testing.T) {
	e := newEdge(t.TempDir())
	e.listeners.Store(15)
	unloaded := e.Readiness(t.Context())
	if unloaded.Ready || !slices.Contains(unloaded.Missing, "routes unavailable") || unloaded.InfraErr() == nil {
		t.Fatalf("unloaded manager inventory: %+v", unloaded)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	e.FollowInventory(ctx, func() (mesh.EdgeInventory, bool) {
		return mesh.EdgeInventory{}, true
	}, func(context.Context, string) error { return nil }, nil)
	loaded := e.Readiness(t.Context())
	if !loaded.Ready || loaded.InfraErr() != nil {
		t.Fatalf("loaded empty manager inventory: %+v", loaded)
	}
}
