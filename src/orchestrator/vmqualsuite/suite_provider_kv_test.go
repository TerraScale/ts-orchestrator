package vmqualsuite

import (
	"context"
	"path/filepath"
	"testing"

	cf "terrascale.tech/orchestrator/src/orchestrator/cloudflare"
)

func TestProviderKVSourcePinsPersistedRevisionAcrossNotification(t *testing.T) {
	factory := newScenarioTestFactory()
	providers, _, stack := newScenarioHarness(t, factory, &scenarioTestNetwork{}, nil)
	t.Cleanup(func() {
		if err := providers.Close(); err != nil {
			t.Error(err)
		}
	})
	root := t.TempDir()
	oldRegistry, oldPlacement := filepath.Join(root, "regions-1.json"), filepath.Join(root, "placement-1.json")
	newRegistry, newPlacement := filepath.Join(root, "regions-2.json"), filepath.Join(root, "placement-2.json")
	for path, value := range map[string]any{
		oldRegistry:  map[string]any{"regions": []string{"gru", "fra"}},
		newRegistry:  map[string]any{"regions": []string{"gru"}},
		oldPlacement: map[string]cf.DBPlacement{"db": {Regions: []string{"gru", "fra"}, PlacementLock: "explicit", Generation: 1}},
		newPlacement: map[string]cf.DBPlacement{"db": {Regions: []string{"gru"}, PlacementLock: "explicit", Generation: 2}},
	} {
		if err := writeProviderJSON(path, value); err != nil {
			t.Fatal(err)
		}
	}
	source := &providerKVSource{stack: stack, registryPath: oldRegistry, placementPath: oldPlacement}
	ctx := context.Background()
	if _, err := source.ObserveDBPlacement(ctx); err == nil {
		t.Fatal("placement was read without a health revision")
	}
	health, err := source.ObserveRegionHealth(ctx)
	if err != nil || len(health) != 2 {
		t.Fatalf("initial health=%v error=%v", health, err)
	}
	// A change arriving between the writer's two observation calls must apply
	// to the next pass, not narrow placement under an older health revision.
	source.selectRevision(newRegistry, newPlacement)
	placement, err := source.ObserveDBPlacement(ctx)
	if err != nil || placement["db"].Generation != 1 {
		t.Fatalf("mixed source revision: placement=%v error=%v", placement, err)
	}
	health, err = source.ObserveRegionHealth(ctx)
	if err != nil || len(health) != 1 {
		t.Fatalf("changed health=%v error=%v", health, err)
	}
	placement, err = source.ObserveDBPlacement(ctx)
	if err != nil || placement["db"].Generation != 2 {
		t.Fatalf("changed placement=%v error=%v", placement, err)
	}
}
