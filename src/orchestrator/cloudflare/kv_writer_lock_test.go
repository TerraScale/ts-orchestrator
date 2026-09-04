package cloudflare

import (
	"context"
	"strings"
	"testing"
)

func TestKVWriterRejectsInvalidPlacementBeforeHealthWrite(t *testing.T) {
	store := &kvWriterStoreFake{}
	w, err := NewKVWriter(kvWriterTestConfig(store,
		map[string]RegionHealth{"gru": {Healthy: true}},
		map[string]DBPlacement{"db-1": {Regions: []string{"gru"}, PlacementLock: "explicit", Generation: 0}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Step(context.Background()); err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatalf("invalid placement result = %v", err)
	}
	if len(store.events) != 0 {
		t.Fatalf("invalid placement partially published health: %v", store.events)
	}
}

func TestKVWriterRejectsExplicitPlacementWidening(t *testing.T) {
	store := &kvWriterStoreFake{}
	placement := &kvWriterPlacementFake{placement: map[string]DBPlacement{
		"db-1": {Regions: []string{"gru"}, PlacementLock: "explicit", Generation: 1},
	}}
	w, err := NewKVWriter(KVWriterConfig{
		Store: store, Health: &kvWriterHealthFake{health: map[string]RegionHealth{"gru": {}}}, Placement: placement,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	placement.placement["db-1"] = DBPlacement{Regions: []string{"gru", "fra"}, PlacementLock: "explicit", Generation: 2}
	if _, err := w.Step(context.Background()); err == nil || !strings.Contains(err.Error(), "widened") {
		t.Fatalf("widening result = %v", err)
	}
}
