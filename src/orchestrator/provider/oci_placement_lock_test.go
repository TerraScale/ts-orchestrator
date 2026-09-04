package provider

import (
	"errors"
	"testing"
)

func TestResolveNamedPlacementLock(t *testing.T) {
	registered := []string{"gru", "sfo", "fra"}

	euOnly, err := ResolveNamedPlacementLock("eu-only", registered, 3)
	if err != nil {
		t.Fatalf("eu-only: %v", err)
	}
	if euOnly.Policy != "eu-only" || euOnly.Generation != 3 {
		t.Fatalf("eu-only lock = %#v", euOnly)
	}
	if regions := euOnly.PlacementLockRegions(); len(regions) != 1 || regions[0] != "fra" {
		t.Fatalf("eu-only regions = %v, want [fra]", regions)
	}

	brOnly, err := ResolveNamedPlacementLock("br-only", registered, 1)
	if err != nil {
		t.Fatalf("br-only: %v", err)
	}
	if regions := brOnly.PlacementLockRegions(); len(regions) != 1 || regions[0] != "gru" {
		t.Fatalf("br-only regions = %v, want [gru]", regions)
	}

	// OCI-shaped names resolve through the eu- prefix rule.
	euNames, err := ResolveNamedPlacementLock("eu-only", []string{"gru", "eu-frankfurt-1"}, 1)
	if err != nil {
		t.Fatalf("eu-only with OCI names: %v", err)
	}
	if regions := euNames.PlacementLockRegions(); len(regions) != 1 || regions[0] != "eu-frankfurt-1" {
		t.Fatalf("eu-only OCI-name regions = %v, want [eu-frankfurt-1]", regions)
	}

	if _, err := ResolveNamedPlacementLock("us-only", registered, 1); err == nil {
		t.Fatal("unknown policy accepted")
	}
	if _, err := ResolveNamedPlacementLock("eu-only", []string{"gru", "sfo"}, 1); err == nil {
		t.Fatal("eu-only without a registered eu Region accepted")
	}
}

func TestNewPlacementLockForPolicy(t *testing.T) {
	explicit, err := NewPlacementLockForPolicy("explicit", []string{"gru", "sfo"}, []string{"gru", "sfo", "fra"}, 7)
	if err != nil {
		t.Fatalf("explicit: %v", err)
	}
	if explicit.Policy != "explicit" || explicit.Generation != 7 || explicit.PlacementGeneration != 7 {
		t.Fatalf("explicit lock = %#v", explicit)
	}
	if regions := explicit.PlacementLockRegions(); len(regions) != 2 || regions[0] != "gru" || regions[1] != "sfo" {
		t.Fatalf("explicit regions = %v, want [gru sfo]", regions)
	}

	named, err := NewPlacementLockForPolicy("eu-only", nil, []string{"gru", "fra"}, 4)
	if err != nil {
		t.Fatalf("named: %v", err)
	}
	if named.Policy != "eu-only" || named.Generation != 4 {
		t.Fatalf("named lock = %#v", named)
	}
	if regions := named.PlacementLockRegions(); len(regions) != 1 || regions[0] != "fra" {
		t.Fatalf("named regions = %v, want [fra]", regions)
	}
}

func TestPlacementLockPolicyChangeIsWidening(t *testing.T) {
	// Swapping a named policy for an explicit list that adds Regions is
	// refused as a policy change even when the generations advance.
	prior, err := ResolveNamedPlacementLock("eu-only", []string{"gru", "fra"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	updated := PlacementLock{
		Regions: []string{"fra", "gru"}, Policy: "explicit",
		Generation: 2, PlacementGeneration: 2,
	}
	err = CheckPlacementWidening(prior, updated)
	var refused *PlacementError
	if !errors.As(err, &refused) {
		t.Fatalf("policy change accepted: %v", err)
	}
}
