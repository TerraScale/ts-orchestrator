package placement

import "testing"

func TestNamedPlacementLockResolvesOnlyRegisteredResidency(t *testing.T) {
	catalog := NewRegionCatalog([]*RegionCatalogEntry{
		{Region: RegionCodeGru, Residency: "br", MemberHosts: 2},
		{Region: RegionCodeFra, Residency: "eu", MemberHosts: 2},
	})
	lock, err := NewEUOnlyPlacementLock(4)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolvePlacementLock(lock, catalog)
	if err != nil || len(resolved.Regions) != 1 || resolved.Regions[0] != RegionCodeFra {
		t.Fatalf("resolved EU lock = %#v, %v", resolved, err)
	}
	if _, err := ResolvePlacementLock(&PlacementLock{Kind: PlacementLockKindExplicit, Generation: 1, Regions: []RegionCode{RegionCodeSfo}}, catalog); err == nil {
		t.Fatal("unregistered explicit Region was accepted")
	}
}

func TestPlacementLockCannotWidenOrReuseGeneration(t *testing.T) {
	prior, _ := NewPlacementLock(PlacementLockKindExplicit, []RegionCode{RegionCodeGru, RegionCodeSfo}, 7)
	for _, updated := range []*PlacementLock{
		{Kind: PlacementLockKindExplicit, Regions: []RegionCode{RegionCodeGru, RegionCodeFra}, Generation: 8},
		{Kind: PlacementLockKindExplicit, Regions: []RegionCode{RegionCodeGru}, Generation: 7},
	} {
		if err := CheckPlacementLockWidening(prior, updated); err == nil {
			t.Fatalf("lock update %#v was accepted", updated)
		}
	}
	updated := &PlacementLock{Kind: PlacementLockKindExplicit, Regions: []RegionCode{RegionCodeGru}, Generation: 8}
	if err := CheckPlacementLockWidening(prior, updated); err != nil {
		t.Fatalf("narrowing with a new generation was refused: %v", err)
	}
}
