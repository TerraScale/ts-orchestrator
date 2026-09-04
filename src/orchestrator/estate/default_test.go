package estate

import "testing"

func TestDefaultEstateIsValid(t *testing.T) {
	spec := Default()
	if err := spec.Validate(); err != nil {
		t.Fatalf("default declared estate rejected: %v", err)
	}
	refs, err := spec.ResourceRefs()
	if err != nil {
		t.Fatalf("default resource inventory failed: %v", err)
	}
	if len(refs) == 0 {
		t.Fatal("default estate declares no resources")
	}
}

// TestDefaultEstateMatchesLaunchDecisions pins the D-65/D-06 launch shape:
// three Regions, two member hosts each, one co-hosted control replica per
// Region forming the single R3 group.
func TestDefaultEstateMatchesLaunchDecisions(t *testing.T) {
	spec := Default()
	wantMembers := map[string]struct{}{"gru": {}, "sfo": {}, "fra": {}}
	if len(spec.Regions) != len(wantMembers) {
		t.Fatalf("default estate has %d Regions, want %d", len(spec.Regions), len(wantMembers))
	}
	for _, region := range spec.Regions {
		if _, ok := wantMembers[region.Code]; !ok {
			t.Fatalf("unexpected Region %q in the launch estate", region.Code)
		}
		delete(wantMembers, region.Code)
		if region.Members.Count != 2 {
			t.Fatalf("Region %s declares %d members, want 2 (D-65)", region.Code, region.Members.Count)
		}
		if region.Members.ControlReplicas != 1 {
			t.Fatalf("Region %s declares %d control replicas, want 1 co-hosted (D-06)", region.Code, region.Members.ControlReplicas)
		}
		if region.Members.PrimaryShape != "VM.Standard.A1.Flex" {
			t.Fatalf("Region %s declares primary shape %q, want the Ampere launch shape (D-65)", region.Code, region.Members.PrimaryShape)
		}
	}
	if len(wantMembers) != 0 {
		t.Fatalf("launch Regions missing from the estate: %v", wantMembers)
	}
	if spec.ControlPlane.Replicas != 3 || len(spec.ControlPlane.Regions) != 3 {
		t.Fatalf("default control plane is %+v, want one R3 group across the three Regions", spec.ControlPlane)
	}
	if spec.HomeRegion != "gru" {
		t.Fatalf("home Region is %q, want gru", spec.HomeRegion)
	}
}
