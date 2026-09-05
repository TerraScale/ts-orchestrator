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

// TestDefaultEstateTiersBackupSegmentsPerD29 pins the Native backup segment
// lifecycle: 24 h to Infrequent Access, 7 days to Archive (D-29).
func TestDefaultEstateTiersBackupSegmentsPerD29(t *testing.T) {
	for _, region := range Default().Regions {
		var backups *Bucket
		for i := range region.Buckets {
			if region.Buckets[i].Name == "backups" {
				backups = &region.Buckets[i]
			}
		}
		if backups == nil {
			t.Fatalf("Region %s declares no backups bucket", region.Code)
		}
		tiered := map[string]uint16{}
		for _, rule := range backups.LifecycleRules {
			switch rule.Action {
			case "infrequent-access":
				tiered["infrequent-access"] = rule.AfterDays
			case "archive":
				tiered["archive"] = rule.AfterDays
			}
		}
		if tiered["infrequent-access"] != 1 {
			t.Fatalf("Region %s moves segments to Infrequent Access after %d days, want 1 (24 h)", region.Code, tiered["infrequent-access"])
		}
		if tiered["archive"] != 7 {
			t.Fatalf("Region %s moves segments to Archive after %d days, want 7", region.Code, tiered["archive"])
		}
	}
}

func TestValidateAdmitsD29LifecycleTiersAndRefusesUnknownActions(t *testing.T) {
	spec := Default()
	spec.Regions[0].Buckets[0].LifecycleRules = append(spec.Regions[0].Buckets[0].LifecycleRules,
		BucketLifecycleRule{Name: "tier-infrequent", Action: "infrequent-access", AfterDays: 1},
		BucketLifecycleRule{Name: "tier-archive", Action: "archive", AfterDays: 7},
	)
	if err := spec.Validate(); err != nil {
		t.Fatalf("D-29 lifecycle tiers rejected: %v", err)
	}
	spec.Regions[0].Buckets[0].LifecycleRules[0].Action = "glacier"
	if err := spec.Validate(); err == nil {
		t.Fatal("unknown lifecycle action accepted")
	}
}
