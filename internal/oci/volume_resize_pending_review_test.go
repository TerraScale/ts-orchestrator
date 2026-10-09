package oci

import (
	"testing"
	"time"
)

// A resize this controller journaled and OCI applied, whose receipt was never
// confirmed, keeps the grown volume owned, so the create/recover path no
// longer rejects it before the resize path can confirm the receipt
// (#127 12051, 12107). Any size other than the journaled target stays
// unowned.
func TestKVJournalOwnsAVolumeGrownByItsOwnUnconfirmedResize(t *testing.T) {
	for _, outcome := range []string{"no result", "unknown result"} {
		t.Run(outcome, func(t *testing.T) {
			ctx := t.Context()
			kv := testJournalBucket(t)
			journal, err := NewKVJournal(kv)
			if err != nil {
				t.Fatal(err)
			}
			config, _ := testRegionConfig()
			volumeID := "ocid1.volume.kv-pending"
			create := OperationIntent{Action: actionVolumeCreate, Key: "0000000000EC741T888EGXAX24", Region: config.Region,
				Generation: config.Generation, Owner: config.Owner, CreateKey: "0000000000EC741T888EGXAX24",
				AvailabilityDomain: config.AvailabilityDomain, SizeGB: 50, CreatedAt: time.Now().UTC()}
			if err := journal.RecordIntent(ctx, create); err != nil {
				t.Fatal(err)
			}
			if err := journal.RecordResult(ctx, OperationResult{Intent: create, ResourceID: volumeID}); err != nil {
				t.Fatal(err)
			}
			identity := ResourceIdentity{ID: volumeID, Region: config.Region, Generation: config.Generation,
				Owner: config.Owner, CreateKey: "0000000000EC741T888EGXAX24", AvailabilityDomain: config.AvailabilityDomain, SizeGB: 50}
			if owned, err := journal.IsOwnedVolume(ctx, identity); err != nil || !owned {
				t.Fatalf("created volume not owned: %v %v", owned, err)
			}
			grown := identity
			grown.SizeGB = 100
			if owned, _ := journal.IsOwnedVolume(ctx, grown); owned {
				t.Fatal("a grown size was owned without any resize intent")
			}
			resize := OperationIntent{Action: actionVolumeResize, Key: volumeResizeKey(volumeID, 100), Region: config.Region,
				Generation: config.Generation, Owner: config.Owner, ResourceID: volumeID, VolumeID: volumeID,
				CreateKey: "0000000000EC741T888EGXAX24", ExpectedETag: "etag-50", AvailabilityDomain: config.AvailabilityDomain,
				SizeGB: 100, PreviousSizeGB: 50, CreatedAt: time.Now().UTC()}
			if err := journal.RecordIntent(ctx, resize); err != nil {
				t.Fatal(err)
			}
			if outcome == "unknown result" {
				if err := journal.RecordResult(ctx, OperationResult{Intent: resize, Unknown: true}); err != nil {
					t.Fatal(err)
				}
			}
			other := grown
			other.SizeGB = 120
			if owned, _ := journal.IsOwnedVolume(ctx, other); owned {
				t.Fatal("a size other than the journaled target was owned")
			}
			moved := grown
			moved.CreateKey = "00000000005KBY8XNJ83MMCJWP"
			if owned, _ := journal.IsOwnedVolume(ctx, moved); owned {
				t.Fatal("a volume with another create key was owned")
			}
			if owned, err := journal.IsOwnedVolume(ctx, grown); err != nil || !owned {
				t.Fatalf("volume grown by its own resize intent is not owned: %v %v", owned, err)
			}
			if owned, _ := journal.IsOwnedVolume(ctx, identity); owned {
				t.Fatal("the predecessor size is still owned after the advance")
			}
			// The resize path still confirms the receipt afterwards.
			if err := journal.RecordResult(ctx, OperationResult{Intent: resize, ResourceID: volumeID, ETag: "etag-100"}); err != nil {
				t.Fatalf("confirming the receipt after recovery: %v", err)
			}
			if owned, err := journal.IsOwnedVolume(ctx, grown); err != nil || !owned {
				t.Fatalf("confirmed volume not owned: %v %v", owned, err)
			}
		})
	}
}
