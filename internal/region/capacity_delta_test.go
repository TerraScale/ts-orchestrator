package region

import (
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
)

func TestCapacityDeltaCannotAcquireRegionalOwnershipOrMintDrain(t *testing.T) {
	original := FoundationRecord{Cell: "SFO", OperationID: "regional-foundation-owner", Epoch: 17, ResourceIDs: map[string]string{"subnet": "original-subnet"}}
	if err := validateCapacityOnlyDelta(original, original); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		name   string
		change func(*FoundationRecord)
	}{
		{"regional epoch", func(r *FoundationRecord) { r.Epoch++ }},
		{"regional lease", func(r *FoundationRecord) { r.LeaseID = "home-capacity-owner" }},
		{"signed grant", func(r *FoundationRecord) { r.GrantSHA256 = "other-grant" }},
		{"resource", func(r *FoundationRecord) { r.ResourceIDs = map[string]string{"subnet": "other-subnet"} }},
		{"new drain authority", func(r *FoundationRecord) { r.PoolDrains = map[string]drainwire.PoolReceipt{"unproven": {}} }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			next := original
			mutation.change(&next)
			if err := validateCapacityOnlyDelta(original, next); err == nil {
				t.Fatal("dedicated capacity writer acquired unrelated regional authority")
			}
		})
	}
}
