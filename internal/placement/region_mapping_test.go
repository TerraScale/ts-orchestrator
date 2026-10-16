package placement

import (
	"errors"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

// A region added to the catalog must also get a permanent seat mapping;
// until it does, placement refuses it instead of emitting an empty seat ID.
func TestEveryPlacementRegionHasAPermanentSeat(t *testing.T) {
	for _, region := range oci.Regions() {
		if permanentMember(region) == "" {
			t.Errorf("catalog region %s has no permanent member mapping", region)
		}
	}
	unmapped := oci.Region("LHR")
	if knownRegion(unmapped) {
		t.Fatal("a region without a permanent seat mapping is known to placement")
	}
	if _, err := RegionSeatIDs(unmapped); !errors.Is(err, ErrInvalidIntent) {
		t.Fatalf("RegionSeatIDs for an unmapped region = %v", err)
	}
}
