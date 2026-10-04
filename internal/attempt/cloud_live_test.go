package attempt

import (
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/tier"
)

// TestLiveReadOnlyCellInstancesFollowTheNamingScheme reads the live tenancy
// through the operator's ~/.oci/config with the SDK calls phase status uses:
// it lists the instances of every compartment in TS_OCI_LIVE_COMPARTMENTS
// (comma-separated OCIDs) and gets each one back. It never mutates OCI. Every
// live instance under the GRU cell prefix must carry a static name.
func TestLiveReadOnlyCellInstancesFollowTheNamingScheme(t *testing.T) {
	compartments := tier.Qualification(t, "TS_OCI_LIVE_COMPARTMENTS")[0]
	cloud, err := newSDKCloud(Region)
	if err != nil {
		t.Fatal(err)
	}
	cell, err := naming.RegionCell("GRU").Name()
	if err != nil {
		t.Fatal(err)
	}
	for _, compartment := range strings.Split(compartments, ",") {
		instances, err := cloud.ListInstances(t.Context(), strings.TrimSpace(compartment))
		if err != nil {
			t.Fatal(err)
		}
		for _, listed := range instances {
			got, err := cloud.GetInstance(t.Context(), listed.ID)
			if err != nil || got.ID != listed.ID || got.DisplayName != listed.DisplayName {
				t.Fatalf("instance %s did not read back: got=%+v err=%v", listed.ID, got, err)
			}
			t.Logf("%s %s %s", listed.DisplayName, listed.LifecycleState, listed.ID)
			if listed.LifecycleState != "TERMINATED" && strings.HasPrefix(listed.DisplayName, cell+"-") {
				if err := naming.Validate(listed.DisplayName); err != nil {
					t.Errorf("live cell instance %s: %v", listed.ID, err)
				}
			}
		}
	}
}
