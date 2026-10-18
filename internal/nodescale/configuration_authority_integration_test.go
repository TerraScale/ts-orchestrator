package nodescale

import (
	"strings"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/core"
)

// Configuration-body authority is checked by rootcapacity's signed SDK readback regression.
func TestCapacityObservesActualInstanceIMDSSecurity(t *testing.T) {
	for _, scenario := range []string{"positively disabled", "legacy enabled", "missing setting", "missing options"} {
		t.Run(scenario, func(t *testing.T) {
			cloud := newCapacityCloud()
			recipe := capacityRecipe()
			seeded := seedCapacityPool(cloud, recipe, 1)
			instance := cloud.launch("ts-gru-4", seeded.PoolID, "10.0.0.4", core.InstanceLifecycleStateRunning, launchTags(recipe, roleNode, ""))
			switch scenario {
			case "legacy enabled":
				cloud.instances[instance].InstanceOptions.AreLegacyImdsEndpointsDisabled = new(false)
			case "missing setting":
				cloud.instances[instance].InstanceOptions.AreLegacyImdsEndpointsDisabled = nil
			case "missing options":
				cloud.instances[instance].InstanceOptions = nil
			}
			observed, err := protocolPool(t, cloud, recipe.Capacity).Observe(t.Context())
			if err != nil || len(observed.Instances) != 1 || observed.Instances[0].ID != instance || observed.Instances[0].Birth != nil {
				t.Fatalf("actual observation was hidden or gained birth authority: %+v err=%v", observed, err)
			}
			if scenario == "positively disabled" {
				if observed.Pending != "" {
					t.Fatalf("safe actual IMDS configuration was held: %+v", observed)
				}
			} else if !strings.Contains(observed.Pending, "has not positively disabled legacy IMDS endpoints") {
				t.Fatalf("unsafe actual IMDS setting was accepted: %+v", observed)
			}
		})
	}
}
