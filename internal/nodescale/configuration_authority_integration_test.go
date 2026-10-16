package nodescale

import (
	"errors"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/core"
)

func TestCapacityChecksActualConfigurationBeforeGrowth(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(*core.InstanceConfigurationLaunchInstanceDetails)
	}{
		{"image", func(launch *core.InstanceConfigurationLaunchInstanceDetails) {
			launch.SourceDetails = core.InstanceConfigurationInstanceSourceViaImageDetails{ImageId: new("ocid1.image.unapproved")}
		}},
		{"network", func(launch *core.InstanceConfigurationLaunchInstanceDetails) {
			launch.CreateVnicDetails.NsgIds = []string{"ocid1.networksecuritygroup.unapproved"}
		}},
		{"metadata", func(launch *core.InstanceConfigurationLaunchInstanceDetails) {
			launch.Metadata["unapproved"] = "bootstrap"
		}},
		{"shape", func(launch *core.InstanceConfigurationLaunchInstanceDetails) {
			launch.Shape = new("VM.Standard.E4.Flex")
		}},
		{"legacy IMDS", func(launch *core.InstanceConfigurationLaunchInstanceDetails) {
			launch.InstanceOptions.AreLegacyImdsEndpointsDisabled = new(false)
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			cloud := newCapacityCloud()
			recipe := capacityRecipe()
			pool := protocolPool(t, cloud, recipe.Capacity)
			state, err := pool.Ensure(t.Context(), recipe)
			if err != nil {
				t.Fatal(err)
			}
			config := cloud.configs[state.ConfigurationID]
			launch := config.InstanceDetails.(core.ComputeInstanceDetails).LaunchDetails
			if launch.InstanceOptions == nil || !deref(launch.InstanceOptions.AreLegacyImdsEndpointsDisabled) {
				t.Fatal("actual creation omitted the required IMDS setting")
			}
			change.edit(launch)
			if err := pool.Grow(t.Context(), 0); !errors.Is(err, ErrCapacityPending) || cloud.updates != 0 {
				t.Fatalf("same tags and name admitted a different actual launch body: %v, updates=%d", err, cloud.updates)
			}
		})
	}
}

func TestCapacityObservesActualInstanceIMDSSecurity(t *testing.T) {
	cloud := newCapacityCloud()
	recipe := capacityRecipe()
	pool := protocolPool(t, cloud, recipe.Capacity)
	state, err := pool.Ensure(t.Context(), recipe)
	if err != nil {
		t.Fatal(err)
	}
	instance := cloud.launch("ts-gru-4", state.PoolID, "10.0.0.4", core.InstanceLifecycleStateRunning, launchTags(recipe, roleNode, ""))
	cloud.instances[instance].InstanceOptions.AreLegacyImdsEndpointsDisabled = new(false)
	observed, err := pool.Observe(t.Context())
	if err != nil || observed.Pending == "" || len(observed.Instances) != 1 {
		t.Fatalf("unsafe observed instance was accepted or hidden: %+v, %v", observed, err)
	}
}
