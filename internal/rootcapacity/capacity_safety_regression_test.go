package rootcapacity

import (
	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
)

func capacitySafetyAttempt() attempt {
	return attempt{receipt: budget.Reservation{OperationID: "original-birth", CompartmentID: "ocid1.compartment.oc1..fixture"},
		recipe: nodescale.Recipe{Cell: "gru", Capacity: nodescale.Capacity{Role: nodescale.RoleContainer, Architecture: "arm64", Shape: nodescale.PreferredShape},
			ImageID: "ocid1.image.oc1..fixture", SubnetID: "ocid1.subnet.oc1..fixture", NSGIDs: []string{"ocid1.networksecuritygroup.oc1..fixture"},
			AvailabilityDomains: []string{"AD-1", "AD-2"}, OCPUs: 2, MemoryGB: 12, Metadata: map[string]string{"base": "signed"}}}
}
