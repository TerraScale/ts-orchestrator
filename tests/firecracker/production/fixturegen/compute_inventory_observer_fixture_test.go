//go:build fixturetest

package fixturegen

import (
	"slices"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func assertPacketComputeObserver(t *testing.T, provider common.ConfigurationProvider,
	compute *core.ComputeClient, network *core.VirtualNetworkClient,
	observed ObservedController, vnic GuestObservation,
	instance core.GetInstanceResponse, primary core.GetVnicResponse,
) int {
	t.Helper()
	observer, err := bootstrapstart.NewOCIInstanceObserverWithClients(oci.RegionGRU,
		provider, compute, network)
	if err != nil {
		t.Fatalf("production OCI observer construction: %v", err)
	}
	actual, err := observer.ObserveInstance(t.Context(), observed.InstanceOCID)
	if err != nil || actual.InstanceOCID != observed.InstanceOCID || actual.ETag != observed.ETag ||
		actual.CompartmentOCID != *instance.CompartmentId || actual.ImageOCID != *instance.ImageId ||
		actual.AvailabilityDomain != *instance.AvailabilityDomain ||
		actual.FaultDomain != *instance.FaultDomain || actual.Shape != *instance.Shape ||
		actual.SubnetOCID != *primary.SubnetId || actual.PrimaryVNICOCID != vnic.PrimaryVNICOCID ||
		actual.PrimaryPrivateIP != vnic.PrimaryPrivateIP || !actual.PrimaryVNIC ||
		actual.LifecycleState != string(core.InstanceLifecycleStateRunning) ||
		!slices.Equal(actual.NSGOCIDs, primary.NsgIds) {
		t.Fatalf("production OCI observer rejected packet Compute evidence: %+v, %v", actual, err)
	}
	return 4
}
