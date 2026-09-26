//go:build fixturetest

package bootstrapstart

import (
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// NewOCIInstanceObserverWithClients uses prebuilt SDK clients only in offline
// packet fixtures. Production construction retains the pinned SDK transport.
func NewOCIInstanceObserverWithClients(region oci.Region, provider common.ConfigurationProvider,
	compute *core.ComputeClient, network *core.VirtualNetworkClient,
) (*OCIInstanceObserver, error) {
	ociRegion, err := observerRegion(region, provider)
	if err != nil || compute == nil || network == nil {
		return nil, ErrInstanceObservation
	}
	compute.SetRegion(ociRegion)
	network.SetRegion(ociRegion)
	return &OCIInstanceObserver{compute: compute, network: network}, nil
}
