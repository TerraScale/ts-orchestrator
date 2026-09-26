//go:build !fixturetest

package fixturegen

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func assertPacketComputeObserver(_ *testing.T, _ common.ConfigurationProvider,
	_ *core.ComputeClient, _ *core.VirtualNetworkClient,
	_ ObservedController, _ GuestObservation,
	_ core.GetInstanceResponse, _ core.GetVnicResponse,
) int {
	return 0
}
