package rootoci

import (
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/rootvolumeclient"
)

// VolumeMountObserver preserves the concrete DATA proof boundary while keeping
// the regional SDK principal and ownership journal inside the root process.
func (client *Client) VolumeMountObserver() (*oci.VolumeMountObserver, error) {
	if client == nil || !validExpectations(client.expected) {
		return nil, ErrInvalid
	}
	if client.isClosed() || client.root != nil {
		return nil, ErrUnauthorized
	}
	remote, err := rootvolumeclient.New(rootvolumeclient.Expectations(client.expected), &client.pin)
	if err != nil {
		return nil, err
	}
	return oci.NewRemoteVolumeMountObserver(remote)
}
