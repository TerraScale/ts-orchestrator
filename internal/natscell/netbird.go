package natscell

import (
	"errors"
	"net"
	"net/netip"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/networkplan"
)

// ListenNetBird adds an authenticated client path on the exact local mesh IP.
// The signed OCI listener and broker admission gate remain the same.
func (r *Runtime) ListenNetBird(address netip.Addr) (net.Listener, error) {
	if r == nil || r.bridge == nil || r.brokerTLS == nil || !address.Is4() ||
		!netip.MustParsePrefix(networkplan.Mesh).Contains(address) {
		return nil, errors.New("NetBird NATS listener requires a production bridge and a mesh IPv4 address")
	}
	_, port, err := net.SplitHostPort(r.bridge.Addr().String())
	if err != nil {
		return nil, err
	}
	return r.bridge.listen(net.JoinHostPort(address.String(), port), r.brokerTLS.ServerConfig())
}
