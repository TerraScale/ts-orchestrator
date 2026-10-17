package netbird

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/netip"

	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/networkplan"
)

// BrokerRoute supplies only an untrusted locator. The caller independently pins
// the original signed slot's TLS identity and the fixed broker port.
func BrokerRoute(ctx context.Context, canonicalPeerName string) (netip.Addr, error) {
	if ctx == nil || naming.Validate(canonicalPeerName) != nil {
		return netip.Addr{}, errors.New("NetBird broker route requires a canonical signed peer name")
	}
	e := enroller{run: runCommand}
	wire, err := e.command(ctx, "status", "--json", "--config", netbirdConfig)
	defer clear(wire)
	if err != nil {
		return netip.Addr{}, errors.New("cannot query NetBird broker routing status")
	}
	return brokerRoute(wire, canonicalPeerName)
}

func brokerRoute(wire []byte, name string) (netip.Addr, error) {
	var status struct {
		LocalStatus
		Peers struct {
			Details []struct {
				FQDN string `json:"fqdn"`
				IP   string `json:"netbirdIp"`
			} `json:"details"`
		} `json:"peers"`
	}
	if len(wire) == 0 || len(wire) > 1<<20 || naming.Validate(name) != nil || json.Unmarshal(wire, &status) != nil {
		return netip.Addr{}, errors.New("NetBird broker routing status is invalid")
	}
	manager, err := normalizeManagerURL(status.Management.URL)
	if err != nil || manager != DefaultManagementURL || status.State != "Connected" || !status.Management.Connected || !status.Signal.Connected {
		return netip.Addr{}, errors.New("NetBird broker route requires its connected management and signal service")
	}
	fqdn := name + ".nb.ts.internal"
	var route netip.Addr
	matches := 0
	if status.FQDN == fqdn {
		prefix, err := netip.ParsePrefix(status.IP)
		if err != nil {
			return netip.Addr{}, errors.New("NetBird local broker address is invalid")
		}
		route, matches = prefix.Addr(), 1
	}
	for _, peer := range status.Peers.Details {
		if peer.FQDN != fqdn {
			continue
		}
		address, err := netip.ParseAddr(peer.IP)
		if err != nil {
			return netip.Addr{}, errors.New("NetBird peer broker address is invalid")
		}
		route = address
		matches++
	}
	if matches != 1 || !route.Is4() || !netip.MustParsePrefix(networkplan.Mesh).Contains(route) {
		return netip.Addr{}, errors.New("NetBird broker route is absent, ambiguous or outside the fixed mesh")
	}
	return route, nil
}
