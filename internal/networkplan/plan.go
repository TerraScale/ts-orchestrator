// Package networkplan reserves TerraScale's routed address space. Allocations
// are stable: extending the region catalog must never renumber existing cells.
package networkplan

import (
	"fmt"
	"net/netip"
)

const (
	Mesh          = "10.200.0.0/16"
	MeshIPv6      = "fd9c:200:2182:65f2::/64"
	Tailscale     = "100.64.0.0/10"
	TailscaleIPv6 = "fd7a:115c:a1e0::/48"
	RegionPool    = "10.240.0.0/12"
	BridgePool    = "10.208.0.0/12"
)

// RegionReservation is the dedicated /16, containing the existing /24 VCN.
// 10.250/16 belongs to shared ts-ops and is never allocated to a cell.
func RegionReservation(cell string) (netip.Prefix, error) {
	var cidr string
	switch cell {
	case "GRU":
		cidr = "10.251.0.0/16"
	case "SFO":
		cidr = "10.252.0.0/16"
	case "FRA":
		cidr = "10.253.0.0/16"
	default:
		return netip.Prefix{}, fmt.Errorf("cell %q has no address-plan reservation", cell)
	}
	return netip.MustParsePrefix(cidr), nil
}

// RegionNetwork preserves the initial VCN /24 inside each /16 reservation.
func RegionNetwork(cell string) (string, error) {
	p, err := RegionReservation(cell)
	if err != nil {
		return "", err
	}
	return netip.PrefixFrom(p.Addr(), 24).String(), nil
}

func ValidateRegion(cell, cidr string) error {
	reserved, err := RegionReservation(cell)
	if err != nil {
		return err
	}
	p, err := netip.ParsePrefix(cidr)
	if err != nil || p != p.Masked() || p.String() != cidr {
		return fmt.Errorf("address plan: %q must be a canonical IPv4 CIDR", cidr)
	}
	if !p.Addr().Is4() || p.Bits() < reserved.Bits() || !reserved.Contains(p.Addr()) {
		return fmt.Errorf("address plan: %s CIDRs must not overlap other networks; %s must be within %s", cell, cidr, reserved)
	}
	return nil
}

func ValidateMesh(cidr string) error {
	if cidr != Mesh {
		return fmt.Errorf("address plan: NetBird network_range must be %s; %q may overlap Tailscale, LANs or regional networks", Mesh, cidr)
	}
	return nil
}
