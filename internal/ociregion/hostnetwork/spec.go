// Package hostnetwork converges a static-host cell's OCI network: the VCN,
// its gateways and route tables, a public host subnet, a private workload
// subnet, empty subnet security lists and one NSG per host role on the
// host's VNIC. Every value is fixed here; ts-orch adopts the existing
// same-named resources, tags them and recreates any that are missing.
package hostnetwork

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/networkplan"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// operatorEgress is the shared public egress of delta, mariogk-dev and beta.
const operatorEgress = "179.124.206.245/32"

// rule is one stateful CIDR security rule. port 0 is every port; icmp is
// "type/code", "type" or "" for every ICMP message.
type rule struct {
	egress bool
	proto  string // "all", "1" ICMP, "6" TCP, "17" UDP
	cidr   string
	port   int
	icmp   string
}

func (r rule) key() string {
	return fmt.Sprintf("%t|%s|%s|%d|%s", r.egress, r.proto, r.cidr, r.port, r.icmp)
}

type nsg struct {
	name  string
	rules []rule
}

// spec is a cell's whole desired network.
type spec struct {
	cell, code, region, compartment, host, node string
	vcn, publicSubnet, privateSubnet      string
	nsgs                                  []nsg
}

func desired(cellName string) (spec, error) {
	entry, ok := catalog.LookupName(strings.TrimSuffix(cellName, "-1"))
	if name, _ := naming.RegionCell(entry.Cell).Name(); !ok || name != cellName {
		return spec{}, fmt.Errorf("unknown cell %q", cellName)
	}
	vcn, err := networkplan.RegionNetwork(entry.Cell)
	if err != nil {
		return spec{}, err
	}
	host, err := naming.RegionCell(entry.Cell).Server(naming.Controller, 1)
	if err != nil {
		return spec{}, err
	}
	node, err := naming.RegionCell(entry.Cell).Node(1)
	if err != nil {
		return spec{}, err
	}
	p := netip.MustParsePrefix(vcn)
	// The first /25 is public hosts, .128/26 stays reserved for the planned
	// public API load balancer and .192/26 holds private workload hosts.
	public := netip.PrefixFrom(p.Addr(), 25).String()
	b := p.Addr().As4()
	b[3] = 192
	private := netip.PrefixFrom(netip.AddrFrom4(b), 26)
	tcp := func(port int) rule { return rule{proto: "6", cidr: "0.0.0.0/0", port: port} }
	udp := func(port int) rule { return rule{proto: "17", cidr: "0.0.0.0/0", port: port} }
	return spec{
		cell: cellName, code: entry.Cell, region: entry.OCIRegion, compartment: cellName + "-control", host: host, node: node,
		vcn: vcn, publicSubnet: public, privateSubnet: private.String(),
		nsgs: []nsg{
			// Every host: the VCN, path MTU discovery and the egress image
			// pulls, package mirrors, Vault and NetBird peers need.
			{cellName + "-host-nsg", []rule{
				{proto: "all", cidr: vcn}, {proto: "1", cidr: "0.0.0.0/0", icmp: "3/4"},
				{egress: true, proto: "all", cidr: vcn}, {egress: true, proto: "all", cidr: "169.254.0.0/16"},
				{egress: true, proto: "6", cidr: "0.0.0.0/0", port: 80}, {egress: true, proto: "6", cidr: "0.0.0.0/0", port: 443},
				{egress: true, proto: "17", cidr: "0.0.0.0/0"}, {egress: true, proto: "1", cidr: "0.0.0.0/0"},
			}},
			// The public edge: HTTPS, ACME, the NetBird ports in docs/netbird-m1.md
			// and release pushes over NATS (docs/m1-single-host.md).
			{cellName + "-edge-nsg", []rule{tcp(80), tcp(443), udp(3478), udp(51820), tcp(4222)}},
			// shortcut: operator SSH from the internet, remove once SSH over NetBird is proven.
			{cellName + "-operator-ssh-nsg", []rule{{proto: "6", cidr: operatorEgress, port: 22}}},
		},
	}, nil
}

func (r rule) add() core.AddSecurityRuleDetails {
	d := core.AddSecurityRuleDetails{Direction: core.AddSecurityRuleDetailsDirectionIngress, Protocol: new(r.proto), IsStateless: new(false)}
	if r.egress {
		d.Direction, d.Destination, d.DestinationType = core.AddSecurityRuleDetailsDirectionEgress, new(r.cidr), core.AddSecurityRuleDetailsDestinationTypeCidrBlock
	} else {
		d.Source, d.SourceType = new(r.cidr), core.AddSecurityRuleDetailsSourceTypeCidrBlock
	}
	ports := &core.PortRange{Min: new(r.port), Max: new(r.port)}
	switch {
	case r.port != 0 && r.proto == "6":
		d.TcpOptions = &core.TcpOptions{DestinationPortRange: ports}
	case r.port != 0 && r.proto == "17":
		d.UdpOptions = &core.UdpOptions{DestinationPortRange: ports}
	case r.icmp != "":
		var t, c int
		if n, _ := fmt.Sscanf(r.icmp, "%d/%d", &t, &c); n == 2 {
			d.IcmpOptions = &core.IcmpOptions{Type: new(t), Code: new(c)}
		} else {
			d.IcmpOptions = &core.IcmpOptions{Type: new(t)}
		}
	}
	return d
}

// liveKey is a live rule's key; a rule outside the shapes above gets a key
// no desired rule has, so it is removed.
func liveKey(s core.SecurityRule) string {
	r := rule{egress: s.Direction == core.SecurityRuleDirectionEgress, proto: deref(s.Protocol)}
	cidr, kind := s.Source, string(s.SourceType)
	if r.egress {
		cidr, kind = s.Destination, string(s.DestinationType)
	}
	r.cidr = deref(cidr)
	if kind != "CIDR_BLOCK" || s.IsStateless != nil && *s.IsStateless {
		return "foreign|" + deref(s.Id)
	}
	var ports *core.PortRange
	if o := s.TcpOptions; o != nil {
		if o.SourcePortRange != nil {
			return "foreign|" + deref(s.Id)
		}
		ports = o.DestinationPortRange
	}
	if o := s.UdpOptions; o != nil {
		if o.SourcePortRange != nil {
			return "foreign|" + deref(s.Id)
		}
		ports = o.DestinationPortRange
	}
	if ports != nil {
		if *ports.Min != *ports.Max {
			return "foreign|" + deref(s.Id)
		}
		r.port = *ports.Min
	}
	if o := s.IcmpOptions; o != nil {
		r.icmp = strconv.Itoa(*o.Type)
		if o.Code != nil {
			r.icmp += "/" + strconv.Itoa(*o.Code)
		}
	}
	return r.key()
}

// diff returns the desired rules to add and the live rule IDs to remove.
func diff(live []core.SecurityRule, want []rule) (add []rule, remove []string) {
	have := map[string]bool{}
	wanted := map[string]bool{}
	for _, r := range want {
		wanted[r.key()] = true
	}
	for _, s := range live {
		k := liveKey(s)
		if wanted[k] && !have[k] {
			have[k] = true
		} else {
			remove = append(remove, deref(s.Id))
		}
	}
	for _, r := range want {
		if !have[r.key()] {
			add = append(add, r)
		}
	}
	return add, remove
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
