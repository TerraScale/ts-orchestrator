// Package manager reconciles TerraScale's NetBird manager: groups, the GRU
// cell network, access policies, account and DNS settings, the cell DNS zone
// and the hygiene of server peers. The CLI and the leading controller share
// one embedded desired state. Objects are matched by name, never by stored ID;
// a renamed object lists its former names so the first sync renames it in
// place and keeps its ID, memberships and setup-key auto-groups.
package manager

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
)

// DefaultManagementURL is the TerraScale NetBird manager.
const DefaultManagementURL = "https://netbird.terrascale.tech"

// Slot is one fixed cell address. Every revision of the slot's server uses
// the same private IP, NetBird peer name and cell DNS name.
type Slot struct {
	Name string // DNS label inside the cell zone, e.g. controller-a
	IP   string // fixed primary private IPv4 address
	Role string // controller or member
}

type GroupSpec struct {
	Name        string
	RenamedFrom []string
}

type ResourceSpec struct {
	Name        string
	RenamedFrom []string
	Description string
	Address     string
}

type NetworkSpec struct {
	Name        string
	Description string
	Resource    ResourceSpec
	// The router is the single peer named RouterPeer in RouterGroup.
	RouterPeer  string
	RouterGroup string
	Metric      int
	Masquerade  bool
}

// PolicySpec has exactly one one-way accept rule named and described like
// the policy. Destination is a group, or DestinationResource a network
// resource of the managed network.
type PolicySpec struct {
	Name                string
	RenamedFrom         []string
	Description         string
	Protocol            string
	Ports               []string
	Sources             []string
	Destinations        []string
	DestinationResource string
}

type ZoneSpec struct {
	Name               string
	Domain             string
	DistributionGroups []string
	TTL                int
}

// Desired is the complete managed shape of one NetBird account.
type Desired struct {
	Cell              string
	Groups            []GroupSpec
	ServersGroup      string
	Network           NetworkSpec
	Policies          []PolicySpec
	NetworkRange      string
	PeerDNSDomain     string
	DNSDisabledGroups []string
	Zone              ZoneSpec
	Slots             []Slot
	// RoleAliases names a cell DNS name that resolves to every slot of a role.
	RoleAliases  map[string]string
	SetupKeyName string
}

// GRU returns the canonical desired state of the TerraScale manager.
func GRU() Desired {
	return Desired{
		Cell: "gru",
		Groups: []GroupSpec{
			{Name: "operators"},
			{Name: "ts-ops-gateway", RenamedFrom: []string{"gateway"}},
			{Name: "gru-servers", RenamedFrom: []string{"ts-orch-servers"}},
		},
		ServersGroup: "gru-servers",
		Network: NetworkSpec{
			Name: "gru-cell", Description: "TerraScale GRU private cell",
			Resource: ResourceSpec{Name: "gru-cell-private-subnet", RenamedFrom: []string{"gru-cell"},
				Description: "GRU cell private subnet, reached through the ts-ops routing peer",
				Address:     "10.251.0.0/25"},
			RouterPeer: "ts-ops", RouterGroup: "ts-ops-gateway", Metric: 100, Masquerade: true,
		},
		Policies: []PolicySpec{
			{Name: "operators-to-gru-cell-ops-ports", RenamedFrom: []string{"operators-to-gru-cell"},
				Description: "Operators → GRU cell subnet: SSH 22, NATS 4222, TerraBase 9465",
				Protocol:    "tcp", Ports: []string{"22", "4222", "9465"},
				Sources: []string{"operators"}, DestinationResource: "gru-cell-private-subnet"},
			{Name: "operators-to-gru-servers-ssh", RenamedFrom: []string{"operators-ssh-to-ts-orch-servers"},
				Description: "Operators → GRU servers: NetBird SSH with identity-provider login",
				Protocol:    "netbird-ssh", Sources: []string{"operators"}, Destinations: []string{"gru-servers"}},
			{Name: "operators-to-ts-ops-forgejo", RenamedFrom: []string{"operators-to-forgejo"},
				Description: "Operators → ts-ops: Git SSH 22, HTTPS 443, admin SSH 2022",
				Protocol:    "tcp", Ports: []string{"22", "443", "2022"},
				Sources: []string{"operators"}, Destinations: []string{"ts-ops-gateway"}},
			{Name: "operators-to-ts-ops-ping", RenamedFrom: []string{"operators-ping-to-forgejo"},
				Description: "Operators → ts-ops: ICMP ping",
				Protocol:    "icmp", Sources: []string{"operators"}, Destinations: []string{"ts-ops-gateway"}},
		},
		NetworkRange:      "10.200.0.0/16",
		PeerDNSDomain:     "nb.ts.internal",
		DNSDisabledGroups: []string{"gru-servers"},
		Zone: ZoneSpec{Name: "gru-cell", Domain: "gru.ts.internal",
			DistributionGroups: []string{"operators"}, TTL: 300},
		Slots: []Slot{
			{Name: "controller-a", IP: "10.251.0.11", Role: "controller"},
			{Name: "controller-b", IP: "10.251.0.12", Role: "controller"},
			{Name: "controller-c", IP: "10.251.0.13", Role: "controller"},
			{Name: "member-1", IP: "10.251.0.21", Role: "member"},
			{Name: "member-2", IP: "10.251.0.22", Role: "member"},
		},
		RoleAliases:  map[string]string{"nats": "controller", "terrabase": "member"},
		SetupKeyName: "gru-ts-orch-servers",
	}
}

// PeerName is the stable NetBird peer name of a slot, e.g. gru-controller-a.
func (d Desired) PeerName(slot Slot) string { return d.Cell + "-" + slot.Name }

// PeerNames maps every slot's private IP to its stable peer name. It is the
// source of the image's netbird.json peer_names.
func (d Desired) PeerNames() map[string]string {
	names := make(map[string]string, len(d.Slots))
	for _, slot := range d.Slots {
		names[slot.IP] = d.PeerName(slot)
	}
	return names
}

// Record is one desired A record in the cell zone.
type Record struct {
	Name    string // fully qualified, e.g. controller-a.gru.ts.internal
	Content string
}

// Records lists the cell zone's A records: one per slot and one per slot of
// each role alias, sorted.
func (d Desired) Records() []Record {
	var records []Record
	for _, slot := range d.Slots {
		records = append(records, Record{slot.Name + "." + d.Zone.Domain, slot.IP})
	}
	for _, alias := range slices.Sorted(maps.Keys(d.RoleAliases)) {
		for _, slot := range d.Slots {
			if slot.Role == d.RoleAliases[alias] {
				records = append(records, Record{alias + "." + d.Zone.Domain, slot.IP})
			}
		}
	}
	slices.SortFunc(records, func(a, b Record) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		return strings.Compare(a.Content, b.Content)
	})
	return records
}

// Validate checks internal consistency: referenced groups exist, slots are
// unique private addresses inside the cell subnet, names are unique.
func (d Desired) Validate() error {
	groups := map[string]bool{}
	for _, group := range d.Groups {
		for _, name := range append([]string{group.Name}, group.RenamedFrom...) {
			if name == "" || groups[name] {
				return fmt.Errorf("desired NetBird group name %q is empty or repeated", name)
			}
			groups[name] = true
		}
	}
	known := func(names ...string) error {
		for _, name := range names {
			if !groups[name] {
				return fmt.Errorf("desired NetBird state references unknown group %q", name)
			}
		}
		return nil
	}
	if err := known(append(append([]string{d.ServersGroup, d.Network.RouterGroup}, d.DNSDisabledGroups...), d.Zone.DistributionGroups...)...); err != nil {
		return err
	}
	subnet, err := netip.ParsePrefix(d.Network.Resource.Address)
	if err != nil || subnet != subnet.Masked() {
		return errors.New("desired NetBird cell subnet is not a canonical prefix")
	}
	policies := map[string]bool{}
	for _, policy := range d.Policies {
		for _, name := range append([]string{policy.Name}, policy.RenamedFrom...) {
			if policies[name] {
				return fmt.Errorf("desired NetBird policy name %q is repeated", name)
			}
			policies[name] = true
		}
		if err := known(append(slices.Clone(policy.Sources), policy.Destinations...)...); err != nil {
			return err
		}
		if (len(policy.Destinations) == 0) == (policy.DestinationResource == "") ||
			policy.DestinationResource != "" && policy.DestinationResource != d.Network.Resource.Name {
			return fmt.Errorf("desired NetBird policy %q needs exactly one destination kind", policy.Name)
		}
	}
	seenIP, seenName := map[string]bool{}, map[string]bool{}
	for _, slot := range d.Slots {
		ip, err := netip.ParseAddr(slot.IP)
		if err != nil || !ip.Is4() || ip.String() != slot.IP || seenIP[slot.IP] || seenName[slot.Name] || slot.Name == "" {
			return fmt.Errorf("desired NetBird slot %q is invalid or repeated", slot.Name)
		}
		if _, alias := d.RoleAliases[slot.Name]; alias {
			return fmt.Errorf("desired NetBird slot %q collides with a role alias", slot.Name)
		}
		seenIP[slot.IP], seenName[slot.Name] = true, true
	}
	return nil
}
