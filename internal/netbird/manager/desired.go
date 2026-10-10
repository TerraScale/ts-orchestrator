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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/networkplan"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// DefaultManagementURL is the TerraScale NetBird manager.
const DefaultManagementURL = "https://netbird.terrascale.tech"

// Slot is one fixed cell address. Every revision of the slot's server uses
// the same private IP, NetBird peer name and cell DNS name.
type Slot struct {
	// Name is the slot's DNS label in the cell zone: its node, ts-gru-1
	// (TS-609), which is also its peer name, or <role>-<n>, e.g. db-1.
	Name string
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
	Region            string // OCI region; only its controllers reconcile this state
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

// GRU returns the home region's network, access and peer-hygiene state.
// Sync adds other regions from the authenticated manager's server groups.
func GRU() Desired {
	return Desired{
		Cell: "gru-1", Region: "sa-saopaulo-1",
		Groups: []GroupSpec{
			{Name: "operators"},
			{Name: "ts-ops-gateway", RenamedFrom: []string{"gateway"}},
			{Name: "gru-servers", RenamedFrom: []string{"ts-orch-servers"}},
			{Name: "ops-automation"},
		},
		ServersGroup: "gru-servers",
		Network: NetworkSpec{
			Name: "gru-cell", Description: "TerraScale GRU private cell",
			Resource: ResourceSpec{Name: "gru-cell-private-subnet", RenamedFrom: []string{"gru-cell"},
				Description: "GRU cell private subnet, reached through the ts-ops routing peer",
				Address:     "10.251.0.0/25"},
			RouterPeer: "ts-ops", RouterGroup: "ts-ops-gateway", Metric: 100, Masquerade: true,
		},
		Policies: slices.Concat([]PolicySpec{
			{Name: "operators-to-gru-cell-ops-ports", RenamedFrom: []string{"operators-to-gru-cell"},
				Description: "Operators → GRU cell subnet: SSH 22, NATS 4222, TerraBase 9465",
				Protocol:    "tcp", Ports: []string{"22", "4222", "9465"},
				Sources: []string{"operators"}, DestinationResource: "gru-cell-private-subnet"},
			{Name: "operators-to-gru-servers-ssh", RenamedFrom: []string{"operators-ssh-to-ts-orch-servers"},
				Description: "Operators → GRU servers: NetBird SSH with identity-provider login",
				Protocol:    "netbird-ssh", Sources: []string{"operators"}, Destinations: []string{"gru-servers"}},
			{Name: "ops-automation-to-gru-servers-ssh",
				Description: "Operator automation peers → GRU servers: NetBird SSH with identity-provider login",
				Protocol:    "netbird-ssh", Sources: []string{"ops-automation"}, Destinations: []string{"gru-servers"}},
		}, serverAccessPolicies([]string{"gru-servers"}), []PolicySpec{
			{Name: "operators-to-ts-ops-forgejo", RenamedFrom: []string{"operators-to-forgejo"},
				Description: "Operators → ts-ops: Git SSH 22, HTTPS 443, admin SSH 2022",
				Protocol:    "tcp", Ports: []string{"22", "443", "2022"},
				Sources: []string{"operators"}, Destinations: []string{"ts-ops-gateway"}},
			{Name: "operators-to-ts-ops-ping", RenamedFrom: []string{"operators-ping-to-forgejo"},
				Description: "Operators → ts-ops: ICMP ping",
				Protocol:    "icmp", Sources: []string{"operators"}, Destinations: []string{"ts-ops-gateway"}},
		}),
		NetworkRange:      networkplan.Mesh,
		PeerDNSDomain:     "nb.ts.internal",
		DNSDisabledGroups: []string{},
		Zone: ZoneSpec{Name: "gru-cell", Domain: "gru.ts.internal",
			DistributionGroups: []string{"operators"}, TTL: 300},
		Slots: []Slot{
			{Name: "ts-gru-1", IP: "10.251.0.11", Role: "controller"},
			{Name: "ts-gru-2", IP: "10.251.0.12", Role: "controller"},
			{Name: "ts-gru-3", IP: "10.251.0.13", Role: "controller"},
			{Name: "db-1", IP: "10.251.0.21", Role: "member"},
			{Name: "db-2", IP: "10.251.0.22", Role: "member"},
		},
		RoleAliases:  map[string]string{"nats": "controller", "terrabase": "member"},
		SetupKeyName: "gru-servers",
	}
}

func regionServerGroup(name string) bool {
	cell, ok := strings.CutSuffix(name, "-servers")
	_, known := catalog.LookupName(cell)
	return ok && known
}

func (d Desired) withServerGroups(names []string) (Desired, error) {
	d.Groups, d.Policies = slices.Clone(d.Groups), slices.Clone(d.Policies)
	names = slices.Clone(names)
	slices.Sort(names)
	for _, name := range slices.Compact(names) {
		if !regionServerGroup(name) {
			return d, fmt.Errorf("NetBird group %q is not a canonical regional servers group", name)
		}
		if slices.ContainsFunc(d.Groups, func(group GroupSpec) bool { return group.Name == name }) {
			continue
		}
		d.Groups = append(d.Groups, GroupSpec{Name: name})
		d.Policies = slices.Concat(d.Policies, regionPolicies([]string{name}), serverAccessPolicies([]string{name}))
	}
	return d, nil
}

// serverAccessPolicies grant dashboard access, DNS visibility and the
// same-cell service probes used by managed NetBird rollouts.
func serverAccessPolicies(groups []string) []PolicySpec {
	var policies []PolicySpec
	for _, group := range groups {
		cell := strings.ToUpper(strings.TrimSuffix(group, "-servers"))
		policies = append(policies, PolicySpec{Name: "operators-to-" + group + "-dashboard",
			Description: "Operators and operator automation → " + cell + " servers: operator dashboard 9463 on their NetBird addresses",
			Protocol:    "tcp", Ports: []string{"9463"}, Sources: []string{"operators", "ops-automation"}, Destinations: []string{group}},
			PolicySpec{Name: group + "-to-" + group + "-ping",
				Description: cell + " servers → same-region servers: ICMP diagnostics and peer DNS visibility",
				Protocol:    "icmp", Sources: []string{group}, Destinations: []string{group}},
			PolicySpec{Name: group + "-to-" + group + "-service-health",
				Description: cell + " servers → same-region servers: NATS client 4222, ts-auth readiness 8080, TerraBase readiness 9465",
				Protocol:    "tcp", Ports: []string{"4222", "8080", "9465"}, Sources: []string{group}, Destinations: []string{group}})
	}
	return policies
}

// fabricPorts are the region-to-region ports between the home region's
// servers and another region's, the fallback path beside the OCI private
// peering (TS-668): the NATS interregion leafnode link and TerraBase's
// member peer port.
var fabricPorts = []string{"7422", "9443"}

// regionPolicies grants operators and operator automation NetBird SSH to
// every other region's servers group, and lets the home region's servers and
// that group reach each other on fabricPorts.
func regionPolicies(groups []string) []PolicySpec {
	var policies []PolicySpec
	for _, group := range groups {
		cell := strings.ToUpper(strings.TrimSuffix(group, "-servers"))
		ports := "NATS leafnodes " + fabricPorts[0] + ", TerraBase peers " + fabricPorts[1]
		policies = append(policies,
			PolicySpec{Name: "operators-to-" + group + "-ssh",
				Description: "Operators → " + cell + " servers: NetBird SSH with identity-provider login",
				Protocol:    "netbird-ssh", Sources: []string{"operators"}, Destinations: []string{group}},
			PolicySpec{Name: "ops-automation-to-" + group + "-ssh",
				Description: "Operator automation peers → " + cell + " servers: NetBird SSH with identity-provider login",
				Protocol:    "netbird-ssh", Sources: []string{"ops-automation"}, Destinations: []string{group}},
			PolicySpec{Name: "gru-servers-to-" + group + "-fabric",
				Description: "GRU servers → " + cell + " servers: " + ports,
				Protocol:    "tcp", Ports: fabricPorts, Sources: []string{"gru-servers"}, Destinations: []string{group}},
			PolicySpec{Name: group + "-to-gru-servers-fabric",
				Description: cell + " servers → GRU servers: " + ports,
				Protocol:    "tcp", Ports: fabricPorts, Sources: []string{group}, Destinations: []string{"gru-servers"}})
	}
	return policies
}

// PeerName is the stable NetBird peer name of a slot: its node, e.g.
// ts-gru-1, or <cell>-<role>-<n>, e.g. gru-1-db-1.
func (d Desired) PeerName(slot Slot) string {
	if region, _, _ := strings.Cut(d.Cell, "-"); naming.IsNode(slot.Name, region) {
		return slot.Name
	}
	return d.Cell + "-" + slot.Name
}

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
	Name    string // fully qualified, e.g. ctl-1.gru.ts.internal
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
	if err := networkplan.ValidateMesh(d.NetworkRange); err != nil {
		return err
	}
	// Names must be unique across current and former names, but references
	// resolve only against current names: a former name is renamed away.
	seenGroup, groups := map[string]bool{}, map[string]bool{}
	for _, group := range d.Groups {
		for _, name := range append([]string{group.Name}, group.RenamedFrom...) {
			if name == "" || seenGroup[name] {
				return fmt.Errorf("desired NetBird group name %q is empty or repeated", name)
			}
			seenGroup[name] = true
		}
		groups[group.Name] = true
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
	cell, _, _ := strings.Cut(d.Cell, "-")
	if err := networkplan.ValidateRegion(strings.ToUpper(cell), d.Network.Resource.Address); err != nil {
		return err
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
	seenIP, seenName, roles := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, slot := range d.Slots {
		ip, err := netip.ParseAddr(slot.IP)
		if err != nil || !ip.Is4() || ip.String() != slot.IP || seenIP[slot.IP] || seenName[slot.Name] || slot.Name == "" {
			return fmt.Errorf("desired NetBird slot %q is invalid or repeated", slot.Name)
		}
		if err := naming.Validate(d.PeerName(slot)); err != nil {
			return fmt.Errorf("desired NetBird peer name: %w", err)
		}
		if !ip.IsPrivate() || !subnet.Contains(ip) {
			return fmt.Errorf("desired NetBird slot %q address %s is not a private address inside the cell subnet %s", slot.Name, slot.IP, subnet)
		}
		roles[slot.Role] = true
		if _, alias := d.RoleAliases[slot.Name]; alias {
			return fmt.Errorf("desired NetBird slot %q collides with a role alias", slot.Name)
		}
		seenIP[slot.IP], seenName[slot.Name] = true, true
	}
	for _, alias := range slices.Sorted(maps.Keys(d.RoleAliases)) {
		if role := d.RoleAliases[alias]; role == "" || !roles[role] {
			return fmt.Errorf("desired NetBird role alias %q targets unknown role %q", alias, role)
		}
	}
	return nil
}
