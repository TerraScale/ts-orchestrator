// Package manager reconciles TerraScale's NetBird manager: groups, the GRU
// access policies, account and DNS settings, the cell DNS zone
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
	"strconv"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/networkplan"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
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
			{Name: "gru-servers", RenamedFrom: []string{"ts-orch-servers"}},
			{Name: "ops-automation"},
		},
		ServersGroup: "gru-servers",
		Network: NetworkSpec{
			Name: "gru-cell", Description: "TerraScale GRU private cell",
			Resource: ResourceSpec{Name: "gru-cell-private-subnet", RenamedFrom: []string{"gru-cell"},
				Description: "GRU cell private address plan",
				Address:     "10.251.0.0/25"},
		},
		Policies: slices.Concat([]PolicySpec{
			{Name: "operators-to-gru-servers-ssh", RenamedFrom: []string{"operators-ssh-to-ts-orch-servers"},
				Description: "Operators → GRU servers: NetBird SSH with identity-provider login",
				Protocol:    "netbird-ssh", Sources: []string{"operators"}, Destinations: []string{"gru-servers"}},
			{Name: "ops-automation-to-gru-servers-ssh",
				Description: "Operator automation peers → GRU servers: NetBird SSH with identity-provider login",
				Protocol:    "netbird-ssh", Sources: []string{"ops-automation"}, Destinations: []string{"gru-servers"}},
			{Name: "operators-to-gru-servers-openssh",
				Description: "Operators and operator automation → GRU servers: OpenSSH 22 on their NetBird addresses",
				Protocol:    "tcp", Ports: []string{"22"}, Sources: []string{"operators", "ops-automation"}, Destinations: []string{"gru-servers"}},
		}, serverAccessPolicies([]string{"gru-servers"})),

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
			PolicySpec{Name: group + "-to-" + group + "-mesh-routes",
				Description: cell + " servers → same-group servers: mesh NATS routes 6222 (mutual TLS, JetStream raft)",
				Protocol:    "tcp", Ports: []string{"6222"}, Sources: []string{group}, Destinations: []string{group}},
			PolicySpec{Name: group + "-to-" + group + "-service-health",
				Description: cell + " servers → same-region servers: NATS client 4222, ts-auth readiness 8080, TerraBase readiness 9465",
				Protocol:    "tcp", Ports: []string{"4222", "8080", "9465"}, Sources: []string{group}, Destinations: []string{group}},
			// Peers dial http://<wt0-ip>:<port> from the task peers file; requests carry the peer secret.
			PolicySpec{Name: group + "-to-" + group + "-terrabase-peers",
				Description: "TerraBase internal listener between servers (8081 production, 18081 the disposable terrabase-e2e; drop 18081 after the live proof)",
				Protocol:    "tcp", Ports: []string{"8081", "18081"}, Sources: []string{group}, Destinations: []string{group}})
	}
	return policies
}

// regionPolicies follows the production NATS star: spokes dial only the
// home listener. Network access does not issue NATS or OCI admission.
func regionPolicies(groups []string) []PolicySpec {
	var policies []PolicySpec
	home := natscell.LinkHome + "-servers"
	for _, group := range groups {
		cell := strings.ToUpper(strings.TrimSuffix(group, "-servers"))
		policies = append(policies,
			PolicySpec{Name: "operators-to-" + group + "-ssh",
				Description: "Operators → " + cell + " servers: NetBird SSH with identity-provider login",
				Protocol:    "netbird-ssh", Sources: []string{"operators"}, Destinations: []string{group}},
			PolicySpec{Name: "ops-automation-to-" + group + "-ssh",
				Description: "Operator automation peers → " + cell + " servers: NetBird SSH with identity-provider login",
				Protocol:    "netbird-ssh", Sources: []string{"ops-automation"}, Destinations: []string{group}},
			PolicySpec{Name: home + "-to-" + group + "-terrabase", RenamedFrom: []string{home + "-to-" + group + "-fabric"},
				Description: "Home servers → " + cell + " servers: TerraBase peers 9443",
				Protocol:    "tcp", Ports: []string{"9443"}, Sources: []string{home}, Destinations: []string{group}},
			PolicySpec{Name: group + "-to-" + home + "-terrabase",
				Description: cell + " servers → home servers: TerraBase peers 9443",
				Protocol:    "tcp", Ports: []string{"9443"}, Sources: []string{group}, Destinations: []string{home}},
			PolicySpec{Name: group + "-to-" + home + "-fabric",
				Description: cell + " servers → home servers: NATS leafnodes",
				Protocol:    "tcp", Ports: []string{strconv.Itoa(natscell.LinkPort)}, Sources: []string{group}, Destinations: []string{home}})
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
// historical private address plan, independent of enrolled peer discovery.
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
	if err := known(append(append([]string{d.ServersGroup}, d.DNSDisabledGroups...), d.Zone.DistributionGroups...)...); err != nil {
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
