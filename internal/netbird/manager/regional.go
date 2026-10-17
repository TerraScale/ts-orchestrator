package manager

import (
	"fmt"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/networkplan"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// Regional derives the fixed access policy from an authenticated region and its
// adopted host inventory. Callers must authenticate the subnet and slots first.
func Regional(cell, subnet string, slots []Slot) (Desired, error) {
	region, ok := catalog.LookupName(strings.ToLower(cell))
	if !ok || cell != strings.ToUpper(cell) {
		return Desired{}, fmt.Errorf("NetBird intent cell %q is not canonical", cell)
	}
	name := strings.ToLower(cell)
	servers := name + "-servers"
	d := Desired{
		Cell: name + "-1", Region: region.OCIRegion,
		Groups:       []GroupSpec{{Name: "operators"}, {Name: servers}, {Name: "ops-automation"}},
		ServersGroup: servers,
		Network: NetworkSpec{Name: name + "-cell", Description: "TerraScale " + cell + " private cell",
			Resource: ResourceSpec{Name: name + "-cell-private-subnet", Description: cell + " cell private address plan", Address: subnet}},
		Policies: []PolicySpec{
			{Name: "operators-to-" + servers + "-ssh", Description: "Operators → " + cell + " servers: NetBird SSH with identity-provider login",
				Protocol: "netbird-ssh", Sources: []string{"operators"}, Destinations: []string{servers}},
			{Name: "ops-automation-to-" + servers + "-ssh", Description: "Operator automation peers → " + cell + " servers: NetBird SSH with identity-provider login",
				Protocol: "netbird-ssh", Sources: []string{"ops-automation"}, Destinations: []string{servers}},
		},
		NetworkRange: networkplan.Mesh, PeerDNSDomain: "nb.ts.internal", DNSDisabledGroups: []string{},
		Zone:  ZoneSpec{Name: name + "-cell", Domain: name + ".ts.internal", DistributionGroups: []string{"operators"}, TTL: 300},
		Slots: slices.Clone(slots), SetupKeyName: servers, RoleAliases: map[string]string{},
	}
	for _, slot := range slots {
		switch slot.Role {
		case "controller":
			d.RoleAliases["nats"] = "controller"
		case "member":
			d.RoleAliases["terrabase"] = "member"
		default:
			return Desired{}, fmt.Errorf("NetBird intent slot %q has unsupported role %q", slot.Name, slot.Role)
		}
	}
	if cell == "GRU" {
		d.Groups[1].RenamedFrom = []string{"ts-orch-servers"}
		d.Network.Resource.RenamedFrom = []string{"gru-cell"}
		d.Policies[0].RenamedFrom = []string{"operators-ssh-to-ts-orch-servers"}
	}
	if cell != "GRU" {
		d.Groups = append(d.Groups, GroupSpec{Name: "gru-servers", RenamedFrom: []string{"ts-orch-servers"}})
		d.Policies = regionPolicies([]string{servers})
	}
	d.Policies = slices.Concat(d.Policies, serverAccessPolicies([]string{servers}))
	slices.SortFunc(d.Slots, func(a, b Slot) int { return strings.Compare(a.Name, b.Name) })
	if err := d.Validate(); err != nil {
		return Desired{}, err
	}
	return d, nil
}
