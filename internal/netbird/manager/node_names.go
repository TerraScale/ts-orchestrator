package manager

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// nodeRegion recognizes canonical node names without treating a hostname as
// admission. M1's common servers setup key admits nodes from every region to
// gru-servers; their automatic peer DNS is independent of the GRU cell zone.
func nodeRegion(name string) string {
	parts := strings.Split(name, "-")
	if len(parts) != 3 || parts[0] != "ts" {
		return ""
	}
	if _, ok := catalog.LookupName(parts[1]); ok && naming.IsNode(name, parts[1]) {
		return parts[1]
	}
	return ""
}

// planNodeNames migrates the admitted legacy controller identity in place.
// ConnectionIP may be a public NAT address, and the OS hostname may still be
// stale, so neither can identify an M1 controller. Its retained canonical
// legacy name does. A conflicting name or DNS label fails before any writes;
// no peer is deleted or re-enrolled to free a name.
func (p *plan) planNodeNames(api *API, d Desired, peers []apiPeer, groups []apiGroup) ([]apiPeer, error) {
	var spec GroupSpec
	for _, candidate := range d.Groups {
		if candidate.Name == d.ServersGroup {
			spec = candidate
			break
		}
	}
	group, err := matchName(groups, func(g apiGroup) string { return g.Name }, spec.Name, spec.RenamedFrom, "group")
	if err != nil || group == nil {
		return peers, err
	}
	if group.ID == "" || group.Issued != "api" {
		return nil, fmt.Errorf("NetBird peer naming requires an API-owned server admission group")
	}
	region, _, _ := strings.Cut(d.Cell, "-")
	peers = slices.Clone(peers)
	for i, peer := range peers {
		if !hasGroup(peer.Groups, group.ID) {
			continue
		}
		number, legacy := strings.CutPrefix(peer.Name, d.Cell+"-ctl-")
		name := "ts-" + region + "-" + number
		if !legacy || !naming.IsNode(name, region) {
			continue
		}
		for _, other := range peers {
			if other.ID != peer.ID && (other.Name == name || cleanLabel(other, name)) {
				return nil, fmt.Errorf("NetBird node %s conflicts with another peer; retained peers left unchanged", name)
			}
		}
		p.add(Change{"rename", "peer", name, "from " + peer.Name}, func(ctx context.Context, _ *refs) error {
			var out apiPeer
			request := peerRequest{Name: name, SSHEnabled: peer.SSHEnabled,
				LoginExpirationEnabled:      peer.LoginExpirationEnabled,
				InactivityExpirationEnabled: peer.InactivityExpirationEnabled}
			if err := api.do(ctx, "PUT", "/peers/"+peer.ID, request, &out); err != nil {
				return err
			}
			if out.Name != name || !cleanLabel(out, name) {
				return fmt.Errorf("NetBird node %s did not receive its canonical DNS label", name)
			}
			return nil
		})
		peers[i].Name = name
	}
	return peers, nil
}
