package manager

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/naming"
)

// DefaultOfflineFor is how long an unattributed server peer may stay
// disconnected before prune deletes it.
const DefaultOfflineFor = 24 * time.Hour

// PruneOptions tunes peer hygiene.
type PruneOptions struct {
	OfflineFor time.Duration
	Now        time.Time
}

// slotIP returns the cell address a server peer registered from. The 0.80
// REST API does not expose the client's reported interface addresses; the
// manager records the source address of the peer's management connection as
// connection_ip, and cell servers reach the manager over the private LPG
// path, so it is the slot's fixed private IP.
func slotIP(peer apiPeer) string {
	ip, err := netip.ParseAddr(peer.ConnectionIP)
	if err != nil {
		return ""
	}
	return ip.Unmap().String()
}

// cleanLabel reports whether a peer's DNS label is exactly its name, without
// the -<ip3>-<ip4> suffix NetBird adds on a label conflict.
func cleanLabel(peer apiPeer, name string) bool {
	return peer.DNSLabel == name || strings.HasPrefix(peer.DNSLabel, name+".")
}

// Prune keeps server peers named by slot: for each slot whose current
// revision is connected, it deletes the slot's disconnected peers (replaced
// revisions) and then names the connected peer after the slot. It also
// deletes server peers disconnected for longer than OfflineFor that belong
// to no connected slot, keeping the most recently seen peer of a slot that is
// down. Peers outside the servers group are never touched.
func Prune(ctx context.Context, api *API, d Desired, options PruneOptions, apply bool) (Report, error) {
	if err := d.Validate(); err != nil {
		return Report{}, err
	}
	if options.OfflineFor <= 0 {
		options.OfflineFor = DefaultOfflineFor
	}
	if options.Now.IsZero() {
		options.Now = time.Now()
	}
	peers, err := serverPeers(ctx, api, d)
	if err != nil {
		return Report{}, err
	}
	p := &plan{}
	handled := map[string]bool{}
	deletePeer := func(peer apiPeer, reason string) {
		handled[peer.ID] = true
		id := peer.ID
		p.add(Change{"delete", "peer", peer.Name, reason}, func(ctx context.Context, _ *refs) error {
			return api.do(ctx, "DELETE", "/peers/"+id, nil, nil)
		})
	}
	for _, slot := range d.Slots {
		name := d.PeerName(slot)
		var live, holders []apiPeer
		for _, peer := range peers {
			byIP := slotIP(peer) == slot.IP
			if byIP && peer.Connected {
				live = append(live, peer)
			}
			if byIP || peer.Name == name {
				holders = append(holders, peer)
			}
		}
		switch {
		case len(live) > 1:
			p.warn("slot %s has %d connected peers at %s; left alone", slot.Name, len(live), slot.IP)
			for _, peer := range holders {
				handled[peer.ID] = true
			}
			continue
		case len(live) == 0:
			// The slot is down: keep its most recently seen peer, the
			// revision expected to come back.
			if len(holders) > 0 {
				newest := slices.MaxFunc(holders, func(a, b apiPeer) int { return a.LastSeen.Compare(b.LastSeen) })
				handled[newest.ID] = true
			}
			continue
		}
		current := live[0]
		// A connected peer at another address holding the slot's name would
		// make the rename fail or churn every cycle: leave the whole slot
		// alone until an operator resolves it, so prune converges.
		squatter := slices.IndexFunc(holders, func(peer apiPeer) bool {
			return peer.ID != current.ID && peer.Connected
		})
		if squatter >= 0 {
			peer := holders[squatter]
			p.warn("connected peer %s at %s holds slot name %s; slot %s left alone", peer.Name, slotIP(peer), name, slot.Name)
			for _, peer := range holders {
				handled[peer.ID] = true
			}
			continue
		}
		handled[current.ID] = true
		for _, peer := range holders {
			if peer.ID != current.ID {
				deletePeer(peer, "replaced revision of "+slot.Name)
			}
		}
		if current.Name == name && cleanLabel(current, name) {
			continue
		}
		detail := "from " + current.Name
		if current.Name == name {
			detail = "clear DNS label " + current.DNSLabel
		}
		peer := current
		p.add(Change{"rename", "peer", name, detail}, func(ctx context.Context, _ *refs) error {
			request := peerRequest{Name: name, SSHEnabled: peer.SSHEnabled,
				LoginExpirationEnabled:      peer.LoginExpirationEnabled,
				InactivityExpirationEnabled: peer.InactivityExpirationEnabled}
			if peer.Name == name {
				// NetBird recomputes the DNS label only when the name
				// changes: step through a temporary name.
				temporary := request
				temporary.Name = name + "-renaming"
				if err := api.do(ctx, "PUT", "/peers/"+peer.ID, temporary, nil); err != nil {
					return err
				}
			}
			var out apiPeer
			if err := api.do(ctx, "PUT", "/peers/"+peer.ID, request, &out); err != nil {
				return err
			}
			if out.Name != name {
				return errors.New("manager did not rename the peer")
			}
			// Another peer holding the label would leave a suffixed label
			// and replan this rename every cycle: surface it instead.
			if !cleanLabel(out, name) {
				return fmt.Errorf("peer %s got DNS label %s: another peer holds the DNS label %s", name, out.DNSLabel, name)
			}
			return nil
		})
	}
	for _, peer := range peers {
		if handled[peer.ID] || peer.Connected {
			continue
		}
		if peer.LastSeen.IsZero() {
			p.warn("peer %s has no last-seen time; left alone", peer.Name)
			continue
		}
		if offline := options.Now.Sub(peer.LastSeen); offline > options.OfflineFor {
			deletePeer(peer, "disconnected for "+offline.Truncate(time.Minute).String())
		}
	}
	// Deletions run before renames so a slot name is free when its live peer
	// takes it.
	slices.SortStableFunc(p.steps, func(a, b step) int {
		return boolOrder(a.change.Action != "delete") - boolOrder(b.change.Action != "delete")
	})
	return p.run(ctx, apply, nil)
}

// Remove deletes the disconnected server peers of the named slots, matched
// by slot IP or slot peer name, or every disconnected server peer when slots
// is empty. It decommissions a torn-down server or cell, whose last peers
// prune keeps for the slot's return. Connected peers are left alone.
func Remove(ctx context.Context, api *API, d Desired, slots []string, apply bool) (Report, error) {
	if err := d.Validate(); err != nil {
		return Report{}, err
	}
	var targets []Slot
	for _, name := range slots {
		index := slices.IndexFunc(d.Slots, func(slot Slot) bool { return slot.Name == name })
		if index < 0 {
			return Report{}, fmt.Errorf("NetBird desired state has no slot %q", name)
		}
		targets = append(targets, d.Slots[index])
	}
	peers, err := serverPeers(ctx, api, d)
	if err != nil {
		return Report{}, err
	}
	p := &plan{}
	for _, peer := range peers {
		if len(targets) > 0 && !slices.ContainsFunc(targets, func(slot Slot) bool {
			return slotIP(peer) == slot.IP || peer.Name == d.PeerName(slot)
		}) {
			continue
		}
		if peer.Connected {
			p.warn("peer %s at %s is connected; stop its server first", peer.Name, slotIP(peer))
			continue
		}
		id := peer.ID
		p.add(Change{"delete", "peer", peer.Name, "decommissioned"}, func(ctx context.Context, _ *refs) error {
			return api.do(ctx, "DELETE", "/peers/"+id, nil, nil)
		})
	}
	return p.run(ctx, apply, nil)
}

// serverPeers lists the peers in the servers group. Peers outside it are
// never touched.
func serverPeers(ctx context.Context, api *API, d Desired) ([]apiPeer, error) {
	servers, err := serversGroupID(ctx, api, d)
	if err != nil {
		return nil, err
	}
	var all []apiPeer
	if err := api.do(ctx, "GET", "/peers", nil, &all); err != nil {
		return nil, err
	}
	var peers []apiPeer
	for _, peer := range all {
		if hasGroup(peer.Groups, servers) {
			peers = append(peers, peer)
		}
	}
	return peers, nil
}

// serversGroupID finds the servers group by its name or a former name.
func serversGroupID(ctx context.Context, api *API, d Desired) (string, error) {
	var groups []apiGroup
	if err := api.do(ctx, "GET", "/groups", nil, &groups); err != nil {
		return "", err
	}
	var spec GroupSpec
	for _, group := range d.Groups {
		if group.Name == d.ServersGroup {
			spec = group
		}
	}
	servers, err := matchName(groups, func(g apiGroup) string { return g.Name }, spec.Name, spec.RenamedFrom, "group")
	if err != nil {
		return "", err
	}
	if servers == nil {
		return "", fmt.Errorf("NetBird group %s does not exist", d.ServersGroup)
	}
	return servers.ID, nil
}

func boolOrder(value bool) int {
	if value {
		return 1
	}
	return 0
}

// admittedPeerRecords uses only the managed admission group, never a matching
// hostname in an operator group. Offline membership survives health outages.
func admittedPeerRecords(d Desired, peers []apiPeer, groups []apiGroup) ([]Record, error) {
	var spec GroupSpec
	for _, candidate := range d.Groups {
		if candidate.Name == d.ServersGroup {
			spec = candidate
			break
		}
	}
	group, err := matchName(groups, func(g apiGroup) string { return g.Name }, spec.Name, spec.RenamedFrom, "group")
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}
	if group.ID == "" || group.Issued != "api" {
		return nil, errors.New("NetBird DNS requires an API-owned server admission group")
	}
	region, _, _ := strings.Cut(d.Cell, "-")
	mesh := netip.MustParsePrefix(d.NetworkRange)
	selected := map[string]apiPeer{}
	for _, peer := range peers {
		if !hasGroup(peer.Groups, group.ID) {
			continue
		}
		if err := naming.Validate(peer.Name); err != nil || strings.HasSuffix(peer.Name, "-data") ||
			(!naming.IsNode(peer.Name, region) && !strings.HasPrefix(peer.Name, d.Cell+"-")) {
			return nil, fmt.Errorf("admitted NetBird peer %q has no canonical identity in %s", peer.Name, d.Cell)
		}
		ip, err := netip.ParseAddr(peer.IP)
		if err != nil || !ip.Is4() || ip.String() != peer.IP || !mesh.Contains(ip) {
			return nil, fmt.Errorf("admitted NetBird peer %s has no address in %s", peer.Name, d.NetworkRange)
		}
		old, exists := selected[peer.Name]
		if exists && old.Connected && peer.Connected {
			return nil, fmt.Errorf("several connected admitted peers are named %s", peer.Name)
		}
		if !exists || peer.Connected || !old.Connected && peer.LastSeen.After(old.LastSeen) {
			selected[peer.Name] = peer
		}
	}
	var records []Record
	addresses := map[string]string{}
	for _, peer := range selected {
		if other := addresses[peer.IP]; other != "" {
			return nil, fmt.Errorf("admitted NetBird peers %s and %s share %s", other, peer.Name, peer.IP)
		}
		addresses[peer.IP] = peer.Name
		label, role := peer.Name, ""
		for _, slot := range d.Slots {
			if d.PeerName(slot) == peer.Name {
				label, role = slot.Name, slot.Role
				break
			}
		}
		records = append(records, Record{label + "." + d.Zone.Domain, peer.IP})
		for alias, target := range d.RoleAliases {
			if role == target {
				records = append(records, Record{alias + "." + d.Zone.Domain, peer.IP})
			}
		}
	}
	slices.SortFunc(records, func(a, b Record) int {
		if n := strings.Compare(a.Name, b.Name); n != 0 {
			return n
		}
		return strings.Compare(a.Content, b.Content)
	})
	return records, nil
}
