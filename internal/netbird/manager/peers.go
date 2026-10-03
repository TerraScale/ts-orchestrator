package manager

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
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
	var groups []apiGroup
	if err := api.do(ctx, "GET", "/groups", nil, &groups); err != nil {
		return Report{}, err
	}
	var spec GroupSpec
	for _, group := range d.Groups {
		if group.Name == d.ServersGroup {
			spec = group
		}
	}
	servers, err := matchName(groups, func(g apiGroup) string { return g.Name }, spec.Name, spec.RenamedFrom, "group")
	if err != nil {
		return Report{}, err
	}
	if servers == nil {
		return Report{}, fmt.Errorf("NetBird group %s does not exist", d.ServersGroup)
	}
	var all []apiPeer
	if err := api.do(ctx, "GET", "/peers", nil, &all); err != nil {
		return Report{}, err
	}
	var peers []apiPeer
	for _, peer := range all {
		if hasGroup(peer.Groups, servers.ID) {
			peers = append(peers, peer)
		}
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
	return p.run(ctx, apply)
}

func boolOrder(value bool) int {
	if value {
		return 1
	}
	return 0
}
