package manager

import (
	"context"
	"encoding/json/v2"
	"slices"
)

var opsGroups = []string{"operators", "ops-automation"}

const netbirdSSH = "netbird-ssh"

type sshGate struct {
	opsGroupIDs   map[string]bool
	serverPeerIDs map[string]bool
	serverGroups  map[string]bool
}

func newSSHGate(groups []apiGroup) sshGate {
	gate := sshGate{opsGroupIDs: map[string]bool{}, serverPeerIDs: map[string]bool{}, serverGroups: map[string]bool{}}
	for _, group := range groups {
		if slices.Contains(opsGroups, group.Name) {
			gate.opsGroupIDs[group.ID] = true
		}
		if regionServerGroup(group.Name) {
			for _, peer := range group.Peers {
				gate.serverPeerIDs[peer.ID] = true
			}
		}
	}
	for _, group := range groups {
		for _, peer := range group.Peers {
			if gate.serverPeerIDs[peer.ID] {
				gate.serverGroups[group.ID] = true
			}
		}
	}
	return gate
}

func (g sshGate) outsideOps(policies []apiPolicy) []string {
	var offending []string
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		if slices.ContainsFunc(policy.Rules, g.grantsOutsideOps) {
			offending = append(offending, policy.Name)
		}
	}
	return offending
}

func (g sshGate) grantsOutsideOps(rule apiRule) bool {
	if !rule.Enabled || rule.Action != "accept" || !admitsSSHPort(rule) {
		return false
	}
	return g.reachesServerFromOutsideOps(rule.Sources, rule.SourceResource, rule.Destinations, rule.DestinationResource) ||
		rule.Bidirectional && g.reachesServerFromOutsideOps(rule.Destinations, rule.DestinationResource, rule.Sources, rule.SourceResource)
}

func (g sshGate) reachesServerFromOutsideOps(from []groupMinimum, fromResource *resourceRef, to []groupMinimum, toResource *resourceRef) bool {
	reachesServer := slices.ContainsFunc(to, func(group groupMinimum) bool { return g.serverGroups[group.ID] }) ||
		toResource != nil && toResource.Type == "peer" && g.serverPeerIDs[toResource.ID]
	outsideOps := fromResource != nil || slices.ContainsFunc(from, func(group groupMinimum) bool { return !g.opsGroupIDs[group.ID] })
	return reachesServer && outsideOps
}

func admitsSSHPort(rule apiRule) bool {
	switch rule.Protocol {
	case "all", netbirdSSH:
		return true
	case "tcp":
	default:
		return false
	}
	if len(rule.Ports) == 0 && len(rule.PortRanges) == 0 {
		return true
	}
	if slices.Contains(rule.Ports, "22") || slices.Contains(rule.Ports, "22022") {
		return true
	}
	for _, raw := range rule.PortRanges {
		var span struct {
			Start int `json:"start"`
			End   int `json:"end"`
		}
		if json.Unmarshal(raw, &span) != nil {
			return true
		}
		if span.Start <= 22 && span.End >= 22 || span.Start <= 22022 && span.End >= 22022 {
			return true
		}
	}
	return false
}

func (p *plan) planServerSSHFlags(api *API, gate sshGate, peers []apiPeer) {
	for _, peer := range peers {
		if !gate.serverPeerIDs[peer.ID] || !peer.SSHEnabled {
			continue
		}
		p.add(Change{"update", "peer", peer.Name, "legacy SSH flag off"}, func(ctx context.Context, _ *refs) error {
			request := peerRequest{Name: peer.Name, SSHEnabled: false,
				LoginExpirationEnabled:      peer.LoginExpirationEnabled,
				InactivityExpirationEnabled: peer.InactivityExpirationEnabled}
			return api.do(ctx, "PUT", "/peers/"+peer.ID, request, nil)
		})
	}
}
