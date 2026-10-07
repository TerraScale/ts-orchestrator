package app

import (
	"context"
	"slices"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

// topologySource lists the cell's granted nodes for the region view. Every
// read is best effort: one that fails leaves its fields empty. ops is nil
// without a release channel.
func topologySource(cell string, brokerIDs []string, services *specRegistry, hosts *host.Controller,
	ops *nodeOps,
) func(context.Context) []regionview.Node {
	return func(ctx context.Context) []regionview.Node {
		// A controller's member name is its broker ID; its node is the one
		// the node operations' serverOf resolves too.
		members := make(map[string]string, len(brokerIDs))
		for _, id := range brokerIDs {
			members[services.controllerNode(cell, id)] = id
		}
		statuses, _ := hosts.ListHosts(ctx)
		var status nodeOpReply
		if ops != nil {
			status, _ = ops.status(ctx)
		}
		var sets []cellspec.FencedSet
		if fence, _ := services.releaseFence(); fence != nil {
			sets = fence.BackendSets
		}
		return topologyNodes(services.hostGrants(), members, statuses, status, sets)
	}
}

// topologyNodes is one node per host grant, sorted by name: its controller
// member, each granted role's verified report, its fence and active
// operation, and its backends (the fenced ones, else one per backend set of
// a role it runs).
func topologyNodes(grants []cellspec.HostGrant, members map[string]string, hosts []host.HostStatus,
	status nodeOpReply, sets []cellspec.FencedSet,
) []regionview.Node {
	nodes := make([]regionview.Node, 0, len(grants))
	for _, grant := range grants {
		node := regionview.Node{Name: grant.Node, Address: grant.PrivateIP, Member: members[grant.Node]}
		at := slices.IndexFunc(hosts, func(candidate host.HostStatus) bool {
			return candidate.Verified && candidate.Registration.Node == grant.Node
		})
		for _, role := range grant.Roles {
			service := regionview.Service{Role: role}
			if at >= 0 {
				for _, report := range hosts[at].Reports {
					if report.Role == role {
						service.Digest, service.State = report.Digest, report.State
					}
				}
			}
			node.Services = append(node.Services, service)
		}
		for _, op := range status.Operations {
			if op.Node == grant.Node && op.active() {
				node.Operation = op.Op
				if op.Step != "" {
					node.Operation += ": " + op.Step
				}
			}
		}
		if fenced := slices.IndexFunc(status.Fences, func(fence nodeFenceStatus) bool { return fence.Node == grant.Node }); fenced >= 0 {
			node.Fence = slices.Clone(status.Fences[fenced].Holders)
			for _, backend := range status.Fences[fenced].Backends {
				node.Backends = append(node.Backends, regionview.Backend{Set: backend.Set, Offline: backend.Offline})
			}
		} else {
			for _, set := range sets {
				if set.Role != "" && slices.Contains(grant.Roles, set.Role) {
					node.Backends = append(node.Backends, regionview.Backend{Set: set.Name})
				}
			}
		}
		nodes = append(nodes, node)
	}
	slices.SortFunc(nodes, func(a, b regionview.Node) int { return strings.Compare(a.Name, b.Name) })
	return nodes
}
