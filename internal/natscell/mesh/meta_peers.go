package mesh

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats-server/v2/server"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

const metaTendEvery = 30 * time.Second

type PeerGone func(ctx context.Context, id, name string) (bool, error)

func (n *FabricLifecycle) TendMeta(ctx context.Context, gone PeerGone) error {
	meta := n.metaRaft()
	if meta == nil || meta.GroupLeader() == "" {
		return nil
	}
	var local raftGroup
	for _, group := range n.raftGroups() {
		if group.Group == metaGroup {
			local = group
		}
	}
	if local.Size <= 1 || !slices.Contains(local.Members, local.ID) {
		return nil
	}
	observeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	leaders, err := n.groupLeaders(observeCtx, []raftGroup{local})
	leader, ok := leaders[metaGroup]
	if !ok || leader.Term < local.Term {
		return fmt.Errorf("raft group %s: no current leader observation: %v", metaGroup, err)
	}
	if local.Changing || leader.Changing || !sameMembers(local.Members, leader.Members) || len(leader.Members) != leader.Size {
		return nil
	}
	if local.Leader {
		if err := n.alignMetaViews(ctx, meta, leader); err != nil {
			return err
		}
	}
	return removeGonePeer(ctx, meta, leader, gone)
}

func (n *FabricLifecycle) metaRaft() server.RaftNode {
	for _, node := range n.server.RaftNodes() {
		if node.Group() == metaGroup {
			return node
		}
	}
	return nil
}

func (n *FabricLifecycle) alignMetaViews(ctx context.Context, meta server.RaftNode, leader raftGroup) error {
	members, err := n.metaMembers(ctx)
	if err != nil {
		return err
	}
	for _, member := range members {
		if member.ID == leader.ID || member.Observer || !slices.Contains(leader.Members, member.ID) {
			continue
		}
		ids := []string{member.ID}
		pending := false
		for _, peer := range member.Peers {
			ids = append(ids, peer.ID)
			pending = pending || !peer.Known
		}
		if pending || member.Size == leader.Size && sameMembers(ids, leader.Members) {
			continue
		}
		slog.Warn("mesh metadata member disagrees with its leader's membership; the leader sends its peer state again",
			"member", member.Server, "size", member.Size, "members", len(ids), "leader_size", leader.Size, "leader_members", len(leader.Members))
		return meta.AdjustClusterSize(leader.Size)
	}
	return nil
}

func removeGonePeer(ctx context.Context, meta server.RaftNode, leader raftGroup, gone PeerGone) error {
	if len(leader.Active) < leader.Quorum {
		return nil
	}
	for _, id := range slices.Sorted(slices.Values(leader.Members)) {
		if slices.Contains(leader.Active, id) {
			continue
		}
		confirmed, err := gone(ctx, id, leader.Names[id])
		if err != nil {
			return err
		}
		if !confirmed {
			continue
		}
		slog.Warn("mesh metadata removes a peer that is offline and no longer a manager", "peer", id, "server", leader.Names[id],
			"last_seen", cmp.Or(leader.Seen[id], "never"), "size", leader.Size, "active", len(leader.Active))
		return meta.ProposeRemovePeer(id)
	}
	return nil
}

func (n *Node) tendMeta(ctx context.Context) {
	tick := time.NewTicker(metaTendEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if err := n.lifecycle.TendMeta(ctx, n.metaPeerGone); err != nil && ctx.Err() == nil {
			slog.Warn("mesh metadata membership not tended", "error", err)
		}
	}
}

func (n *Node) metaPeerGone(ctx context.Context, _, name string) (bool, error) {
	region, nodeID, ok := strings.Cut(name, ".")
	if !ok || region != n.cfg.region || nodeID == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client, conn, err := swarmruntime.DialControl(filepath.Dir(n.cfg.dir))
	if err != nil {
		return false, err
	}
	defer conn.Close()
	listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return false, err
	}
	if !swarmruntime.IsLeader(listed.Nodes, n.cfg.nodeID) {
		return false, nil
	}
	for _, node := range listed.Nodes {
		if strings.HasPrefix(node.ID, nodeID) && (node.Role == api.NodeRoleManager || node.Spec.DesiredRole == api.NodeRoleManager) {
			return false, nil
		}
	}
	return true, nil
}
