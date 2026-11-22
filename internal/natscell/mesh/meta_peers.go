package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

const (
	metaTendEvery   = 30 * time.Second
	metaClaimsWait  = 5 * time.Second
	metaStepdownAPI = "$JS.API.META.LEADER.STEPDOWN"
)

type ManagerClaims func(ctx context.Context) (map[string]bool, error)

type peerStateRealigner interface {
	RealignPeerState(term uint64) error
}

type silentPeerRemover interface {
	ProposeRemoveSilentPeer(peer string, term uint64, silent time.Duration) error
}

func ClaimedPeers(serverNames []string) map[string]bool {
	claimed := map[string]bool{}
	for _, name := range serverNames {
		claimed[server.ServerNodeID(name)] = true
	}
	return claimed
}

func (n *FabricLifecycle) TendMeta(ctx context.Context, claims ManagerClaims) error {
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
	if local.Changing || leader.Changing || leader.Change != nil || !sameMembers(local.Members, leader.Members) {
		n.observeDisagreement(false)
		return nil
	}
	members, err := n.metaMembers(ctx)
	if err != nil {
		return err
	}
	disagreeing, pending := metaDisagreement(members, leader)
	if pending {
		return nil
	}
	if len(leader.Members) != leader.Size {
		disagreeing = append(disagreeing, fmt.Sprintf("leader size %d for %d members", leader.Size, len(leader.Members)))
	}
	if len(disagreeing) == 0 {
		n.observeDisagreement(false)
		if !local.Leader {
			return nil
		}
		return n.removeUnclaimed(ctx, meta, leader, claims)
	}
	if local.Leader {
		realigner, ok := meta.(peerStateRealigner)
		if !ok {
			return errors.New("metadata raft node cannot realign its peer state")
		}
		slog.Warn("mesh metadata views disagree with the leader's membership; the leader realigns its size and sends its peer state",
			"disagreeing", disagreeing, "members", len(leader.Members), "size", leader.Size, "term", leader.Term)
		return realigner.RealignPeerState(leader.Term)
	}
	if !n.observeDisagreement(true) {
		return nil
	}
	slog.Warn("mesh metadata views still disagree after a tend pass; this server asks to lead the metadata group to realign it",
		"disagreeing", disagreeing, "leader", leader.ID, "term", leader.Term)
	return n.takeMetaLeadership(ctx)
}

func (n *FabricLifecycle) observeDisagreement(disagreeing bool) bool {
	n.changeMu.Lock()
	defer n.changeMu.Unlock()
	repeated := disagreeing && n.disagreed
	n.disagreed = disagreeing && !repeated
	return repeated
}

func metaDisagreement(members []MetaMember, leader raftGroup) (disagreeing []string, pending bool) {
	for _, member := range members {
		if member.Observer || !slices.Contains(leader.Members, member.ID) {
			continue
		}
		pending = pending || member.Change != nil
		ids := []string{member.ID}
		for _, peer := range member.Peers {
			ids = append(ids, peer.ID)
			pending = pending || !peer.Known
		}
		if member.Size != len(leader.Members) || !sameMembers(ids, leader.Members) {
			disagreeing = append(disagreeing, fmt.Sprintf("%s: size %d, %d members", member.Server, member.Size, len(ids)))
		}
	}
	return disagreeing, pending
}

func (n *FabricLifecycle) takeMetaLeadership(ctx context.Context) error {
	payload, err := json.Marshal(server.JSApiLeaderStepdownRequest{Placement: &server.Placement{Preferred: n.server.Name()}})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, metaClaimsWait)
	defer cancel()
	reply, err := n.monitor.RequestWithContext(ctx, metaStepdownAPI, payload)
	if err != nil {
		return err
	}
	var response server.JSApiLeaderStepDownResponse
	if err := json.Unmarshal(reply.Data, &response); err != nil {
		return err
	}
	if response.Error != nil {
		return fmt.Errorf("metadata leader stepdown: %s", response.Error.Description)
	}
	return nil
}

func (n *FabricLifecycle) metaRaft() server.RaftNode {
	for _, node := range n.server.RaftNodes() {
		if node.Group() == metaGroup {
			return node
		}
	}
	return nil
}

func (n *FabricLifecycle) removeUnclaimed(ctx context.Context, meta server.RaftNode, leader raftGroup, claims ManagerClaims) error {
	var silent []string
	for _, id := range slices.Sorted(slices.Values(leader.Members)) {
		if !slices.Contains(leader.Active, id) {
			silent = append(silent, id)
		}
	}
	if len(silent) == 0 {
		return nil
	}
	claimed, err := claims(ctx)
	if err != nil {
		return err
	}
	remover, ok := meta.(silentPeerRemover)
	if !ok {
		return errors.New("metadata raft node cannot remove a silent peer")
	}
	for _, id := range silent {
		if claimed[id] {
			continue
		}
		slog.Warn("mesh metadata removes a silent peer that no region claims as a manager", "peer", id, "server", leader.Names[id],
			"last_seen", leader.Seen[id], "size", leader.Size, "active", len(leader.Active), "term", leader.Term)
		return remover.ProposeRemoveSilentPeer(id, leader.Term, replicaActiveMax)
	}
	return nil
}

type metaClaimsReply struct {
	Region string   `json:"region"`
	Peers  []string `json:"peers"`
	Error  string   `json:"error,omitempty"`
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
		if err := n.lifecycle.TendMeta(ctx, n.metaClaims); err != nil && ctx.Err() == nil {
			slog.Warn("mesh metadata membership not tended", "error", err)
		}
	}
}

func (n *Node) metaClaims(ctx context.Context) (map[string]bool, error) {
	claimed := map[string]bool{}
	for _, region := range Regions(n.cfg.region) {
		requestCtx, cancel := context.WithTimeout(ctx, metaClaimsWait)
		message, err := n.conn.RequestWithContext(requestCtx, protocol.MeshMetaClaimsPrefix+region, nil)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("%s manager claims: %w", region, err)
		}
		var reply metaClaimsReply
		if err := protocol.DecodeStrict(message.Data, &reply, maxWire); err != nil {
			return nil, fmt.Errorf("%s manager claims: %w", region, err)
		}
		if reply.Error != "" || reply.Region != region {
			return nil, fmt.Errorf("%s manager claims: region %q: %s", region, reply.Region, reply.Error)
		}
		for _, id := range reply.Peers {
			claimed[id] = true
		}
	}
	return claimed, nil
}

func (n *Node) serveMetaClaims(m *nats.Msg) {
	reply := metaClaimsReply{Region: n.cfg.region}
	names, err := n.managerServerNames(n.ctx)
	if err != nil {
		reply.Error = err.Error()
	} else {
		reply.Peers = slices.Sorted(maps.Keys(ClaimedPeers(names)))
	}
	n.respond(m, reply)
}

func (n *Node) managerServerNames(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, metaClaimsWait)
	defer cancel()
	client, conn, err := swarmruntime.DialControl(filepath.Dir(n.cfg.dir))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return nil, err
	}
	names := []string{n.cfg.region}
	for _, node := range listed.Nodes {
		if node.Role == api.NodeRoleManager || node.Spec.DesiredRole == api.NodeRoleManager {
			names = append(names, n.cfg.region+"."+node.ID[:min(12, len(node.ID))])
		}
	}
	return names, nil
}
