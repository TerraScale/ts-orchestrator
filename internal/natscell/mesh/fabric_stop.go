package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

const metaGroup = "_meta_"

type FabricLifecycle struct {
	server       *server.Server
	monitor      *nats.Conn
	stopMu       sync.Mutex
	stopPrepared bool
}

func NewFabricLifecycle(s *server.Server, monitor *nats.Conn) *FabricLifecycle {
	return &FabricLifecycle{server: s, monitor: monitor}
}

func (n *Node) PrepareStop(ctx context.Context) error {
	return n.lifecycle.PrepareStop(ctx)
}

func (n *Node) AbortStop() {
	n.lifecycle.AbortStop()
}

func (n *FabricLifecycle) Health(ctx context.Context) error {
	targets := make(map[string]uint64)
	catchup := time.NewTimer(replicaActiveMax)
	defer catchup.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		err := n.fabricQuorum(ctx, false, targets)
		if err == nil {
			err = n.placement()
		}
		var catchingUp *replicaCatchup
		if !errors.As(err, &catchingUp) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-catchup.C:
			return err
		case <-tick.C:
		}
	}
}

func (n *FabricLifecycle) placement() error {
	for _, group := range n.raftGroups() {
		if group.Group != metaGroup || !group.Leader {
			continue
		}
		placeable := n.server.JetStreamClusterPeers()
		if len(placeable) < len(group.Members) {
			return &replicaCatchup{fmt.Sprintf("raft group %s: %d/%d members accept placement", group.Group, len(placeable), len(group.Members))}
		}
	}
	return nil
}

type raftGroup struct {
	Group      string
	ID         string
	Leader     bool
	Term       uint64
	Members    []string
	Active     []string
	Committed  uint64
	Replicated map[string]uint64
	Quorum     int
	Size       int
	Changing   bool
}

func (n *FabricLifecycle) raftGroups() []raftGroup {
	groups := make([]raftGroup, 0)
	for _, node := range n.server.RaftNodes() {
		group := raftGroup{Group: node.Group(), ID: node.ID(), Leader: node.Leader(), Term: node.Term(),
			Members: node.VotingPeerNames(), Quorum: node.QuorumNeeded(), Size: node.ClusterSize(), Changing: node.MembershipChangeInProgress()}
		groups = append(groups, group)
	}
	return groups
}

func (n *FabricLifecycle) groupLeaders(ctx context.Context, groups []raftGroup) (map[string]raftGroup, error) {
	leaders := make(map[string]raftGroup)
	accounts, err := n.server.Accountz(nil)
	if err != nil {
		return nil, err
	}
	for _, account := range accounts.Accounts {
		if status := n.server.Raftz(&server.RaftzOptions{AccountFilter: account}); status != nil {
			observeLeaders(leaders, *status)
		}
	}
	complete := func() bool {
		for _, group := range groups {
			if group.Size > 1 && slices.Contains(group.Members, group.ID) {
				leader, ok := leaders[group.Group]
				if !ok || leader.Term < group.Term {
					return false
				}
			}
		}
		return true
	}
	if complete() {
		return leaders, nil
	}
	inbox := n.monitor.NewRespInbox()
	sub, err := n.monitor.SubscribeSync(inbox)
	if err != nil {
		return nil, err
	}
	defer sub.Unsubscribe()
	for _, account := range accounts.Accounts {
		payload, err := json.Marshal(server.RaftzOptions{AccountFilter: account})
		if err != nil {
			return nil, err
		}
		if err := n.monitor.PublishRequest("$SYS.REQ.SERVER.PING.RAFTZ", inbox, payload); err != nil {
			return nil, err
		}
	}
	for !complete() {
		message, err := sub.NextMsgWithContext(ctx)
		if err != nil {
			return leaders, err
		}
		var reply struct {
			Data server.RaftzStatus
		}
		if err := json.Unmarshal(message.Data, &reply); err != nil {
			return leaders, err
		}
		observeLeaders(leaders, reply.Data)
	}
	return leaders, nil
}

func observeLeaders(leaders map[string]raftGroup, status server.RaftzStatus) {
	for _, account := range status {
		for name, raft := range account {
			if raft.State != "LEADER" || raft.Term < leaders[name].Term {
				continue
			}
			group := raftGroup{Group: name, ID: raft.ID, Leader: true, Term: raft.Term, Size: raft.Size, Quorum: raft.QuorumNeeded,
				Members: []string{raft.ID}, Active: []string{raft.ID}, Committed: raft.Committed, Replicated: map[string]uint64{raft.ID: raft.Committed}}
			for id, peer := range raft.Peers {
				group.Members = append(group.Members, id)
				age, err := time.ParseDuration(peer.LastSeen)
				if peer.Known && err == nil && age < replicaActiveMax {
					group.Active = append(group.Active, id)
					group.Replicated[id] = peer.LastReplicatedIndex
				}
				group.Changing = group.Changing || !peer.Known
			}
			leaders[name] = group
		}
	}
}

func (n *FabricLifecycle) fabricQuorum(ctx context.Context, stopping bool, targets map[string]uint64) error {
	groups := n.raftGroups()
	if len(groups) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	leaders, queryErr := n.groupLeaders(ctx, groups)
	for _, group := range groups {
		if group.Size <= 1 || !slices.Contains(group.Members, group.ID) {
			continue
		}
		leader, ok := leaders[group.Group]
		if !ok || leader.Term < group.Term {
			if stopping {
				return fmt.Errorf("raft group %s: planned stop refused: quorum cannot be verified without a current leader observation: %v", group.Group, queryErr)
			}
			return fmt.Errorf("raft group %s: no current leader observation: %v", group.Group, queryErr)
		}
		if group.Changing || leader.Changing || len(group.Members) != group.Size || !sameMembers(group.Members, leader.Members) {
			return fmt.Errorf("raft group %s: membership is changing", group.Group)
		}
		target := leader.Committed
		if targets != nil {
			key := fmt.Sprintf("%s/%d", leader.Group, leader.Term)
			if pinned, ok := targets[key]; ok {
				target = pinned
			} else {
				targets[key] = target
			}
		}
		current, active := 0, 0
		for _, id := range leader.Active {
			if !slices.Contains(group.Members, id) || (stopping && id == group.ID) {
				continue
			}
			active++
			if leader.Replicated[id] >= target {
				current++
			}
		}
		if stopping && current < group.Quorum {
			message := fmt.Sprintf("raft group %s: planned stop refused: %d current replicas remain, quorum needs %d", group.Group, current, group.Quorum)
			if active >= group.Quorum {
				return &replicaCatchup{message}
			}
			return fmt.Errorf("%s", message)
		}
		if !stopping && current != group.Size {
			message := fmt.Sprintf("raft group %s: leader %s, %d/%d current replicas, quorum needs %d", group.Group, leader.ID, current, group.Size, group.Quorum)
			if active == group.Size {
				return &replicaCatchup{message}
			}
			return fmt.Errorf("%s", message)
		}
	}
	return nil
}

type replicaCatchup struct {
	message string
}

func (e *replicaCatchup) Error() string { return e.message }

func sameMembers(a, b []string) bool {
	return len(a) == len(b) && slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}

func (n *FabricLifecycle) PrepareStop(ctx context.Context) error {
	n.stopMu.Lock()
	defer n.stopMu.Unlock()
	if n.stopPrepared {
		for _, group := range n.raftGroups() {
			if group.Leader && group.Size > 1 {
				n.stopPrepared = false
				break
			}
		}
		if n.stopPrepared {
			return nil
		}
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		err := n.fabricQuorum(ctx, true, nil)
		if err == nil {
			break
		}
		if _, catchingUp := err.(*replicaCatchup); !catchingUp {
			slog.Warn("mesh planned stop refused", "error", err)
			return err
		}
		select {
		case <-ctx.Done():
			err = fmt.Errorf("%w: %w", err, ctx.Err())
			slog.Warn("mesh planned stop refused", "error", err)
			return err
		case <-tick.C:
		}
	}
	before := n.raftGroups()
	led := make(map[string]uint64)
	for _, group := range before {
		if group.Leader && group.Size > 1 {
			led[group.Group] = group.Term
		}
	}
	n.server.TransferRaftLeaders()
	var remaining []string
	for {
		groups := n.raftGroups()
		observation, done := context.WithTimeout(ctx, time.Second)
		leaders, _ := n.groupLeaders(observation, groups)
		done()
		remaining = nil
		for name, term := range led {
			leader, ok := leaders[name]
			if !ok || leader.Term <= term {
				remaining = append(remaining, name)
			}
		}
		for _, group := range groups {
			if group.Leader && group.Size > 1 && !slices.Contains(remaining, group.Group) {
				remaining = append(remaining, group.Group)
			}
		}
		if len(remaining) == 0 {
			n.stopPrepared = true
			break
		}
		select {
		case <-ctx.Done():
			n.abortStopLocked()
			transferred := 0
			for name := range led {
				if !slices.Contains(remaining, name) {
					transferred++
				}
			}
			slog.Warn("mesh leaders transferred", "groups", transferred, "elapsed", time.Since(started), "remaining", remaining)
			return fmt.Errorf("planned stop refused: leadership handoff incomplete for raft groups %s: %w", strings.Join(remaining, ", "), ctx.Err())
		case <-tick.C:
		}
	}
	slog.Info("mesh leaders transferred", "groups", len(led), "elapsed", time.Since(started), "remaining", remaining)
	return nil
}

func (n *FabricLifecycle) AbortStop() {
	n.stopMu.Lock()
	defer n.stopMu.Unlock()
	n.abortStopLocked()
}

func (n *FabricLifecycle) abortStopLocked() {
	for _, node := range n.server.RaftNodes() {
		node.SetObserver(false)
	}
	n.stopPrepared = false
}
