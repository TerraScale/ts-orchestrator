package mesh

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

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
	return n.fabricQuorum(ctx, false)
}

type raftGroup struct {
	Group    string
	ID       string
	Leader   bool
	Term     uint64
	Members  []string
	Current  []string
	Active   []string
	Quorum   int
	Size     int
	Changing bool
}

func (n *FabricLifecycle) raftGroups() []raftGroup {
	groups := make([]raftGroup, 0)
	for _, node := range n.server.RaftNodes() {
		group := raftGroup{Group: node.Group(), ID: node.ID(), Leader: node.Leader(), Term: node.Term(),
			Members: node.VotingPeerNames(), Quorum: node.QuorumNeeded(), Size: node.ClusterSize(), Changing: node.MembershipChangeInProgress()}
		if group.Leader {
			for _, peer := range node.Peers() {
				if peer.ID == group.ID || time.Since(peer.Last) < replicaActiveMax {
					group.Active = append(group.Active, peer.ID)
					if peer.Current {
						group.Current = append(group.Current, peer.ID)
					}
				}
			}
		}
		groups = append(groups, group)
	}
	return groups
}

func (n *FabricLifecycle) groupLeaders(ctx context.Context, groups []raftGroup) (map[string]raftGroup, error) {
	leaders := make(map[string]raftGroup)
	for _, group := range groups {
		if group.Leader {
			leaders[group.Group] = group
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
	accounts, err := n.server.Accountz(nil)
	if err != nil {
		return nil, err
	}
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
		for _, account := range reply.Data {
			for name, raft := range account {
				if raft.State != "LEADER" || raft.Term < leaders[name].Term {
					continue
				}
				group := raftGroup{Group: name, ID: raft.ID, Leader: true, Term: raft.Term,
					Size: raft.Size, Quorum: raft.QuorumNeeded, Members: []string{raft.ID}, Current: []string{raft.ID}, Active: []string{raft.ID}}
				for id, peer := range raft.Peers {
					group.Members = append(group.Members, id)
					age, err := time.ParseDuration(peer.LastSeen)
					if peer.Known && err == nil && age < replicaActiveMax {
						group.Active = append(group.Active, id)
						if peer.LastReplicatedIndex >= raft.Committed {
							group.Current = append(group.Current, id)
						}
					}
					group.Changing = group.Changing || !peer.Known
				}
				leaders[name] = group
			}
		}
	}
	return leaders, nil
}

func (n *FabricLifecycle) fabricQuorum(ctx context.Context, stopping bool) error {
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
		current := 0
		for _, id := range leader.Current {
			if slices.Contains(group.Members, id) && (!stopping || id != group.ID) {
				current++
			}
		}
		if stopping && current < group.Quorum {
			active := 0
			for _, id := range leader.Active {
				if id != group.ID && slices.Contains(group.Members, id) {
					active++
				}
			}
			message := fmt.Sprintf("raft group %s: planned stop refused: %d current replicas remain, quorum needs %d", group.Group, current, group.Quorum)
			if active >= group.Quorum {
				return &replicaCatchup{message}
			}
			return fmt.Errorf("%s", message)
		}
		if !stopping && current != group.Size {
			return fmt.Errorf("raft group %s: leader %s, %d/%d current replicas, quorum needs %d", group.Group, leader.ID, current, group.Size, group.Quorum)
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
		err := n.fabricQuorum(ctx, true)
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
