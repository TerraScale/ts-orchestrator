package mesh

import (
	"cmp"
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

const (
	metaGroup           = "_meta_"
	sustainWindow       = replicaActiveMax
	observeEvery        = 100 * time.Millisecond
	sustainObservations = 3
	stopBudget          = 5 * time.Second
)

type FabricLifecycle struct {
	server       *server.Server
	monitor      *nats.Conn
	stopMu       sync.Mutex
	stopPrepared bool
	changeMu     sync.Mutex
	changes      map[string]membershipChange
}

type membershipChange struct {
	description string
	since       time.Time
}

func NewFabricLifecycle(s *server.Server, monitor *nats.Conn) *FabricLifecycle {
	return &FabricLifecycle{server: s, monitor: monitor, changes: map[string]membershipChange{}}
}

func (n *Node) PrepareStop(ctx context.Context) error {
	return n.lifecycle.PrepareStop(ctx)
}

func (n *Node) AbortStop() {
	n.lifecycle.AbortStop()
}

func (n *FabricLifecycle) Health(ctx context.Context) error {
	targets := make(map[string]uint64)
	return sustained(ctx, replicaActiveMax, func() error { return n.observe(ctx, targets) })
}

func (n *FabricLifecycle) observe(ctx context.Context, targets map[string]uint64) error {
	if err := n.fabricQuorum(ctx, false, targets); err != nil {
		return err
	}
	return n.placement()
}

func sustained(ctx context.Context, catchup time.Duration, observe func() error) error {
	failing, failures := time.Now(), 0
	tick := time.NewTicker(observeEvery)
	defer tick.Stop()
	for {
		err := observe()
		if err == nil {
			return nil
		}
		failures++
		window := sustainWindow
		var catchingUp *replicaCatchup
		if errors.As(err, &catchingUp) {
			window = catchup
		}
		if failures >= sustainObservations && time.Since(failing) >= window {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", err, ctx.Err())
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
	Names      map[string]string
	Seen       map[string]string
	Pending    []string
	Change     *server.RaftzMembershipChange
	Quorum     int
	Size       int
	Changing   bool
}

func (n *FabricLifecycle) raftGroups() []raftGroup {
	groups := make([]raftGroup, 0)
	for _, node := range n.server.RaftNodes() {
		group := raftGroup{Group: node.Group(), ID: node.ID(), Leader: node.State() == server.Leader, Term: node.Term(),
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
				Members: []string{raft.ID}, Active: []string{raft.ID}, Committed: raft.Committed, Replicated: map[string]uint64{raft.ID: raft.Committed},
				Names: map[string]string{}, Seen: map[string]string{}, Change: raft.Change}
			for id, peer := range raft.Peers {
				group.Members = append(group.Members, id)
				group.Names[id], group.Seen[id] = peer.Name, peer.LastSeen
				if !peer.Known {
					group.Pending = append(group.Pending, id)
				}
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
		if group.Changing || leader.Changing || leader.Change != nil || !sameMembers(group.Members, leader.Members) {
			return n.membershipUnsettled(group, leader)
		}
		members := len(leader.Members)
		quorum := max(leader.Quorum, members/2+1)
		n.settled(group.Group)
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
		if stopping && current < quorum {
			message := fmt.Sprintf("raft group %s: planned stop refused: %d current replicas remain, quorum needs %d; not current: %s",
				group.Group, current, quorum, lagging(group, leader, target))
			if active >= quorum {
				return &replicaCatchup{message}
			}
			return fmt.Errorf("%s", message)
		}
		if !stopping && current != members {
			message := fmt.Sprintf("raft group %s: leader %s, %d/%d current replicas, quorum needs %d", group.Group, leader.ID, current, members, quorum)
			if active == members {
				return &replicaCatchup{message}
			}
			return fmt.Errorf("%s", message)
		}
	}
	return nil
}

func (n *FabricLifecycle) membershipUnsettled(local, leader raftGroup) error {
	names, localChange, namesErr := n.localMembership(local.Group)
	for id, name := range leader.Names {
		if name != "" {
			names[id] = name
		}
	}
	label := func(id string) string {
		if name := names[id]; name != "" {
			return name + " (" + id + ")"
		}
		return id + " (name unknown)"
	}
	pendingEntry := func(who string, change *server.RaftzMembershipChange) string {
		operation := "adding"
		if change.Removing {
			operation = "removing"
		}
		if change.Name != "" {
			names[change.Peer] = change.Name
		}
		return fmt.Sprintf("%s has not committed %s %s at index %d", who, operation, label(change.Peer), change.Index)
	}
	var parts []string
	if leader.Change != nil {
		parts = append(parts, pendingEntry("the leader", leader.Change))
	}
	for _, id := range slices.Sorted(slices.Values(leader.Pending)) {
		if leader.Change == nil || leader.Change.Peer != id {
			parts = append(parts, "the leader has not committed adding "+label(id))
		}
	}
	if localChange != nil && !local.Leader {
		parts = append(parts, pendingEntry("this server", localChange))
	} else if local.Changing && leader.Change == nil {
		parts = append(parts, "this server holds an uncommitted membership entry")
	}
	state := "membership change in progress"
	if len(parts) == 0 {
		state = "membership views disagree"
	}
	changing := func(id string) bool {
		return leader.Change != nil && leader.Change.Peer == id || localChange != nil && localChange.Peer == id
	}
	for _, id := range slices.Sorted(slices.Values(local.Members)) {
		if !slices.Contains(leader.Members, id) && !changing(id) {
			parts = append(parts, "this server lists "+label(id)+", the leader does not")
		}
	}
	for _, id := range slices.Sorted(slices.Values(leader.Members)) {
		if !slices.Contains(local.Members, id) && !slices.Contains(leader.Pending, id) && !changing(id) {
			parts = append(parts, "the leader lists "+label(id)+", this server does not")
		}
	}
	if len(leader.Members) != leader.Size {
		parts = append(parts, fmt.Sprintf("the leader counts %d members for cluster size %d", len(leader.Members), leader.Size))
	}
	if namesErr != nil {
		parts = append(parts, "local peer names unavailable: "+namesErr.Error())
	}
	description := strings.Join(parts, "; ")
	n.changeMu.Lock()
	change, ok := n.changes[local.Group]
	if !ok || change.description != description {
		change = membershipChange{description: description, since: time.Now()}
		n.changes[local.Group] = change
	}
	n.changeMu.Unlock()
	return fmt.Errorf("raft group %s: %s for %s: %s", local.Group, state, time.Since(change.since).Round(time.Second), description)
}

func (n *FabricLifecycle) settled(group string) {
	n.changeMu.Lock()
	delete(n.changes, group)
	n.changeMu.Unlock()
}

func (n *FabricLifecycle) localMembership(group string) (map[string]string, *server.RaftzMembershipChange, error) {
	names := map[string]string{}
	var change *server.RaftzMembershipChange
	accounts, err := n.server.Accountz(nil)
	if err != nil {
		return names, nil, err
	}
	for _, account := range accounts.Accounts {
		status := n.server.Raftz(&server.RaftzOptions{AccountFilter: account, GroupFilter: group})
		if status == nil {
			continue
		}
		for _, groups := range *status {
			if raft, ok := groups[group]; ok {
				change = raft.Change
				names[raft.ID] = n.server.Name()
				for id, peer := range raft.Peers {
					if peer.Name != "" {
						names[id] = peer.Name
					}
				}
			}
		}
	}
	return names, change, nil
}

func lagging(group, leader raftGroup, target uint64) string {
	var parts []string
	for _, id := range slices.Sorted(slices.Values(leader.Members)) {
		if id == group.ID || !slices.Contains(group.Members, id) || leader.Replicated[id] >= target && slices.Contains(leader.Active, id) {
			continue
		}
		seen := cmp.Or(leader.Seen[id], "never")
		parts = append(parts, fmt.Sprintf("%s (%s) last seen %s", cmp.Or(leader.Names[id], "name unknown"), id, seen))
	}
	if len(parts) == 0 {
		return "none besides this server"
	}
	return strings.Join(parts, ", ")
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
	ctx, cancel := context.WithTimeout(ctx, stopBudget)
	defer cancel()
	if err := sustained(ctx, stopBudget, func() error { return n.fabricQuorum(ctx, true, nil) }); err != nil {
		slog.Warn("mesh planned stop refused", "error", err)
		return err
	}
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	before := n.raftGroups()
	led := make(map[string]uint64)
	for _, group := range before {
		if group.Leader && group.Size > 1 {
			led[group.Group] = group.Term
		}
	}
	var remaining []string
	for {
		n.server.TransferRaftLeaders()
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
