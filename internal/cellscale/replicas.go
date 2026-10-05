package cellscale

import (
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"
)

const ReplicaPath = "/v1/cell/replicas"
const maxReplicaBytes = 1 << 20

// ReplicaPlacement lists independently live, caught-up copies of one shard.
// A node appears at most once; stopped, lagging or receiver-only copies do not
// belong in LiveReplicas. The inventory includes every database, not a top-N.
type ReplicaPlacement struct {
	Org          string   `json:"org"`
	Database     string   `json:"database"`
	Shard        uint64   `json:"shard"`
	LiveReplicas []string `json:"live_replicas"`
}

// ReplicaSnapshot is an authoritative complete placement inventory. Missing
// inventory never means an empty cell; an empty Placements must be explicit.
type ReplicaSnapshot struct {
	Schema    int       `json:"schema"`
	Cell      string    `json:"cell"`
	SampledAt time.Time `json:"sampled_at"`
	Complete  bool      `json:"complete"`
	// Members binds every name in this inventory to its actual node lifetime.
	Members    []NodeIdentity     `json:"members"`
	Placements []ReplicaPlacement `json:"placements"`
}

func (s ReplicaSnapshot) Validate() error {
	if s.Schema != 1 || ValidateCell(s.Cell) != nil || s.SampledAt.IsZero() || !s.Complete || s.Members == nil || s.Placements == nil {
		return errors.New("missing or incomplete replica inventory")
	}
	members := make(map[string]bool, len(s.Members))
	for _, member := range s.Members {
		if _, ok := Ordinal(s.Cell, member.Name); !ok || !member.valid() || members[member.Name] {
			return errors.New("invalid or duplicate inventory member identity")
		}
		members[member.Name] = true
	}
	type key struct {
		org, database string
		shard         uint64
	}
	seen := map[key]bool{}
	for _, placement := range s.Placements {
		k := key{placement.Org, placement.Database, placement.Shard}
		if !orgRE.MatchString(placement.Org) || !releaseRE.MatchString(placement.Database) || placement.Shard == 0 ||
			placement.LiveReplicas == nil || seen[k] {
			return errors.New("invalid or duplicate database/shard placement")
		}
		seen[k] = true
		nodes := map[string]bool{}
		for _, node := range placement.LiveReplicas {
			if _, ok := Ordinal(s.Cell, node); !ok || nodes[node] || !members[node] {
				return fmt.Errorf("invalid or duplicate replica node %q", node)
			}
			nodes[node] = true
		}
	}
	return nil
}

// Replicas reads a bounded, complete inventory from a cell member. Scalar
// zero values cannot pass validation; null/absent lists remain nil.
func (m HTTPMembers) Replicas(ctx context.Context, node string) (ReplicaSnapshot, error) {
	client := m.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(m.Endpoint(node), "/")+ReplicaPath, nil)
	if err != nil {
		return ReplicaSnapshot{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return ReplicaSnapshot{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxReplicaBytes+1))
	if err != nil {
		return ReplicaSnapshot{}, err
	}
	if response.StatusCode != http.StatusOK || len(body) > maxReplicaBytes {
		return ReplicaSnapshot{}, fmt.Errorf("replica inventory: HTTP %d or response exceeds %d bytes", response.StatusCode, maxReplicaBytes)
	}
	var snapshot ReplicaSnapshot
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return ReplicaSnapshot{}, err
	}
	return snapshot, snapshot.Validate()
}

// fenceReplicas includes the whole allowed source clock skew, and never
// lowers the placement floor when the controller clock moves backwards.
func (c *Controller) fenceReplicas() {
	if after := c.config.Now().Add(MaxPressureClockSkew).UTC(); after.After(c.replicasAfter) {
		c.replicasAfter = after
	}
}

// replicasUsable retains even valid under-replicated evidence. Older or
// contradictory placement cannot replace it, including during a wait.
func (c *Controller) replicasUsable(snapshot ReplicaSnapshot) bool {
	if snapshot.Validate() != nil || snapshot.Cell != c.config.Cell || !(NodePressure{SampledAt: snapshot.SampledAt}).Fresh(c.config.Now()) {
		return false
	}
	// Inventory cannot establish a lifetime that OCI and pressure have not
	// independently observed. Keep only its timestamp as a refusal floor.
	matches := len(snapshot.Members) == len(c.lastMembership)
	for _, member := range snapshot.Members {
		matches = matches && c.lastMembership[member.Name] == member
	}
	if !matches {
		if previous := c.lastReplicas; previous != nil && previous.SampledAt.After(c.replicasAfter) {
			c.replicasAfter = previous.SampledAt.Round(0)
		}
		if snapshot.SampledAt.After(c.replicasAfter) {
			c.replicasAfter = snapshot.SampledAt.Round(0)
		}
		c.lastReplicas = nil
		return false
	}
	// Inventories are sets: wire order must not manufacture a contradiction.
	snapshot.SampledAt = snapshot.SampledAt.UTC()
	snapshot.Members = slices.Clone(snapshot.Members)
	slices.SortFunc(snapshot.Members, func(a, b NodeIdentity) int { return cmp.Compare(a.Name, b.Name) })
	snapshot.Placements = slices.Clone(snapshot.Placements)
	for i := range snapshot.Placements {
		snapshot.Placements[i].LiveReplicas = sorted(snapshot.Placements[i].LiveReplicas)
	}
	slices.SortFunc(snapshot.Placements, func(a, b ReplicaPlacement) int {
		return cmp.Or(cmp.Compare(a.Org, b.Org), cmp.Compare(a.Database, b.Database), cmp.Compare(a.Shard, b.Shard))
	})
	if previous := c.lastReplicas; previous != nil {
		if snapshot.SampledAt.Before(previous.SampledAt) {
			return false
		}
		if snapshot.SampledAt.Equal(previous.SampledAt) && !reflect.DeepEqual(snapshot, *previous) {
			// Poison this timestamp until a strictly newer inventory arrives.
			previous.Complete = false
			return false
		}
	}
	c.lastReplicas = &snapshot
	return snapshot.SampledAt.After(c.replicasAfter)
}

func (c *Controller) readReplicas(ctx context.Context, nodes []string, state State) *ReplicaSnapshot {
	for _, node := range nodes {
		if ctx.Err() != nil {
			return nil
		}
		snapshot, err := c.config.Members.Replicas(ctx, node)
		if err != nil {
			c.config.Logf("cellscale %s: replica inventory from %s: %v", c.config.Cell, node, err)
			continue
		}
		if c.replicasUsable(snapshot) {
			state.Now, state.Replicas = c.config.Now(), c.lastReplicas
			if validReplicaInventory(state) == nil {
				return c.lastReplicas
			}
		}
	}
	return nil
}

func (c *Controller) waitReplicas(ctx context.Context, _ []string, state State, accept ...func(State) bool) error {
	want := identities(state.Nodes)
	allowed := map[string]NodeState{}
	for _, node := range state.Nodes {
		if node.Pressure != nil && node.Pressure.State != StateReady {
			allowed[node.Name] = node.Pressure.State
		}
	}
	return c.waitIdentity(ctx, want, "", "", "post-convergence replica inventory", func(ctx context.Context, _ []Instance) (bool, error) {
		// A drain can take longer than the pressure age limit. Every poll
		// must re-observe the peers as well as their replacement copies.
		current, err := c.observe(ctx)
		if err != nil {
			return false, err
		}
		// Check identity and lifecycle after the RPC, then evidence freshness.
		if _, err := c.actionInstances(ctx, want, "", "", allowed); err != nil {
			return false, err
		}
		current.Now = c.config.Now()
		for i := range current.Nodes {
			node := &current.Nodes[i]
			pressure, found := c.lastPressure[want[node.Name]]
			if !found || !pressure.Fresh(current.Now) {
				return false, nil
			}
			node.Pressure = &pressure
		}
		if current.Replicas == nil || !c.replicasUsable(*current.Replicas) || validReplicaInventory(current) != nil {
			return false, nil
		}
		return len(accept) == 0 || accept[0](current), nil
	}, allowed)
}

// removalSafe is the termination gate: every database/shard must have its
// full live replica floor on surviving peers after drain convergence.
func removalSafe(policy Policy, state State, target string) error {
	if len(state.Nodes)-1 < max(policy.Nodes.Min, policy.ReplicationFactor) {
		return errors.New("removal would violate the cell or replica floor")
	}
	return replicasSafe(policy, state, target, max(policy.ReplicationFactor, policy.quorum()))
}

// replicasSafe also protects restarts, whose surviving replicas must retain
// quorum even if an individual database is already under-replicated.
func replicasSafe(policy Policy, state State, target string, required int) error {
	if err := validReplicaInventory(state); err != nil {
		return err
	}
	peers := map[string]bool{}
	for _, node := range state.Nodes {
		peers[node.Name] = node.Name != target && node.ready() && node.Pressure.Fresh(state.Now) &&
			node.Pressure.Load.ReplicationLagSeq <= policy.MaxReplicationLagSeq
	}
	for _, placement := range state.Replicas.Placements {
		survivors := 0
		for _, node := range placement.LiveReplicas {
			if peers[node] {
				survivors++
			}
		}
		if survivors < required {
			return fmt.Errorf("%s/%s shard %d would retain %d live replicas, need %d",
				placement.Org, placement.Database, placement.Shard, survivors, required)
		}
	}
	return nil
}

func validReplicaInventory(state State) error {
	if state.Replicas == nil {
		return errors.New("replica inventory unavailable")
	}
	snapshot := *state.Replicas
	if err := snapshot.Validate(); err != nil {
		return err
	}
	if snapshot.Cell != state.Cell || !(NodePressure{SampledAt: snapshot.SampledAt}).Fresh(state.Now) {
		return errors.New("replica inventory is stale or belongs to another cell")
	}
	known := map[string]bool{}
	members := make(map[string]NodeIdentity, len(snapshot.Members))
	for _, member := range snapshot.Members {
		members[member.Name] = member
	}
	if len(members) != len(state.Nodes) {
		return errors.New("replica inventory membership changed")
	}
	for _, node := range state.Nodes {
		if members[node.Name] != node.Identity() {
			return fmt.Errorf("replica inventory identity changed for node %s", node.Name)
		}
		known[node.Name] = true
	}
	for _, placement := range snapshot.Placements {
		for _, node := range placement.LiveReplicas {
			if !known[node] {
				return fmt.Errorf("replica inventory names unknown node %s", node)
			}
		}
	}
	return nil
}

// drainSafe checks space for each placement on target before asking TerraBase
// to prepare its replacement. Full surviving RF is required only at termination.
func drainSafe(policy Policy, state State, target string) error {
	if len(state.Nodes)-1 < max(policy.Nodes.Min, policy.ReplicationFactor) {
		return errors.New("drain would violate the cell or replica floor")
	}
	if err := validReplicaInventory(state); err != nil {
		return err
	}
	index := slices.IndexFunc(state.Nodes, func(n Node) bool { return n.Name == target })
	if index < 0 {
		return fmt.Errorf("drain target %s is unknown", target)
	}
	from := state.Nodes[index]
	if !from.ready() || !from.Pressure.Fresh(state.Now) || from.Pressure.Load.ReplicationLagSeq > policy.MaxReplicationLagSeq {
		return fmt.Errorf("drain target %s is not ready", target)
	}
	for _, placement := range state.Replicas.Placements {
		if !slices.Contains(placement.LiveReplicas, target) {
			continue
		}
		survivors := 0
		for _, peer := range state.Nodes {
			if peer.Name != target && peer.ready() && peer.Pressure.Fresh(state.Now) &&
				peer.Pressure.Load.ReplicationLagSeq <= policy.MaxReplicationLagSeq && slices.Contains(placement.LiveReplicas, peer.Name) {
				survivors++
			}
		}
		fits := slices.ContainsFunc(state.Nodes, func(peer Node) bool {
			return peer.Name != target && peer.ready() && peer.Pressure.Fresh(state.Now) &&
				peer.Pressure.Load.ReplicationLagSeq <= policy.MaxReplicationLagSeq &&
				(survivors >= policy.ReplicationFactor || !slices.Contains(placement.LiveReplicas, peer.Name)) &&
				drainFits(policy.Targets, from, peer)
		})
		if !fits {
			return fmt.Errorf("%s/%s shard %d has no destination that fits drain of %s", placement.Org, placement.Database, placement.Shard, target)
		}
	}
	return nil
}

func drainFits(targets Targets, from, to Node) bool {
	if from.Shape.OCPUs <= 0 || from.Shape.MemoryGB <= 0 || to.Shape.OCPUs <= 0 || to.Shape.MemoryGB <= 0 {
		return false
	}
	// ponytail: per-placement demand is unavailable; fit the target's whole
	// measured load on each destination so independent subset picks cannot
	// overbook it. Use per-placement demand if this bound blocks useful drains.
	p := *to.Pressure
	if from.Pressure.DiskUsedBytes > p.DiskTotalBytes-p.DiskUsedBytes {
		return false
	}
	p.CPUUtil += from.Pressure.CPUUtil * from.Shape.OCPUs / to.Shape.OCPUs
	p.MemoryUtil += from.Pressure.MemoryUtil * from.Shape.MemoryGB / to.Shape.MemoryGB
	p.DiskUsedBytes += from.Pressure.DiskUsedBytes
	p.DiskIOPS += from.Pressure.DiskIOPS
	p.RequestRate += from.Pressure.RequestRate
	p.IOQueueDepth += from.Pressure.IOQueueDepth
	p.P95LatencyMS += from.Pressure.P95LatencyMS
	return peak(p, targets) < 1
}
