package cellscale

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

const (
	actor               = "cellscale"
	DefaultPoll         = 10 * time.Second
	DefaultReadyTimeout = 30 * time.Minute
)

// Config wires one cell's controller.
type Config struct {
	Cell    string
	Policy  Policy
	Cloud   Cloud
	Members Members
	Source  Source
	// Rollouts reports a rollout in flight that the nodes' releases do not
	// show yet, for example the regional rollout store; nil relies on the
	// node releases alone.
	Rollouts func(context.Context) (bool, error)
	Now      func() time.Time
	// Poll paces the waits for a node to run, become ready or drain;
	// ReadyTimeout bounds each wait.
	Poll         time.Duration
	ReadyTimeout time.Duration
	Logf         func(string, ...any)
}

// Controller applies one cell's decisions. It runs at most one action at a
// time: Tick returns only after the action finished, failed or timed out.
type Controller struct {
	config Config

	// tick serializes whole ticks; mu guards history for readers.
	tick     sync.Mutex
	mu       sync.Mutex
	history  History
	lastHold string
	// blind counts consecutive ticks that could not observe the cell.
	blind int
	// Only the complete identity can own operational evidence or progress.
	lastPressure     map[NodeIdentity]NodePressure
	pendingRestarts  map[NodeIdentity]restartFence
	activeIdentities map[string]NodeIdentity
	lastMembership   map[string]NodeIdentity
	// Tombstones and floors can refuse evidence, never authorize an action.
	retiredIncarnations map[NodeIdentity]bool
	retiredInstances    map[NodeIdentity]bool
	pressureAfter       map[string]time.Time
	pressureHighWater   map[string]time.Time
	// OCI shape observations supply refusal only, independent of incarnation.
	observedShapes map[NodeIdentity]Shape
	// An ambiguous resize remains a refusal barrier after its progress is
	// invalidated. It belongs to the old identity, never to its successor.
	restartBarriers map[NodeIdentity]restartFence
	// A new controller has lost its in-memory restart fences. Never let
	// cached reports from before startup authorize its first mutations.
	startedAfter time.Time
	// Placement evidence must also follow membership/restart convergence.
	// Keep its sample high-water mark even while that evidence is fenced.
	replicasAfter time.Time
	lastReplicas  *ReplicaSnapshot
}

type restartFence struct {
	shape   Shape
	process string
	after   time.Time
}

// New validates config. The history starts as if an action just happened,
// so a restart waits out the cooldowns instead of acting at once.
func New(config Config) (*Controller, error) {
	if err := ValidateCell(config.Cell); err != nil {
		return nil, err
	}
	if err := config.Policy.Validate(); err != nil {
		return nil, err
	}
	if config.Cloud == nil || config.Members == nil || config.Source == nil {
		return nil, errors.New("cell autoscaler requires cloud, members and pressure source")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Poll <= 0 {
		config.Poll = DefaultPoll
	}
	if config.ReadyTimeout <= 0 {
		config.ReadyTimeout = DefaultReadyTimeout
	}
	if config.Logf == nil {
		config.Logf = func(string, ...any) {}
	}
	now := config.Now()
	return &Controller{config: config, history: History{LastAction: now}, startedAfter: now.Add(MaxPressureClockSkew), replicasAfter: now.Add(MaxPressureClockSkew),
		lastPressure: map[NodeIdentity]NodePressure{}, pendingRestarts: map[NodeIdentity]restartFence{},
		activeIdentities: map[string]NodeIdentity{}, retiredIncarnations: map[NodeIdentity]bool{}, retiredInstances: map[NodeIdentity]bool{},
		pressureAfter: map[string]time.Time{}, pressureHighWater: map[string]time.Time{}, observedShapes: map[NodeIdentity]Shape{}, restartBarriers: map[NodeIdentity]restartFence{}}, nil
}

// History returns the controller's decision memory.
func (c *Controller) History() History {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.history
}

// Resume clears a pause after an operator has looked at its failures.
func (c *Controller) Resume() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.history.Paused, c.history.Failures = false, 0
}

// Tick observes the cell, decides and applies at most one action. Ticks of
// one controller run one at a time.
func (c *Controller) Tick(ctx context.Context) (Action, error) {
	c.tick.Lock()
	defer c.tick.Unlock()
	state, err := c.observe(ctx)
	if err != nil {
		// A gap in observation is not sustained load: restart the window.
		c.mu.Lock()
		c.history.Want, c.history.WantSince = "", time.Time{}
		c.mu.Unlock()
		// The cell cannot act blind, so it needs no pause, but a lasting
		// outage of OCI or the rollout gate must reach an operator.
		if c.blind++; c.blind == c.config.Policy.MaxFailures {
			c.alert(ctx, fmt.Sprintf("Cell %s autoscaler cannot observe the cell after %d attempts", c.config.Cell, c.blind),
				"The autoscaler holds every action until OCI and the rollout gate answer again.", "observation-failing", err)
		}
		return Action{}, err
	}
	c.blind = 0
	c.mu.Lock()
	action, history := Decide(c.config.Policy, state, c.history)
	c.history = history
	c.mu.Unlock()
	if action.Kind == KindHold {
		c.journalHold(ctx, action)
		return action, nil
	}
	c.lastHold = ""
	dryRun := c.config.Policy.DryRun
	status := decisionlog.StatusInProgress
	if dryRun {
		status = decisionlog.StatusPending
	}
	id := c.journal(ctx, action, status, "", "")
	if !dryRun {
		err = c.apply(ctx, state, action)
	}
	now := c.config.Now()
	c.mu.Lock()
	wasPaused := c.history.Paused
	c.history = c.history.Recorded(now, err == nil, c.config.Policy.MaxFailures)
	paused := c.history.Paused && !wasPaused
	failures := c.history.Failures
	c.mu.Unlock()
	switch {
	case dryRun:
	case err != nil:
		c.journal(ctx, action, decisionlog.StatusFailed, id, "failed")
	default:
		c.journal(ctx, action, decisionlog.StatusSucceeded, id, "applied")
	}
	if paused {
		c.alert(ctx, fmt.Sprintf("Cell %s autoscaler paused after %d consecutive failed actions", c.config.Cell, failures),
			"Repeated failures pause the autoscaler until an operator resumes it.", ReasonPaused, err)
	}
	return action, err
}

// observe lists the cell's instances and reads every running node's
// pressure. An unreadable node stays in the state without pressure, which
// holds the cell. Failed listings, rollout checks or restart recovery
// identity/lifecycle checks fail the tick.
func (c *Controller) observe(ctx context.Context) (State, error) {
	instances, err := c.config.Cloud.List(ctx)
	if err != nil {
		c.fenceReplicas()
		return State{}, err
	}
	c.trackPressureIdentities(instances)
	state := State{Cell: c.config.Cell}
	membership := make(map[string]NodeIdentity)
	restartReady := false
	for _, instance := range instances {
		ordinal, ok := Ordinal(c.config.Cell, instance.Name)
		if !ok {
			continue
		}
		if instance.Foreign {
			state.Reserved = append(state.Reserved, ordinal)
			continue
		}
		membership[instance.Name] = c.activeIdentities[instance.Name]
		node := Node{Name: instance.Name, Ordinal: ordinal, ID: instance.ID, Shape: instance.Shape}
		if instance.Running() {
			c.convergeRestart(instance)
			if pressure, err := c.config.Source.Pressure(ctx, instance.Name); err == nil {
				if c.retainPressure(instance.Name, pressure) {
					node.Pressure = &pressure
					if _, _, pending := c.restartFor(instance.Name); pending {
						// Stage recovery; RPCs must not release the fence before
						// a final OCI read confirms the whole cell still runs.
						restartReady = true
						c.fenceReplicas()
					}
				} else {
					c.fenceReplicas()
				}
			} else {
				c.fenceReplicas()
				c.config.Logf("cellscale %s: node %s pressure: %v", c.config.Cell, instance.Name, err)
			}
		} else {
			c.fenceReplicas()
		}
		node.Incarnation = c.activeIdentities[instance.Name].Incarnation
		membership[instance.Name] = c.activeIdentities[instance.Name]
		state.Nodes = append(state.Nodes, node)
	}
	if !maps.Equal(membership, c.lastMembership) {
		c.fenceReplicas()
		c.lastMembership = membership
	}
	// The placement inventory is independent of top-tenant load telemetry.
	// An unavailable inventory holds removals and restarts.
	var replicaSources []string
	for _, node := range state.Nodes {
		if node.ready() {
			replicaSources = append(replicaSources, node.Name)
		}
	}
	state.Replicas = c.readReplicas(ctx, replicaSources, state)
	if c.config.Rollouts != nil {
		if state.RolloutInFlight, err = c.config.Rollouts(ctx); err != nil {
			return State{}, fmt.Errorf("rollout check: %w", err)
		}
	}
	if restartReady {
		confirmed, err := c.actionInstances(ctx, membership, "", "")
		if err != nil {
			return State{}, err
		}
		for i := range state.Nodes {
			node := &state.Nodes[i]
			if _, fence, pending := c.restartFor(node.Name); pending && node.Pressure != nil {
				converged := slices.ContainsFunc(confirmed, func(i Instance) bool {
					return i.Name == node.Name && i.ID == node.ID && i.Running() && sameShape(i.Shape, fence.shape)
				})
				pressure, found := c.lastPressure[node.Identity()]
				if converged && found && c.retainPressure(node.Name, pressure) {
					node.Pressure = &pressure
					// Placement was fenced before its RPC above.
					c.releaseRestart(node.Identity(), false)
				} else {
					node.Pressure = nil
				}
			}
		}
	}
	state.Now = c.config.Now()
	return state, nil
}

// apply runs one action. Before each step that changes the cell it
// rechecks what Decide saw, since a peer can fail or a rollout start during
// the minutes an action waits.
func (c *Controller) apply(ctx context.Context, state State, action Action) error {
	cloud, members := c.config.Cloud, c.config.Members
	expected := identities(state.Nodes)
	planned := slices.Clone(state.Nodes)
	switch action.Kind {
	case KindScaleOut:
		// Join once the node answers at all, then wait until it serves.
		launched := time.Time{}
		if !action.Recovery {
			if _, err := c.recheck(ctx, expected, "", "", planned); err != nil {
				return err
			}
			launched = c.config.Now().Add(MaxPressureClockSkew)
			c.fenceReplicas()
			instance, err := cloud.Launch(ctx, action.Node, action.To)
			if err != nil {
				c.fenceReplicas()
				return err
			}
			expected[action.Node] = NodeIdentity{Name: action.Node, InstanceID: instance.ID}
			planned = append(planned, Node{Name: action.Node, ID: instance.ID, Shape: action.To})
		}
		if err := c.waitNode(ctx, expected, action.Node, func(p NodePressure) bool { return p.SampledAt.After(launched) }); err != nil {
			return err
		}
		if _, err := c.recheck(ctx, expected, action.Node, StateJoining, planned); err != nil {
			return err
		}
		joined := c.config.Now().Add(MaxPressureClockSkew)
		c.fenceReplicas()
		if err := members.Join(ctx, expected[action.Node]); err != nil {
			c.fenceReplicas()
			return fmt.Errorf("join %s: %w", action.Node, err)
		}
		err := c.waitNode(ctx, expected, action.Node, func(p NodePressure) bool { return p.State == StateReady && p.SampledAt.After(joined) })
		c.fenceReplicas()
		if err == nil {
			_, err = c.recheck(ctx, expected, "", "", planned)
		}
		return err
	case KindScaleIn:
		index := slices.IndexFunc(state.Nodes, func(n Node) bool { return n.Name == action.Node })
		if index < 0 {
			return fmt.Errorf("instance %s not found", action.Node)
		}
		target := state.Nodes[index]
		skip, skipState := "", NodeState("")
		if action.Recovery {
			skip, skipState = action.Node, StateDraining
		}
		current, err := c.recheck(ctx, expected, skip, skipState, planned)
		if err != nil {
			return err
		}
		if !action.Recovery && action.Reason != ReasonAboveMax && !scaleInFits(c.config.Policy, current.Nodes) {
			return fmt.Errorf("before draining %s: projected pressure exceeds the scale-in threshold", action.Node)
		}
		drained := time.Time{}
		if !action.Recovery {
			if err := drainSafe(c.config.Policy, current, action.Node); err != nil {
				return fmt.Errorf("before draining %s: %w", action.Node, err)
			}
			drained = c.config.Now().Add(MaxPressureClockSkew)
			c.fenceReplicas()
			if err := members.Drain(ctx, expected[action.Node]); err != nil {
				c.fenceReplicas()
				return fmt.Errorf("drain %s: %w", action.Node, err)
			}
		} else {
			if len(current.Nodes)-1 < max(c.config.Policy.Nodes.Min, c.config.Policy.ReplicationFactor) {
				return errors.New("removal would violate the cell or replica floor")
			}
			if err := validReplicaInventory(current); err != nil {
				return fmt.Errorf("recovering drain %s: %w", action.Node, err)
			}
			for _, node := range current.Nodes {
				if node.Name == action.Node && node.Pressure.State == StateDrained {
					if err := removalSafe(c.config.Policy, current, action.Node); err != nil {
						return fmt.Errorf("before terminating %s: %w", action.Node, err)
					}
				}
			}
		}
		if err := c.waitNode(ctx, expected, action.Node, func(p NodePressure) bool { return p.State == StateDrained && p.SampledAt.After(drained) }); err != nil {
			return err
		}
		current, err = c.recheck(ctx, expected, action.Node, StateDrained, planned)
		if err != nil {
			return err
		}
		peers := slices.DeleteFunc(names(state.Nodes), func(node string) bool { return node == action.Node })
		if err := c.waitReplicas(ctx, peers, current, func(s State) bool { return removalSafe(c.config.Policy, s, action.Node) == nil }); err != nil {
			return fmt.Errorf("before terminating %s: %w", action.Node, err)
		}
		// The drained node's replicas now live on its peers: all must serve.
		current, err = c.recheck(ctx, expected, action.Node, StateDrained, planned)
		if err != nil {
			return err
		}
		if err := removalSafe(c.config.Policy, current, action.Node); err != nil {
			return fmt.Errorf("before terminating %s: %w", action.Node, err)
		}
		c.fenceReplicas()
		if err := cloud.Terminate(ctx, target.ID); err != nil {
			c.fenceReplicas()
			return err
		}
		// Termination is asynchronous; the name stays taken until it ends.
		err = c.waitIdentity(ctx, expected, action.Node, action.Node, "termination of "+action.Node, func(_ context.Context, instances []Instance) (bool, error) {
			return !slices.ContainsFunc(instances, func(i Instance) bool { return i.Name == action.Node }), nil
		})
		c.fenceReplicas()
		return err
	case KindResize:
		return c.rollingResize(ctx, state, action.To)
	case KindRebalance:
		current, err := c.recheck(ctx, expected, "", "", planned)
		if err != nil {
			return err
		}
		from := slices.IndexFunc(current.Nodes, func(n Node) bool { return n.Name == action.Node })
		to := slices.IndexFunc(current.Nodes, func(n Node) bool { return n.Name == action.Target })
		if from < 0 || to < 0 {
			return errors.New("tenant move source or destination is no longer observable")
		}
		tenants := current.Nodes[from].Pressure.TopTenants
		tenant := slices.IndexFunc(tenants, func(t TenantLoad) bool { return t.Org == action.Tenant })
		if tenant < 0 || !moveFits(c.config.Policy.Targets, current.Nodes[from], current.Nodes[to], tenants[tenant]) {
			return fmt.Errorf("tenant %s is no longer observable or does not fit on %s", action.Tenant, action.Target)
		}
		c.fenceReplicas()
		err = members.MoveTenant(ctx, action.Tenant, expected[action.Node], expected[action.Target])
		c.fenceReplicas()
		return err
	default:
		return fmt.Errorf("unknown action %q", action.Kind)
	}
}

// rollingResize resizes one node at a time and waits until each runs at the
// new shape and serves again before the next. Every node must serve before
// each restart, so a replica quorum stays up while one node is down. Cost
// reductions precede increases, keeping intermediate run rates within the
// larger of the original and final costs.
func (c *Controller) rollingResize(ctx context.Context, state State, shape Shape) error {
	nodes := names(state.Nodes)
	expected := identities(state.Nodes)
	if !c.config.Policy.canRestart(len(nodes)) {
		return fmt.Errorf("a rolling restart of %d nodes with replication factor %d would lose replica quorum %d",
			len(nodes), c.config.Policy.ReplicationFactor, c.config.Policy.quorum())
	}
	targets := slices.Clone(state.Nodes)
	slices.SortStableFunc(targets, func(a, b Node) int {
		return cmp.Compare(c.config.Policy.MonthlyCost(1, b.Shape), c.config.Policy.MonthlyCost(1, a.Shape))
	})
	for targetIndex, target := range targets {
		if sameShape(target.Shape, shape) {
			continue
		}
		current, err := c.recheck(ctx, expected, "", "", targets)
		if err != nil {
			return fmt.Errorf("before restarting %s: %w", target.Name, err)
		}
		if !resizeFits(c.config.Policy, current.Nodes, shape) {
			return fmt.Errorf("before restarting %s: projected pressure exceeds the downsize threshold", target.Name)
		}
		if err := replicasSafe(c.config.Policy, current, target.Name, c.config.Policy.quorum()); err != nil {
			return fmt.Errorf("before restarting %s: %w", target.Name, err)
		}
		index := slices.IndexFunc(current.Nodes, func(n Node) bool { return n.Name == target.Name })
		fence := restartFence{shape: shape, process: current.Nodes[index].Pressure.ProcessID}
		c.pendingRestarts[expected[target.Name]] = fence
		if err := c.config.Cloud.Resize(ctx, target.ID, shape); err != nil {
			if errors.Is(err, ErrResizeRejected) {
				delete(c.pendingRestarts, expected[target.Name])
			} else {
				c.fenceReplicas()
			}
			return err
		}
		c.fenceReplicas()
		if err := c.waitIdentity(ctx, expected, "", target.Name, "resize of "+target.Name, func(_ context.Context, instances []Instance) (bool, error) {
			return slices.ContainsFunc(instances, func(i Instance) bool {
				return i.Name == target.Name && i.Running() && sameShape(i.Shape, shape)
			}), nil
		}); err != nil {
			return err
		}
		// A fast node clock can date a pre-effect report after this observation.
		// Require a new process and a sample beyond the whole allowed skew.
		fence.after = c.config.Now().Add(MaxPressureClockSkew)
		c.pendingRestarts[expected[target.Name]] = fence
		if err := c.waitNode(ctx, expected, target.Name, func(p NodePressure) bool { return p.State == StateReady }); err != nil {
			return err
		}
		targets[targetIndex].Shape = shape
		// Refresh the action's evidence after its explicitly authorized restart.
		state, err = c.recheck(ctx, expected, "", "", targets)
		if err != nil {
			return err
		}
		if err := c.waitReplicas(ctx, nodes, state); err != nil {
			return fmt.Errorf("after restarting %s: %w", target.Name, err)
		}
	}
	_, err := c.recheck(ctx, expected, "", "", targets)
	return err
}

// recheck observes the cell right before a step and refuses it unless the
// names and OCI IDs are exactly want, every instance runs, every peer is ready,
// and every node (including skip) reports one release with no rollout in flight.
// skipState bounds the transitioning node's state before its next step.
// Capacity must still match the plan; only completed controlled effects update it.
func (c *Controller) recheck(ctx context.Context, want map[string]NodeIdentity, skip string, skipState NodeState, planned []Node) (State, error) {
	current, err := c.observe(ctx)
	if err != nil {
		return State{}, err
	}
	if got := identities(current.Nodes); !maps.Equal(got, want) {
		return State{}, fmt.Errorf("cell membership changed: %v, expected %v", got, want)
	}
	for _, node := range current.Nodes {
		index := slices.IndexFunc(planned, func(n Node) bool { return n.Name == node.Name && n.ID == node.ID })
		if index < 0 || !sameShape(node.Shape, planned[index].Shape) {
			return State{}, fmt.Errorf("node %s capacity no longer matches the action plan", node.Name)
		}
	}
	// Evidence reads must not hide a replacement or a stopped instance, or
	// age beyond their limit while the final OCI request is in flight.
	if _, err := c.actionInstances(ctx, want, "", "", map[string]NodeState{skip: skipState}); err != nil {
		return State{}, err
	}
	current.Now = c.config.Now()
	// The final peer probes can supersede the original observation's state.
	for i := range current.Nodes {
		node := &current.Nodes[i]
		if pressure, found := c.lastPressure[want[node.Name]]; found {
			node.Pressure = &pressure
		}
	}
	if current.Replicas != nil && !c.replicasUsable(*current.Replicas) {
		current.Replicas = nil
	}
	release := ""
	for _, node := range current.Nodes {
		if node.Pressure == nil || !node.Pressure.Fresh(current.Now) {
			return State{}, fmt.Errorf("node %s is not ready", node.Name)
		}
		if release == "" {
			release = node.Pressure.Release
		}
		current.RolloutInFlight = current.RolloutInFlight || node.Pressure.Release != release
		if node.Name == skip {
			state := node.Pressure.State
			allowed := state == skipState || skipState == StateJoining && state == StateReady || skipState == StateDraining && state == StateDrained
			if !allowed {
				return State{}, fmt.Errorf("node %s state %s, expected %s", node.Name, state, skipState)
			}
			continue
		}
		if !node.ready() {
			return State{}, fmt.Errorf("node %s is not ready", node.Name)
		}
		if node.Pressure.Load.ReplicationLagSeq > c.config.Policy.MaxReplicationLagSeq {
			return State{}, fmt.Errorf("node %s reports a peer %d events behind", node.Name, node.Pressure.Load.ReplicationLagSeq)
		}
	}
	if current.RolloutInFlight {
		return State{}, errors.New("a rollout is in flight")
	}
	return current, nil
}

func names(nodes []Node) []string {
	out := make([]string, len(nodes))
	for index, node := range nodes {
		out[index] = node.Name
	}
	return out
}

func sorted(values []string) []string {
	values = slices.Clone(values)
	slices.Sort(values)
	return values
}

// actionInstances fences against the original identities and stopped members.
// Only departing may disappear; only transitioning may be non-running during
// a controlled wait. Mutations allow neither lifecycle exception.
func (c *Controller) actionInstances(ctx context.Context, want map[string]NodeIdentity, departing, transitioning string, allowed ...map[string]NodeState) ([]Instance, error) {
	instances, err := c.config.Cloud.List(ctx)
	if err != nil {
		c.fenceReplicas()
		return nil, err
	}
	if err := c.checkInstances(instances, want, departing, transitioning); err != nil {
		return nil, err
	}
	// OCI cannot report a process restart. Check each serving peer during
	// waits too, so a changed incarnation cannot hide behind the same OCID.
	release := ""
	for _, instance := range instances {
		id, member := want[instance.Name]
		if !member || instance.Name == transitioning || id.Incarnation == "" {
			continue
		}
		p, err := c.config.Source.Pressure(ctx, instance.Name)
		if err != nil {
			c.fenceReplicas()
			return nil, fmt.Errorf("node %s is not ready: %w", instance.Name, err)
		}
		usable := c.retainPressure(instance.Name, p)
		if c.activeIdentities[instance.Name] != id {
			return nil, fmt.Errorf("cell membership changed: node %s identity %v, expected %v", instance.Name, c.activeIdentities[instance.Name], id)
		}
		stateOK := p.State == StateReady
		if len(allowed) != 0 {
			if state, found := allowed[0][instance.Name]; found {
				stateOK = p.State == state || state == StateJoining && p.State == StateReady || state == StateDraining && p.State == StateDrained
			}
		}
		if !usable || !stateOK && instance.Name != departing {
			c.fenceReplicas()
			return nil, fmt.Errorf("node %s is not ready", instance.Name)
		}
		if p.Load.ReplicationLagSeq > c.config.Policy.MaxReplicationLagSeq && instance.Name != departing {
			c.fenceReplicas()
			return nil, fmt.Errorf("node %s reports a peer %d events behind", instance.Name, p.Load.ReplicationLagSeq)
		}
		if release == "" {
			release = p.Release
		} else if p.Release != release {
			return nil, errors.New("a rollout is in flight")
		}
	}
	if c.config.Rollouts != nil {
		rolling, err := c.config.Rollouts(ctx)
		if err != nil {
			return nil, fmt.Errorf("rollout check: %w", err)
		}
		if rolling {
			return nil, errors.New("a rollout is in flight")
		}
	}
	// An OCI replacement can occur inside any pressure RPC.
	instances, err = c.config.Cloud.List(ctx)
	if err != nil {
		c.fenceReplicas()
		return nil, err
	}
	if err := c.checkInstances(instances, want, departing, transitioning); err != nil {
		return nil, err
	}
	for _, instance := range instances {
		id, member := want[instance.Name]
		if member && instance.Name != transitioning && id.Incarnation != "" && !c.lastPressure[id].Fresh(c.config.Now()) {
			c.fenceReplicas()
			return nil, fmt.Errorf("node %s is not ready", instance.Name)
		}
	}
	return instances, nil
}

func (c *Controller) checkInstances(instances []Instance, want map[string]NodeIdentity, departing, transitioning string) error {
	changedShapes := c.trackPressureIdentities(instances)
	got := make(map[string]NodeIdentity)
	for _, instance := range instances {
		if _, ok := Ordinal(c.config.Cell, instance.Name); ok && !instance.Foreign {
			got[instance.Name] = c.activeIdentities[instance.Name]
		}
	}
	if departing != "" && !slices.ContainsFunc(instances, func(i Instance) bool { return i.Name == departing }) {
		want = maps.Clone(want)
		delete(want, departing)
	}
	for name, id := range want {
		actual, found := got[name]
		if !found || actual.InstanceID != id.InstanceID || id.Incarnation != "" && actual.Incarnation != id.Incarnation {
			c.fenceReplicas()
			return fmt.Errorf("cell membership changed: %v, expected %v", got, want)
		}
	}
	if len(got) != len(want) {
		c.fenceReplicas()
		return fmt.Errorf("cell membership changed: %v, expected %v", got, want)
	}
	for _, instance := range instances {
		if _, member := want[instance.Name]; member && instance.Name != transitioning && !instance.Running() {
			c.fenceReplicas()
			return fmt.Errorf("node %s OCI lifecycle %s is not RUNNING", instance.Name, instance.State)
		}
	}
	for _, name := range changedShapes {
		if name != transitioning {
			return fmt.Errorf("node %s shape changed during evidence reads", name)
		}
	}
	return nil
}

func (c *Controller) waitIdentity(ctx context.Context, want map[string]NodeIdentity, departing, transitioning, what string, done func(context.Context, []Instance) (bool, error), allowed ...map[string]NodeState) error {
	return c.wait(ctx, what, func(ctx context.Context) (bool, error) {
		instances, err := c.actionInstances(ctx, want, departing, transitioning, allowed...)
		if err != nil {
			return false, err
		}
		return done(ctx, instances)
	})
}

// waitNode waits until the node's pressure satisfies done.
func (c *Controller) waitNode(ctx context.Context, want map[string]NodeIdentity, node string, done func(NodePressure) bool) error {
	return c.waitIdentity(ctx, want, "", node, "node "+node, func(ctx context.Context, instances []Instance) (bool, error) {
		if !slices.ContainsFunc(instances, func(i Instance) bool { return i.Name == node && i.Running() }) {
			c.fenceReplicas()
			return false, nil
		}
		pressure, err := c.config.Source.Pressure(ctx, node)
		if err != nil {
			return false, nil
		}
		// Verify the entire original OCI membership after the target RPC,
		// before accepting a controlled new incarnation or releasing a fence.
		instances, err = c.actionInstances(ctx, want, "", node)
		if err != nil {
			return false, err
		}
		index := slices.IndexFunc(instances, func(i Instance) bool { return i.Name == node && i.Running() })
		if index < 0 {
			c.fenceReplicas()
			return false, nil
		}
		old := want[node]
		_, fence, restarting := c.restartFor(node)
		controlled := restarting && sameShape(instances[index].Shape, fence.shape) &&
			pressure.InstanceID == old.InstanceID && pressure.ProcessID != fence.process &&
			!fence.after.IsZero() && pressure.State == StateReady && pressure.SampledAt.After(fence.after)
		usable := c.retainPressure(node, pressure)
		actual := c.activeIdentities[node]
		if old.Incarnation != "" && actual != old && !controlled {
			return false, fmt.Errorf("cell membership changed: node %s identity %v, expected %v", node, actual, old)
		}
		if !usable || !done(pressure) {
			return false, nil
		}
		for name, id := range want {
			if name != node && c.lastPressure[id].Release != pressure.Release {
				return false, errors.New("a rollout is in flight")
			}
		}
		// The only permitted bindings are a new node's first incarnation and
		// this action's restart, proved after OCI and pressure convergence.
		if old.Incarnation == "" || controlled {
			want[node] = pressure.Identity()
		}
		c.releaseRestart(pressure.Identity())
		return true, nil
	})
}

func (c *Controller) wait(ctx context.Context, what string, done func(context.Context) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, c.config.ReadyTimeout)
	defer cancel()
	ticker := time.NewTicker(c.config.Poll)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("wait for %s: %w", what, err)
		}
		ok, err := done(ctx)
		if ctx.Err() != nil {
			return fmt.Errorf("wait for %s: %w", what, ctx.Err())
		}
		if err != nil || ok {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for %s: %w", what, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (c *Controller) region() string { return strings.SplitN(c.config.Cell, "-", 2)[0] }

// journal records one action, with its undo, and returns the decision ID.
func (c *Controller) journal(ctx context.Context, action Action, status decisionlog.Status, parent, outcome string) string {
	kind := decisionlog.KindScaleDown
	switch {
	case action.Kind == KindRebalance:
		kind = "tenant_moved"
	case action.up():
		kind = decisionlog.KindScaleUp
	}
	summary := describe(c.config.Cell, action)
	if c.config.Policy.DryRun {
		summary = "Dry run: would " + summary
	}
	attrs := map[string]string{"action": string(action.Kind), "monthly_cost": fmt.Sprintf("%.2f", action.MonthlyCost)}
	if action.Recovery {
		attrs["recovery"] = "true"
	}
	for key, value := range map[string]string{"node": action.Node, "tenant": action.Tenant, "plan": string(action.Plan), "target": action.Target} {
		if value != "" {
			attrs[key] = value
		}
	}
	if action.Kind == KindResize {
		attrs["from"], attrs["to"] = action.From.String(), action.To.String()
	}
	if c.config.Policy.DryRun {
		attrs["dry_run"] = "true"
	}
	if undo, ok := action.Undo(); ok {
		encoded, _ := json.Marshal(undo)
		attrs["undo"] = string(encoded)
	}
	return decisionlog.Record(ctx, decisionlog.Decision{
		Region:   c.region(),
		Actor:    decisionlog.Actor{Slice: actor},
		Kind:     kind,
		Subject:  decisionlog.Subject{Kind: "cell", ID: c.config.Cell},
		Summary:  summary,
		Reason:   action.Reason,
		Rule:     "cellscale." + action.Reason,
		Signals:  signals(action.Pressure),
		Status:   status,
		Outcome:  outcome,
		ParentID: parent,
		Attrs:    attrs,
	})
}

// journalHold records a hold once per reason, so a steady hold is not
// journaled every tick.
func (c *Controller) journalHold(ctx context.Context, action Action) {
	if action.Reason == c.lastHold {
		return
	}
	c.lastHold = action.Reason
	summary := fmt.Sprintf("Cell %s holds: %s", c.config.Cell, action.Reason)
	var refused []decisionlog.Alternative
	if action.Held != nil {
		summary = fmt.Sprintf("Cell %s holds instead of: %s (%s)", c.config.Cell, describe(c.config.Cell, *action.Held), action.Reason)
		refused = []decisionlog.Alternative{{Option: describe(c.config.Cell, *action.Held), Reason: action.Reason}}
	}
	decisionlog.Record(ctx, decisionlog.Decision{
		Region:       c.region(),
		Actor:        decisionlog.Actor{Slice: actor},
		Kind:         decisionlog.KindHeld,
		Subject:      decisionlog.Subject{Kind: "cell", ID: c.config.Cell},
		Summary:      summary,
		Reason:       action.Reason,
		Rule:         "cellscale." + action.Reason,
		Signals:      signals(action.Pressure),
		Alternatives: refused,
		Status:       decisionlog.StatusSucceeded,
	})
}

// alert journals the pause as a failed hold and logs it, so the dashboard
// and the operator both see that the cell needs attention.
func (c *Controller) alert(ctx context.Context, summary, reason, outcome string, err error) {
	c.config.Logf("ALERT cellscale %s: %s; last error: %v", c.config.Cell, summary, err)
	decisionlog.Record(ctx, decisionlog.Decision{
		Region:  c.region(),
		Actor:   decisionlog.Actor{Slice: actor},
		Kind:    decisionlog.KindHeld,
		Subject: decisionlog.Subject{Kind: "cell", ID: c.config.Cell},
		Summary: summary,
		Reason:  reason,
		Rule:    "cellscale." + outcome,
		Status:  decisionlog.StatusFailed,
		Outcome: outcome,
	})
}

func describe(cell string, action Action) string {
	switch action.Kind {
	case KindScaleOut:
		return fmt.Sprintf("add node %s at %s to cell %s", action.Node, action.To, cell)
	case KindScaleIn:
		return fmt.Sprintf("drain and remove node %s from cell %s", action.Node, cell)
	case KindResize:
		return fmt.Sprintf("resize cell %s from %s to %s, one node at a time", cell, action.From, action.To)
	default:
		return fmt.Sprintf("move %s tenant %s from %s to %s", action.Plan, action.Tenant, action.Node, action.Target)
	}
}

// signals journals each pressure against 1, the full mark, as
// workload.recordScale journals readings against their targets.
func signals(pressure map[string]float64) []decisionlog.Signal {
	var out []decisionlog.Signal
	for _, name := range signalNames {
		if value, ok := pressure[string(name)]; ok {
			out = append(out, decisionlog.Signal{Name: string(name), Value: value, Comparison: "<",
				Threshold: decisionlog.Threshold(1), Passed: decisionlog.Passed(value < 1)})
		}
	}
	return out
}
