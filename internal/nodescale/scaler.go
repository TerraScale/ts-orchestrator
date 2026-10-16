package nodescale

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/moby/swarmkit/v2/api"
)

const (
	FirstPoolNode = 4 // quorum nodes hold 1..3
	LaunchTimeout = 20 * time.Minute
	DrainTimeout  = 30 * time.Minute

	roleTerraBase = "terrabase"
	sliceName     = "nodescale"

	stepGrow   = "grow"
	stepEnroll = "enroll"
	stepCordon = "cordon"
	stepDrain  = "drain"
	stepRemove = "remove"
	stepGone   = "gone"
)

// Scaler scales one region's pool nodes. Tick acts on the leader only.
type Scaler struct {
	Cell           string // e.g. "gru"; nodes are naming.RegionCell(strings.ToUpper(Cell)).Node(n)
	Pool           Pool
	Recipe         func(ctx context.Context) (Recipe, error)
	Reserve        func(context.Context, string, Recipe) (budget.Reservation, error)
	FunctionDemand func(context.Context) ([]CapacityDemand, error)
	FunctionRecipe func(context.Context, string) (Recipe, error)
	Control        api.ControlClient
	// CanRetire verifies owned retained-volume inventory and DATA retirement safety; nil holds scale-down.
	CanRetire func(ctx context.Context, node, instanceID string) error
	Loads     func() []NodeLoad                                            // latest load per node
	Allowance func(now time.Time) (int, bool)                              // false: no fresh allowance, so no growth
	Revoke    func(ctx context.Context, instanceID string) error           // ends a removed node's enrollment
	Backends  func(ctx context.Context, node, address string) (int, error) // load balancer backends still at the node
	Journal   func(ctx context.Context, decision decisionlog.Decision)
	// Cost is the region's spend for the home's allowances: TS-807's ocicost
	// supplies it, the per-region forecast with this region's pool nodes as
	// pending cost, and the node price. Nil, or failing, leaves spend unknown
	// and the global allocator holds growth.
	Cost func(ctx context.Context, pool PoolState) (Cost, error)
	// RTT is the latest measured round trip to each OCI region, from the Prober. Nil publishes none.
	RTT    func() map[string]time.Duration
	Leader authority.Fencer
	Store  RecordStore
	Now    func() time.Time

	mu               sync.Mutex
	history          History
	containerHistory History
	status           Status
	addresses        map[string]string
	heldKey          string // reason of the last journaled hold, without a cooldown's time left
	costErr          string // last cost error logged, so a repeat is not logged every tick
}

// tick is one pass of the loop: what it observed, the record it changes, and the journal entries it queues.
type tick struct {
	epoch   uint64
	now     time.Time
	record  Record
	pool    PoolState
	obs     observation
	loads   []NodeLoad
	journal []decisionlog.Decision
	blocked string
	hosts   []*api.Node
}

// observation is the pool and the hosts at one tick: which nodes count toward the sample, and how many.
type observation struct {
	nodes, quorum, pool int
	live                map[string]bool   // nodes ready in SwarmKit
	counted             map[string]bool   // nodes whose load counts toward the sample
	addresses           map[string]string // named pool instance -> private IP
}

// Run ticks every Interval until ctx ends. A failed tick is logged; the next one retries from the store.
func (s *Scaler) Run(ctx context.Context) {
	ticker := time.NewTicker(Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Tick(ctx); err != nil {
				slog.Error("node scaling tick failed", observability.ComponentKey, sliceName, "cell", s.Cell, "error", err)
			}
		}
	}
}

// Tick samples the region, advances the action in flight by one step, decides, and saves the record.
// A follower resets its load windows and its status; a new leader rebuilds them, which only delays action.
func (s *Scaler) Tick(ctx context.Context) error {
	snapshot := s.Leader.Current()
	if !snapshot.CanMutate() {
		s.history = History{}
		s.containerHistory = History{}
		s.mu.Lock()
		s.status, s.addresses = Status{}, nil
		s.mu.Unlock()
		return nil
	}
	record, revision, err := s.Store.Load(ctx)
	if err != nil {
		return fmt.Errorf("load node scaler record: %w", err)
	}
	pool, err := s.Pool.Observe(ctx)
	if err != nil {
		return fmt.Errorf("observe node pool: %w", err)
	}
	if s.Control == nil {
		return errors.New("SwarmKit control API is unavailable")
	}
	hosts, err := s.Control.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return fmt.Errorf("list SwarmKit nodes: %w", err)
	}
	t := &tick{epoch: snapshot.Epoch, now: s.Now(), record: record, pool: pool, hosts: hosts.Nodes}
	if t.pool.Pending == "" {
		if err := s.nameUnnamed(ctx, t, hosts.Nodes); err != nil {
			return err
		}
	}
	t.obs = s.observe(t.pool, hosts.Nodes)
	t.loads = countedLoads(s.Loads(), t.obs)
	s.mu.Lock()
	s.addresses = t.obs.addresses
	s.mu.Unlock()
	s.history.Add(Measure(t.obs.nodes, t.loads, t.now))
	container, _ := containerSample(t)
	s.containerHistory.Add(container)
	if t.record.Action != nil && t.pool.Pending == "" {
		if err := s.advance(ctx, t); err != nil {
			return err
		}
	}
	allowance, fresh := s.Allowance(t.now)
	if !fresh {
		allowance = t.obs.nodes
	}
	samples := s.history.Samples()
	decision, err := s.decide(ctx, t, State{Nodes: t.obs.nodes, Allowance: allowance, LastChange: t.record.LastChange,
		Busy: t.record.Action != nil, Samples: samples})
	if err != nil {
		return err
	}
	status := s.buildStatus(t, decision, allowance, fresh, samples, s.costOf(ctx, t.pool))
	status.RTTMillis = s.roundTrips()
	t.record.Status = status
	if err := s.Leader.Guard(ctx, t.epoch); err != nil {
		return err
	}
	if _, err := s.Store.Save(ctx, t.record, revision); err != nil {
		return fmt.Errorf("save node scaler record: %w", err)
	}
	s.mu.Lock()
	s.status = status
	s.mu.Unlock()
	for _, entry := range t.journal {
		s.Journal(ctx, entry)
	}
	return nil
}

// Status returns the last status the region published.
func (s *Scaler) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := s.status
	if status.InFlight != nil {
		inFlight := *status.InFlight
		status.InFlight = &inFlight
	}
	status.Signals = maps.Clone(status.Signals)
	return status
}

// Addresses returns each named pool node's private IP as of the last observation.
func (s *Scaler) Addresses() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.addresses)
}

// named reports whether name is a node name of this region.
func (s *Scaler) named(name string) bool {
	return naming.IsNode(name, strings.ToUpper(s.Cell))
}

// nameUnnamed gives each live pool instance without a node name the lowest free one, and updates t to match.
func (s *Scaler) nameUnnamed(ctx context.Context, t *tick, hosts []*api.Node) error {
	used := map[string]bool{}
	for _, h := range hosts {
		used[h.Spec.Annotations.Name] = true
	}
	for _, in := range t.pool.Instances {
		used[in.Name] = true
	}
	cell := naming.RegionCell(strings.ToUpper(s.Cell))
	for i := range t.pool.Instances {
		in := &t.pool.Instances[i]
		if s.named(in.Name) || absent(in.State) {
			continue
		}
		node, err := freeNode(cell, used)
		if err != nil {
			return err
		}
		used[node] = true
		if err := s.Leader.Guard(ctx, t.epoch); err != nil {
			return err
		}
		if err := s.Pool.Name(ctx, in.ID, node); err != nil {
			return fmt.Errorf("name pool instance %s %s: %w", in.ID, node, err)
		}
		in.Name = node
	}
	return nil
}

// freeNode returns the lowest node name from FirstPoolNode up that no host or pool instance holds.
func freeNode(cell naming.Cell, used map[string]bool) (string, error) {
	for n := FirstPoolNode; ; n++ {
		node, err := cell.Node(n)
		if err != nil {
			return "", err
		}
		if !used[node] {
			return node, nil
		}
	}
}

// observe binds worker identities to the current OCI pool and counts admitted regional managers.
func (s *Scaler) observe(pool PoolState, hosts []*api.Node) observation {
	obs := observation{live: map[string]bool{}, counted: map[string]bool{}, addresses: map[string]string{}}
	byInstance := nodesByInstance(hosts)
	for _, node := range byInstance {
		if s.admitted(node, api.NodeRoleManager) && node.Status.State == api.NodeStatus_READY {
			obs.quorum++
			obs.live[node.Spec.Annotations.Name] = true
			obs.counted[node.Spec.Annotations.Name] = true
		}
	}
	for _, in := range pool.Instances {
		if s.named(in.Name) {
			obs.addresses[in.Name] = in.PrivateIP
		}
		if absent(in.State) {
			continue
		}
		obs.pool++
		if node := byInstance[in.ID]; s.admitted(node, api.NodeRoleWorker) && node.Status.State == api.NodeStatus_READY {
			obs.live[in.Name] = true
			obs.counted[in.Name] = true
		}
	}
	obs.nodes = obs.quorum + obs.pool
	return obs
}

// nodesByInstance leaves duplicate OCI identities unresolved, including historical node certificates.
func nodesByInstance(nodes []*api.Node) map[string]*api.Node {
	byInstance := make(map[string]*api.Node, len(nodes))
	for _, node := range nodes {
		id := node.Spec.Annotations.Labels["terrascale.instance-id"]
		if id == "" {
			continue
		}
		if _, exists := byInstance[id]; exists {
			byInstance[id] = nil
			continue
		}
		byInstance[id] = node
	}
	return byInstance
}

func (s *Scaler) admitted(node *api.Node, role api.NodeRole) bool {
	region, ok := catalog.LookupName(s.Cell)
	return ok && node != nil && node.Spec.Annotations.Name != "" &&
		node.Spec.Annotations.Labels["terrascale.region"] == region.OCIRegion &&
		node.Role == role && node.Certificate.Role == role && node.Spec.DesiredRole == role && node.Spec.Membership == api.NodeMembershipAccepted
}

// countedLoads keeps the loads of the nodes that count toward the sample.
func countedLoads(loads []NodeLoad, obs observation) []NodeLoad {
	var counted []NodeLoad
	for _, load := range loads {
		if obs.counted[load.Node] {
			counted = append(counted, load)
		}
	}
	return counted
}

// advance moves the action in flight by one step.
func (s *Scaler) advance(ctx context.Context, t *tick) error {
	switch t.record.Action.Step {
	case stepGrow:
		return s.grow(ctx, t)
	case stepEnroll:
		return s.enroll(ctx, t)
	case stepCordon:
		return s.cordon(ctx, t)
	case stepDrain:
		return s.drain(ctx, t)
	case stepRemove:
		return s.remove(ctx, t)
	case stepGone:
		return s.gone(ctx, t)
	}
	return fmt.Errorf("node scale action %s is at unknown step %q", t.record.Action.ID, t.record.Action.Step)
}

// grow raises the pool by one node. A size someone else set fails the action.
func (s *Scaler) grow(ctx context.Context, t *tick) error {
	if t.pool.Size == t.record.From+1 {
		if t.record.Recipe == nil || t.record.TargetFrom == nil {
			t.pool.Pending = "selected capacity pool lacks a durable starting size"
			return nil
		}
		size, err := s.Pool.TargetSize(ctx, *t.record.Recipe)
		if err != nil {
			return fmt.Errorf("observe selected capacity growth: %w", err)
		}
		if size != *t.record.TargetFrom+1 {
			s.fail(t, "another capacity pool changed during the chosen launch")
			return nil
		}
		t.record.Action.Step = stepEnroll
		return nil
	}
	allowance, fresh := s.Allowance(t.now)
	if !fresh || allowance <= t.obs.nodes {
		t.pool.Pending = "a fresh spending allowance for another node is unavailable"
		return nil
	}
	freshRecipe, err := s.Recipe(ctx)
	if err != nil {
		if errors.Is(err, ErrCapacityPending) {
			t.pool.Pending = err.Error()
			return nil
		}
		return fmt.Errorf("read node recipe: %w", err)
	}
	if err := freshRecipe.Validate(); err != nil {
		return fmt.Errorf("validate node recipe: %w", err)
	}
	if t.record.Recipe == nil {
		// Historical actions acquire a durable choice before any provider write.
		t.record.Recipe = new(freshRecipe)
		return nil
	}
	if freshRecipe.SHA256() != t.record.Recipe.SHA256() {
		t.pool.Pending = "the durable chosen capacity recipe is no longer currently qualified"
		return nil
	}
	recipe := *t.record.Recipe
	if t.record.TargetFrom == nil {
		size, err := s.Pool.TargetSize(ctx, recipe)
		if err != nil {
			return fmt.Errorf("read selected pool starting size: %w", err)
		}
		t.record.TargetFrom = new(size)
		return nil
	}
	if s.Reserve != nil && t.record.Reservation == nil {
		receipt, err := s.Reserve(ctx, t.record.Action.ID, recipe)
		if err != nil {
			t.pool.Pending = fmt.Sprintf("home capacity reservation is pending: %v", err)
			return nil
		}
		t.record.Reservation = new(receipt)
		return nil
	}
	if err := s.Leader.Guard(ctx, t.epoch); err != nil {
		return err
	}
	if _, err := s.Pool.Ensure(ctx, recipe); err != nil {
		if errors.Is(err, ErrCapacityPending) {
			t.pool.Pending = err.Error()
			return nil
		}
		return fmt.Errorf("ensure node pool: %w", err)
	}
	if err := s.Leader.Guard(ctx, t.epoch); err != nil {
		return err
	}
	err = s.Pool.Grow(ctx, t.record.From)
	if errors.Is(err, ErrCapacityPending) {
		t.pool.Pending = err.Error()
		return nil
	}
	if errors.Is(err, ErrPoolChanged) {
		s.fail(t, err.Error())
		return nil
	}
	if err != nil {
		return fmt.Errorf("grow node pool: %w", err)
	}
	t.record.Action.Step = stepEnroll
	return nil
}

// enroll ends the scale-up once every pool node is admitted and ready in SwarmKit. A node that never enrolls is removed
// after LaunchTimeout.
func (s *Scaler) enroll(ctx context.Context, t *tick) error {
	action := t.record.Action
	if s.launched(t) {
		nodes := joined(t)
		t.record.Action = nil
		s.queue(t, decisionlog.Decision{Kind: decisionlog.KindHostLaunched, Subject: s.regionSubject(),
			Summary: fmt.Sprintf("launched %s in %s", strings.Join(nodes, ", "), s.Cell),
			Attrs:   map[string]string{"nodes": strings.Join(nodes, ",")}})
		return nil
	}
	if t.now.Sub(action.Started) < LaunchTimeout {
		return nil
	}
	for _, in := range t.pool.Instances {
		if absent(in.State) || in.Created.Before(action.Started) || t.obs.live[in.Name] {
			continue
		}
		if err := s.expiredSafe(ctx, t, in); err != nil {
			t.pool.Pending = fmt.Sprintf("cannot retire expired launch %s: %s", in.Name, err)
			return nil
		}
		if err := s.Leader.Guard(ctx, t.epoch); err != nil {
			return err
		}
		if err := s.Pool.Remove(ctx, in.ID); err != nil {
			return fmt.Errorf("remove unenrolled instance %s: %w", in.ID, err)
		}
	}
	t.record.Action = nil
	s.queue(t, decisionlog.Decision{Kind: decisionlog.KindHeld, Rule: "nodescale.launch-expired",
		Subject: s.regionSubject(), Summary: fmt.Sprintf("stop launching a node in %s", s.Cell),
		Reason: fmt.Sprintf("no SwarmKit ready node within %s", LaunchTimeout)})
	return nil
}

// expiredSafe requires the same DATA proof for launch cleanup, including nodes that joined but never became ready.
func (s *Scaler) expiredSafe(ctx context.Context, t *tick, instance PoolInstance) error {
	if s.CanRetire == nil {
		return errors.New("node retirement safety proof is unavailable")
	}
	if err := s.CanRetire(ctx, instance.Name, instance.ID); err != nil {
		return err
	}
	nodes, err := s.Control.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return err
	}
	for _, node := range nodes.Nodes {
		if node.Spec.Annotations.Labels["terrascale.instance-id"] != instance.ID {
			continue
		}
		safe, err := s.retireSafe(ctx, instance.Name, instance.ID)
		if err != nil {
			return err
		}
		if !safe {
			return errors.New("the admitted node holds protected tasks or has an unverified identity")
		}
		if err := s.setAvailability(ctx, instance.Name, instance.ID, api.NodeAvailabilityDrain, t.epoch); err != nil {
			return err
		}
		probe := *t
		probe.record.Action = &InFlight{Node: instance.Name, InstanceID: instance.ID}
		drained, err := s.drained(ctx, &probe)
		if err != nil {
			return err
		}
		if !drained {
			return errors.New("the admitted node has not finished draining")
		}
	}
	return nil
}

// launched reports whether the pool holds From+1 live instances, each named, admitted and ready in SwarmKit.
func (s *Scaler) launched(t *tick) bool {
	live := 0
	for _, in := range t.pool.Instances {
		if absent(in.State) {
			continue
		}
		if !s.named(in.Name) || !t.obs.live[in.Name] {
			return false
		}
		live++
	}
	return live >= t.record.From+1
}

// joined names the live pool instances created since the action started.
func joined(t *tick) []string {
	var nodes []string
	for _, in := range t.pool.Instances {
		if !absent(in.State) && !in.Created.Before(t.record.Action.Started) {
			nodes = append(nodes, in.Name)
		}
	}
	return nodes
}

// cordon asks SwarmKit to drain a verified stateless worker.
func (s *Scaler) cordon(ctx context.Context, t *tick) error {
	action := t.record.Action
	if err := s.Leader.Guard(ctx, t.epoch); err != nil {
		return err
	}
	safe, err := s.retireSafe(ctx, action.Node, action.InstanceID)
	if err != nil {
		t.pool.Pending = err.Error()
		return nil
	}
	if !safe {
		t.pool.Pending = "node retirement safety is unavailable or the node holds protected tasks"
		return nil
	}
	if err := s.setAvailability(ctx, action.Node, action.InstanceID, api.NodeAvailabilityDrain, t.epoch); err != nil {
		return fmt.Errorf("cordon %s: %w", action.Node, err)
	}
	action.Step = stepDrain
	return nil
}

// drain waits until every task on the node is terminal and no load balancer backend points at it. After
// DrainTimeout the node is uncordoned and the failure counts as a change, so the cooldown holds.
func (s *Scaler) drain(ctx context.Context, t *tick) error {
	action := t.record.Action
	drained, err := s.drained(ctx, t)
	if err != nil {
		return err
	}
	if drained {
		action.Step = stepRemove
		return nil
	}
	if t.now.Sub(action.Started) < DrainTimeout {
		return nil
	}
	if err := s.Leader.Guard(ctx, t.epoch); err != nil {
		return err
	}
	if err := s.setAvailability(ctx, action.Node, action.InstanceID, api.NodeAvailabilityActive, t.epoch); err != nil {
		return fmt.Errorf("uncordon %s: %w", action.Node, err)
	}
	// DownCooldown equals DrainTimeout, so the start stamp has expired by now; the failure restarts it.
	t.record.LastChange = t.now
	t.record.Action = nil
	s.queue(t, decisionlog.Decision{Kind: decisionlog.KindHeld, Subject: s.regionSubject(),
		Summary: fmt.Sprintf("stop draining %s", action.Node),
		Reason:  fmt.Sprintf("drain did not finish within %s", DrainTimeout)})
	return nil
}

// drained reports whether every task on the node is terminal and no load balancer backend still points at it.
func (s *Scaler) drained(ctx context.Context, t *tick) (bool, error) {
	node := t.record.Action.Node
	n, err := s.worker(ctx, node, t.record.Action.InstanceID)
	if err != nil {
		return false, err
	}
	if n.Spec.Availability != api.NodeAvailabilityDrain {
		return false, nil
	}
	tasks, err := s.Control.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{NodeIDs: []string{n.ID}}})
	if err != nil {
		return false, fmt.Errorf("list tasks at %s: %w", node, err)
	}
	for _, task := range tasks.Tasks {
		// Desired SHUTDOWN or manager orphaning cannot prove the agent stopped the process.
		if task.Status.State < api.TaskStateCompleted || task.Status.State == api.TaskStateOrphaned {
			return false, nil
		}
	}
	backends, err := s.Backends(ctx, node, t.obs.addresses[node])
	if err != nil {
		return false, fmt.Errorf("count load balancer backends at %s: %w", node, err)
	}
	return backends == 0, nil
}

// remove detaches and terminates the drained instance.
func (s *Scaler) remove(ctx context.Context, t *tick) error {
	action := t.record.Action
	if err := s.Leader.Guard(ctx, t.epoch); err != nil {
		return err
	}
	safe, err := s.retireSafe(ctx, action.Node, action.InstanceID)
	if err != nil {
		t.pool.Pending = err.Error()
		return nil
	}
	if !safe {
		t.pool.Pending = "node retirement safety is unavailable or the node holds protected tasks"
		return nil
	}
	drained, err := s.drained(ctx, t)
	if err != nil {
		return err
	}
	if !drained {
		action.Step = stepDrain
		return nil
	}
	if err := s.Leader.Guard(ctx, t.epoch); err != nil {
		return err
	}
	if err := s.Pool.Remove(ctx, action.InstanceID); err != nil {
		return fmt.Errorf("remove instance %s: %w", action.InstanceID, err)
	}
	action.Step = stepGone
	return nil
}

// gone waits until OCI no longer lists the instance, then ends its enrollment.
func (s *Scaler) gone(ctx context.Context, t *tick) error {
	action := t.record.Action
	if slices.ContainsFunc(t.pool.Instances, func(in PoolInstance) bool { return in.ID == action.InstanceID }) {
		return nil
	}
	if err := s.Leader.Guard(ctx, t.epoch); err != nil {
		return err
	}
	if err := s.Revoke(ctx, action.InstanceID); err != nil {
		return fmt.Errorf("revoke instance %s: %w", action.InstanceID, err)
	}
	t.record.Action = nil
	s.queue(t, decisionlog.Decision{Kind: decisionlog.KindHostReclaimed, Subject: s.regionSubject(),
		Summary: fmt.Sprintf("reclaimed node %s from %s", action.Node, s.Cell),
		Attrs:   map[string]string{"node": action.Node, "instance_id": action.InstanceID}})
	return nil
}

// decide asks Decide what the region should do, and starts the action it asks for when none is in flight.
func (s *Scaler) decide(ctx context.Context, t *tick, state State) (Decision, error) {
	decision := Decide(state, t.now)
	_, wasmHosts := containerSample(t)
	if wasmHosts > 0 && !state.Busy && state.Nodes < MaxNodes {
		containerState := state
		containerState.Nodes -= wasmHosts
		containerState.Allowance = max(0, state.Allowance-wasmHosts)
		containerState.Samples = s.containerHistory.Samples()
		container := Decide(containerState, t.now)
		if container.Action == Up {
			decision = container
			decision.Nodes, decision.Want = state.Nodes, state.Nodes+1
		} else if decision.Action == Up {
			decision.Action, decision.Want, decision.Reason = Hold, state.Nodes, "container pressure does not require another platform host"
		}
	}
	if t.pool.Pending != "" {
		decision.Action, decision.Reason = Hold, t.pool.Pending
		s.holdOnce(t, decision)
		return decision, nil
	}
	demand, err := s.functionDemand(ctx, t)
	if err != nil {
		decision.Action, decision.Reason = Hold, "current function capacity demand is unavailable"
		s.holdOnce(t, decision)
		return decision, nil
	}
	if demand != nil && !state.Busy {
		decision = Decision{Action: Hold, Nodes: state.Nodes, Want: state.Nodes + 1, Reason: "verified function workers await an isolated host slot"}
		switch {
		case t.obs.quorum < MinNodes:
			decision.Reason = "function capacity waits for admitted regional manager quorum"
		case state.Nodes >= MaxNodes:
			decision.Saturated, decision.Want = true, MaxNodes
			decision.Reason = "function capacity reached the regional host limit"
		case state.Allowance <= state.Nodes:
			decision.Reason = "function capacity waits for infrastructure candidate allowance"
		default:
			decision.Action = Up
		}
	}
	switch decision.Action {
	case Up:
		var recipe Recipe
		if demand != nil {
			if s.FunctionRecipe == nil {
				err = ErrCapacityPending
			} else {
				recipe, err = s.FunctionRecipe(ctx, demand.Architecture)
			}
		} else {
			recipe, err = s.Recipe(ctx)
		}
		if err != nil {
			if !errors.Is(err, ErrCapacityPending) {
				return decision, fmt.Errorf("choose node recipe: %w", err)
			}
			decision.Action, decision.Reason = Hold, err.Error()
			s.holdOnce(t, decision)
			return decision, nil
		}
		if err := recipe.Validate(); err != nil {
			return decision, fmt.Errorf("validate chosen node recipe: %w", err)
		}
		if demand != nil && (recipe.Capacity.Role != RoleWasm || recipe.Capacity.Architecture != demand.Architecture) {
			return decision, fmt.Errorf("function capacity recipe differs from exact isolated architecture demand")
		}
		size, err := s.Pool.TargetSize(ctx, recipe)
		if err != nil {
			return decision, fmt.Errorf("read chosen pool starting size: %w", err)
		}
		t.record.Recipe = new(recipe)
		t.record.TargetFrom = new(size)
		t.record.Reservation = nil
		t.record.Action = &InFlight{ID: entityid.New(), Kind: Up, Step: stepGrow, Started: t.now}
		t.record.From = t.pool.Size
		t.record.LastChange = t.now
		s.queue(t, decisionlog.Decision{Kind: decisionlog.KindScaleUp, Subject: s.regionSubject(),
			Summary: fmt.Sprintf("scale %s from %d to %d nodes", s.Cell, decision.Nodes, decision.Want),
			Reason:  decision.Reason})
	case Down:
		target, found, err := s.pickDrain(ctx, t)
		if err != nil {
			return decision, err
		}
		if !found {
			decision.Action = Hold
			decision.Reason = cmp.Or(t.blocked, "no pool node is free to drain: protected tasks, manager, or missing load")
			break
		}
		t.record.Action = &InFlight{ID: entityid.New(), Kind: Down, Step: stepCordon, Node: target.Name,
			InstanceID: target.ID, Started: t.now}
		t.record.LastChange = t.now
		s.queue(t, decisionlog.Decision{Kind: decisionlog.KindScaleDown, Subject: s.regionSubject(),
			Summary: fmt.Sprintf("scale %s from %d to %d nodes", s.Cell, decision.Nodes, decision.Want),
			Reason:  decision.Reason, Attrs: map[string]string{"node": target.Name, "instance_id": target.ID}})
	}
	if decision.Action == Hold {
		s.holdOnce(t, decision)
	}
	return decision, nil
}

// pickDrain picks the verified stateless worker with the least CPU, ties to the highest n.
func (s *Scaler) pickDrain(ctx context.Context, t *tick) (PoolInstance, bool, error) {
	protected, err := s.protectedNodes(ctx)
	if err != nil {
		return PoolInstance{}, false, err
	}
	nodes, err := s.Control.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return PoolInstance{}, false, fmt.Errorf("list drain candidates: %w", err)
	}
	workers := nodesByInstance(nodes.Nodes)
	cpu := map[string]float64{}
	for _, load := range t.loads {
		cpu[load.Node] = load.CPU
	}
	var candidates []PoolInstance
	for _, in := range t.pool.Instances {
		node := workers[in.ID]
		if _, loaded := cpu[in.Name]; loaded && t.obs.counted[in.Name] && s.named(in.Name) &&
			s.admitted(node, api.NodeRoleWorker) && node.Spec.Availability == api.NodeAvailabilityActive && !protected[node.ID] {
			candidates = append(candidates, in)
		}
	}
	if len(candidates) == 0 {
		return PoolInstance{}, false, nil
	}
	slices.SortFunc(candidates, func(a, b PoolInstance) int {
		return cmp.Or(cmp.Compare(cpu[a.Name], cpu[b.Name]), cmp.Compare(nodeNumber(b.Name), nodeNumber(a.Name)))
	})
	for _, candidate := range candidates {
		if s.CanRetire == nil {
			t.blocked = "node retirement safety proof is unavailable"
			break
		}
		if err := s.CanRetire(ctx, candidate.Name, candidate.ID); err != nil {
			t.blocked = fmt.Sprintf("cannot retire %s: %s", candidate.Name, err)
			continue
		}
		return candidate, true, nil
	}
	return PoolInstance{}, false, nil
}

// protectedNodes retains stateful history and orphan tasks: task state cannot prove a writer fence.
func (s *Scaler) protectedNodes(ctx context.Context) (map[string]bool, error) {
	services, err := s.Control.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil {
		return nil, fmt.Errorf("list services for retirement safety: %w", err)
	}
	known := map[string]*api.Service{}
	for _, service := range services.Services {
		known[service.ID] = service
	}
	tasks, err := s.Control.ListTasks(ctx, &api.ListTasksRequest{})
	if err != nil {
		return nil, fmt.Errorf("list tasks for retirement safety: %w", err)
	}
	protected := map[string]bool{}
	for _, task := range tasks.Tasks {
		service := known[task.ServiceID]
		if service == nil || service.Spec.Annotations.Labels["terrascale.role"] == "" ||
			stateful(service.Spec.Annotations.Labels) || stateful(task.Annotations.Labels) {
			protected[task.NodeID] = true
		}
	}
	return protected, nil
}

func stateful(labels map[string]string) bool {
	_, declared := labels["terrascale.stateful"]
	return declared || labels["terrascale.role"] == roleTerraBase
}

// worker resolves the manager-attested OCI identity, independently of its canonical host ID or pool hostname.
func (s *Scaler) worker(ctx context.Context, name, instanceID string) (*api.Node, error) {
	if name == "" || instanceID == "" {
		return nil, errors.New("worker retirement requires an exact node and OCI instance identity")
	}
	nodes, err := s.Control.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return nil, fmt.Errorf("find worker %s: %w", name, err)
	}
	node := nodesByInstance(nodes.Nodes)[instanceID]
	if !s.admitted(node, api.NodeRoleWorker) {
		return nil, fmt.Errorf("worker %s has no unique admitted OCI instance %s", name, instanceID)
	}
	return node, nil
}

func (s *Scaler) setAvailability(ctx context.Context, name, instanceID string, availability api.NodeSpec_Availability, epoch uint64) error {
	node, err := s.worker(ctx, name, instanceID)
	if err != nil {
		return err
	}
	if node.Spec.Annotations.Labels["terrascale.instance-id"] != instanceID {
		return fmt.Errorf("node %s is not instance %s", name, instanceID)
	}
	if node.Spec.Availability == availability {
		return nil
	}
	spec := node.Spec.Copy()
	spec.Availability = availability
	if err := s.Leader.Guard(ctx, epoch); err != nil {
		return err
	}
	_, err = s.Control.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: node.ID, NodeVersion: &node.Meta.Version, Spec: spec})
	return err
}

func (s *Scaler) retireSafe(ctx context.Context, name, instanceID string) (bool, error) {
	node, err := s.worker(ctx, name, instanceID)
	if err != nil {
		return false, err
	}
	protected, err := s.protectedNodes(ctx)
	if err != nil {
		return false, err
	}
	if node.Spec.Annotations.Labels["terrascale.instance-id"] != instanceID || protected[node.ID] || s.CanRetire == nil {
		return false, nil
	}
	if err := s.CanRetire(ctx, name, instanceID); err != nil {
		return false, fmt.Errorf("retirement safety for %s: %w", name, err)
	}
	return true, nil
}

// nodeNumber is n of a node name ts-<cell>-<n>.
func nodeNumber(node string) int {
	_, suffix, _ := strings.CutLast(node, "-")
	n, _ := strconv.Atoi(suffix)
	return n
}

// holdOnce journals a hold when its reason differs from the last journaled one. A cooldown's time left is not
// a new reason, so it is cut before the comparison.
func (s *Scaler) holdOnce(t *tick, decision Decision) {
	key, _, _ := strings.Cut(decision.Reason, ", ")
	if key == s.heldKey {
		return
	}
	s.heldKey = key
	s.queue(t, decisionlog.Decision{Kind: decisionlog.KindHeld, Subject: s.regionSubject(),
		Summary: fmt.Sprintf("hold %s at %d nodes", s.Cell, decision.Nodes), Reason: decision.Reason})
}

// fail ends the action without a change. LastChange stays, so the cooldown still holds.
func (s *Scaler) fail(t *tick, reason string) {
	t.record.Action = nil
	s.queue(t, decisionlog.Decision{Kind: decisionlog.KindHeld, Subject: s.regionSubject(), Status: decisionlog.StatusFailed,
		Summary: fmt.Sprintf("stop scaling %s", s.Cell), Reason: reason})
}

// queue adds a decision to the tick's journal entries. They are written once the record is saved.
func (s *Scaler) queue(t *tick, decision decisionlog.Decision) {
	decision.Time = t.now
	decision.Region = s.Cell
	decision.Actor = decisionlog.Actor{Slice: sliceName}
	decision.Epoch = t.epoch
	t.journal = append(t.journal, decision)
}

func (s *Scaler) regionSubject() decisionlog.Subject {
	return decisionlog.Subject{Kind: "region", ID: s.Cell}
}

// costOf is the region's spend from the Cost callback. Without one, or when it fails or names a currency that is
// not an ISO code, the spend is zero, which the home reads as unknown.
func (s *Scaler) costOf(ctx context.Context, pool PoolState) Cost {
	if s.Cost == nil {
		return Cost{}
	}
	cost, err := s.Cost(ctx, pool)
	if err == nil && !validCurrency(cost.Currency) {
		err = fmt.Errorf("cost currency %q is not an ISO 4217 code", cost.Currency)
	}
	if err != nil {
		if msg := err.Error(); msg != s.costErr {
			s.costErr = msg
			slog.Warn("node cost unavailable", observability.ComponentKey, sliceName, "cell", s.Cell, "error", err)
		}
		return Cost{}
	}
	s.costErr = ""
	return cost
}

// buildStatus is the region's published view after this tick.
func (s *Scaler) buildStatus(t *tick, decision Decision, allowance int, fresh bool, samples []Sample, cost Cost) Status {
	status := Status{
		Schema: StatusSchema, Cell: s.Cell, At: t.now,
		Nodes: t.obs.nodes, QuorumNodes: t.obs.quorum, PoolNodes: t.obs.pool,
		Want: decision.Want, Allowance: allowance, AllowanceFresh: fresh,
		Action: decision.Action, Saturated: decision.Saturated,
		Pressure: decision.Pressure, Signal: decision.Signal, Reason: decision.Reason,
		InFlight: t.record.Action, LastChange: t.record.LastChange,
		NodeMonthlyCents: cost.NodeMonthlyCents, ProjectedCents: cost.ProjectedCents,
		Currency: cost.Currency, CostAt: cost.At,
	}
	if n := len(samples); n > 0 && samples[n-1].Complete() {
		status.Signals = samples[n-1].Utilization
	}
	return status
}

// roundTrips is the latest round trip to each OCI region in whole milliseconds. A sub-millisecond connect counts
// as 1, since Validate refuses 0.
func (s *Scaler) roundTrips() map[string]int {
	if s.RTT == nil {
		return nil
	}
	rtt := s.RTT()
	millis := make(map[string]int, len(rtt))
	for region, d := range rtt {
		millis[region] = max(1, int(d.Round(time.Millisecond).Milliseconds()))
	}
	return millis
}
