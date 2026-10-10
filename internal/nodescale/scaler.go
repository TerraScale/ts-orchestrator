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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
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

// Hosts is the host registry the scaler reads, and retires nodes through.
type Hosts interface {
	ListHosts(ctx context.Context) ([]host.HostStatus, error)
	ListDesired(ctx context.Context, role string) ([]host.Desired, error)
	Cordon(ctx context.Context, node string) error // retire mark regardless of allocations
	Unretire(ctx context.Context, node string) error
}

// Scaler scales one region's pool nodes. Tick acts on the leader only.
type Scaler struct {
	Cell      string // e.g. "gru"; nodes are naming.RegionCell(strings.ToUpper(Cell)).Node(n)
	Pool      Pool
	Recipe    func(ctx context.Context) (Recipe, error)
	Hosts     Hosts
	Loads     func() []NodeLoad                                            // latest load per node
	Allowance func(now time.Time) (int, bool)                              // false: no fresh allowance, so no growth
	Revoke    func(ctx context.Context, instanceID string) error           // ends a removed node's enrollment
	Backends  func(ctx context.Context, node, address string) (int, error) // load balancer backends still at the node
	Journal   func(ctx context.Context, decision decisionlog.Decision)
	Leader    authority.Fencer
	Store     RecordStore
	Now       func() time.Time

	mu        sync.Mutex
	history   History
	status    Status
	addresses map[string]string
	heldKey   string // reason of the last journaled hold, without a cooldown's time left
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
}

// observation is the pool and the hosts at one tick: which nodes count toward the sample, and how many.
type observation struct {
	nodes, quorum, pool int
	live                map[string]bool   // nodes with a live host session
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
// A follower resets its load windows; a new leader rebuilds them, which only delays action.
func (s *Scaler) Tick(ctx context.Context) error {
	snapshot := s.Leader.Current()
	if !snapshot.CanMutate() {
		s.history = History{}
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
	hosts, err := s.Hosts.ListHosts(ctx)
	if err != nil {
		return fmt.Errorf("list hosts: %w", err)
	}
	t := &tick{epoch: snapshot.Epoch, now: s.Now(), record: record, pool: pool}
	if err := s.nameUnnamed(ctx, t, hosts); err != nil {
		return err
	}
	t.obs = s.observe(t.pool, hosts, t.now)
	t.loads = countedLoads(s.Loads(), t.obs)
	s.mu.Lock()
	s.addresses = t.obs.addresses
	s.mu.Unlock()
	s.history.Add(Measure(t.obs.nodes, t.loads, t.now))
	if t.record.Action != nil {
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
	status := s.buildStatus(t, decision, allowance, fresh, samples)
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
func (s *Scaler) nameUnnamed(ctx context.Context, t *tick, hosts []host.HostStatus) error {
	used := map[string]bool{}
	for _, h := range hosts {
		used[h.Registration.Node] = true
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

// observe counts the region's nodes: quorum hosts with a live session, and pool instances, which all have names by now.
func (s *Scaler) observe(pool PoolState, hosts []host.HostStatus, now time.Time) observation {
	obs := observation{live: map[string]bool{}, counted: map[string]bool{}, addresses: map[string]string{}}
	poolNodes := map[string]bool{}
	for _, in := range pool.Instances {
		poolNodes[in.Name] = true
	}
	for _, h := range hosts {
		if now.Before(h.SessionExpiresAt) {
			obs.live[h.Registration.Node] = true
		}
	}
	for _, h := range hosts {
		if node := h.Registration.Node; obs.live[node] && !poolNodes[node] {
			obs.quorum++
			obs.counted[node] = true
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
		if obs.live[in.Name] {
			obs.counted[in.Name] = true
		}
	}
	obs.nodes = obs.quorum + obs.pool
	return obs
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
	recipe, err := s.Recipe(ctx)
	if err != nil {
		return fmt.Errorf("read node recipe: %w", err)
	}
	if err := s.Leader.Guard(ctx, t.epoch); err != nil {
		return err
	}
	if _, err := s.Pool.Ensure(ctx, recipe); err != nil {
		return fmt.Errorf("ensure node pool: %w", err)
	}
	if err := s.Leader.Guard(ctx, t.epoch); err != nil {
		return err
	}
	err = s.Pool.Grow(ctx, t.record.From)
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

// enroll ends the scale-up once every pool node has a live host session. A node that never enrolls is removed
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
		Reason: fmt.Sprintf("no host session within %s", LaunchTimeout)})
	return nil
}

// launched reports whether the pool holds From+1 live instances, each named and each with a live host session.
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

// cordon retires the node, so the workload reconciler places nothing more on it.
func (s *Scaler) cordon(ctx context.Context, t *tick) error {
	action := t.record.Action
	if err := s.Leader.Guard(ctx, t.epoch); err != nil {
		return err
	}
	if err := s.Hosts.Cordon(ctx, action.Node); err != nil {
		return fmt.Errorf("cordon %s: %w", action.Node, err)
	}
	action.Step = stepDrain
	return nil
}

// drain waits until nothing is desired on the node and no load balancer backend points at it. After
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
	if err := s.Hosts.Unretire(ctx, action.Node); err != nil {
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

// drained reports whether nothing is desired on the node and no load balancer backend still points at it.
func (s *Scaler) drained(ctx context.Context, t *tick) (bool, error) {
	node := t.record.Action.Node
	desired, err := s.Hosts.ListDesired(ctx, "")
	if err != nil {
		return false, fmt.Errorf("list desired state: %w", err)
	}
	if slices.ContainsFunc(desired, func(d host.Desired) bool { return d.Node == node && !d.Withdrawn }) {
		return false, nil
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
	switch decision.Action {
	case Up:
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
			decision.Reason = "no pool node is free to drain: each holds a terrabase member or lacks a load"
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

// pickDrain picks the named pool node with the least CPU, ties to the highest n, that holds no TerraBase member.
func (s *Scaler) pickDrain(ctx context.Context, t *tick) (PoolInstance, bool, error) {
	desired, err := s.Hosts.ListDesired(ctx, roleTerraBase)
	if err != nil {
		return PoolInstance{}, false, fmt.Errorf("list terrabase desired state: %w", err)
	}
	holds := map[string]bool{}
	for _, d := range desired {
		if !d.Withdrawn && d.Role == roleTerraBase {
			holds[d.Node] = true
		}
	}
	cpu := map[string]float64{}
	for _, load := range t.loads {
		cpu[load.Node] = load.CPU
	}
	var candidates []PoolInstance
	for _, in := range t.pool.Instances {
		if _, loaded := cpu[in.Name]; loaded && t.obs.counted[in.Name] && s.named(in.Name) && !holds[in.Name] {
			candidates = append(candidates, in)
		}
	}
	if len(candidates) == 0 {
		return PoolInstance{}, false, nil
	}
	slices.SortFunc(candidates, func(a, b PoolInstance) int {
		return cmp.Or(cmp.Compare(cpu[a.Name], cpu[b.Name]), cmp.Compare(nodeNumber(b.Name), nodeNumber(a.Name)))
	})
	return candidates[0], true, nil
}

// nodeNumber is n of a node name ts-<cell>-<n>.
func nodeNumber(node string) int {
	n, _ := strconv.Atoi(node[strings.LastIndexByte(node, '-')+1:])
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

// buildStatus is the region's published view after this tick.
func (s *Scaler) buildStatus(t *tick, decision Decision, allowance int, fresh bool, samples []Sample) Status {
	status := Status{
		Schema: StatusSchema, Cell: s.Cell, At: t.now,
		Nodes: t.obs.nodes, QuorumNodes: t.obs.quorum, PoolNodes: t.obs.pool,
		Want: decision.Want, Allowance: allowance, AllowanceFresh: fresh,
		Action: decision.Action, Saturated: decision.Saturated,
		Pressure: decision.Pressure, Signal: decision.Signal, Reason: decision.Reason,
		InFlight: t.record.Action, LastChange: t.record.LastChange,
	}
	if n := len(samples); n > 0 && samples[n-1].Complete() {
		status.Signals = samples[n-1].Utilization
	}
	return status
}
