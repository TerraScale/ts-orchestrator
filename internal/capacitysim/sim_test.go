package capacitysim

import (
	"context"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const (
	regionCount      = 20
	homeCell         = "gru"
	quorumNodes      = 3
	partitionedIndex = 6  // this region cannot see the home from partitionFrom to partitionUntil
	rampIndex        = 11 // this region's demand ramps past the 12-node ceiling
	capNodes         = 150
	seed             = 804
	simDuration      = 48 * time.Hour
	partitionFrom    = 20 * time.Hour
	partitionUntil   = 28 * time.Hour
)

var simStart = time.Date(2026, time.October, 10, 0, 0, 0, 0, time.UTC)

// TestTwentyRegionsScaleUnderOneBudget runs 20 scalers and the home allocator for two simulated days, asserting the
// invariants on every 30-second step.
func TestTwentyRegionsScaleUnderOneBudget(t *testing.T) {
	entries := catalog.Entries()
	if len(entries) < regionCount || entries[0].Name() != homeCell {
		t.Fatalf("catalog has %d regions, first %q: need %d regions with %s first", len(entries), entries[0].Name(),
			regionCount, homeCell)
	}
	s := newSim(t, entries[:regionCount])
	steps := int(simDuration / nodescale.Interval)
	for range steps {
		s.step()
	}
	c := s.counts
	if c.scaleUps == 0 || c.scaleDowns == 0 || c.budgetHoldStarts == 0 {
		t.Fatalf("run missed a case: %d scale-ups, %d scale-downs, %d budget-capped holds",
			c.scaleUps, c.scaleDowns, c.budgetHoldStarts)
	}
	t.Logf("%d steps of %s: %d scale-ups, %d scale-downs, %d budget-capped hold starts (%d region ticks held), "+
		"%d unknown-capacity minutes, %d scale-ups in the partition's first %s, peak fleet %d of %d nodes",
		steps, nodescale.Interval, c.scaleUps, c.scaleDowns, c.budgetHoldStarts, c.budgetHoldTicks,
		c.unknownMinutes, c.partitionLaunches, budget.AllowanceMaxAge, c.peakNodes, capNodes)
}

// sim is the home allocator and the regions it allocates to, on one clock.
type sim struct {
	t       *testing.T
	now     time.Time
	budget  budget.Budget
	regions []*simRegion
	counts  simCounts

	lastAllocation time.Time        // the latest minute the home allocated
	lastReason     string           // that allocation's reason, for failure messages
	prior          *budget.Capacity // the capacity the home last wrote, nil before its first allocation
}

// simCounts is what the run observed.
type simCounts struct {
	scaleUps, scaleDowns int
	budgetHoldTicks      int // region ticks held with the budget as the reason
	budgetHoldStarts     int // holds that began on a tick after the region was not held by the budget
	unknownMinutes       int // allocations in which some region had no fresh status
	partitionLaunches    int // scale-ups the partitioned region started in the partition's first AllowanceMaxAge
	peakNodes            int
}

func newSim(t *testing.T, cells []catalog.Entry) *sim {
	s := &sim{t: t, now: simStart.Add(-nodescale.Interval), budget: budget.Budget{Schema: budget.Schema,
		ID: entityid.New(), MonthlyCapCents: capNodes * nodeMonthlyCents, Currency: "BRL", SetBy: "sim", SetAt: simStart}}
	for index, entry := range cells {
		s.regions = append(s.regions, s.newRegion(entry.Name(), index))
	}
	return s
}

func (s *sim) clock() time.Time { return s.now }

func (s *sim) stamp() string { return s.now.Format(time.RFC3339) }

// step advances one nodescale.Interval: the world moves, every scaler ticks, and on each whole minute the home
// allocates.
func (s *sim) step() {
	s.now = s.now.Add(nodescale.Interval)
	for _, r := range s.regions {
		r.world(s.now)
	}
	for _, r := range s.regions {
		if err := r.scaler.Tick(context.Background()); err != nil {
			s.t.Fatalf("%s tick at %s: %v", r.cell, s.stamp(), err)
		}
	}
	if s.now.Sub(simStart)%time.Minute == 0 {
		s.allocate()
	}
	s.check()
}

// allocate is the home's minute. It reads each region's status, except a partitioned region's, writes the capacity
// document and hands it to every region that can see the home.
func (s *sim) allocate() {
	regions := make([]budget.Region, 0, len(s.regions))
	for _, r := range s.regions {
		if r.cut(s.now) {
			regions = append(regions, budget.Region{Cell: r.cell})
			continue
		}
		st := r.scaler.Status()
		regions = append(regions, budget.Region{Cell: r.cell, Nodes: st.Nodes, Want: st.Want, Pressure: st.Pressure,
			NodeMonthlyCents: st.NodeMonthlyCents, ProjectedCents: st.ProjectedCents, Currency: st.Currency, At: st.At})
	}
	capacity := budget.Allocate(&s.budget, regions, s.prior, s.now)
	if err := capacity.Validate(); err != nil {
		s.t.Fatalf("capacity at %s is invalid: %v", s.stamp(), err)
	}
	s.prior = &capacity
	unknown := capacity.State == budget.StateUnknown
	if unknown != inPartition(s.now) {
		s.t.Fatalf("capacity at %s is %s: it must be unknown exactly during the partition. %s", s.stamp(),
			capacity.State, capacity.Reason)
	}
	if unknown {
		s.counts.unknownMinutes++
	}
	s.lastAllocation, s.lastReason = s.now, capacity.Reason
	for _, r := range s.regions {
		if !r.cut(s.now) {
			r.view, r.hasView = capacity, true
		}
	}
}

// check asserts the invariants at the end of a step.
func (s *sim) check() {
	fleet := 0
	for _, r := range s.regions {
		nodes := r.nodes()
		fleet += nodes
		if nodes < nodescale.MinNodes || nodes > nodescale.MaxNodes {
			s.t.Fatalf("%s has %d nodes at %s, want %d to %d%s", r.cell, nodes, s.stamp(), nodescale.MinNodes,
				nodescale.MaxNodes, s.dump())
		}
		s.checkEvents(r)
		s.checkPartition(r)
		st := r.scaler.Status()
		held := st.Action == nodescale.Hold && strings.Contains(st.Reason, "budget")
		if held {
			s.counts.budgetHoldTicks++
			if !r.budgetHeld {
				s.counts.budgetHoldStarts++
			}
		}
		r.budgetHeld = held
	}
	if fleetCents := uint64(fleet) * nodeMonthlyCents; fleetCents > s.budget.MonthlyCapCents {
		s.t.Fatalf("fleet spend at %s is %d cents for %d nodes, over the %d cent cap%s", s.stamp(), fleetCents,
			fleet, s.budget.MonthlyCapCents, s.dump())
	}
	s.counts.peakNodes = max(s.counts.peakNodes, fleet)
}

// checkEvents asserts each scale decision the region journaled since the last step against its cooldown. No
// scale-up may start in the partitioned region after its last capacity went stale.
func (s *sim) checkEvents(r *simRegion) {
	for _, e := range r.events[r.checked:] {
		switch e.Kind {
		case decisionlog.KindScaleUp:
			s.counts.scaleUps++
			if !r.lastChange.IsZero() && e.Time.Sub(r.lastChange) < nodescale.UpCooldown {
				s.t.Fatalf("%s scaled up at %s, %s after its last change, inside the %s up cooldown",
					r.cell, e.Time.Format(time.RFC3339), e.Time.Sub(r.lastChange), nodescale.UpCooldown)
			}
			if r.index == partitionedIndex && inPartition(e.Time) {
				if e.Time.After(simStart.Add(partitionFrom + budget.AllowanceMaxAge)) {
					s.t.Fatalf("partitioned %s scaled up at %s, after its capacity went stale", r.cell,
						e.Time.Format(time.RFC3339))
				}
				s.counts.partitionLaunches++
			}
		case decisionlog.KindScaleDown:
			s.counts.scaleDowns++
			if !r.lastChange.IsZero() && e.Time.Sub(r.lastChange) < nodescale.DownCooldown {
				s.t.Fatalf("%s scaled down at %s, %s after its last change, inside the %s down cooldown",
					r.cell, e.Time.Format(time.RFC3339), e.Time.Sub(r.lastChange), nodescale.DownCooldown)
			}
		default:
			continue
		}
		r.lastChange = e.Time
	}
	r.checked = len(r.events)
}

// checkPartition holds the partitioned region to its size once its capacity is stale: after the first ten minutes
// of the partition, it never gains a node.
func (s *sim) checkPartition(r *simRegion) {
	if r.index != partitionedIndex || !inPartition(s.now) || s.now.Before(simStart.Add(partitionFrom+10*time.Minute)) {
		return
	}
	if r.frozen == 0 {
		r.frozen = r.nodes()
	}
	if nodes := r.nodes(); nodes > r.frozen {
		s.t.Fatalf("partitioned %s grew to %d nodes at %s, above its %d at the freeze", r.cell, nodes, s.stamp(),
			r.frozen)
	}
}

// dump lists every region's nodes and status for a failure message.
func (s *sim) dump() string {
	var b strings.Builder
	for _, r := range s.regions {
		st := r.scaler.Status()
		fmt.Fprintf(&b, "\n  %s nodes=%d status_nodes=%d want=%d action=%s allowance=%d fresh=%t in_flight=%v reason=%q",
			r.cell, r.nodes(), st.Nodes, st.Want, st.Action, st.Allowance, st.AllowanceFresh, st.InFlight, st.Reason)
	}
	fmt.Fprintf(&b, "\n  last allocation at %s: %s", s.lastAllocation.Format(time.RFC3339), s.lastReason)
	return b.String()
}

// inPartition reports whether the home cannot see the partitioned region at now.
func inPartition(now time.Time) bool {
	return !now.Before(simStart.Add(partitionFrom)) && now.Before(simStart.Add(partitionUntil))
}

// simRegion is one region on fakes: its scaler, its demand, and what the home has seen from it.
type simRegion struct {
	cell       string
	index      int
	quorum     []string
	demand     demand
	pool       *fakePool
	hosts      *fakeHosts
	loads      []nodescale.NodeLoad
	store      *fakeStore
	scaler     *nodescale.Scaler
	events     []decisionlog.Decision // the scaler's journal, oldest first
	checked    int                    // events already asserted
	lastChange time.Time              // when the region last started a scale-up or scale-down
	budgetHeld bool
	frozen     int             // nodes when the partition's freeze began; 0 before
	view       budget.Capacity // the last capacity this region received
	hasView    bool
}

// newRegion starts a region with its three quorum nodes live and no pool.
func (s *sim) newRegion(cell string, index int) *simRegion {
	rng := rand.New(rand.NewPCG(seed, uint64(index)))
	r := &simRegion{cell: cell, index: index, demand: newDemand(rng, simStart, index == rampIndex),
		pool:  &fakePool{now: s.clock, namedAt: map[string]time.Time{}},
		hosts: &fakeHosts{now: s.clock, live: map[string]bool{}}, store: &fakeStore{}}
	for n := 1; n <= quorumNodes; n++ {
		node := fmt.Sprintf("ts-%s-%d", cell, n)
		r.quorum = append(r.quorum, node)
		r.hosts.live[node] = true
	}
	r.scaler = &nodescale.Scaler{
		Cell:   cell,
		Pool:   r.pool,
		Recipe: func(context.Context) (nodescale.Recipe, error) { return nodescale.Recipe{Cell: cell}, nil },
		Hosts:  r.hosts,
		Loads:  func() []nodescale.NodeLoad { return r.loads },
		Allowance: func(now time.Time) (int, bool) {
			if !r.hasView {
				return 0, false
			}
			return budget.AllowanceFor(r.view, cell, now)
		},
		Revoke:   func(context.Context, string) error { return nil },
		Backends: func(context.Context, string, string) (int, error) { return 0, nil },
		Journal:  func(_ context.Context, decision decisionlog.Decision) { r.events = append(r.events, decision) },
		Cost: func(_ context.Context, pool nodescale.PoolState) (nodescale.Cost, error) {
			nodes := quorumNodes + len(pool.Instances)
			return nodescale.Cost{NodeMonthlyCents: nodeMonthlyCents, ProjectedCents: uint64(nodes) * nodeMonthlyCents,
				Currency: "BRL", At: s.now}, nil
		},
		Leader: newFakeLeader(),
		Store:  r.store,
		Now:    s.clock,
	}
	return r
}

// nodes is the region's node count as OCI shows it: the quorum and every pool instance.
func (r *simRegion) nodes() int { return quorumNodes + len(r.pool.instances) }

// cut reports whether the home cannot see this region at now.
func (r *simRegion) cut(now time.Time) bool { return r.index == partitionedIndex && inPartition(now) }

// world moves the region to now. A node named at an earlier tick goes live, a removed instance's host goes away,
// and every live node reports the region's load: CPU = min(1, demand/nodes), memory and disk lower.
func (r *simRegion) world(now time.Time) {
	for _, in := range r.pool.instances {
		if named, ok := r.pool.namedAt[in.ID]; ok && now.After(named) {
			r.hosts.live[in.Name] = true
		}
	}
	for node := range r.hosts.live {
		gone := !slices.ContainsFunc(r.pool.instances, func(in nodescale.PoolInstance) bool { return in.Name == node })
		if gone && !slices.Contains(r.quorum, node) {
			delete(r.hosts.live, node)
		}
	}
	cpu := min(1, r.demand.levelAt(now)/float64(r.nodes()))
	r.loads = nil
	for _, node := range slices.Sorted(maps.Keys(r.hosts.live)) {
		r.loads = append(r.loads, nodescale.NodeLoad{Node: node, At: now, CPU: cpu, Memory: 0.8 * cpu,
			Disk: 0.3 * cpu, Cores: 4})
	}
}
