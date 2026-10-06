package seatrollout

import (
	"context"
	"errors"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

// cell is a fake cell: each seat's desired generation, the state its host
// reports at that generation, and its load balancer backend.
type cell struct {
	t        *testing.T
	now      time.Time
	desired  map[string]uint64
	state    map[string]string
	backends map[string]Backend
	members  []Member
	wakes    int
	// withdrawn seats have a withdrawn desired.
	withdrawn map[string]bool
}

func newCell(t *testing.T) *cell {
	return &cell{t: t, now: time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC),
		desired:  map[string]uint64{"gru-1-db-1": 1, "gru-1-db-2": 1},
		state:    map[string]string{"gru-1-db-1": "running", "gru-1-db-2": "running"},
		backends: map[string]Backend{"10.251.0.21:9465": {Healthy: true}, "10.251.0.22:9465": {Healthy: true}},
		members: []Member{{Node: "gru-1-db-1", Backend: "10.251.0.21:9465", Group: "terrabase"},
			{Node: "gru-1-db-2", Backend: "10.251.0.22:9465", Group: "terrabase"}}}
}

func (c *cell) ListDesired(_ context.Context, role string) ([]host.Desired, error) {
	var out []host.Desired
	for node, generation := range c.desired {
		out = append(out, host.Desired{Node: node, Role: role, Digest: "d", Generation: generation, Withdrawn: c.withdrawn[node]})
	}
	return out, nil
}

func (c *cell) ListHosts(context.Context) ([]host.HostStatus, error) {
	var out []host.HostStatus
	for node, state := range c.state {
		out = append(out, host.HostStatus{Reports: []host.Report{{Node: node, Role: terrabase.Role, Digest: "d",
			Generation: c.desired[node], State: state, ObservedAt: c.now}}})
	}
	return out, nil
}

func (c *cell) controller(store *Store, fence authority.Fencer) *Controller {
	return &Controller{Store: store, Fencer: fence, Hosts: c,
		Seats:    func() ([]Member, error) { return c.members, nil },
		Backends: func(context.Context) (map[string]Backend, error) { return c.backends, nil },
		Now:      func() time.Time { return c.now }, Wake: func() { c.wakes++ }}
}

// release moves every seat to generation; their hosts wait for a permit.
func (c *cell) release(generation uint64) {
	for node := range c.desired {
		c.desired[node], c.state[node] = generation, "waiting"
	}
}

func (c *cell) tick(controller *Controller) {
	c.t.Helper()
	if err := controller.Tick(c.t.Context()); err != nil {
		c.t.Fatal(err)
	}
}

// expect checks which seats are drained and which may restart into their
// desired generation.
func (c *cell) expect(store *Store, drained []string, permitted []string) {
	c.t.Helper()
	got, err := store.Drained(c.t.Context())
	if err != nil {
		c.t.Fatal(err)
	}
	if len(got) != len(drained) {
		c.t.Fatalf("drained %v, want %v", got, drained)
	}
	for _, node := range drained {
		if !got[node] {
			c.t.Fatalf("drained %v, want %v", got, drained)
		}
	}
	for _, member := range c.members {
		want := false
		for _, node := range permitted {
			want = want || node == member.Node
		}
		granted, err := store.Granted(c.t.Context(), member.Node, host.Desired{Role: terrabase.Role, Generation: c.desired[member.Node]})
		if err != nil || granted != want {
			c.t.Fatalf("%s permitted=%v err=%v, want %v", member.Node, granted, err, want)
		}
	}
}

// TestSeatsRestartOneAtATimeBehindTheirDrain walks a release across two
// seats: each is drained, permitted only once the load balancer stopped
// sending it requests and the grace passed, returned to rotation once it
// served long enough, and the second is drained only once the first serves
// again on the load balancer.
func TestSeatsRestartOneAtATimeBehindTheirDrain(t *testing.T) {
	store, _, fence := testStore(t)
	c := newCell(t)
	controller := c.controller(store, fence)
	c.tick(controller)
	c.expect(store, nil, []string{})

	c.release(2)
	c.tick(controller)
	c.expect(store, []string{"gru-1-db-1"}, nil)
	if c.wakes != 1 {
		t.Fatalf("the drain woke the load balancer publisher %d times", c.wakes)
	}

	// The load balancer has not applied the drain yet.
	c.now = c.now.Add(time.Minute)
	c.tick(controller)
	c.expect(store, []string{"gru-1-db-1"}, nil)
	if c.wakes != 1 {
		t.Fatalf("a tick that wrote nothing woke the publisher: %d", c.wakes)
	}
	// It applies it a minute late: in-flight requests get their grace from
	// then, not from the drain request.
	c.backends["10.251.0.21:9465"] = Backend{Drained: true, Healthy: true}
	c.tick(controller)
	c.expect(store, []string{"gru-1-db-1"}, nil)
	c.now = c.now.Add(DefaultDrainGrace - time.Second)
	c.tick(controller)
	c.expect(store, []string{"gru-1-db-1"}, nil)
	c.now = c.now.Add(time.Second)
	c.tick(controller)
	c.expect(store, []string{"gru-1-db-1"}, []string{"gru-1-db-1"})

	// The restarted seat serves, but returns to rotation only after the
	// settle time; the other seat waits all along.
	c.state["gru-1-db-1"] = "starting"
	c.tick(controller)
	c.state["gru-1-db-1"] = "running"
	c.tick(controller)
	c.expect(store, []string{"gru-1-db-1"}, []string{"gru-1-db-1"})
	c.now = c.now.Add(DefaultSettle)
	c.tick(controller)
	c.expect(store, nil, []string{"gru-1-db-1"})

	// gru-1-db-2 drains only once gru-1-db-1 serves on the load balancer.
	c.tick(controller)
	c.expect(store, nil, []string{"gru-1-db-1"})
	c.backends["10.251.0.21:9465"] = Backend{Healthy: true}
	c.tick(controller)
	c.expect(store, []string{"gru-1-db-2"}, []string{"gru-1-db-1"})
	c.backends["10.251.0.22:9465"] = Backend{Drained: true, Healthy: true}
	c.tick(controller)
	c.expect(store, []string{"gru-1-db-2"}, []string{"gru-1-db-1"})
	c.now = c.now.Add(DefaultDrainGrace)
	c.tick(controller)
	c.expect(store, []string{"gru-1-db-2"}, []string{"gru-1-db-1", "gru-1-db-2"})
	c.state["gru-1-db-2"] = "running"
	c.tick(controller)
	c.now = c.now.Add(DefaultSettle)
	c.tick(controller)
	c.expect(store, nil, []string{"gru-1-db-1", "gru-1-db-2"})
}

// A seat the load balancer does not serve restarts first and without a
// drain; a seat whose drain would leave no healthy seat waits.
func TestSeatsOutOfRotationGoFirstAndTheLastHealthySeatStays(t *testing.T) {
	store, _, fence := testStore(t)
	c := newCell(t)
	c.members[1].Backend = "" // gru-1-db-2 is not in the backend set
	controller := c.controller(store, fence)
	c.release(2)
	c.tick(controller)
	c.expect(store, nil, []string{"gru-1-db-2"})
	c.state["gru-1-db-2"] = "running"
	c.tick(controller)
	// gru-1-db-1 is the only seat the load balancer serves.
	c.expect(store, nil, []string{"gru-1-db-2"})

	// With both in the set but gru-1-db-2 unhealthy, gru-1-db-1 still waits.
	c.members[1].Backend = "10.251.0.22:9465"
	c.backends["10.251.0.22:9465"] = Backend{}
	c.tick(controller)
	c.expect(store, nil, []string{"gru-1-db-2"})
	c.backends["10.251.0.22:9465"] = Backend{Healthy: true}
	c.tick(controller)
	c.expect(store, []string{"gru-1-db-1"}, []string{"gru-1-db-2"})
}

// A restarted seat that never serves holds its group, and the release's
// rollback (a newer generation) restarts it first.
func TestAFailedSeatHoldsTheGroupUntilTheRollback(t *testing.T) {
	store, _, fence := testStore(t)
	c := newCell(t)
	controller := c.controller(store, fence)
	c.release(2)
	c.tick(controller)
	c.backends["10.251.0.21:9465"] = Backend{Drained: true}
	c.now = c.now.Add(DefaultDrainGrace)
	c.tick(controller)
	c.state["gru-1-db-1"] = "failed"
	for range 5 {
		c.now = c.now.Add(time.Minute)
		c.tick(controller)
	}
	c.expect(store, []string{"gru-1-db-1"}, []string{"gru-1-db-1"})

	c.release(3)
	c.state["gru-1-db-1"] = "failed"
	c.tick(controller)
	c.expect(store, []string{"gru-1-db-1"}, []string{"gru-1-db-1"})
	c.state["gru-1-db-1"] = "running"
	c.tick(controller)
	c.now = c.now.Add(DefaultSettle)
	c.tick(controller)
	// Its host reports it serving, but the load balancer has not found it
	// healthy yet: it stays drained.
	c.expect(store, []string{"gru-1-db-1"}, []string{"gru-1-db-1"})
	// Once it does, the seat settles and returns.
	c.backends["10.251.0.21:9465"] = Backend{Drained: true, Healthy: true}
	c.tick(controller)
	c.expect(store, []string{"gru-1-db-1"}, []string{"gru-1-db-1"})
	c.now = c.now.Add(DefaultSettle)
	c.tick(controller)
	c.expect(store, nil, []string{"gru-1-db-1"})
}

// Only the authority leader writes, and a write under a lost epoch fails.
func TestSeatControllerWritesOnlyUnderAuthority(t *testing.T) {
	store, _, fence := testStore(t)
	c := newCell(t)
	c.release(2)
	follower := c.controller(store, followerFence{})
	c.tick(follower)
	c.expect(store, nil, nil)

	deposed := c.controller(store, staleFence{epochFence: fence})
	if err := deposed.Tick(t.Context()); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("deposed leader tick: %v", err)
	}
	c.expect(store, nil, nil)
}

type followerFence struct{}

func (followerFence) Current() authority.Snapshot         { return authority.Snapshot{} }
func (followerFence) Guard(context.Context, uint64) error { return authority.ErrFenced }

// staleFence reports an epoch the store's fence no longer accepts.
type staleFence struct{ *epochFence }

func (f staleFence) Current() authority.Snapshot {
	snapshot := f.epochFence.Current()
	snapshot.Epoch--
	return snapshot
}

// A seat that leaves the seat list while it settles starts the settle over
// when it comes back, instead of reusing the wait it began before.
func TestASeatThatLeavesStartsItsWaitsOver(t *testing.T) {
	store, _, fence := testStore(t)
	c := newCell(t)
	controller := c.controller(store, fence)
	c.release(2)
	c.tick(controller)
	c.backends["10.251.0.21:9465"] = Backend{Drained: true, Healthy: true}
	c.tick(controller)
	c.now = c.now.Add(DefaultDrainGrace)
	c.tick(controller)
	c.state["gru-1-db-1"] = "running"
	c.tick(controller)
	c.expect(store, []string{"gru-1-db-1"}, []string{"gru-1-db-1"})

	members := c.members
	c.members = members[1:]
	c.now = c.now.Add(DefaultSettle)
	c.tick(controller)
	c.members = members
	c.tick(controller)
	c.expect(store, []string{"gru-1-db-1"}, []string{"gru-1-db-1"})
	c.now = c.now.Add(DefaultSettle)
	c.tick(controller)
	c.expect(store, nil, []string{"gru-1-db-1"})
}

// A drained seat whose desired is withdrawn stays drained while its host
// stops it, and its group waits: it serves nothing and is a member short.
func TestAWithdrawnSeatStaysDrained(t *testing.T) {
	store, _, fence := testStore(t)
	c := newCell(t)
	controller := c.controller(store, fence)
	c.release(2)
	c.tick(controller)
	c.expect(store, []string{"gru-1-db-1"}, nil)
	c.withdrawn = map[string]bool{"gru-1-db-1": true}
	for range 3 {
		c.now = c.now.Add(time.Minute)
		c.tick(controller)
	}
	c.expect(store, []string{"gru-1-db-1"}, nil)
}
