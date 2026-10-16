package capacitysim

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
)

// nodeMonthlyCents is the list price of one node for a month, in BRL cents.
const nodeMonthlyCents = 4100

// fakePool keeps one region's pool in memory. Grow adds an unnamed inst-… instance, and namedAt records when the
// scaler named each instance, so its host goes live one tick later.
type fakePool struct {
	now       func() time.Time
	exists    bool
	instances []nodescale.PoolInstance
	grown     int
	namedAt   map[string]time.Time // instance ID to the time the scaler named it
}

func (p *fakePool) Observe(context.Context) (nodescale.PoolState, error) {
	if !p.exists {
		return nodescale.PoolState{}, nil
	}
	return nodescale.PoolState{Exists: true, PoolID: "pool", LifecycleState: "RUNNING", Size: len(p.instances),
		Instances: slices.Clone(p.instances)}, nil
}

func (p *fakePool) Ensure(ctx context.Context, _ nodescale.Recipe) (nodescale.PoolState, error) {
	p.exists = true
	return p.Observe(ctx)
}

func (p *fakePool) Grow(_ context.Context, from int) error {
	switch size := len(p.instances); size {
	case from + 1:
		return nil
	case from:
	default:
		return fmt.Errorf("%w: pool is %d, expected %d", nodescale.ErrPoolChanged, size, from)
	}
	p.grown++
	p.instances = append(p.instances, nodescale.PoolInstance{ID: fmt.Sprintf("ocid-inst-%d", p.grown),
		Name: fmt.Sprintf("inst-%d", p.grown), State: "PROVISIONING", PrivateIP: fmt.Sprintf("10.0.9.%d", p.grown),
		Created: p.now()})
	return nil
}

func (p *fakePool) Name(_ context.Context, id, node string) error {
	i := slices.IndexFunc(p.instances, func(in nodescale.PoolInstance) bool { return in.ID == id })
	if i < 0 {
		return nodescale.ErrNotPoolInstance
	}
	p.instances[i].Name = node
	p.namedAt[id] = p.now()
	return nil
}

func (p *fakePool) Remove(_ context.Context, id string) error {
	p.instances = slices.DeleteFunc(p.instances, func(in nodescale.PoolInstance) bool { return in.ID == id })
	return nil
}

// fakeHosts lists every live node. The sim adds a node's name when its host goes live and deletes it when its
// instance is gone.
type fakeHosts struct {
	now  func() time.Time
	live map[string]bool
}

func (h *fakeHosts) ListHosts(context.Context) ([]host.HostStatus, error) {
	hosts := make([]host.HostStatus, 0, len(h.live))
	for node := range h.live {
		hosts = append(hosts, host.HostStatus{Registration: host.Registration{Node: node},
			SessionExpiresAt: h.now().Add(time.Hour)})
	}
	slices.SortFunc(hosts, func(a, b host.HostStatus) int {
		return strings.Compare(a.Registration.Node, b.Registration.Node)
	})
	return hosts, nil
}

func (h *fakeHosts) ListDesired(context.Context, string) ([]host.Desired, error) { return nil, nil }

func (h *fakeHosts) Cordon(context.Context, string) error { return nil }

func (h *fakeHosts) Unretire(context.Context, string) error { return nil }

// fakeLeader is a leader that may mutate. CanMutate reads the wall clock, so the lease is real-time, not sim time.
type fakeLeader struct{ snapshot authority.Snapshot }

func newFakeLeader() *fakeLeader {
	return &fakeLeader{snapshot: authority.Snapshot{DeploymentID: entityid.New(), Ready: true, Leader: true,
		Epoch: 7, Revision: 3, ExpiresAt: time.Now().Add(24 * time.Hour)}}
}

func (f *fakeLeader) Current() authority.Snapshot { return f.snapshot }

func (f *fakeLeader) Guard(context.Context, uint64) error { return nil }

// fakeStore keeps the record apart from the scaler's copy, as JetStream does: a load and a save each copy it, so one
// tick never shares memory with the next.
type fakeStore struct {
	record   nodescale.Record
	revision uint64
}

func (f *fakeStore) Load(context.Context) (nodescale.Record, uint64, error) {
	return cloneRecord(f.record), f.revision, nil
}

func (f *fakeStore) Save(_ context.Context, record nodescale.Record, revision uint64) (uint64, error) {
	if revision != f.revision {
		return 0, nodescale.ErrRecordChanged
	}
	f.record = cloneRecord(record)
	f.revision++
	return f.revision, nil
}

// cloneRecord copies what the scaler edits in place: the action in flight, and the pointers and map in its status.
func cloneRecord(record nodescale.Record) nodescale.Record {
	record.Action = cloneAction(record.Action)
	record.Status.InFlight = cloneAction(record.Status.InFlight)
	record.Status.Signals = maps.Clone(record.Status.Signals)
	return record
}

func cloneAction(action *nodescale.InFlight) *nodescale.InFlight {
	if action == nil {
		return nil
	}
	copied := *action
	return &copied
}
