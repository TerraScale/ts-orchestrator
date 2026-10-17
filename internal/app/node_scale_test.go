package app

import (
	"context"
	"maps"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/controlapi"
	"github.com/moby/swarmkit/v2/manager/state/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// fakeScalePool is the pool OCI lists: its instances, all running and named.
type fakeScalePool struct{ instances []nodescale.PoolInstance }

func (pool fakeScalePool) Observe(context.Context) (nodescale.PoolState, error) {
	return nodescale.PoolState{Exists: true, Size: len(pool.instances), Instances: pool.instances}, nil
}
func (pool fakeScalePool) TargetSize(context.Context, nodescale.Recipe) (int, error) {
	return len(pool.instances), nil
}
func (fakeScalePool) Ensure(context.Context, nodescale.Recipe) (nodescale.PoolState, error) {
	return nodescale.PoolState{}, nil
}
func (fakeScalePool) Grow(context.Context, int) error            { return nil }
func (fakeScalePool) Name(context.Context, string, string) error { return nil }
func (fakeScalePool) Remove(context.Context, string) error       { return nil }

func (fakeScalePool) PrepareGrowth(context.Context, nodescale.Record) (rootoci.PoolChildExpectation, error) {
	return rootoci.PoolChildExpectation{}, nodescale.ErrCapacityPending
}

func (fakeScalePool) PrepareRetirement(context.Context, string, string) (rootoci.PoolRetirementExpectation, error) {
	return rootoci.PoolRetirementExpectation{}, nodescale.ErrCapacityPending
}

func (fakeScalePool) Recover(context.Context) error { return nodescale.ErrCapacityPending }

// fakeScaleRecords keeps the scaler record in memory.
type fakeScaleRecords struct{ record nodescale.Record }

func (records *fakeScaleRecords) Load(context.Context) (nodescale.Record, uint64, error) {
	return records.record, 1, nil
}

func (records *fakeScaleRecords) Save(_ context.Context, record nodescale.Record, _ uint64) (uint64, error) {
	records.record = record
	return 2, nil
}

// fakeScaleLeader is this member's authority, which its test can demote.
type fakeScaleLeader struct{ leader bool }

func (leader *fakeScaleLeader) Current() authority.Snapshot {
	return authority.Snapshot{DeploymentID: entityid.New(), Ready: true, Leader: leader.leader, Epoch: 3, Revision: 1,
		ExpiresAt: time.Now().Add(time.Minute)}
}

func (*fakeScaleLeader) Guard(context.Context, uint64) error { return nil }

func newFakeScaler(t *testing.T, pool fakeScalePool, records nodescale.RecordStore, leader authority.Fencer) *nodescale.Scaler {
	t.Helper()
	state := store.NewMemoryStore(nil)
	t.Cleanup(func() { _ = state.Close() })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	api.RegisterControlServer(server, controlapi.NewServer(state, nil, nil, nil, nil))
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	connection, err := grpc.NewClient("passthrough:///"+listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return &nodescale.Scaler{Cell: "gru", Pool: pool, Control: api.NewControlClient(connection), Store: records, Leader: leader,
		Now:       time.Now,
		Loads:     func() []nodescale.NodeLoad { return nil },
		Allowance: func(time.Time) (int, bool) { return 0, false },
		Revoke:    func(context.Context, string) error { return nil },
		Backends:  func(context.Context, string, string) (int, error) { return 0, nil },
		Journal:   func(context.Context, decisionlog.Decision) {}}
}

// A leader publishes its scaler's status. A follower publishes the status the
// leader saved, and a region that never ran a scaler publishes none.
func TestScaleStatusIsTheLeadersOwn(t *testing.T) {
	ctx := t.Context()
	records := &fakeScaleRecords{}
	leader := &fakeScaleLeader{leader: true}
	pool := fakeScalePool{instances: []nodescale.PoolInstance{{ID: "ocid1.instance.a", Name: "ts-gru-4", State: "RUNNING", PrivateIP: "10.0.0.4"}}}
	scaler := newFakeScaler(t, pool, records, leader)
	scale := scaleStatus(scaler)
	if status := scale(); status != nil {
		t.Fatalf("a scaler that never ran published %+v", status)
	}
	if err := scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if status := scale(); status == nil || status.Cell != "gru" || status.Nodes != 1 {
		t.Fatalf("leader status = %+v", status)
	}
	// Only the leader publishes the rollup, so a follower has nothing to say.
	leader.leader = false
	if err := scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if status := scale(); status != nil {
		t.Fatalf("follower status = %+v", status)
	}
}

// The release fence names the pool nodes the scaler observes beside the cell
// spec's nodes, and the cell spec wins a node both name.
func TestReleaseFenceNamesThePoolNodes(t *testing.T) {
	ctx := t.Context()
	pool := fakeScalePool{instances: []nodescale.PoolInstance{
		{ID: "ocid1.instance.a", Name: "ts-gru-4", State: "RUNNING", PrivateIP: "10.0.0.4"},
		{ID: "ocid1.instance.b", Name: "ts-gru-5", State: "RUNNING", PrivateIP: "10.0.0.5"}}}
	scaler := newFakeScaler(t, pool, &fakeScaleRecords{}, &fakeScaleLeader{leader: true})
	if err := scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	var running atomic.Pointer[nodescale.Scaler]
	spec := withPoolAddresses(func() (*cellspec.ReleaseFence, map[string]string) {
		return &cellspec.ReleaseFence{LoadBalancerID: "ocid1.loadbalancer.a"},
			map[string]string{"ts-gru-1": "10.0.0.1", "ts-gru-4": "10.0.9.4"}
	}, &running)
	if _, addresses := spec(); len(addresses) != 2 {
		t.Fatalf("before the scaler runs the fence names only the cell spec: %v", addresses)
	}
	running.Store(scaler)
	fence, addresses := spec()
	want := map[string]string{"ts-gru-1": "10.0.0.1", "ts-gru-4": "10.0.9.4", "ts-gru-5": "10.0.0.5"}
	if fence == nil || fence.LoadBalancerID != "ocid1.loadbalancer.a" || !maps.Equal(addresses, want) {
		t.Fatalf("fence = %+v, addresses = %v, want %v", fence, addresses, want)
	}
}
