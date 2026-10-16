package app

import (
	"context"
	"fmt"
	"maps"
	"net"
	"sync/atomic"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// allowanceTimeout bounds the read of the global capacity document. A read
// that times out holds growth; scaling down never waits for it.
const allowanceTimeout = 5 * time.Second

// nodeScaling is what the node scaler runs on: the cell's pool and the host,
// load and global state it reads, and the leader it acts under.
type nodeScaling struct {
	cell      string
	js        jetstream.JetStream
	replicas  int
	ready     func() bool
	pool      *nodescale.OCIPool
	factory   *ociclient.Factory
	control   api.ControlClient
	canRetire func(context.Context, string, string) error
	load      *hostTelemetry
	global    *globalControl
	fencer    authority.Fencer
	fences    *releaseFence
	// enrollment revokes a removed node's grant; nil when the region admits no pool nodes.
	enrollment *managedHostEnrollment
	// scaler publishes the running scaler to the release fence's spec.
	scaler *atomic.Pointer[nodescale.Scaler]
	// costViews prices the node and forecasts the region for the scaler's Cost (TS-807).
	costViews      *ociCostViews
	reservations   *capacityReservations
	functionDemand func(context.Context) ([]nodescale.CapacityDemand, error)
}

// startNodeScaler runs the region's node scaler on every regional leader and
// returns the status each member publishes in its region summary.
func startNodeScaler(ctx context.Context, in nodeScaling) (func() *nodescale.Status, error) {
	store, _, err := retryControllerOpen(ctx, "open node scaler state", in.ready, false,
		func(attempt context.Context) (*nodescale.Store, error) {
			return nodescale.OpenStore(attempt, in.js, in.replicas)
		}, nil)
	if err != nil {
		return nil, err
	}
	in.pool.Admit = in.reservations.admit(in.pool, store, in.fencer)
	pool, err := nodescale.NewChosenPool(in.pool, store)
	if err != nil {
		return nil, err
	}
	prober := &nodescale.Prober{Regions: ociRegionNames(in.factory), Dial: (&net.Dialer{}).DialContext, Now: time.Now}
	recipe := func(ctx context.Context) (nodescale.Recipe, error) {
		record, _, err := store.Load(ctx)
		if err != nil {
			return nodescale.Recipe{}, err
		}
		if record.Action != nil && record.Action.Kind == nodescale.Up && record.Recipe != nil {
			return in.reservations.choose(ctx, *record.Recipe, in.pool, in.factory, store, "")
		}
		base, err := nodeRecipe(ctx, in.factory, in.cell)
		if err != nil {
			return nodescale.Recipe{}, err
		}
		return in.reservations.choose(ctx, base, in.pool, in.factory, store, "")
	}
	pricedRecipe := func(ctx context.Context) (nodescale.Recipe, error) {
		record, _, err := store.Load(ctx)
		if err != nil {
			return nodescale.Recipe{}, err
		}
		if record.Recipe != nil {
			return *record.Recipe, nil
		}
		return recipe(ctx)
	}
	scaler := &nodescale.Scaler{Cell: in.cell, Pool: pool, Control: in.control, CanRetire: in.canRetire, Store: store, Leader: in.fencer,
		Now:    time.Now,
		Recipe: recipe,
		FunctionDemand: func(ctx context.Context) ([]nodescale.CapacityDemand, error) {
			if in.functionDemand == nil {
				return nil, fmt.Errorf("%w: current signed function service capacity is unavailable", nodescale.ErrCapacityPending)
			}
			return in.functionDemand(ctx)
		},
		FunctionRecipe: func(ctx context.Context, architecture string) (nodescale.Recipe, error) {
			base, err := nodeRecipe(ctx, in.factory, in.cell)
			if err != nil {
				return nodescale.Recipe{}, err
			}
			base.Capacity.Role = nodescale.RoleWasm
			return in.reservations.choose(ctx, base, in.pool, in.factory, store, architecture)
		},
		Reserve: func(ctx context.Context, operationID string, recipe nodescale.Recipe) (budget.Reservation, error) {
			request, err := in.reservations.prepare(ctx, operationID, recipe, in.pool.CompartmentID())
			if err != nil {
				return budget.Reservation{}, err
			}
			return in.reservations.request(ctx, "reserve", request)
		},
		Cost:  in.costViews.nodeCost(in.reservations, in.pool.CompartmentID(), pricedRecipe, time.Now),
		Loads: func() []nodescale.NodeLoad { return nodeLoads(in.load) },
		Allowance: func(now time.Time) (int, bool) {
			return allowance(in.global, in.cell, now)
		},
		Revoke: func(ctx context.Context, instanceID string) error {
			if in.enrollment == nil {
				return nil
			}
			_, err := in.enrollment.grants.Disable(ctx, instanceID)
			return err
		},
		Backends: func(ctx context.Context, _, address string) (int, error) {
			return backendsAt(ctx, in.fences, address)
		},
		Journal: func(ctx context.Context, decision decisionlog.Decision) {
			decisionlog.Record(ctx, decision)
		},
		RTT: func() map[string]time.Duration {
			rtt, _ := prober.Latest()
			return rtt
		},
	}
	in.scaler.Store(scaler)
	go prober.Run(ctx)
	go scaler.Run(ctx)
	return scaleStatus(scaler), nil
}

// ociRegionNames lists every OCI region's name through the instance principal the pool uses.
func ociRegionNames(factory *ociclient.Factory) func(context.Context) ([]string, error) {
	return func(ctx context.Context) ([]string, error) {
		identities, err := factory.Identity()
		if err != nil {
			return nil, err
		}
		listed, err := identities.ListRegions(ctx)
		if err != nil {
			return nil, err
		}
		var names []string
		for _, region := range listed.Items {
			if region.Name != nil {
				names = append(names, *region.Name)
			}
		}
		return names, nil
	}
}

// withPoolAddresses adds the private addresses of the running scaler's pool
// nodes to a release fence's spec, so their replicas get load balancer
// backends. The cell spec's addresses win on a node both name.
func withPoolAddresses(spec func() (*cellspec.ReleaseFence, map[string]string),
	scaler *atomic.Pointer[nodescale.Scaler],
) func() (*cellspec.ReleaseFence, map[string]string) {
	return func() (*cellspec.ReleaseFence, map[string]string) {
		fence, addresses := spec()
		var pool map[string]string
		if running := scaler.Load(); running != nil {
			pool = running.Addresses()
		}
		merged := make(map[string]string, len(pool)+len(addresses))
		maps.Copy(merged, pool)
		maps.Copy(merged, addresses)
		return fence, merged
	}
}

// nodeLoads converts the latest load of each node that reports one.
func nodeLoads(load *hostTelemetry) []nodescale.NodeLoad {
	var loads []nodescale.NodeLoad
	for _, report := range load.load.Nodes() {
		if node, ok := nodescale.FromHostLoad(report); ok {
			loads = append(loads, node)
		}
	}
	return loads
}

// allowance is the most nodes cell may have under the global capacity
// document. A missing, unreadable or stale document holds growth.
func allowance(global *globalControl, cell string, now time.Time) (int, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), allowanceTimeout)
	defer cancel()
	capacity, found, err := budget.ReadCapacity(ctx, global.reader)
	if err != nil || !found {
		return 0, false
	}
	return budget.AllowanceFor(capacity, cell, now)
}

// backendsAt counts the load balancer backends at address in every backend set
// of the release fence. Missing inventory holds retirement.
func backendsAt(ctx context.Context, fence *releaseFence, address string) (int, error) {
	if fence == nil || address == "" {
		return 0, fmt.Errorf("node retirement requires a current load balancer fence and private address")
	}
	spec, _ := fence.spec()
	if spec == nil {
		return 0, fmt.Errorf("node retirement load balancer inventory is unavailable")
	}
	api, err := fence.client(ctx)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, set := range spec.BackendSets {
		backends, err := api.ListBackends(ctx, spec.LoadBalancerID, set.Name)
		if err != nil {
			return 0, err
		}
		for _, backend := range backends {
			if backend.IP == address {
				count++
			}
		}
	}
	return count, nil
}

// scaleStatus is the region's node status for its rollup. Only the leader
// publishes the rollup, and only the leader's scaler has a status; it reads
// memory, never the network.
func scaleStatus(scaler *nodescale.Scaler) func() *nodescale.Status {
	return func() *nodescale.Status {
		if status := scaler.Status(); status.Schema != 0 {
			return &status
		}
		return nil
	}
}
