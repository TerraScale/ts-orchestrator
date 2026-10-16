package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// The tags the node pool launches each instance with.
const (
	poolTagCell  = "ts-cell"
	poolTagRole  = "ts-role"
	poolNodeRole = "node"
)

// nodePoolMembers is what enrollment needs from the cell's node pool.
type nodePoolMembers interface {
	Observe(ctx context.Context) (nodescale.PoolState, error)
}

// nodePoolRetry is how often an unbound node pool is bound again.
const nodePoolRetry = time.Minute

// nodePoolBinding is the cell's node pool once it binds. Worker authority may not
// be available when the controller starts, so enrollment and the region status read
// the pool through here, and see it as soon as it binds.
type nodePoolBinding struct {
	bound atomic.Pointer[boundNodePool]
}

// boundNodePool is a bound pool and the status its running scaler publishes.
type boundNodePool struct {
	pool   *nodescale.OCIPool
	status func() *nodescale.Status
}

// Observe lists the pool once it is bound. Until then every pool node is refused.
func (binding *nodePoolBinding) Observe(ctx context.Context) (nodescale.PoolState, error) {
	bound := binding.bound.Load()
	if bound == nil {
		return nodescale.PoolState{}, errors.New("node pool is not bound yet")
	}
	return bound.pool.Observe(ctx)
}

// scaleStatus is the node status the region publishes, nil until the scaler runs.
func (binding *nodePoolBinding) scaleStatus() *nodescale.Status {
	bound := binding.bound.Load()
	if bound == nil {
		return nil
	}
	return bound.status()
}

// bindNodeScaler is one attempt to bind the cell's pool and start its scaler on it.
func bindNodeScaler(ctx context.Context, in nodeScaling) (boundNodePool, error) {
	attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
	pool, factory, err := newNodePool(attempt, in.cell, in.reservations)
	cancel()
	if err != nil {
		return boundNodePool{}, err
	}
	in.pool, in.factory = pool, factory
	status, err := startNodeScaler(ctx, in)
	if err != nil {
		return boundNodePool{}, fmt.Errorf("start node scaler: %w", err)
	}
	return boundNodePool{pool: pool, status: status}, nil
}

// bindNodePool binds the pool and starts its scaler, trying again every retry
// until ctx ends. A failure is logged when its text changes, so an outage logs
// once rather than every attempt.
func bindNodePool(ctx context.Context, binding *nodePoolBinding, retry time.Duration,
	bind func(context.Context) (boundNodePool, error),
) {
	var last string
	for wait := time.Duration(0); ; wait = retry {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		bound, err := bind(ctx)
		if err == nil {
			binding.bound.Store(&bound)
			return
		}
		if ctx.Err() != nil {
			return
		}
		if msg := err.Error(); msg != last {
			last = msg
			slog.Warn("node pool is unavailable; pool nodes will not enroll and no node scaler runs",
				"component", "nodescale", "error", err)
		}
	}
}

// newNodePool binds only the independently authorized worker compartment.
func newNodePool(ctx context.Context, cell string, reservations *capacityReservations) (*nodescale.OCIPool, *ociclient.Factory, error) {
	ociRegion, err := oci.Region(strings.ToUpper(cell)).OCIRegion()
	if err != nil {
		return nil, nil, err
	}
	factory, err := ociclient.InstancePrincipal(ociRegion)
	if err != nil {
		return nil, nil, err
	}
	base, compartment, err := reservations.workerBase(ctx, nodescale.RoleContainer, "")
	if err != nil {
		base, compartment, err = reservations.workerBase(ctx, nodescale.RoleWasm, "")
		if err != nil {
			return nil, nil, err
		}
	}
	pool, err := nodescale.NewOCIPool(factory, cell, compartment, base.Capacity)
	return pool, factory, err
}
