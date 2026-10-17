package app

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// rootInventoryViews borrows the controller's typed client for one serial
// collector. Dashboard readers share these descriptive observations.
type rootInventoryViews struct {
	client  *rootoci.Client
	current atomic.Pointer[rootInventorySnapshot]
}

type rootInventorySnapshot struct {
	observed rootoci.InventoryObservation
	err      error
}

func (views *rootInventoryViews) run(ctx context.Context) {
	ticks := time.Tick(time.Minute)
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
		observed, err := views.client.Inventory(attempt)
		cancel()
		views.record(observed, err)
		select {
		case <-ctx.Done():
			return
		case <-ticks:
		}
	}
}

func (views *rootInventoryViews) record(observed rootoci.InventoryObservation, err error) {
	if err != nil {
		if retained := views.current.Load(); retained != nil {
			observed = retained.observed
		}
	}
	views.current.Store(&rootInventorySnapshot{observed: cloneRootInventory(observed), err: err})
}

// Inventory performs no I/O and never extends the original observation dates.
func (views *rootInventoryViews) Inventory(ctx context.Context) (rootoci.InventoryObservation, error) {
	current := views.current.Load()
	if current == nil {
		return rootoci.InventoryObservation{}, errors.Join(rootoci.ErrUnavailable, ctx.Err())
	}
	observed := cloneRootInventory(current.observed)
	err := errors.Join(current.err, ctx.Err())
	now := time.Now()
	if observed.ObservedAt.IsZero() || observed.ExpiresAt.IsZero() {
		err = errors.Join(err, rootoci.ErrUnavailable)
	} else if !now.Before(observed.ExpiresAt) {
		err = errors.Join(err, errors.New("root OCI inventory observation has expired"))
	}
	if expires := observed.KnownLiabilities.ExpiresAt; !expires.IsZero() && !now.Before(expires) {
		err = errors.Join(err, errors.New("root OCI liability observation has expired"))
	}
	return observed, err
}

func cloneRootInventory(observed rootoci.InventoryObservation) rootoci.InventoryObservation {
	observed.Resources = slices.Clone(observed.Resources)
	observed.CoveredCompartments = slices.Clone(observed.CoveredCompartments)
	observed.Pending = slices.Clone(observed.Pending)
	known := &observed.KnownLiabilities
	known.Resources = slices.Clone(known.Resources)
	known.Commitments = slices.Clone(known.Commitments)
	for i := range known.Commitments {
		known.Commitments[i].Quote = known.Commitments[i].Quote.Clone()
	}
	known.UnknownOperations = slices.Clone(known.UnknownOperations)
	known.UnboundResources = slices.Clone(known.UnboundResources)
	known.UnboundedCompartments = slices.Clone(known.UnboundedCompartments)
	known.Pending = slices.Clone(known.Pending)
	return observed
}
