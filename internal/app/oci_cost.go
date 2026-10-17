package app

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// ociCostView is the region's cost for its summary: the stored report's
// forecast with the region's autoscaled nodes, hosts being nil until TS-804's
// node scaler supplies them.
func ociCostView(ctx context.Context, cell string, store *ocicost.Store, hosts []ocicost.Host, now time.Time,
) *ocicost.View {
	region, _ := oci.Region(strings.ToUpper(cell)).OCIRegion()
	report, err := store.Report(ctx)
	if err != nil {
		return &ocicost.View{Cell: cell, OCIRegion: region, Missing: err.Error()}
	}
	view := ocicost.Summarize(report, now, hosts)
	return &view
}

// ociCostViews keeps this region's cost view in memory, refreshed every
// minute, so the region summary and the dashboard rollup read it without I/O.
type ociCostViews struct {
	cell    string
	store   *ocicost.Store
	pool    atomic.Pointer[[]ocicost.Host]
	pricing atomic.Pointer[string]
	current atomic.Pointer[ocicost.View]
}

// run refreshes the view at once and then every minute until ctx ends.
func (views *ociCostViews) run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		views.current.Store(ociCostView(ctx, views.cell, views.store, views.nodes(), time.Now()))
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// nodes are the pool nodes nodeCost last priced for the forecast; none before that.
func (views *ociCostViews) nodes() []ocicost.Host {
	if hosts := views.pool.Load(); hosts != nil {
		return *hosts
	}
	return nil
}

// nodeCost prices the exact candidate and this region's observed resources.
// Usage forecasts remain display data; only the home ledger admits spending.
func (views *ociCostViews) nodeCost(reservations *capacityReservations, compartment string,
	recipe func(context.Context) (nodescale.Recipe, error), now func() time.Time,
) func(context.Context, nodescale.PoolState) (nodescale.Cost, error) {
	return func(ctx context.Context, state nodescale.PoolState) (cost nodescale.Cost, err error) {
		defer func() {
			if err != nil {
				reason := err.Error()
				views.pricing.Store(&reason)
				views.pool.Store(nil)
			} else {
				views.pricing.Store(nil)
			}
		}()
		if state.Pending != "" {
			return nodescale.Cost{}, fmt.Errorf("node capacity price is pending: %s", state.Pending)
		}
		shape, err := recipe(ctx)
		if err != nil {
			return nodescale.Cost{}, err
		}
		reader, proof, inventory, err := reservations.facts(ctx)
		if err != nil {
			return nodescale.Cost{}, err
		}
		cell := ""
		for _, scope := range proof.Footprint().Regions {
			if strings.EqualFold(scope.Cell, shape.Cell) {
				cell = scope.Cell
			}
		}
		quote, err := reader.Quote(ctx, proof.Footprint(), cell, compartment, shape.Capacity.Shape, float64(shape.OCPUs), float64(shape.MemoryGB),
			nodescale.BootVolumeGB)
		if err != nil {
			return nodescale.Cost{}, err
		}
		if err := quote.Validate(proof.Footprint(), cell, compartment, shape.Capacity.Shape, float64(shape.OCPUs), float64(shape.MemoryGB), nodescale.BootVolumeGB, now()); err != nil {
			return nodescale.Cost{}, err
		}
		price := quote.MonthlyCents()
		hosts := make([]ocicost.Host, 0, len(state.Instances))
		for _, instance := range state.Instances {
			hosts = append(hosts, ocicost.Host{Created: instance.Created, MonthlyCents: price})
		}
		views.pool.Store(&hosts)
		var projected uint64
		for _, resource := range inventory.Resources {
			if strings.EqualFold(resource.Cell, shape.Cell) {
				if resource.MonthlyCents > math.MaxUint64-projected {
					return nodescale.Cost{}, fmt.Errorf("regional resource cost overflows the accounting range")
				}
				projected += resource.MonthlyCents
			}
		}
		return nodescale.Cost{NodeMonthlyCents: price, ProjectedCents: projected,
			Currency: quote.Currency(), At: inventory.ObservedAt}, nil
	}
}

// view is the latest view; nil before the first refresh.
func (views *ociCostViews) view(context.Context) *ocicost.View {
	current := views.current.Load()
	if issue := views.pricing.Load(); issue != nil {
		view := ocicost.View{Cell: views.cell}
		if current != nil {
			view = *current
		}
		view.Missing = *issue
		return &view
	}
	return current
}

// rollup is the view as the dashboard rollup's cost section: nil until the
// region has a report. Per hour is the daily rate with pending hosts.
func (views *ociCostViews) rollup() *globalview.Cost {
	v := views.view(context.Background())
	if v == nil || v.Missing != "" {
		return nil
	}
	f := v.Forecast
	return &globalview.Cost{Currency: f.Currency, PerHour: float64(f.RateCents+f.PendingDailyCents) / 2400,
		MonthToDate: float64(f.MonthToDateCents) / 100, MonthForecast: float64(f.MonthEndCents) / 100,
		ObservedAt: f.ObservedAt}
}

// newOCICostCollector keeps the region's OCI cost report fresh. It reads the
// cost on the regional authority leader through the admitted root client.
func newOCICostCollector(client *rootoci.Client, store *ocicost.Store, control *authority.Runtime) *ocicost.Collector {
	return &ocicost.Collector{Store: store, Leader: func() bool { return control.Current().CanMutate() },
		Connect: func(context.Context) (ocicost.Reader, error) {
			return rootoci.CostReader{Client: client}, nil
		}}
}

// newOCICostTagger keeps the region's billable resources tagged with their
// region and component, so the cost report can split by component. Its IAM
// limits the search to the region's own compartments (docs/oci-cost.md).
func newOCICostTagger(cell string, control *authority.Runtime) *ocicost.Tagger {
	return &ocicost.Tagger{Cell: cell, Leader: func() bool { return control.Current().CanMutate() },
		Connect: func(ctx context.Context) (ocicost.TagAPI, error) {
			region, err := oci.Region(strings.ToUpper(cell)).OCIRegion()
			if err != nil {
				return nil, err
			}
			factory, err := instancePrincipal(ctx, region)
			if err != nil {
				return nil, err
			}
			return ocicost.ConnectTags(factory, nil)
		}}
}

// instancePrincipal is ociclient.InstancePrincipal bounded by ctx, so a
// stopping controller is not held by the metadata fetch. shortcut: the
// fetch ignores ctx and finishes unobserved, upgrade when ociclient takes one.
func instancePrincipal(ctx context.Context, region string) (*ociclient.Factory, error) {
	type answer struct {
		factory *ociclient.Factory
		err     error
	}
	done := make(chan answer, 1)
	go func() {
		factory, err := ociclient.InstancePrincipal(region)
		done <- answer{factory, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-done:
		return result.factory, result.err
	}
}
