package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nodescale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ocicost"
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

// nodeCost is the node scaler's Cost: this region's forecast with the pool's
// nodes pending at one node's price, the price the home allocator grants
// growth against. The same pending nodes feed the cost view, so /cost and the
// allocator show the same projection. The recipe is read once; a node's shape
// is the leader's own and never changes.
func (views *ociCostViews) nodeCost(recipe func(context.Context) (nodescale.Recipe, error), now func() time.Time,
) func(context.Context, nodescale.PoolState) (nodescale.Cost, error) {
	var shape *nodescale.Recipe
	return func(ctx context.Context, state nodescale.PoolState) (nodescale.Cost, error) {
		if shape == nil {
			read, err := recipe(ctx)
			if err != nil {
				return nodescale.Cost{}, err
			}
			shape = &read
		}
		report, err := views.store.Report(ctx)
		if err != nil {
			return nodescale.Cost{}, err
		}
		at := now()
		if at.Sub(report.ObservedAt) > ocicost.MaxReportAge {
			return nodescale.Cost{}, fmt.Errorf("OCI cost report is %s old", at.Sub(report.ObservedAt))
		}
		price, known := ocicost.NodeMonthlyCents(report.Prices, float64(shape.OCPUs), float64(shape.MemoryGB),
			nodescale.BootVolumeGB)
		if !known {
			return nodescale.Cost{}, errors.New("the cost report has no unit price yet for a node's SKUs")
		}
		hosts := make([]ocicost.Host, 0, len(state.Instances))
		for _, instance := range state.Instances {
			hosts = append(hosts, ocicost.Host{Created: instance.Created, MonthlyCents: price})
		}
		views.pool.Store(&hosts)
		forecast := ocicost.Project(report, at, hosts)
		return nodescale.Cost{NodeMonthlyCents: price, ProjectedCents: max(forecast.MonthEndCents, forecast.NextMonthCents),
			Currency: report.Currency, At: report.ObservedAt}, nil
	}
}

// view is the latest view; nil before the first refresh.
func (views *ociCostViews) view(context.Context) *ocicost.View {
	return views.current.Load()
}

// rollup is the view as the dashboard rollup's cost section: nil until the
// region has a report. Per hour is the daily rate with pending hosts.
func (views *ociCostViews) rollup() *globalview.Cost {
	v := views.current.Load()
	if v == nil || v.Missing != "" {
		return nil
	}
	f := v.Forecast
	return &globalview.Cost{Currency: f.Currency, PerHour: float64(f.RateCents+f.PendingDailyCents) / 2400,
		MonthToDate: float64(f.MonthToDateCents) / 100, MonthForecast: float64(f.MonthEndCents) / 100,
		ObservedAt: f.ObservedAt}
}

// newOCICostCollector keeps the region's OCI cost report fresh. It reads the
// cost on the regional authority leader through the instance principal
// (docs/oci-cost.md).
func newOCICostCollector(cell string, store *ocicost.Store, control *authority.Runtime) *ocicost.Collector {
	return &ocicost.Collector{Store: store, Leader: func() bool { return control.Current().CanMutate() },
		Connect: func(ctx context.Context) (ocicost.Reader, error) {
			region, err := oci.Region(strings.ToUpper(cell)).OCIRegion()
			if err != nil {
				return nil, err
			}
			factory, err := instancePrincipal(ctx, region)
			if err != nil {
				return nil, err
			}
			return ocicost.Connect(ctx, factory, cell, region)
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
