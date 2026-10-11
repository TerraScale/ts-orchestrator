package app

import (
	"context"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/logs"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlink"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabasestats"
)

// startGlobalView follows every region's rollup into the dashboard's global
// view and, while this controller leads the region, publishes the region's
// own rollup (TS-805, docs/dashboard/global-view.md).
func (runtime *runtimeObservability) startGlobalView(ctx context.Context, observed controllerObservation,
	links regionlink.Requester, cluster observability.ClusterSource, volumes insights.VolumeProvider,
) *globalview.View {
	view := globalview.NewView(runtime.cell, links.Regions, nil)
	conn := observed.nats.Conn()
	sources := globalview.Sources{Cell: runtime.cell, Cluster: cluster, Grants: observed.nodes, Volumes: volumes,
		Links: observed.linkProbes, Databases: terrabasestats.Follow(ctx, conn, runtime.cell).Databases}
	if observed.hostLoad != nil {
		sources.Reports = observed.hostLoad.nodes
	}
	if observed.autoscalers != nil {
		sources.Autoscale = observed.autoscalers.Last
	}
	if runtime.events != nil {
		sources.Events = runtime.events.Recent
	}
	sources.Scale = observed.scale
	if observed.costRollup != nil {
		sources.Cost = observed.costRollup
	}
	if logView := runtime.logView; logView != nil {
		// Ten is the rollup's error cap, so the log view never returns more than it keeps.
		sources.Errors = func() []globalview.Error { return logErrors(logView.Errors(10, time.Now())) }
	}
	build := func(ctx context.Context) globalview.Rollup { return globalview.Build(sources.Collect(ctx)) }
	leading := func() bool { return observed.authority != nil && observed.authority.Current().CanMutate() }
	go globalview.Publish(ctx, conn, runtime.cell, leading, build, view)
	go func() {
		if err := view.Follow(ctx, conn); err != nil {
			slog.Warn("dashboard rollups not followed", observability.ComponentKey, "globalview", "error", err)
		}
	}()
	// Live rollups flow without the bucket; it only adds last-known values.
	go func() {
		var kv jetstream.KeyValue
		retryAttachment(ctx, "globalview", "dashboard rollup bucket", func(attempt context.Context) (err error) {
			kv, err = globalview.OpenBucket(attempt, observed.nats.JetStream(), observed.replicas)
			return err
		})
		if ctx.Err() == nil {
			view.KeepLastKnown(ctx, kv, leading)
		}
	}()
	return view
}

// logErrors maps the log view's error classes to the rollup's errors (TS-808).
func logErrors(classes []logs.ReplyClass) []globalview.Error {
	var out []globalview.Error
	for _, class := range classes {
		out = append(out, globalview.Error{At: class.Last, Level: class.Level, Service: class.Service,
			Component: class.Component, Message: class.Message, Count: class.Count, Nodes: class.Nodes})
	}
	return out
}
