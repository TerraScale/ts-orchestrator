package app

import (
	"context"
	"log/slog"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlink"
)

// startGlobalView follows every region's rollup into the dashboard's global
// view and, while this controller leads the region, publishes the region's
// own rollup (TS-805, docs/dashboard/global-view.md).
func (runtime *runtimeObservability) startGlobalView(ctx context.Context, observed controllerObservation,
	links regionlink.Requester, cluster observability.ClusterSource, volumes insights.VolumeProvider,
) *globalview.View {
	view := globalview.NewView(runtime.cell, links.Regions, nil)
	sources := globalview.Sources{Cell: runtime.cell, Cluster: cluster, Grants: observed.nodes, Volumes: volumes,
		Links: observed.linkProbes}
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
	build := func(ctx context.Context) globalview.Rollup { return globalview.Build(sources.Collect(ctx)) }
	leading := func() bool { return observed.authority != nil && observed.authority.Current().CanMutate() }
	conn := observed.nats.Conn()
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
