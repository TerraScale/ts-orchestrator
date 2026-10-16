package natscell

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/nats-io/nats-server/v2/server"
)

func TestObserveRoutesGroupsPoolingAndPreservesCoverage(t *testing.T) {
	t.Parallel()
	routes := &server.Routez{ID: "local", Routes: []*server.RouteInfo{
		{RemoteID: "b", RemoteName: "peer-b", Rid: 1, RTT: "2ms"},
		{RemoteID: "b", RemoteName: "peer-b", Rid: 2, RTT: "0s"},
		{RemoteID: "b", RemoteName: "peer-b", Rid: 3, Account: "$SYS", RTT: "5ms"},
		{RemoteID: "a", RemoteName: "peer-a", RTT: ""},
		{RemoteID: "a", RemoteName: "peer-a", RTT: "broken"},
		{RemoteID: "a", RemoteName: "peer-a", RTT: "-3ms"},
		{RemoteID: "a", RemoteName: "peer-a", RTT: "999999999999999999999h"},
		{RemoteID: "unnamed-id", RTT: "1us"},
		{RemoteName: "name-only", RTT: "0s"},
		nil,
	}}
	var view observability.NATSView
	observeRoutes(&view, routes)
	want := []observability.RouteRTTView{
		{RemoteName: "name-only", Connections: 1},
		{RemoteName: "peer-a", Connections: 4},
		{RemoteName: "peer-b", Connections: 3, MeasuredConnections: 2, RTTSeconds: new(0.005)},
		{RemoteName: "unnamed-id", Connections: 1, MeasuredConnections: 1, RTTSeconds: new(0.000001)},
	}
	if !reflect.DeepEqual(view.RouteRTTs, want) || view.RouteRTTsTruncated || view.ClusterPeers != 4 {
		t.Fatalf("routes = %+v, peers = %d, truncated = %v; want %+v", view.RouteRTTs, view.ClusterPeers, view.RouteRTTsTruncated, want)
	}
	// A connection with no observed identity cannot be assigned a peer label.
	routes.Routes = append(routes.Routes, &server.RouteInfo{RTT: "1ms"})
	view = observability.NATSView{}
	observeRoutes(&view, routes)
	if !view.RouteRTTsTruncated || !reflect.DeepEqual(view.RouteRTTs, want) {
		t.Fatalf("unidentified route was not reported as incomplete: %+v", view)
	}
}

func TestObserveRoutesSortsBeforeBoundingPeers(t *testing.T) {
	t.Parallel()
	for _, count := range []int{0, maxObservedRoutePeers, maxObservedRoutePeers + 1} {
		routes := &server.Routez{ID: "local"}
		for index := count - 1; index >= 0; index-- {
			name := fmt.Sprintf("peer-%03d", index)
			routes.Routes = append(routes.Routes, &server.RouteInfo{RemoteID: name, RemoteName: name, RTT: "1ms"})
		}
		if count > 0 {
			// A late dedicated route must count even for a retained peer at the cap.
			routes.Routes = append(routes.Routes, &server.RouteInfo{RemoteID: "peer-000", RemoteName: "peer-000", Account: "$SYS", RTT: "9ms"})
		}
		var view observability.NATSView
		observeRoutes(&view, routes)
		if len(view.RouteRTTs) != min(count, maxObservedRoutePeers) || view.RouteRTTsTruncated != (count > maxObservedRoutePeers) || view.ClusterPeers != count+1 {
			t.Fatalf("%d peers: %+v", count, view)
		}
		for index, peer := range view.RouteRTTs {
			if peer.RemoteName != fmt.Sprintf("peer-%03d", index) {
				t.Fatalf("%d peers: row %d = %+v", count, index, peer)
			}
		}
		if count > 0 && (view.RouteRTTs[0].Connections != 2 || view.RouteRTTs[0].MeasuredConnections != 2 || *view.RouteRTTs[0].RTTSeconds != 0.009) {
			t.Fatalf("late dedicated route lost at cap: %+v", view.RouteRTTs[0])
		}
	}
}

func TestEmbeddedRouteRTTFlowsToMetricsAndHistory(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	cluster := newLabCluster(t, 3)
	local := cluster.start(t, ctx, 0)
	remote := cluster.start(t, ctx, 1)
	cluster.start(t, ctx, 2)
	var view observability.NATSView
	waitUntil(t, ctx, "measured embedded pooled routes", func() bool {
		var err error
		view, err = local.Observe(ctx)
		return err == nil && len(view.RouteRTTs) == 2 && view.RouteRTTs[0].Connections > 1 &&
			view.RouteRTTs[0].RTTSeconds != nil && view.RouteRTTs[0].MeasuredConnections == view.RouteRTTs[0].Connections
	})
	routes, err := local.server.Routez(nil)
	if err != nil {
		t.Fatal(err)
	}
	peer := view.RouteRTTs[0]
	if view.ClusterPeers != 3 || view.RouteRTTsTruncated || peer.RemoteName != remote.server.Name() {
		t.Fatalf("embedded routes = %+v, Routez = %+v", view, routes)
	}
	connections := 0
	for _, route := range routes.Routes {
		if route.RemoteID != remote.server.ID() {
			continue
		}
		connections++
		if route.RemoteName != peer.RemoteName {
			t.Fatalf("peer identity differs from Routez: %+v", route)
		}
	}
	if peer.Connections != connections {
		t.Fatalf("pooled connections = %d, Routez reports %d", peer.Connections, connections)
	}
	var output bytes.Buffer
	observability.WriteNATSMetrics(&output, view)
	series := observability.Series(observability.MetricPrefix+"nats_route_rtt_seconds", "server", view.ServerName, "peer", peer.RemoteName)
	if !strings.Contains(output.String(), fmt.Sprintf("%s %g\n", series, *peer.RTTSeconds)) {
		t.Fatalf("embedded RTT missing from metrics:\n%s", output.String())
	}
	sampler := new(observability.SnapshotSampler)
	snapshot := observability.ClusterSnapshot{Members: []observability.MemberSnapshot{{Member: "member-0", NATS: &view}}}
	history := observability.NewHistory(observability.HistoryConfig{})
	at := time.Now().UTC()
	history.Append(at, sampler.Samples(snapshot))
	query := observability.HistoryQuery{Metric: observability.HistNATSRouteRTT, Labels: map[string]string{"peer": peer.RemoteName}, Start: at.Add(-time.Minute), End: at.Add(time.Second)}
	result := history.Range(query)
	if len(result.Series) != 1 || len(result.Series[0].Points) != 1 || result.Series[0].Points[0].Value != *peer.RTTSeconds ||
		!reflect.DeepEqual(result.Series[0].Labels, map[string]string{"member": "member-0", "server": view.ServerName, "peer": peer.RemoteName}) {
		t.Fatalf("embedded RTT missing from history: %+v", result)
	}
	// Disconnect removes current RTT and coverage; retained history gets no new point.
	cluster.stop(1)
	waitUntil(t, ctx, "disconnected route removed", func() bool {
		var err error
		view, err = local.Observe(ctx)
		return err == nil && len(view.RouteRTTs) == 1 && view.ClusterPeers == 2 && view.RouteRTTs[0].RemoteName != peer.RemoteName
	})
	output.Reset()
	observability.WriteNATSMetrics(&output, view)
	if strings.Contains(output.String(), series) || strings.Contains(output.String(), observability.Series(observability.MetricPrefix+"nats_route_connections", "server", view.ServerName, "peer", peer.RemoteName)) {
		t.Fatalf("disconnected peer still has current metrics:\n%s", output.String())
	}
	samples := sampler.Samples(snapshot)
	for _, sample := range samples {
		if (sample.Metric == observability.HistNATSRouteRTT || sample.Metric == observability.HistNATSRouteConnections || sample.Metric == observability.HistNATSRouteMeasuredConnections) &&
			slices.Contains(sample.Labels, observability.Label{Name: "peer", Value: peer.RemoteName}) {
			t.Fatalf("disconnected peer still sampled: %+v", sample)
		}
	}
	history.Append(at.Add(10*time.Second), samples)
	query.End = at.Add(20 * time.Second)
	if got := history.Range(query); len(got.Series) != 1 || len(got.Series[0].Points) != 1 {
		t.Fatalf("disconnect added an RTT history point: %+v", got)
	}
	if err := local.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := local.Observe(ctx); err == nil || !reflect.DeepEqual(got, observability.NATSView{}) {
		t.Fatalf("stopped broker reported known health: %+v, %v", got, err)
	}
}
