package globalview

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

const (
	// warnAt is the utilization at which a node needs attention.
	warnAt = 0.9
	// linkUnknown is a peer seen only in TerraBase WAN reports, not probed.
	linkUnknown = "unknown"
)

// Collect reads every source once.
func (s Sources) Collect(ctx context.Context) Inputs {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	in := Inputs{Cell: s.Cell, Now: now().UTC()}
	if s.Cluster != nil {
		snapshot, err := s.Cluster.Cluster(ctx, false)
		in.Cluster, in.ClusterOK = snapshot, err == nil
	}
	if s.Grants != nil {
		in.Grants = s.Grants(ctx)
	}
	if s.Reports != nil {
		in.Reports = s.Reports()
	}
	if s.Volumes != nil {
		if list, err := s.Volumes.Volumes(ctx); err == nil {
			in.Volumes = list
		}
	}
	if s.Links != nil {
		in.Links = s.Links()
	}
	if s.Autoscale != nil {
		in.Autoscale = s.Autoscale()
	}
	if s.Cost != nil {
		in.Cost = s.Cost()
	}
	if s.Databases != nil {
		in.Databases = s.Databases()
	}
	switch {
	case s.Errors != nil:
		in.Errors = s.Errors()
	case s.Events != nil:
		in.Events = s.Events(256)
	}
	return in
}

// Build turns one collection into a bounded rollup. It is pure.
func Build(in Inputs) Rollup {
	var truncated bool
	rollup := Rollup{Version: Version, Cell: strings.ToLower(in.Cell), ObservedAt: in.Now}
	var routes []Route
	if in.ClusterOK {
		rollup.Controllers = buildControllers(in.Cluster)
		rollup.Versions = buildVersions(in.Cluster.Members)
		routes = buildRoutes(in.Cluster.Members)
	}
	nodes := buildNodes(in, &truncated)
	rollup.Totals = buildTotals(nodes)
	wan := wanSources(in.Reports)
	rollup.Replication = buildReplication(wan)
	links := buildLinks(in.Links, wan)
	rollup.Health = buildHealth(in, rollup.Controllers, nodes, links, routes)

	rollup.Nodes = keep(nodes, maxNodes, &truncated)
	rollup.Volumes = buildVolumes(in.Volumes, &truncated)
	rollup.Links = keep(links, maxLinks, &truncated)
	rollup.Routes = keep(routes, maxRoutes, &truncated)
	rollup.Autoscale = Autoscale{Services: buildScaling(in.Autoscale)}
	rollup.Cost = in.Cost
	rollup.Databases = buildDatabases(in.Databases, &truncated)
	rollup.Errors = buildErrors(in, &truncated)
	rollup.Truncated = truncated
	return rollup
}

func buildControllers(snapshot observability.ClusterSnapshot) Controllers {
	controllers := Controllers{Expected: len(snapshot.Expected)}
	if controllers.Expected == 0 {
		controllers.Expected = len(snapshot.Members)
	}
	for _, member := range snapshot.Members {
		if member.Ready {
			controllers.Ready++
		}
		if controllers.Leader == "" && member.Authority != nil && member.Authority.Leader {
			controllers.Leader = member.Member
		}
		if controllers.MetaLeader == "" && member.NATS != nil {
			controllers.MetaLeader = member.NATS.MetaLeader
		}
	}
	return controllers
}

func buildVersions(members []observability.MemberSnapshot) []BuildCount {
	counts := map[string]int{}
	for _, member := range members {
		if member.BuildVersion != "" {
			counts[member.BuildVersion]++
		}
	}
	var out []BuildCount
	for _, version := range slices.Sorted(maps.Keys(counts)) {
		out = append(out, BuildCount{Version: version, Count: counts[version]})
	}
	return out
}

// buildNodes returns every node by name, untruncated for health and totals.
// Its services and filesystems are capped here, after their totals are read.
func buildNodes(in Inputs, truncated *bool) []Node {
	grants := make(map[string]regionview.Node, len(in.Grants))
	for _, grant := range in.Grants {
		grants[grant.Name] = grant
	}
	reports := make(map[string]hostload.NodeLoad, len(in.Reports))
	for _, report := range in.Reports {
		reports[report.Origin.Node] = report
	}
	names := map[string]bool{}
	for name := range grants {
		names[name] = true
	}
	for name := range reports {
		names[name] = true
	}
	out := make([]Node, 0, len(names))
	for _, name := range slices.Sorted(maps.Keys(names)) {
		node := Node{Name: name, Services: buildServices(grants[name].Services)}
		report, reported := reports[name]
		if reported {
			node.ReportedAt = report.At
			fillHost(&node, report.Report.Host)
		}
		node.Health = nodeHealth(node, reported && in.Now.Sub(report.At) <= NodeDownAfter)
		node.Services = keep(node.Services, maxServices, truncated)
		node.Filesystems = keep(node.Filesystems, maxFilesystems, truncated)
		out = append(out, node)
	}
	return out
}

func buildServices(services []regionview.Service) []Service {
	out := make([]Service, 0, len(services))
	for _, service := range services {
		out = append(out, Service{Role: service.Role, State: service.State, Digest: service.Digest})
	}
	return out
}

// fillHost copies a node's measured capacity, usage and distinct disks.
func fillHost(node *Node, host hostload.HostUsage) {
	node.CPU = host.CPU
	node.CPUCores = host.CPUCores
	node.MemoryBytes = host.MemoryBytes
	if host.Memory != nil {
		node.MemoryUsedBytes = uint64(*host.Memory * float64(host.MemoryBytes))
	}
	node.NetworkRxBps = host.NetworkRxBps
	node.NetworkTxBps = host.NetworkTxBps
	node.Load1 = host.Load1
	for _, filesystem := range observability.DistinctFilesystems(host.Filesystems) {
		disk := Filesystem{Role: filesystem.Role, SizeBytes: filesystem.SizeBytes}
		if filesystem.FreeBytes <= filesystem.SizeBytes {
			disk.UsedBytes = filesystem.SizeBytes - filesystem.FreeBytes
		}
		node.Filesystems = append(node.Filesystems, disk)
		node.DiskBytes += disk.SizeBytes
		node.DiskUsedBytes += disk.UsedBytes
	}
}

// nodeHealth is down without a fresh report; otherwise warn when a role is
// failed or stopped or a resource is near its limit.
func nodeHealth(node Node, fresh bool) string {
	switch {
	case !fresh:
		return NodeDown
	case slices.ContainsFunc(node.Services, func(service Service) bool {
		return service.State == "failed" || service.State == "stopped"
	}):
		return NodeWarn
	case node.CPU != nil && *node.CPU >= warnAt, nearFull(node.MemoryUsedBytes, node.MemoryBytes):
		return NodeWarn
	case slices.ContainsFunc(node.Filesystems, func(disk Filesystem) bool {
		return nearFull(disk.UsedBytes, disk.SizeBytes)
	}):
		return NodeWarn
	}
	return NodeOK
}

// nearFull reports whether used reaches warnAt of a nonzero total.
func nearFull(used, total uint64) bool {
	return total > 0 && float64(used) >= warnAt*float64(total)
}

// buildTotals sums the nodes that are not down. Nodes counts every node.
func buildTotals(nodes []Node) Totals {
	totals := Totals{Nodes: len(nodes)}
	for _, node := range nodes {
		if node.Health == NodeDown {
			continue
		}
		totals.Ready++
		totals.CPUCores += node.CPUCores
		if node.CPU != nil {
			totals.CPUUsedCores += *node.CPU * float64(node.CPUCores)
		}
		totals.MemoryBytes += node.MemoryBytes
		totals.MemoryUsedBytes += node.MemoryUsedBytes
		totals.DiskBytes += node.DiskBytes
		totals.DiskUsedBytes += node.DiskUsedBytes
		if node.NetworkRxBps != nil {
			totals.NetworkRxBps += *node.NetworkRxBps
		}
		if node.NetworkTxBps != nil {
			totals.NetworkTxBps += *node.NetworkTxBps
		}
		if node.Load1 != nil {
			totals.Load1 += *node.Load1
		}
	}
	return totals
}

// wanSources is every WAN source named by any report's role.
func wanSources(reports []hostload.NodeLoad) []terrabase.WANSource {
	var out []terrabase.WANSource
	for _, report := range reports {
		for _, role := range report.Report.Roles {
			if role.WAN != nil {
				out = append(out, role.WAN.Sources...)
			}
		}
	}
	return out
}

func buildReplication(wan []terrabase.WANSource) Replication {
	var out Replication
	for _, source := range wan {
		out.LagSeconds = peak(out.LagSeconds, source.StalenessSeconds)
		out.LagGroups = peak(out.LagGroups, source.LagGroups)
	}
	return out
}

// buildLinks returns one link per probe, plus one unknown link per WAN
// source region that no probe covers. It is untruncated.
func buildLinks(probes []regionview.LinkProbe, wan []terrabase.WANSource) []Link {
	lag := map[string]*float64{}
	for _, source := range wan {
		region := strings.ToLower(source.SourceRegion)
		lag[region] = peak(lag[region], source.StalenessSeconds)
	}
	var out []Link
	seen := map[string]bool{}
	for _, probe := range probes {
		region := strings.ToLower(probe.Region)
		seen[region] = true
		link := Link{Region: region, Reach: probe.Reach, LagSeconds: lag[region], ObservedAt: probe.ObservedAt}
		if probe.Reach == decisionlog.RegionOK {
			rtt := probe.RoundTripMS
			link.RTTMillis = &rtt
		} else {
			link.Error = probe.Detail
		}
		out = append(out, link)
	}
	for _, source := range wan {
		region := strings.ToLower(source.SourceRegion)
		if seen[region] {
			continue
		}
		seen[region] = true
		out = append(out, Link{Region: region, Reach: linkUnknown, LagSeconds: lag[region]})
	}
	slices.SortStableFunc(out, func(a, b Link) int { return cmp.Compare(a.Region, b.Region) })
	return out
}

// buildRoutes returns each controller's NATS routes and the meta peers it
// has no route to. It is untruncated.
func buildRoutes(members []observability.MemberSnapshot) []Route {
	var out []Route
	for _, member := range members {
		nats := member.NATS
		if nats == nil {
			continue
		}
		peers := make(map[string]observability.PeerView, len(nats.MetaPeers))
		for _, peer := range nats.MetaPeers {
			peers[peer.Name] = peer
		}
		routed := map[string]bool{}
		for _, rtt := range nats.RouteRTTs {
			routed[rtt.RemoteName] = true
			route := Route{From: nats.ServerName, To: rtt.RemoteName}
			if rtt.RTTSeconds != nil {
				ms := *rtt.RTTSeconds * 1000
				route.RTTMillis = &ms
			} else {
				route.Error = "no measurement"
			}
			if peer, ok := peers[rtt.RemoteName]; ok {
				route.Lag = peer.Lag
				if peer.Offline {
					route.Error = "offline"
				}
			}
			out = append(out, route)
		}
		for _, peer := range nats.MetaPeers {
			if routed[peer.Name] || peer.Name == nats.ServerName {
				continue
			}
			out = append(out, Route{From: nats.ServerName, To: peer.Name, Lag: peer.Lag, Error: "no route"})
		}
	}
	slices.SortStableFunc(out, func(a, b Route) int {
		return cmp.Or(cmp.Compare(a.From, b.From), cmp.Compare(a.To, b.To))
	})
	return out
}

func buildVolumes(list []insights.Volume, truncated *bool) []Volume {
	out := make([]Volume, 0, len(list))
	for _, volume := range list {
		out = append(out, Volume{ID: volume.ID, Node: volume.Host, State: volume.State, Detail: volume.Detail, Since: volume.StateSince})
	}
	slices.SortStableFunc(out, func(a, b Volume) int {
		return cmp.Or(cmp.Compare(a.Node, b.Node), cmp.Compare(a.ID, b.ID))
	})
	return keep(out, maxVolumes, truncated)
}

func buildScaling(results map[string]workload.Result) []Scaling {
	var out []Scaling
	for _, service := range slices.Sorted(maps.Keys(results)) {
		result := results[service]
		if result.Reason == "awaiting-release" {
			continue
		}
		out = append(out, Scaling{Service: service, Replicas: result.Replicas, Goal: result.Target, Reason: result.Reason})
	}
	return out
}

func buildDatabases(databases []Database, truncated *bool) []Database {
	out := slices.Clone(databases)
	slices.SortStableFunc(out, func(a, b Database) int {
		return cmp.Compare(b.ReplicationBytesPerSecond, a.ReplicationBytesPerSecond)
	})
	return keep(out, maxDatabases, truncated)
}

// buildErrors prefers the error source. Otherwise it takes ERROR events. It
// is newest first, and each message is clipped to maxMessage runes.
func buildErrors(in Inputs, truncated *bool) []Error {
	out := slices.Clone(in.Errors)
	if in.Errors == nil {
		for _, event := range in.Events {
			if event.Level == slog.LevelError.String() {
				out = append(out, Error{At: event.Time, Node: event.Attrs["node"], Component: event.Component, Message: event.Message})
			}
		}
	}
	slices.SortStableFunc(out, func(a, b Error) int { return b.At.Compare(a.At) })
	out = keep(out, maxErrors, truncated)
	for i := range out {
		out[i].Message = clip(out[i].Message, maxMessage)
	}
	return out
}

// buildHealth is critical when the controllers cannot be read, lost quorum or
// have no leader. Otherwise it is degraded for anything below full health.
// Reasons list critical causes first.
func buildHealth(in Inputs, controllers Controllers, nodes []Node, links []Link, routes []Route) Health {
	var critical, degraded []string
	quorumLost := controllers.Expected > 0 && controllers.Ready < controllers.Expected/2+1
	switch {
	case !in.ClusterOK:
		critical = append(critical, "controller snapshot unavailable")
	case quorumLost:
		critical = append(critical, fmt.Sprintf("controller quorum %d of %d", controllers.Ready, controllers.Expected))
	case controllers.Expected > 0 && controllers.Ready < controllers.Expected:
		degraded = append(degraded, fmt.Sprintf("controllers ready %d of %d", controllers.Ready, controllers.Expected))
	}
	if in.ClusterOK && controllers.Leader == "" {
		critical = append(critical, "no authority leader")
	}
	down, warn := 0, 0
	for _, node := range nodes {
		switch node.Health {
		case NodeDown:
			down++
		case NodeWarn:
			warn++
		}
	}
	if down > 0 {
		degraded = append(degraded, fmt.Sprintf("%d of %d nodes down", down, len(nodes)))
	}
	if warn > 0 {
		degraded = append(degraded, fmt.Sprintf("%d of %d nodes need attention", warn, len(nodes)))
	}
	for _, link := range links {
		// An unknown link is not a failure until TS-796's probe says so.
		if link.Reach != decisionlog.RegionOK && link.Reach != linkUnknown {
			degraded = append(degraded, fmt.Sprintf("link to %s: %s", link.Region, link.Reach))
		}
	}
	for _, route := range routes {
		if route.Error != "" {
			degraded = append(degraded, fmt.Sprintf("route %s → %s: %s", route.From, route.To, route.Error))
		}
	}
	status := Healthy
	switch {
	case len(critical) > 0:
		status = Critical
	case len(degraded) > 0:
		status = Degraded
	}
	reasons := append(critical, degraded...)
	return Health{Status: status, Reasons: reasons[:min(len(reasons), maxReasons)]}
}

// keep returns the first limit items and records in truncated when it drops any.
func keep[T any](items []T, limit int, truncated *bool) []T {
	if len(items) <= limit {
		return items
	}
	*truncated = true
	return items[:limit]
}

// peak returns the larger of two optional readings. nil is unmeasured.
func peak(a, b *float64) *float64 {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case *b > *a:
		return b
	}
	return a
}

// clip shortens s to at most limit runes without splitting one.
func clip(s string, limit int) string {
	n := 0
	for at := range s {
		if n == limit {
			return s[:at]
		}
		n++
	}
	return s
}
