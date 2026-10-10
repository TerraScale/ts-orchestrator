package globalview

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

var rollupNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func ptrTo[T any](v T) *T { return &v }

// healthyRegion is three ready controllers with ctl-1 leading and four nodes
// that reported 15 seconds ago.
func healthyRegion() Inputs {
	in := Inputs{Cell: "GRU", Now: rollupNow, ClusterOK: true}
	in.Cluster.Expected = []string{"ctl-1", "ctl-2", "ctl-3"}
	for i, name := range in.Cluster.Expected {
		in.Cluster.Members = append(in.Cluster.Members, observability.MemberSnapshot{
			Member:       name,
			Ready:        true,
			BuildVersion: "2026.10.1",
			Authority:    &observability.AuthorityView{Leader: i == 0},
			NATS:         &observability.NATSView{ServerName: "nats-" + name, MetaLeader: "nats-ctl-1"},
		})
	}
	for i := range 4 {
		name := fmt.Sprintf("ts-gru-%d", i)
		in.Grants = append(in.Grants, regionview.Node{Name: name, Services: []regionview.Service{{Role: "terrabase", State: "running"}}})
		in.Reports = append(in.Reports, reportOf(name, rollupNow.Add(-15*time.Second), 8, 0.4, 0.5, []observability.FilesystemView{
			{Role: "state", SizeBytes: 100, FreeBytes: 60, Device: 1},
		}))
	}
	return in
}

func reportOf(name string, at time.Time, cores int, cpu, memory float64, filesystems []observability.FilesystemView) hostload.NodeLoad {
	return hostload.NodeLoad{
		Origin: hostload.Origin{Node: name},
		At:     at,
		Report: hostload.Report{Host: hostload.HostUsage{
			CPUCores:     cores,
			MemoryBytes:  32 << 30,
			CPU:          ptrTo(cpu),
			Memory:       ptrTo(memory),
			Filesystems:  filesystems,
			NetworkRxBps: ptrTo(1000.0),
			NetworkTxBps: ptrTo(500.0),
			Load1:        ptrTo(1.5),
		}},
	}
}

func TestBuildHealth(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Inputs)
		status string
		reason string
	}{
		{name: "healthy", mutate: func(*Inputs) {}, status: Healthy},
		{name: "quorum lost", mutate: func(in *Inputs) {
			in.Cluster.Members[1].Ready = false
			in.Cluster.Members[2].Ready = false
		}, status: Critical, reason: "controller quorum 1 of 3"},
		{name: "no leader", mutate: func(in *Inputs) {
			in.Cluster.Members[0].Authority.Leader = false
		}, status: Critical, reason: "no authority leader"},
		{name: "snapshot unavailable", mutate: func(in *Inputs) {
			in.ClusterOK = false
		}, status: Critical, reason: "controller snapshot unavailable"},
		{name: "controller not ready", mutate: func(in *Inputs) {
			in.Cluster.Members[2].Ready = false
		}, status: Degraded, reason: "controllers ready 2 of 3"},
		{name: "node with old report", mutate: func(in *Inputs) {
			in.Reports[0].At = rollupNow.Add(-2 * time.Minute)
		}, status: Degraded, reason: "1 of 4 nodes down"},
		{name: "node without report", mutate: func(in *Inputs) {
			in.Reports = in.Reports[1:]
		}, status: Degraded, reason: "1 of 4 nodes down"},
		{name: "failed service", mutate: func(in *Inputs) {
			in.Grants[0].Services[0].State = "failed"
		}, status: Degraded, reason: "1 of 4 nodes need attention"},
		{name: "cpu near limit", mutate: func(in *Inputs) {
			in.Reports[0].Report.Host.CPU = ptrTo(0.95)
		}, status: Degraded, reason: "1 of 4 nodes need attention"},
		{name: "disk near full", mutate: func(in *Inputs) {
			in.Reports[0].Report.Host.Filesystems = []observability.FilesystemView{{Role: "state", SizeBytes: 100, FreeBytes: 5, Device: 1}}
		}, status: Degraded, reason: "1 of 4 nodes need attention"},
		{name: "link unreachable", mutate: func(in *Inputs) {
			in.Links = []regionview.LinkProbe{{Region: "SFO", Reach: "unreachable", Detail: "timeout"}}
		}, status: Degraded, reason: "link to sfo: unreachable"},
		{name: "unprobed WAN peer stays healthy", mutate: func(in *Inputs) {
			in.Reports[0].Report.Roles = []hostload.RoleUsage{{Role: "terrabase", WAN: &terrabase.WANObservation{
				ReceiverRegion: "gru", Sources: []terrabase.WANSource{{SourceRegion: "nrt"}}}}}
		}, status: Healthy},
		{name: "route without route", mutate: func(in *Inputs) {
			in.Cluster.Members[0].NATS.MetaPeers = []observability.PeerView{{Name: "nats-ctl-9"}}
		}, status: Degraded, reason: "route nats-ctl-1 → nats-ctl-9: no route"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			in := healthyRegion()
			test.mutate(&in)
			got := Build(in).Health
			if got.Status != test.status {
				t.Fatalf("status = %q, want %q (reasons %v)", got.Status, test.status, got.Reasons)
			}
			if test.reason != "" && !slices.Contains(got.Reasons, test.reason) {
				t.Fatalf("reasons = %v, want %q", got.Reasons, test.reason)
			}
		})
	}
}

func TestBuildNodeHealthPerNode(t *testing.T) {
	rollup := Build(healthyRegion())
	if got := len(rollup.Nodes); got != 4 {
		t.Fatalf("nodes = %d, want 4", got)
	}
	for _, node := range rollup.Nodes {
		if node.Health != NodeOK {
			t.Fatalf("%s health = %q, want %q", node.Name, node.Health, NodeOK)
		}
	}
	if got := rollup.Nodes[0].MemoryUsedBytes; got != 16<<30 {
		t.Fatalf("memory used = %d, want %d", got, 16<<30)
	}
}

func TestBuildNodeMissingReportIsDown(t *testing.T) {
	in := healthyRegion()
	in.Reports = in.Reports[1:]
	rollup := Build(in)
	if got := rollup.Nodes[0]; got.Name != "ts-gru-0" || got.Health != NodeDown || got.Services == nil {
		t.Fatalf("node 0 = %+v, want down with its grant services", got)
	}
}

func TestBuildTotalsExcludeDownNodesAndCountBeyondCap(t *testing.T) {
	in := Inputs{Cell: "GRU", Now: rollupNow, ClusterOK: true}
	for i := range 70 {
		name := fmt.Sprintf("ts-gru-%02d", i)
		at := rollupNow.Add(-15 * time.Second)
		if i == 0 || i == 69 {
			at = rollupNow.Add(-time.Hour)
		}
		in.Grants = append(in.Grants, regionview.Node{Name: name})
		in.Reports = append(in.Reports, reportOf(name, at, 8, 0.5, 0.5, nil))
	}
	rollup := Build(in)
	if rollup.Totals.Nodes != 70 || rollup.Totals.Ready != 68 {
		t.Fatalf("totals nodes/ready = %d/%d, want 70/68", rollup.Totals.Nodes, rollup.Totals.Ready)
	}
	if rollup.Totals.CPUCores != 68*8 || rollup.Totals.CPUUsedCores != 68*4 {
		t.Fatalf("cpu = %d cores %v used, want %d and %d", rollup.Totals.CPUCores, rollup.Totals.CPUUsedCores, 68*8, 68*4)
	}
	if rollup.Totals.MemoryBytes != 68*(32<<30) {
		t.Fatalf("memory = %d, want %d", rollup.Totals.MemoryBytes, 68*(32<<30))
	}
	if !rollup.Truncated || len(rollup.Nodes) != 64 {
		t.Fatalf("truncated = %v with %d nodes, want true with 64", rollup.Truncated, len(rollup.Nodes))
	}
	if rollup.Nodes[0].Name != "ts-gru-00" || rollup.Nodes[0].Health != NodeDown {
		t.Fatalf("first node = %s %s, want ts-gru-00 down", rollup.Nodes[0].Name, rollup.Nodes[0].Health)
	}
}

func TestBuildFilesystemsDedupeByDevice(t *testing.T) {
	in := healthyRegion()
	in.Reports[0].Report.Host.Filesystems = []observability.FilesystemView{
		{Role: "state", SizeBytes: 100, FreeBytes: 60, Device: 7},
		{Role: "install", SizeBytes: 100, FreeBytes: 60, Device: 7},
		{Role: "scratch", SizeBytes: 50, FreeBytes: 60, Device: 9},
	}
	node := Build(in).Nodes[0]
	if len(node.Filesystems) != 2 || node.Filesystems[0].Role != "state, install" {
		t.Fatalf("filesystems = %+v, want state, install and scratch", node.Filesystems)
	}
	if node.Filesystems[1].UsedBytes != 0 {
		t.Fatalf("scratch used = %d, want 0 when free exceeds size", node.Filesystems[1].UsedBytes)
	}
	if node.DiskBytes != 150 || node.DiskUsedBytes != 40 {
		t.Fatalf("disk = %d/%d, want 150/40", node.DiskBytes, node.DiskUsedBytes)
	}
}

func TestBuildLinksCarryWANLag(t *testing.T) {
	in := healthyRegion()
	in.Links = []regionview.LinkProbe{
		{Region: "GRU", Reach: "ok", RoundTripMS: 12.5},
		{Region: "SFO", Reach: "unreachable", Detail: "timeout"},
	}
	in.Reports[0].Report.Roles = []hostload.RoleUsage{{Role: "terrabase", WAN: &terrabase.WANObservation{
		ReceiverRegion: "gru",
		Sources: []terrabase.WANSource{
			{SourceRegion: "sfo", StalenessSeconds: ptrTo(4.0)},
			{SourceRegion: "NRT", StalenessSeconds: ptrTo(9.0)},
		},
	}}}
	in.Reports[1].Report.Roles = []hostload.RoleUsage{{Role: "terrabase", WAN: &terrabase.WANObservation{
		ReceiverRegion: "gru",
		Sources:        []terrabase.WANSource{{SourceRegion: "SFO", StalenessSeconds: ptrTo(7.0)}},
	}}}
	rollup := Build(in)
	want := []Link{
		{Region: "gru", Reach: "ok", RTTMillis: ptrTo(12.5)},
		{Region: "nrt", Reach: "unknown", LagSeconds: ptrTo(9.0)},
		{Region: "sfo", Reach: "unreachable", Error: "timeout", LagSeconds: ptrTo(7.0)},
	}
	if len(rollup.Links) != len(want) {
		t.Fatalf("links = %+v, want %d", rollup.Links, len(want))
	}
	for i, link := range rollup.Links {
		if link.Region != want[i].Region || link.Reach != want[i].Reach || link.Error != want[i].Error {
			t.Fatalf("link %d = %+v, want %+v", i, link, want[i])
		}
		if !samePtr(link.RTTMillis, want[i].RTTMillis) || !samePtr(link.LagSeconds, want[i].LagSeconds) {
			t.Fatalf("link %d rtt/lag = %v/%v, want %v/%v", i, link.RTTMillis, link.LagSeconds, want[i].RTTMillis, want[i].LagSeconds)
		}
	}
	if rollup.Replication.LagSeconds == nil || *rollup.Replication.LagSeconds != 9 {
		t.Fatalf("replication lag = %v, want 9", rollup.Replication.LagSeconds)
	}
}

func TestBuildRoutes(t *testing.T) {
	in := healthyRegion()
	in.Cluster.Members[0].NATS.RouteRTTs = []observability.RouteRTTView{
		{RemoteName: "nats-ctl-2"},
		{RemoteName: "nats-ctl-3", RTTSeconds: ptrTo(0.02)},
	}
	in.Cluster.Members[0].NATS.MetaPeers = []observability.PeerView{
		{Name: "nats-ctl-1"},
		{Name: "nats-ctl-2", Lag: 3},
		{Name: "nats-ctl-3", Offline: true},
		{Name: "nats-ctl-4", Lag: 5},
	}
	routes := Build(in).Routes
	want := []Route{
		{From: "nats-ctl-1", To: "nats-ctl-2", Lag: 3, Error: "no measurement"},
		{From: "nats-ctl-1", To: "nats-ctl-3", RTTMillis: ptrTo(20.0), Error: "offline"},
		{From: "nats-ctl-1", To: "nats-ctl-4", Lag: 5, Error: "no route"},
	}
	if len(routes) != len(want) {
		t.Fatalf("routes = %+v, want %d", routes, len(want))
	}
	for i, route := range routes {
		if route.From != want[i].From || route.To != want[i].To || route.Lag != want[i].Lag || route.Error != want[i].Error || !samePtr(route.RTTMillis, want[i].RTTMillis) {
			t.Fatalf("route %d = %+v, want %+v", i, route, want[i])
		}
	}
}

func TestBuildErrorsFromEvents(t *testing.T) {
	t0 := rollupNow.Add(-time.Hour)
	in := healthyRegion()
	in.Events = []observability.Event{
		{Time: t0, Level: "INFO", Message: "ignored"},
		{Time: t0.Add(time.Minute), Level: slog.LevelError.String(), Component: "host", Message: "old", Attrs: map[string]string{"node": "ts-gru-1"}},
		{Time: t0.Add(3 * time.Minute), Level: slog.LevelError.String(), Message: strings.Repeat("é", 300)},
	}
	errs := Build(in).Errors
	if len(errs) != 2 {
		t.Fatalf("errors = %+v, want 2 ERROR events", errs)
	}
	if got := utf8.RuneCountInString(errs[0].Message); got != maxMessage {
		t.Fatalf("message runes = %d, want %d", got, maxMessage)
	}
	if errs[1].Level != "ERROR" || errs[1].Count != 1 || !slices.Equal(errs[1].Nodes, []string{"ts-gru-1"}) ||
		errs[1].Component != "host" || errs[1].Message != "old" {
		t.Fatalf("second error = %+v", errs[1])
	}
	if errs[0].Nodes != nil {
		t.Fatalf("event without node has nodes %v, want nil", errs[0].Nodes)
	}
}

func TestBuildErrorsClipsNodes(t *testing.T) {
	in := healthyRegion()
	var nodes []string
	for i := range 10 {
		nodes = append(nodes, fmt.Sprintf("ts-gru-%02d", i))
	}
	in.Errors = []Error{{At: rollupNow, Level: "WARN", Count: 40, Nodes: nodes}}
	rollup := Build(in)
	if len(rollup.Errors) != 1 || len(rollup.Errors[0].Nodes) != maxErrorNodes || rollup.Errors[0].Count != 40 {
		t.Fatalf("errors = %+v, want one with %d nodes and count 40", rollup.Errors, maxErrorNodes)
	}
	if !rollup.Truncated {
		t.Fatal("truncated = false, want true")
	}
	if len(nodes) != 10 {
		t.Fatal("Build changed the input nodes")
	}
}

func TestBuildErrorsSourceOverridesEvents(t *testing.T) {
	in := healthyRegion()
	in.Errors = []Error{{At: rollupNow, Message: "from source"}}
	in.Events = []observability.Event{{Time: rollupNow, Level: slog.LevelError.String(), Message: "from events"}}
	errs := Build(in).Errors
	if len(errs) != 1 || errs[0].Message != "from source" {
		t.Fatalf("errors = %+v, want only the source error", errs)
	}
}

func TestBuildDatabasesSortedAndCapped(t *testing.T) {
	in := healthyRegion()
	for i := range 12 {
		in.Databases = append(in.Databases, Database{ID: fmt.Sprintf("db-%02d", i), ReplicationBytesPerSecond: float64(i * 10)})
	}
	rollup := Build(in)
	if len(rollup.Databases) != maxDatabases || rollup.Databases[0].ID != "db-11" || rollup.Databases[9].ID != "db-02" {
		t.Fatalf("databases = %+v, want db-11 down to db-02", rollup.Databases)
	}
	if !rollup.Truncated {
		t.Fatal("truncated = false, want true")
	}
	if in.Databases[0].ID != "db-00" {
		t.Fatal("Build reordered the input databases")
	}
}

func TestBuildAutoscaleSkipsAwaitingRelease(t *testing.T) {
	in := healthyRegion()
	in.Autoscale = map[string]workload.Result{
		"web":    {Replicas: 2, Target: 4, Reason: "scale-up"},
		"worker": {Replicas: 1, Target: 1, Reason: "awaiting-release"},
	}
	services := Build(in).Autoscale.Services
	if len(services) != 1 || services[0] != (Scaling{Service: "web", Replicas: 2, Goal: 4, Reason: "scale-up"}) {
		t.Fatalf("scaling = %+v, want only web", services)
	}
}

func TestBuildVolumesSortedAndCapped(t *testing.T) {
	in := healthyRegion()
	for i := range maxVolumes + 1 {
		in.Volumes = append(in.Volumes, insights.Volume{ID: fmt.Sprintf("vol-%03d", i), Host: fmt.Sprintf("ts-gru-%d", i%4), State: "attached"})
	}
	rollup := Build(in)
	if len(rollup.Volumes) != maxVolumes || !rollup.Truncated {
		t.Fatalf("volumes = %d truncated = %v, want %d and true", len(rollup.Volumes), rollup.Truncated, maxVolumes)
	}
	if rollup.Volumes[0].Node != "ts-gru-0" || rollup.Volumes[0].ID != "vol-000" {
		t.Fatalf("first volume = %+v", rollup.Volumes[0])
	}
}

func TestBuildVersionsAndControllers(t *testing.T) {
	in := healthyRegion()
	in.Cluster.Members[1].BuildVersion = "2026.09.4"
	in.Cluster.Members[2].BuildVersion = ""
	rollup := Build(in)
	if rollup.Controllers != (Controllers{Expected: 3, Ready: 3, Leader: "ctl-1", MetaLeader: "nats-ctl-1"}) {
		t.Fatalf("controllers = %+v", rollup.Controllers)
	}
	want := []BuildCount{{Version: "2026.09.4", Count: 1, Members: []string{"ctl-2"}},
		{Version: "2026.10.1", Count: 1, Members: []string{"ctl-1"}}}
	if !slices.EqualFunc(rollup.Versions, want, func(a, b BuildCount) bool {
		return a.Version == b.Version && a.Count == b.Count && slices.Equal(a.Members, b.Members)
	}) {
		t.Fatalf("versions = %+v, want %+v", rollup.Versions, want)
	}
}

func TestBuildRollupJSONStaysUnder16KB(t *testing.T) {
	in := healthyRegion()
	in.Grants, in.Reports = nil, nil
	for i := range 12 {
		name := fmt.Sprintf("ts-gru-%02d", i)
		in.Grants = append(in.Grants, regionview.Node{Name: name, Services: []regionview.Service{
			{Role: "terrabase", State: "running", Digest: "sha256:0123456789abcdef"},
			{Role: "orchestrator", State: "running", Digest: "sha256:0123456789abcdef"},
			{Role: "nats", State: "running", Digest: "sha256:0123456789abcdef"},
			{Role: "proxy", State: "running", Digest: "sha256:0123456789abcdef"},
		}})
		in.Reports = append(in.Reports, reportOf(name, rollupNow.Add(-15*time.Second), 16, 0.6, 0.7, []observability.FilesystemView{
			{Role: "state", SizeBytes: 500 << 30, FreeBytes: 200 << 30, Device: 1},
			{Role: "artifacts", SizeBytes: 900 << 30, FreeBytes: 300 << 30, Device: 2},
		}))
	}
	for i := range 20 {
		in.Links = append(in.Links, regionview.LinkProbe{Region: fmt.Sprintf("r%02d", i), Reach: "ok", RoundTripMS: 80.5})
		in.Reports[i%12].Report.Roles = append(in.Reports[i%12].Report.Roles, hostload.RoleUsage{Role: "terrabase", WAN: &terrabase.WANObservation{
			Sources: []terrabase.WANSource{{SourceRegion: fmt.Sprintf("r%02d", i), StalenessSeconds: ptrTo(2.0)}},
		}})
	}
	for i := range 10 {
		in.Errors = append(in.Errors, Error{At: rollupNow, Level: "ERROR", Count: i + 1, Nodes: []string{"ts-gru-01"}, Component: "terrabase", Message: strings.Repeat("x", 300) + fmt.Sprint(i)})
		in.Databases = append(in.Databases, Database{ID: fmt.Sprintf("db-%d", i), ReplicationBytesPerSecond: float64(i)})
	}
	raw, err := json.Marshal(Build(in))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("12-node region with 20 links: %d bytes", len(raw))
	if len(raw) >= 16<<10 {
		t.Fatalf("rollup is %d bytes, want under 16 KB", len(raw))
	}
}

func TestCollectReadsSourcesOnce(t *testing.T) {
	cluster := &fakeClusterSource{err: errors.New("unreachable")}
	sources := Sources{
		Cell:    "GRU",
		Cluster: cluster,
		Now:     func() time.Time { return rollupNow.In(time.FixedZone("UTC+2", 2*3600)) },
		Errors:  func() []Error { return []Error{{At: rollupNow, Message: "boom"}} },
		Events: func(int) []observability.Event {
			t.Fatal("Events called although Errors is set")
			return nil
		},
	}
	in := sources.Collect(context.Background())
	if in.ClusterOK || cluster.calls != 1 {
		t.Fatalf("ClusterOK = %v after %d calls, want false after 1", in.ClusterOK, cluster.calls)
	}
	if in.Now.Location() != time.UTC || !in.Now.Equal(rollupNow) {
		t.Fatalf("Now = %v, want %v in UTC", in.Now, rollupNow)
	}
	if len(in.Errors) != 1 || in.Cell != "GRU" {
		t.Fatalf("inputs = %+v", in)
	}
	rollup := Build(in)
	if rollup.Health.Status != Critical || rollup.Cell != "gru" {
		t.Fatalf("rollup = %s %+v, want critical gru", rollup.Cell, rollup.Health)
	}
}

func TestCollectEventsWhenNoErrorSource(t *testing.T) {
	sources := Sources{
		Cluster: &fakeClusterSource{},
		Now:     func() time.Time { return rollupNow },
		Events: func(limit int) []observability.Event {
			if limit != 256 {
				t.Fatalf("limit = %d, want 256", limit)
			}
			return []observability.Event{{Level: slog.LevelError.String(), Message: "boom"}}
		},
	}
	in := sources.Collect(context.Background())
	if !in.ClusterOK || len(in.Events) != 1 || in.Errors != nil {
		t.Fatalf("inputs = ClusterOK %v events %d errors %v", in.ClusterOK, len(in.Events), in.Errors)
	}
}

type fakeClusterSource struct {
	err   error
	calls int
}

func (f *fakeClusterSource) Cluster(context.Context, bool) (observability.ClusterSnapshot, error) {
	f.calls++
	return observability.ClusterSnapshot{Expected: []string{"ctl-1"}}, f.err
}

// samePtr compares optional readings by value. nil must match nil.
func samePtr(a, b *float64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

type failingVolumes struct{}

func (failingVolumes) Volumes(context.Context) ([]insights.Volume, error) {
	return nil, errors.New("placement store unavailable")
}

func TestFailedVolumeReadIsNotAnEmptyList(t *testing.T) {
	in := Sources{Cell: "gru", Volumes: failingVolumes{}}.Collect(context.Background())
	if !in.VolumesUnavailable {
		t.Fatal("a failed volume read was collected as an empty list")
	}
	healthy := healthyRegion()
	healthy.VolumesUnavailable = true
	rollup := Build(healthy)
	if !rollup.VolumesUnavailable || rollup.Health.Status != Degraded ||
		!slices.Contains(rollup.Health.Reasons, "volume list unavailable") {
		t.Fatalf("rollup = unavailable %v, health %+v", rollup.VolumesUnavailable, rollup.Health)
	}
}
