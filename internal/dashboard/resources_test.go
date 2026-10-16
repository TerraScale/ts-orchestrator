package dashboard

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/regionview"
)

func nodeResourceFixture() view {
	now := time.Now().UTC().Truncate(time.Minute)
	history := observability.NewHistory(observability.HistoryConfig{})
	for _, node := range []struct {
		name string
		cpu  float64
		at   time.Time
	}{
		{"physical", 0, now}, {"controller", .25, now}, {"worker", .5, now}, {"stale", 0, now.Add(-6 * time.Minute)},
	} {
		labels := observability.L("member", node.name)
		history.Append(node.at, []observability.Sample{
			{Metric: observability.HistHostReceivedAt, Labels: labels, Value: float64(node.at.UnixMilli())},
			{Metric: observability.HistHostCPUUtilization, Labels: labels, Value: node.cpu},
			{Metric: observability.HistHostCPUCores, Labels: labels, Value: 4},
			{Metric: observability.HistHostMemoryTotal, Labels: labels, Value: 2 << 30},
			{Metric: observability.HistHostMemoryRatio, Labels: labels, Value: 0},
			{Metric: observability.HistHostDiskRatio, Labels: labels, Value: 0},
		})
	}
	history.Append(now, []observability.Sample{{Metric: observability.HistCPUUtilization,
		Labels: observability.L("member", "controller"), Value: .91}})
	for _, role := range []string{"root", "state"} {
		labels := observability.L("member", "physical", "role", role, "path", "/"+role, "device", "7")
		history.Append(now, []observability.Sample{
			{Metric: observability.HistHostFSSize, Labels: labels, Value: 10 << 30},
			{Metric: observability.HistHostFSUsed, Labels: labels, Value: 0},
			{Metric: observability.HistHostFSRatio, Labels: labels, Value: 0},
		})
	}
	snapshot := memberSnapshot()
	snapshot.Cell, snapshot.Member = "fra", "controller"
	return view{Now: now, Ready: true, State: parseState(url.Values{}), Local: &snapshot,
		Journal: &Journal{History: history}, LocalSummary: &regionview.Summary{Region: "fra", Local: true,
			Nodes: []regionview.Node{{Name: "physical", Member: "controller"}, {Name: "controller", Member: "other-controller"},
				{Name: "worker"}, {Name: "stale"}, {Name: "missing"}}}}
}

func TestAllNodesRenderAuthenticatedResourcesWithoutClusterSnapshots(t *testing.T) {
	t.Parallel()
	current := nodeResourceFixture()
	for name, body := range map[string]string{"topology": renderTopology(t, current), "hosts": fixturePage(t, current, "/members")} {
		for _, want := range []string{"physical", "worker", "4 cores", "0.0%", "25.0%", "50.0%", "(stale)", "unavailable"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %q", name, want)
			}
		}
	}
	current.Path = map[string]string{"r": "fra", "h": "physical"}
	current.Page.slug = "host"
	body := fixturePage(t, current, "/regions/"+current.Path["r"]+"/hosts/"+current.Path["h"])
	for _, want := range []string{"Resources", "4 cores", "0 B / 2.0 GiB", "0.0%"} {
		if !strings.Contains(body, want) {
			t.Errorf("host detail lacks %q", want)
		}
	}
	current.Page.slug, current.Path = "member", map[string]string{"id": "controller"}
	body = fixturePage(t, current, "/members/controller")
	found := false
	for _, chart := range pageCharts(t, body) {
		for _, series := range chart.Series {
			for _, point := range series.Points {
				if point[1] == .91 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("member page lost control-plane CPU history")
	}
}

func TestStorageUsesPhysicalFilesystemsAndChartJSON(t *testing.T) {
	t.Parallel()
	current := nodeResourceFixture()
	body := fixturePage(t, current, "/storage")
	found := false
	for _, chart := range pageCharts(t, body) {
		if chart.Kind == "treemap" {
			found = true
			if len(chart.Tree) != 1 || chart.Tree[0].Name != "physical" || chart.Tree[0].Value != 10<<30 || len(chart.Tree[0].Children) != 1 || chart.Tree[0].Children[0].Status != "ok" {
				t.Fatalf("physical filesystem chart lost capacity: %+v", chart.Tree)
			}
		}
	}
	if !found {
		t.Fatal("physical filesystem chart missing")
	}

	for _, want := range []string{"physical", "root, state", "/root", "10.0 GiB", "0.0%"} {
		if !strings.Contains(body, want) {
			t.Errorf("storage lacks %q", want)
		}
	}
	if strings.Contains(body, "/var/lib/ts/nats") {
		t.Error("storage mixed controller snapshots into physical host reports")
	}
	current.Path = map[string]string{"r": "fra", "h": "missing"}
	if body := fixturePage(t, current, "/regions/"+current.Path["r"]+"/hosts/"+current.Path["h"]); !strings.Contains(body, "unavailable") || strings.Contains(body, "4 cores") {
		t.Error("missing host resources were synthesized")
	}
}

func TestResourcePagesExposeCollectorErrorsAndUnknownCapacity(t *testing.T) {
	t.Parallel()
	current := nodeResourceFixture()
	current.Local.Errors = map[string]string{"system": "unavailable"}
	for name, component := range map[string]page{
		"hosts": {slug: "members", body: membersBody}, "storage": {slug: "storage", body: storageBody},
		"topology": {slug: "topology", body: topologyBody}, "host": {slug: "host", body: hostDetailBody},
	} {
		current.Page = component
		current.Path = map[string]string{"r": "fra", "h": "physical"}
		if body := fixturePage(t, current, map[string]string{"hosts": "/members", "storage": "/storage", "topology": "/topology", "host": "/regions/fra/hosts/physical"}[name]); !strings.Contains(body, "Collection failed: controller: system unavailable") {
			t.Errorf("%s hides collector failure", name)
		}
	}

	body := fixturePage(t, current, "/regions/fra/hosts/missing")
	if !strings.Contains(body, "unavailable") || strings.Contains(body, "0 B / 0 B") {
		t.Fatal("unknown host capacity was rendered as zero")
	}

}

func TestVolumeAttachingWithoutTimestampIsNotOverdue(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		since  time.Time
		status string
	}{{time.Time{}, "run"}, {testNow.Add(-16 * time.Minute), "bad"}} {
		body := fixturePage(t, view{Journal: &Journal{Volumes: fakeVolumes{{ID: "pending-volume", State: "attaching", StateSince: test.since}}}}, "/storage")
		if !strings.Contains(body, `class="pill s-`+test.status+`">attaching</span>`) {
			t.Fatal("storage misreported pending attachment age")
		}
	}
}

func TestHostsAndRolloutsExcludeTerminalPartitions(t *testing.T) {
	t.Parallel()
	current := view{Local: &observability.MemberSnapshot{Placement: &observability.PlacementView{Databases: []observability.DatabaseView{
		{DatabaseID: "active", Members: []observability.MemberView{{HostNode: "host", Stage: "serving"}}, Rollout: &observability.RolloutView{}},
		{DatabaseID: "terminal", Terminal: true, Members: []observability.MemberView{{HostNode: "removed-host", Stage: "serving"}}, Rollout: &observability.RolloutView{}},
	}}}}
	for _, path := range []string{"/members", "/rollouts"} {
		body := fixturePage(t, current, path)
		if strings.Contains(body, "removed-host") || strings.Contains(body, ">terminal<") {
			t.Fatalf("terminal partition leaked into %s", path)
		}
	}
}

func TestTopologyResourceAlarmControlsNodeStatus(t *testing.T) {
	t.Parallel()
	for _, metric := range []string{"cpu", "memory", "disk"} {
		t.Run(metric, func(t *testing.T) {
			current := topologyFixture("")
			resources := current.LocalSummary.Nodes[0].Resources
			switch metric {
			case "cpu":
				resources.CPU.Value = .99
			case "memory":
				resources.Memory.Value = .99
			case "disk":
				resources.Disk.Value = .99
			}
			if got := nodeClass(renderTopology(t, current), "ts-gru-1"); got != "node s-bad" {
				t.Fatalf("%s alarm left node status %q", metric, got)
			}
		})
	}
}

func TestCapacityDisplaysPartialCoverage(t *testing.T) {
	t.Parallel()
	current := topologyFixture("")
	summary := *current.LocalSummary
	summary.Capacity = regionview.Capacity{Partial: true, MemoryBytes: 100, MemoryUsedBytes: 90, DiskBytes: 100, DiskUsedBytes: 90}
	current.LocalSummary = &summary
	body := fixturePage(t, current, "/region")
	if !strings.Contains(body, "Resource coverage is partial") || !strings.Contains(body, "90.0%") || !strings.Contains(body, "unavailable") {
		t.Fatalf("partial capacity lost its coverage evidence: %s", body)
	}
}

func TestStorageWarnsWhenOneFilesystemFailedCollection(t *testing.T) {
	t.Parallel()
	current := nodeResourceFixture()
	node := &current.LocalSummary.Nodes[0]
	node.Resources = regionview.CollectResources(*node, current.Journal.History, current.Now)
	node.Resources.Incomplete = true
	body := fixturePage(t, current, "/storage")
	if !strings.Contains(body, "10.0 GiB") || !strings.Contains(body, "Resource collection or regional metric history is incomplete.") {
		t.Fatal("successful disk reading hid the failed filesystem collection")
	}
}
