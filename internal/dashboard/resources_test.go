package dashboard

import (
	"encoding/json/v2"
	"net/url"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
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
		Journal: &Journal{History: history}, Regions: []regionview.Summary{{Region: "fra", Local: true,
			Nodes: []regionview.Node{{Name: "physical", Member: "controller"}, {Name: "controller", Member: "other-controller"},
				{Name: "worker"}, {Name: "stale"}, {Name: "missing"}}}}}
}

func TestAllNodesRenderAuthenticatedResourcesWithoutClusterSnapshots(t *testing.T) {
	t.Parallel()
	current := nodeResourceFixture()
	for name, body := range map[string]string{"topology": renderTopology(t, current), "hosts": renderHTML(t, membersBody(current))} {
		for _, want := range []string{"physical", "worker", "4 cores", "0.0%", "25.0%", "50.0%", "(stale)", "unavailable"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %q", name, want)
			}
		}
	}
	current.Path = map[string]string{"r": "fra", "h": "physical"}
	current.Page.slug = "host"
	chart := current.hostChart(observability.HistHostCPUUtilization, "percent", "member", "missing")
	if len(chart.Series) != 1 || chart.Series[0].Points[0][1] != 0 {
		t.Fatalf("host chart used controller instead of host origin: %+v", chart)
	}
	body := renderHTML(t, hostDetailBody(current))
	for _, want := range []string{"Resources", "4 cores", "0 B / 2.0 GiB", "0.0%"} {
		if !strings.Contains(body, want) {
			t.Errorf("host detail lacks %q", want)
		}
	}
	current.Page.slug, current.Path = "member", map[string]string{"id": "controller"}
	member := current.memberChart(observability.HistCPUUtilization, "percent", false, "missing")
	if len(member.Series) != 1 || member.Series[0].Points[0][1] != .91 {
		t.Fatalf("member chart lost its control-plane namespace: %+v", member)
	}
}

func TestStorageUsesPhysicalFilesystemsAndChartJSON(t *testing.T) {
	t.Parallel()
	current := nodeResourceFixture()
	tree := current.filesystemTree()
	if len(tree.Tree) != 1 || tree.Tree[0].Name != "physical" || tree.Tree[0].Value != 10<<30 || len(tree.Tree[0].Children) != 1 {
		t.Fatalf("physical filesystem capacity = %+v", tree.Tree)
	}
	var encoded chartSpec
	if err := json.Unmarshal([]byte(tree.JSON()), &encoded); err != nil {
		t.Fatal(err)
	}
	if encoded.Tree[0].Value != 10<<30 || encoded.Tree[0].Children[0].Status != "ok" {
		t.Fatalf("resource visual JSON = %s", tree.JSON())
	}
	body := renderHTML(t, storageBody(current))
	for _, want := range []string{"physical", "root, state", "/root", "10.0 GiB", "0.0%"} {
		if !strings.Contains(body, want) {
			t.Errorf("storage lacks %q", want)
		}
	}
	if strings.Contains(body, "/var/lib/ts/nats") {
		t.Error("storage mixed controller snapshots into physical host reports")
	}
	current.Path = map[string]string{"r": "fra", "h": "missing"}
	if body := renderHTML(t, hostDetailBody(current)); !strings.Contains(body, "unavailable") || strings.Contains(body, "4 cores") {
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
		if body := renderHTML(t, component.body(current)); !strings.Contains(body, "Collection failed: controller: system unavailable") {
			t.Errorf("%s hides collector failure", name)
		}
	}
	filesystem := regionview.Filesystem{Role: "unknown", UsedRatio: &regionview.Reading{Value: 0, ObservedAt: current.Now}}
	if current.readingText(filesystem.SizeBytes, "bytes") != "unavailable" || current.filesystemAvailable(filesystem) != "unavailable" {
		t.Fatal("unknown filesystem size appeared as zero capacity")
	}
}

func TestVolumeAttachingWithoutTimestampIsNotOverdue(t *testing.T) {
	t.Parallel()
	now := time.Now()
	if status := volumeStatus(insights.Volume{State: "attaching"}, now); status != "run" {
		t.Fatalf("unknown attachment time = %s", status)
	}
	if status := volumeStatus(insights.Volume{State: "attaching", StateSince: now.Add(-16 * time.Minute)}, now); status != "bad" {
		t.Fatalf("overdue attachment = %s", status)
	}
}

func TestHostsAndRolloutsExcludeTerminalPartitions(t *testing.T) {
	t.Parallel()
	current := view{Local: &observability.MemberSnapshot{Placement: &observability.PlacementView{Databases: []observability.DatabaseView{
		{DatabaseID: "active", Members: []observability.MemberView{{HostNode: "host", Stage: "serving"}}, Rollout: &observability.RolloutView{}},
		{DatabaseID: "terminal", Terminal: true, Members: []observability.MemberView{{HostNode: "host", Stage: "serving"},
			{HostNode: "removed-host", Stage: "serving"}}, Rollout: &observability.RolloutView{}},
	}}}}
	hosts := current.hosts()
	if len(hosts) != 1 || hosts[0].Node != "host" || hosts[0].Seats != 1 || hosts[0].Serving != 1 {
		t.Fatalf("terminal seats included in hosts: %+v", hosts)
	}
	rollouts := current.rollouts()
	if len(rollouts) != 1 || rollouts[0].DatabaseID != "active" {
		t.Fatalf("terminal rollout included: %+v", rollouts)
	}
}

func TestTopologyResourceAlarmControlsNodeStatus(t *testing.T) {
	t.Parallel()
	for _, metric := range []string{"cpu", "memory", "disk"} {
		t.Run(metric, func(t *testing.T) {
			current := topologyFixture("")
			resources := current.Regions[0].Nodes[0].Resources
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
	summary := current.Regions[0]
	summary.Capacity = regionview.Capacity{Partial: true, MemoryBytes: 100, MemoryUsedBytes: 90, DiskBytes: 100, DiskUsedBytes: 90}
	body := renderHTML(t, regionCard(current, summary))
	if !strings.Contains(body, "Resource coverage is partial") || !strings.Contains(body, "90.0%") || !strings.Contains(body, "unavailable") {
		t.Fatalf("partial capacity lost its coverage evidence: %s", body)
	}
	current.Regions = []regionview.Summary{summary}
	for _, tile := range current.globalKPIs() {
		if tile.Label == "Storage used" {
			if !strings.Contains(tile.Sub, "partial resource coverage") || tile.Status != "bad" {
				t.Fatalf("partial global capacity = %+v", tile)
			}
			return
		}
	}
	t.Fatal("observed storage capacity tile missing")
}

func TestStorageWarnsWhenOneFilesystemFailedCollection(t *testing.T) {
	t.Parallel()
	current := nodeResourceFixture()
	node := &current.Regions[0].Nodes[0]
	node.Resources = regionview.CollectResources(*node, current.Journal.History, current.Now)
	node.Resources.Incomplete = true
	body := renderHTML(t, storageBody(current))
	if !strings.Contains(body, "10.0 GiB") || !strings.Contains(body, "Resource collection or regional metric history is incomplete.") {
		t.Fatal("successful disk reading hid the failed filesystem collection")
	}
}
