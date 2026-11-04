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
