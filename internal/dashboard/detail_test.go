package dashboard

import (
	"encoding/json"
	"html"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// detailDecisions are placement, rollout and volume decisions for the
// detail pages of the test member's partition 00000000000DMQEY0YD7RZ04RR/00000000003K6TBW31R91GBDRD.
func detailDecisions() []decisionlog.Decision {
	at := func(minutes int) time.Time { return testNow.Add(-time.Duration(minutes) * time.Minute) }
	placement := decisionlog.Actor{Slice: "placement"}
	return append(testDecisions(),
		decisionlog.Decision{ID: "p1", Time: at(40), Region: "fra", Actor: placement, Kind: decisionlog.KindStageChanged,
			Subject: decisionlog.Subject{Kind: "seat", ID: "00000000000DMQEY0YD7RZ04RR/00000000003K6TBW31R91GBDRD/000000000036XR713YE93E9M0S", Name: "00000000000DMQEY0YD7RZ04RR/00000000003K6TBW31R91GBDRD 000000000036XR713YE93E9M0S"},
			Summary: "Seat 000000000036XR713YE93E9M0S moved to joining", Status: decisionlog.StatusInProgress,
			Attrs: map[string]string{"database_id": "00000000000DMQEY0YD7RZ04RR", "partition_id": "00000000003K6TBW31R91GBDRD", "host_node": "host-a"}},
		decisionlog.Decision{ID: "p2", Time: at(30), Region: "fra", Actor: placement, Kind: decisionlog.KindHeld,
			Subject: decisionlog.Subject{Kind: "database", ID: "00000000000DMQEY0YD7RZ04RR/00000000003K6TBW31R91GBDRD"}, Summary: "Placement held database/00000000000DMQEY0YD7RZ04RR/00000000003K6TBW31R91GBDRD",
			Reason: "database 00000000000DMQEY0YD7RZ04RR/00000000003K6TBW31R91GBDRD has no admitted managed placement profile; host reconciliation is held",
			Status: decisionlog.StatusPending},
		decisionlog.Decision{ID: "p3", Time: at(20), Region: "fra", Actor: placement, Kind: decisionlog.KindHeld,
			Subject: decisionlog.Subject{Kind: "seat", ID: "000000000036XR713YE93E9M0S"}, Summary: "Placement held seat/000000000036XR713YE93E9M0S",
			Reason: "member 000000000036XR713YE93E9M0S OCI host is not currently observed; retained volume is kept", Status: decisionlog.StatusPending},
		decisionlog.Decision{ID: "p4", Time: at(15), Region: "fra", Actor: placement, Kind: decisionlog.KindHeld,
			Subject: decisionlog.Subject{Kind: "database", ID: "billing/p9"}, Summary: "Placement held database/billing/p9",
			Reason: "database billing/p9 has a committed terminal teardown fence", Status: decisionlog.StatusPending},
		decisionlog.Decision{ID: "u1", Time: at(25), Region: "fra", Actor: placement, Kind: decisionlog.KindUpgradeStarted,
			Subject: decisionlog.Subject{Kind: "operation", ID: "0000000000HAAS49GS9KYXGSQT", Name: "managed update of 00000000000DMQEY0YD7RZ04RR/00000000003K6TBW31R91GBDRD 0000000000DNKA8DBDEPN1J9XM"},
			Summary: "Managed update started on canary seat 0000000000DNKA8DBDEPN1J9XM", Status: decisionlog.StatusInProgress},
		decisionlog.Decision{ID: "u2", ParentID: "0000000000S6V256J3P07Q0W6X", Time: at(12), Region: "fra", Actor: placement,
			Kind: decisionlog.KindCanaryPromoted, Subject: decisionlog.Subject{Kind: "operation", ID: "0000000000HAAS49GS9KYXGSQT"},
			Summary: "Canary 0000000000DNKA8DBDEPN1J9XM promoted", Status: decisionlog.StatusSucceeded},
		decisionlog.Decision{ID: "v1", Time: at(8), Region: "fra", Actor: placement, Kind: decisionlog.KindVolumeResized,
			Subject: decisionlog.Subject{Kind: "volume", ID: "vol-stuck", Name: "00000000000DMQEY0YD7RZ04RR/00000000003K6TBW31R91GBDRD"},
			Summary: "Grew volume vol-stuck to 200 GB", Status: decisionlog.StatusSucceeded},
		decisionlog.Decision{ID: "h1", Time: at(35), Region: "fra", Actor: decisionlog.Actor{Slice: "nodescale"},
			Kind: decisionlog.KindHostLaunched, Subject: decisionlog.Subject{Kind: "host", ID: "host-a", Name: "pool/host-a"},
			Summary: "Launched host host-a", Status: decisionlog.StatusSucceeded},
	)
}

func detailDashboard(t *testing.T) http.Handler {
	t.Helper()
	journal, source, _ := fullJournal()
	journal.Decisions = &fakeDecisions{decisions: detailDecisions(), complete: true}
	source.evaluation.Insights = append(source.evaluation.Insights,
		insights.Insight{Key: "member_held:seat:00000000000DMQEY0YD7RZ04RR/00000000003K6TBW31R91GBDRD/0000000000DNKA8DBDEPN1J9XM", Severity: insights.SeverityWarning, Region: "fra",
			Title: "Managed update held on seat 0000000000DNKA8DBDEPN1J9XM", Entity: insights.Entity{Kind: "seat", ID: "00000000000DMQEY0YD7RZ04RR/00000000003K6TBW31R91GBDRD/0000000000DNKA8DBDEPN1J9XM"}},
		insights.Insight{Key: "volume_stuck:vol-stuck", Severity: insights.SeverityWarning, Region: "fra",
			Title: "Volume vol-stuck stuck attaching", Entity: insights.Entity{Kind: "volume", ID: "vol-stuck"}},
		insights.Insight{Key: "rollout_deadline:0000000000N6KCZG3MWDGZ0WBE", Severity: insights.SeverityCritical, Region: "fra",
			Title: "Rollout 0000000000N6KCZG3MWDGZ0WBE is past its batch deadline", Entity: insights.Entity{Kind: "rollout", ID: "0000000000N6KCZG3MWDGZ0WBE"}})
	now := testNow
	for minute := 30; minute >= 0; minute-- {
		journal.History.(*observability.History).Append(now.Add(-time.Duration(minute)*time.Minute), []observability.Sample{
			{Metric: observability.HistPartitionDesired, Labels: observability.L("database", "00000000000DMQEY0YD7RZ04RR", "partition", "00000000003K6TBW31R91GBDRD"), Value: 3},
			{Metric: observability.HistPartitionServing, Labels: observability.L("database", "00000000000DMQEY0YD7RZ04RR", "partition", "00000000003K6TBW31R91GBDRD"), Value: 2},
			{Metric: observability.HistRolloutProgress, Labels: observability.L("operation", "0000000000HAAS49GS9KYXGSQT"), Value: 0.33},
		})
	}
	snapshot := memberSnapshot()
	other := memberSnapshot()
	other.Member, other.Authority.Leader, other.Checks = "ctl-2", false,
		[]observability.CheckResult{{Name: "authority", OK: false, Detail: "lease not observed"}}
	other.Ready = false
	dashboard := newTestDashboard(Options{Health: readyHealth(true), Journal: journal,
		Snapshots: fixedSnapshots{snapshot: snapshot},
		Cluster: fixedCluster{snapshot: observability.ClusterSnapshot{Cell: "fra",
			Members: []observability.MemberSnapshot{snapshot, other}, Missing: []string{"ctl-3"}}}})
	return dashboard.Handler()
}

func TestDetailPagesRenderTheirEntity(t *testing.T) {
	t.Parallel()
	handler := detailDashboard(t)
	for path, wants := range map[string][]string{
		"/members/ctl-2": {"ctl-2", "follower · epoch 7", "lease not observed", "Decisions about this member",
			`aria-current="page"`, `data-init="@get(&#39;/members/ctl-2/stream`},
		"/members/ctl-3": {"is expected but did not answer"},
		"/members/ctl-1": {"ctl-1 became the regional authority leader", "ctl-1 nats filesystem full in about 2d",
			"newest decision's chain"},
		"/terrabase/00000000000DMQEY0YD7RZ04RR/00000000003K6TBW31R91GBDRD": {"2 of 3 desired", "0000000000HAAS49GS9KYXGSQT", "000000000036XR713YE93E9M0S", "host-a", "Placement hold history",
			"no admitted managed placement profile", "OCI host is not currently observed", "Seat 000000000036XR713YE93E9M0S moved to joining",
			"Managed update held on seat 0000000000DNKA8DBDEPN1J9XM", "Seats serving vs desired", "Canary 0000000000DNKA8DBDEPN1J9XM promoted",
			`href="/regions/fra/hosts/host-a"`},
		"/rollouts/0000000000N6KCZG3MWDGZ0WBE": {"v0.43.0", "batch-1", "Rollout 0000000000N6KCZG3MWDGZ0WBE is past its batch deadline"},
		"/rollouts/0000000000HAAS49GS9KYXGSQT": {"Managed TerraBase update", "00000000000DMQEY0YD7RZ04RR / 00000000003K6TBW31R91GBDRD", "sha256:feedface", "Canary 0000000000DNKA8DBDEPN1J9XM promoted", "done 1, pending 2"},
		"/volumes/vol-stuck":                   {"attaching", "host-a", "Grew volume vol-stuck to 200 GB", "Volume vol-stuck stuck attaching"},
		"/regions/fra/hosts/host-a": {"Host in FRA", "00000000000DMQEY0YD7RZ04RR / 00000000003K6TBW31R91GBDRD", "000000000036XR713YE93E9M0S", "vol-stuck", "Launched host host-a",
			"host load telemetry must be enabled", "Memory used", "Disk used", "Service CPU", "Service memory used"},
		"/regions/sfo/hosts/host-z": {"Host in SFO", "served by that region"},
		"/members/nobody":           {"is not a member that answered"},
	} {
		response := get(t, handler, path)
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, response.Code)
		}
		body := response.Body.String()
		for _, want := range wants {
			if !strings.Contains(body, want) {
				t.Errorf("GET %s lacks %q", path, want)
			}
		}
	}
}

func TestPartitionHoldHistoryIsScopedToThePartition(t *testing.T) {
	t.Parallel()
	body := get(t, detailDashboard(t), "/terrabase/00000000000DMQEY0YD7RZ04RR/00000000003K6TBW31R91GBDRD").Body.String()
	if strings.Contains(body, "billing/p9") || strings.Contains(body, "Launched host host-a") {
		t.Fatalf("the partition page lists another partition's decisions")
	}
	if strings.Contains(body, "seat ID shared") {
		t.Fatalf("a seat ID only this partition has is flagged as shared")
	}
}

type replayingHostHistory struct {
	*observability.History
	pending, incomplete bool
}

func (h replayingHostHistory) Range(query observability.HistoryQuery) observability.HistoryResult {
	result := h.History.Range(query)
	result.Pending = h.pending
	result.Incomplete = h.incomplete
	return result
}

type incompleteHostHistory struct{ *observability.History }

func (h incompleteHostHistory) Range(query observability.HistoryQuery) observability.HistoryResult {
	result := h.History.Range(query)
	result.Incomplete = true
	return result
}

func TestHostDetailChartsDiscloseReplayCapacity(t *testing.T) {
	now := time.Now()
	history := observability.NewHistory(observability.HistoryConfig{})
	history.Append(now, []observability.Sample{{Metric: observability.HistHostCPUUtilization,
		Labels: observability.L("member", "host-a"), Value: 0.25}})
	handler := New(Options{Now: func() time.Time { return now }, Journal: &Journal{History: incompleteHostHistory{history}},
		Snapshots: fixedSnapshots{snapshot: memberSnapshot()}}).Handler()
	response := get(t, handler, "/regions/fra/hosts/host-a")
	body := response.Body.String()
	if response.Code != http.StatusOK || strings.Count(body, "Regional metric history is incomplete:") != 5 ||
		!strings.Contains(body, `role="status"`) || !strings.Contains(body, "0.25") ||
		strings.Contains(body, "Loading regional metric history") {
		t.Fatalf("host charts hid incomplete replay or available samples: status=%d body=%s", response.Code, body)
	}
}

func TestHostDetailChartsWaitForRegionalReplay(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name               string
		cached, incomplete bool
		loadingCharts      int
	}{
		{name: "cached CPU", cached: true, loadingCharts: 4},
		{name: "no samples", loadingCharts: 5},
		{name: "cached CPU with loss", cached: true, incomplete: true, loadingCharts: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Hour)
			history := &replayingHostHistory{History: observability.NewHistory(observability.HistoryConfig{}),
				pending: true, incomplete: test.incomplete}
			if test.cached {
				history.Append(now, []observability.Sample{{Metric: observability.HistHostCPUUtilization,
					Labels: observability.L("member", "host-a"), Value: 0.25}})
			}
			handler := New(Options{Now: func() time.Time { return now }, Journal: &Journal{History: history},
				Snapshots: fixedSnapshots{snapshot: memberSnapshot()}}).Handler()
			response := get(t, handler, "/regions/fra/hosts/host-a")
			body := response.Body.String()
			warning := "Regional metric history is loading."
			if test.incomplete {
				warning = "Regional metric history is incomplete: some retained measurements are unavailable. " + warning
			}
			if response.Code != http.StatusOK ||
				strings.Count(body, `aria-label="Loading regional metric history"`) != test.loadingCharts ||
				strings.Count(body, `<p class="note warn" role="status">`+warning+`</p>`) != 5 {
				t.Fatalf("host charts hid replay status: status=%d body=%s", response.Code, body)
			}
			matches := regexp.MustCompile(`<ts-chart[^>]*data-spec="([^"]*)"`).FindAllStringSubmatch(body, -1)
			if len(matches) != 5 {
				t.Fatalf("rendered %d charts, want 5", len(matches))
			}
			var cpu chartSpec
			if err := json.Unmarshal([]byte(html.UnescapeString(matches[0][1])), &cpu); err != nil {
				t.Fatal(err)
			}
			if test.cached && (cpu.Empty != "" || cpu.Unit != "percent" || len(cpu.Series) != 1 ||
				cpu.Series[0].Name != "host-a" || len(cpu.Series[0].Points) != 1 ||
				cpu.Series[0].Points[0] != [2]float64{float64(now.UnixMilli()), 0.25}) {
				t.Fatalf("pending replay hid cached CPU sample: %+v", cpu)
			}

			history.pending = false
			response = get(t, handler, "/regions/fra/hosts/host-a")
			body = response.Body.String()
			lossWarnings := 0
			if test.incomplete {
				lossWarnings = 5
			}
			if response.Code != http.StatusOK || strings.Contains(body, "Regional metric history is loading.") ||
				strings.Contains(body, "Loading regional metric history") ||
				strings.Count(body, "Regional metric history is incomplete:") != lossWarnings {
				t.Fatalf("replay completion did not clear only loading status: status=%d body=%s", response.Code, body)
			}
		})
	}
}

func TestHostDetailChartsScopeNodeAndRange(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Hour)
	history := observability.NewHistory(observability.HistoryConfig{})
	wants := []struct {
		metric, unit string
		values       map[string]float64
	}{
		{observability.HistHostCPUUtilization, "percent", map[string]float64{"host-a": 0.25}},
		{observability.HistHostMemoryRatio, "percent", map[string]float64{"host-a": 0.5}},
		{observability.HistHostDiskRatio, "percent", map[string]float64{"host-a": 0.75}},
		{observability.HistServiceCPUCores, "", map[string]float64{"api": 0.125, "web": 1.5}},
		{observability.HistServiceMemoryUsed, "bytes", map[string]float64{"api": 128 << 20, "web": 256 << 20}},
	}
	for _, at := range []time.Time{now.Add(-15 * 24 * time.Hour), now.Add(-13 * 24 * time.Hour), now.Add(-15 * time.Minute)} {
		var samples []observability.Sample
		for index, want := range wants {
			for name, value := range want.values {
				for _, node := range []string{"host-a", "host-ab", "ctl-1"} {
					sampleValue := value
					labels := observability.L("member", node)
					if index >= 3 {
						labels = append(labels, observability.Label{Name: "service", Value: name})
					}
					if node != "host-a" {
						sampleValue = 9
						if want.unit == "percent" {
							sampleValue = 0.99
						}
					}
					if at.Before(now.Add(-time.Hour)) {
						sampleValue /= 2
					}
					samples = append(samples, observability.Sample{Metric: want.metric, Labels: labels, Value: sampleValue})
				}
			}
		}
		// Controller series sharing a node label must not supply host charts.
		for _, metric := range []string{observability.HistCPUUtilization, observability.HistMemoryRatio, observability.HistFSRatio} {
			samples = append(samples, observability.Sample{Metric: metric, Labels: observability.L("member", "host-a"), Value: 0.99})
		}
		history.Append(at, samples)
	}
	handler := New(Options{Now: func() time.Time { return now }, Journal: &Journal{History: history},
		Snapshots: fixedSnapshots{snapshot: memberSnapshot()}}).Handler()
	specAttribute := regexp.MustCompile(`<ts-chart[^>]*data-spec="([^"]*)"`)
	for _, test := range []struct {
		path     string
		duration time.Duration
		points   int
	}{
		{"/regions/fra/hosts/host-a", time.Hour, 1},
		{"/regions/FRA/hosts/HOST-A?range=14d", 14 * 24 * time.Hour, 2},
		{"/regions/fra/hosts/host-a?range=14d&host=host-ab&r=sfo", 14 * 24 * time.Hour, 2},
		{"/regions/sfo/hosts/host-a?range=14d", 14 * 24 * time.Hour, 0},
	} {
		t.Run(test.path, func(t *testing.T) {
			response := get(t, handler, test.path)
			if response.Code != http.StatusOK {
				t.Fatalf("GET = %d", response.Code)
			}
			matches := specAttribute.FindAllStringSubmatch(response.Body.String(), -1)
			if test.points == 0 {
				if len(matches) != 0 || !strings.Contains(response.Body.String(), "served by that region") {
					t.Fatal("remote host page must not show local metric history")
				}
				return
			}
			if len(matches) != len(wants) {
				t.Fatalf("rendered %d charts, want %d", len(matches), len(wants))
			}
			for index, match := range matches {
				var spec chartSpec
				if err := json.Unmarshal([]byte(html.UnescapeString(match[1])), &spec); err != nil {
					t.Fatal(err)
				}
				want := wants[index]
				if spec.Kind != "line" || spec.Unit != want.unit || spec.Empty != "" ||
					spec.Start != now.Add(-test.duration).UnixMilli() || spec.End != now.UnixMilli() {
					t.Fatalf("%s chart has wrong units, range or empty state: %+v", want.metric, spec)
				}
				if len(spec.Series) != len(want.values) {
					t.Fatalf("%s has %d series, want %d", want.metric, len(spec.Series), len(want.values))
				}
				for _, series := range spec.Series {
					value, found := want.values[series.Name]
					if !found || len(series.Points) != test.points {
						t.Fatalf("%s includes wrong host/service or point count: %+v", want.metric, series)
					}
					values := []float64{value}
					if test.points == 2 {
						values = []float64{value / 2, value}
					}
					for pointIndex, point := range series.Points {
						if point[0] < float64(spec.Start) || point[0] > float64(spec.End) || point[1] != values[pointIndex] {
							t.Fatalf("%s wrong history point: %v, want value %v within range", want.metric, point, values[pointIndex])
						}
					}
				}
			}
		})
	}
}

func TestDetailPathsAreValidated(t *testing.T) {
	t.Parallel()
	handler := detailDashboard(t)
	for _, path := range []string{"/members/bad%20name", "/regions/FRA%21/hosts/a", "/volumes/%3Cscript%3E",
		"/terrabase/00000000000DMQEY0YD7RZ04RR/p%20x"} {
		if response := get(t, handler, path); response.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, response.Code)
		}
	}
	// The region in the path is case-insensitive like r=.
	if response := get(t, handler, "/regions/FRA/hosts/host-a"); response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), "Host in FRA") {
		t.Fatalf("GET /regions/FRA/hosts/host-a = %d", response.Code)
	}
}

func TestListPagesLinkToDetailPages(t *testing.T) {
	t.Parallel()
	handler := detailDashboard(t)
	for path, wants := range map[string][]string{
		"/members":   {`href="/members/ctl-2"`, `href="/regions/fra/hosts/host-a"`},
		"/terrabase": {`href="/terrabase/00000000000DMQEY0YD7RZ04RR/00000000003K6TBW31R91GBDRD"`},
		"/rollouts":  {`href="/rollouts/0000000000N6KCZG3MWDGZ0WBE"`, `href="/rollouts/0000000000HAAS49GS9KYXGSQT"`},
		"/storage":   {`href="/volumes/vol-stuck"`},
	} {
		body := get(t, handler, path).Body.String()
		for _, want := range wants {
			if !strings.Contains(body, want) {
				t.Errorf("GET %s lacks %s", path, want)
			}
		}
	}
}

func TestDetailPageStreamsCarryContentAndChrome(t *testing.T) {
	t.Parallel()
	journal, _, _ := fullJournal()
	dashboard := newTestDashboard(Options{Journal: journal, Snapshots: fixedSnapshots{snapshot: memberSnapshot()}})
	server := newStreamServer(t, dashboard)
	for _, path := range []string{"/members/ctl-1/stream", "/terrabase/00000000000DMQEY0YD7RZ04RR/00000000003K6TBW31R91GBDRD/stream", "/rollouts/0000000000N6KCZG3MWDGZ0WBE/stream",
		"/volumes/vol-stuck/stream", "/regions/fra/hosts/host-a/stream"} {
		reader, _ := openStream(t, server, path)
		eventType, data := reader.next()
		if eventType != "datastar-patch-elements" || !strings.Contains(data, `<div id="content">`) ||
			!strings.Contains(data, `id="region-switcher"`) {
			t.Fatalf("%s first patch lacks content or chrome: %q", path, data)
		}
	}
}

func TestDetailPagesRenderWithoutProviders(t *testing.T) {
	t.Parallel()
	handler := newTestDashboard(Options{}).Handler()
	for _, path := range []string{"/members/ctl-1", "/terrabase/00000000000DMQEY0YD7RZ04RR/00000000003K6TBW31R91GBDRD", "/rollouts/0000000000N6KCZG3MWDGZ0WBE", "/volumes/v",
		"/regions/fra/hosts/h"} {
		response := get(t, handler, path)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "still starting") {
			t.Errorf("GET %s = %d without explaining the missing providers", path, response.Code)
		}
	}
}

func TestOCIPageCountsTheFleetByLifecycleState(t *testing.T) {
	t.Parallel()
	older, newer := memberSnapshot(), memberSnapshot()
	older.OCI.Fleet = []observability.OCIFleetView{{Region: "fra", ObservedAt: testNow.Add(-time.Hour),
		Instances: map[string]int{"STOPPED": 9}}}
	newer.Member = "ctl-2"
	newer.OCI.Fleet = []observability.OCIFleetView{{Region: "fra", ObservedAt: testNow.Add(-time.Minute),
		Instances: map[string]int{"RUNNING": 3, "PROVISIONING": 1}, Volumes: map[string]int{"AVAILABLE": 3},
		Attachments: map[string]int{"ATTACHED": 2, "ATTACHING": 1}}}
	handler := newTestDashboard(Options{Snapshots: fixedSnapshots{snapshot: older},
		Cluster: fixedCluster{snapshot: observability.ClusterSnapshot{Cell: "fra",
			Members: []observability.MemberSnapshot{older, newer}}}}).Handler()
	body := get(t, handler, "/oci").Body.String()
	for _, want := range []string{"Fleet by lifecycle state", "RUNNING 3", "PROVISIONING 1", "AVAILABLE 3",
		"ATTACHED 2", "ATTACHING 1"} {
		if !strings.Contains(body, want) {
			t.Errorf("/oci lacks %q", want)
		}
	}
	if strings.Contains(body, "STOPPED 9") {
		t.Error("/oci shows an older sweep of the same region")
	}
	if body := get(t, newTestDashboard(Options{}).Handler(), "/oci").Body.String(); !strings.Contains(body,
		"No member reported an OCI fleet sweep") {
		t.Error("/oci does not explain a missing fleet sweep")
	}
}

func TestDeepRegionLinksAreKept(t *testing.T) {
	t.Parallel()
	board, source, _ := journalDashboard(Options{})
	insight := testInsight("deep-link", "Deep region link", insights.SeverityWarning, "")
	insight.Entity = insights.Entity{Kind: "host", ID: "h-1", Href: "/regions/sfo/hosts/h-1"}
	source.evaluation.Insights = []insights.Insight{insight}
	if body := get(t, board.Handler(), "/insights").Body.String(); !strings.Contains(body, `href="/regions/sfo/hosts/h-1"`) {
		t.Fatal("deep region entity link was rewritten")
	}
}

// TestDetailPagesListOnlyTheirEntitysDecisions pins that a detail page does
// not list a decision that merely contains the entity's ID inside a longer
// identifier, and that a host page lists the placement decisions whose
// host is named only in the host_node attribute.
func TestDetailPagesListOnlyTheirEntitysDecisions(t *testing.T) {
	t.Parallel()
	journal, _, _ := fullJournal()
	at := testNow.Add(-5 * time.Minute)
	journal.Decisions = &fakeDecisions{complete: true, decisions: append(detailDecisions(),
		decisionlog.Decision{ID: "m10", Time: at, Region: "fra", Actor: decisionlog.Actor{Slice: "cluster"},
			Kind: decisionlog.KindMemberReplaced, Subject: decisionlog.Subject{Kind: "member", ID: "ctl-10"},
			Summary: "Replaced member ctl-10", Status: decisionlog.StatusSucceeded},
		decisionlog.Decision{ID: "hb", Time: at, Region: "fra", Actor: decisionlog.Actor{Slice: "nodescale"},
			Kind: decisionlog.KindHostLaunched, Subject: decisionlog.Subject{Kind: "host", ID: "host-ab", Name: "pool/host-ab"},
			Summary: "Launched host host-ab", Status: decisionlog.StatusSucceeded})}
	handler := newTestDashboard(Options{Health: readyHealth(true), Journal: journal,
		Snapshots: fixedSnapshots{snapshot: memberSnapshot()}}).Handler()
	member := get(t, handler, "/members/ctl-1").Body.String()
	if strings.Contains(member, "Replaced member ctl-10") {
		t.Error("the ctl-1 page lists ctl-10's decision")
	}
	host := get(t, handler, "/regions/fra/hosts/host-a").Body.String()
	if strings.Contains(host, "Launched host host-ab") {
		t.Error("the host-a page lists host-ab's decision")
	}
	if !strings.Contains(host, "Seat 000000000036XR713YE93E9M0S moved to joining") || !strings.Contains(host, "Launched host host-a") {
		t.Error("the host page lacks the decisions naming the host in host_node or the subject")
	}
	for text, want := range map[[2]string]bool{
		{"Replaced member ctl-1", "ctl-1"}: true, {"member ctl-10 left", "ctl-1"}: false,
		{"pool/HOST-A", "host-a"}: true, {"host-ab", "host-a"}: false, {"ctl-10 and ctl-1.", "ctl-1"}: true,
		{"", "x"}: false, {"x", ""}: false,
	} {
		if got := mentionsID(text[0], text[1]); got != want {
			t.Errorf("mentionsID(%q, %q) = %v", text[0], text[1], got)
		}
	}
}
