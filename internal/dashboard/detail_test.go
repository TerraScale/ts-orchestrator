package dashboard

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/insights"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

// detailDecisions are placement, rollout and volume decisions for the
// detail pages of the test member's partition orders/p0.
func detailDecisions() []decisionlog.Decision {
	at := func(minutes int) time.Time { return testNow.Add(-time.Duration(minutes) * time.Minute) }
	placement := decisionlog.Actor{Slice: "placement"}
	return append(testDecisions(),
		decisionlog.Decision{ID: "p1", Time: at(40), Region: "fra", Actor: placement, Kind: decisionlog.KindStageChanged,
			Subject: decisionlog.Subject{Kind: "seat", ID: "orders/p0/s3", Name: "orders/p0 s3"},
			Summary: "Seat s3 moved to joining", Status: decisionlog.StatusInProgress,
			Attrs: map[string]string{"database_id": "orders", "partition_id": "p0", "host_node": "host-a"}},
		decisionlog.Decision{ID: "p2", Time: at(30), Region: "fra", Actor: placement, Kind: decisionlog.KindHeld,
			Subject: decisionlog.Subject{Kind: "database", ID: "orders/p0"}, Summary: "Placement held database/orders/p0",
			Reason: "database orders/p0 has no admitted managed placement profile; host reconciliation is held",
			Status: decisionlog.StatusPending},
		decisionlog.Decision{ID: "p3", Time: at(20), Region: "fra", Actor: placement, Kind: decisionlog.KindHeld,
			Subject: decisionlog.Subject{Kind: "seat", ID: "s3"}, Summary: "Placement held seat/s3",
			Reason: "member s3 OCI host is not currently observed; retained volume is kept", Status: decisionlog.StatusPending},
		decisionlog.Decision{ID: "p4", Time: at(15), Region: "fra", Actor: placement, Kind: decisionlog.KindHeld,
			Subject: decisionlog.Subject{Kind: "database", ID: "billing/p9"}, Summary: "Placement held database/billing/p9",
			Reason: "database billing/p9 has a committed terminal teardown fence", Status: decisionlog.StatusPending},
		decisionlog.Decision{ID: "u1", Time: at(25), Region: "fra", Actor: placement, Kind: decisionlog.KindUpgradeStarted,
			Subject: decisionlog.Subject{Kind: "operation", ID: "op-rollout-1", Name: "managed update of orders/p0 s1"},
			Summary: "Managed update started on canary seat s1", Status: decisionlog.StatusInProgress},
		decisionlog.Decision{ID: "u2", ParentID: "u1", Time: at(12), Region: "fra", Actor: placement,
			Kind: decisionlog.KindCanaryPromoted, Subject: decisionlog.Subject{Kind: "operation", ID: "op-rollout-1"},
			Summary: "Canary s1 promoted", Status: decisionlog.StatusSucceeded},
		decisionlog.Decision{ID: "v1", Time: at(8), Region: "fra", Actor: placement, Kind: decisionlog.KindVolumeResized,
			Subject: decisionlog.Subject{Kind: "volume", ID: "vol-stuck", Name: "orders/p0"},
			Summary: "Grew volume vol-stuck to 200 GB", Status: decisionlog.StatusSucceeded},
		decisionlog.Decision{ID: "h1", Time: at(35), Region: "fra", Actor: decisionlog.Actor{Slice: "hostpool"},
			Kind: decisionlog.KindHostLaunched, Subject: decisionlog.Subject{Kind: "host", ID: "host-a", Name: "pool/host-a"},
			Summary: "Launched host host-a", Status: decisionlog.StatusSucceeded},
	)
}

func detailDashboard(t *testing.T) http.Handler {
	t.Helper()
	journal, source, _ := fullJournal()
	journal.Decisions = &fakeDecisions{decisions: detailDecisions(), complete: true}
	source.evaluation.Insights = append(source.evaluation.Insights,
		insights.Insight{Key: "member_held:seat:orders/p0/s1", Severity: insights.SeverityWarning, Region: "fra",
			Title: "Managed update held on seat s1", Entity: insights.Entity{Kind: "seat", ID: "orders/p0/s1"}},
		insights.Insight{Key: "volume_stuck:vol-stuck", Severity: insights.SeverityWarning, Region: "fra",
			Title: "Volume vol-stuck stuck attaching", Entity: insights.Entity{Kind: "volume", ID: "vol-stuck"}},
		insights.Insight{Key: "rollout_deadline:ro-1", Severity: insights.SeverityCritical, Region: "fra",
			Title: "Rollout ro-1 is past its batch deadline", Entity: insights.Entity{Kind: "rollout", ID: "ro-1"}})
	now := testNow
	for minute := 30; minute >= 0; minute-- {
		journal.History.(*observability.History).Append(now.Add(-time.Duration(minute)*time.Minute), []observability.Sample{
			{Metric: observability.HistPartitionDesired, Labels: observability.L("database", "orders", "partition", "p0"), Value: 3},
			{Metric: observability.HistPartitionServing, Labels: observability.L("database", "orders", "partition", "p0"), Value: 2},
			{Metric: observability.HistRolloutProgress, Labels: observability.L("operation", "op-rollout-1"), Value: 0.33},
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
		"/terrabase/orders/p0": {"2 of 3 desired", "op-rollout-1", "s3", "host-a", "Placement hold history",
			"no admitted managed placement profile", "OCI host is not currently observed", "Seat s3 moved to joining",
			"Managed update held on seat s1", "Seats serving vs desired", "Canary s1 promoted",
			`href="/regions/fra/hosts/host-a"`},
		"/rollouts/ro-1":         {"v0.43.0", "batch-1", "Rollout ro-1 is past its batch deadline"},
		"/rollouts/op-rollout-1": {"Managed TerraBase update", "orders / p0", "sha256:feedface", "Canary s1 promoted", "completed"},
		"/volumes/vol-stuck":     {"attaching", "host-a", "Grew volume vol-stuck to 200 GB", "Volume vol-stuck stuck attaching"},
		"/regions/fra/hosts/host-a": {"Host in FRA", "orders / p0", "s3", "vol-stuck", "Launched host host-a",
			"host agents report their system view"},
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
	body := get(t, detailDashboard(t), "/terrabase/orders/p0").Body.String()
	if strings.Contains(body, "billing/p9") || strings.Contains(body, "Launched host host-a") {
		t.Fatalf("the partition page lists another partition's decisions")
	}
	if strings.Contains(body, "seat ID shared") {
		t.Fatalf("a seat ID only this partition has is flagged as shared")
	}
}

func TestDetailPathsAreValidated(t *testing.T) {
	t.Parallel()
	handler := detailDashboard(t)
	for _, path := range []string{"/members/bad%20name", "/regions/FRA%21/hosts/a", "/volumes/%3Cscript%3E",
		"/terrabase/orders/p%20x"} {
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
		"/terrabase": {`href="/terrabase/orders/p0"`},
		"/rollouts":  {`href="/rollouts/ro-1"`, `href="/rollouts/op-rollout-1"`},
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
	for _, path := range []string{"/members/ctl-1/stream", "/terrabase/orders/p0/stream", "/rollouts/ro-1/stream",
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
	for _, path := range []string{"/members/ctl-1", "/terrabase/orders/p0", "/rollouts/ro-1", "/volumes/v",
		"/regions/fra/hosts/h"} {
		response := get(t, handler, path)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "still starting") {
			t.Errorf("GET %s = %d without explaining the missing providers", path, response.Code)
		}
	}
}

func TestDeepRegionLinksAreKept(t *testing.T) {
	t.Parallel()
	state := parseState(nil)
	if got := state.adopt("/regions/sfo/hosts/h-1", ""); got != "/regions/sfo/hosts/h-1" {
		t.Fatalf("adopt kept %q", got)
	}
	if got := state.adopt("/regions/sfo", ""); got != "/region?r=sfo" {
		t.Fatalf("adopt rewrote %q", got)
	}
	if got := state.hostLink("sfo", "a b"); got != "/regions/sfo/hosts/a%20b" {
		t.Fatalf("hostLink = %q", got)
	}
}
