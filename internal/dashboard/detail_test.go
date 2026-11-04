package dashboard

import (
	"net/http"
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
	// Serving counts only render with live native readiness.
	snapshot.Placement.Databases[0].Readiness = "observed"
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
		"/regions/sjc/hosts/host-z": {"Host in SJC", "served by that region"},
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
