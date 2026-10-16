package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func TestStorageShowsSnapshotCoverageAndPreservesFailureEvidence(t *testing.T) {
	member := memberSnapshot()
	member.ObservedAt = testNow
	member.KVSnapshots = &observability.KVSnapshotView{State: "failed", IntervalSeconds: 3600, CheckTimeoutSeconds: 120,
		LastCheckAt: testNow, Buckets: []observability.KVSnapshotBucketView{
			{Bucket: "TS_CONFIG", State: "current", Sequence: 42, LastCurrentAt: testNow, LastUploadedAt: testNow.Add(-24 * time.Hour)},
			{Bucket: "TS_AUTH", State: "failed", Sequence: 19, LastCurrentAt: testNow.Add(-30 * time.Minute),
				LastUploadedAt: testNow.Add(-time.Hour), ErrorClass: "unauthorized"},
		}}
	handler := newTestDashboard(Options{Snapshots: fixedSnapshots{snapshot: member}}).Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/storage", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("storage status = %d", response.Code)
	}
	body := response.Body.String()
	for _, want := range []string{"Object Storage configuration snapshots", "TS_CONFIG", "TS_AUTH", ">42<", ">19<",
		"unauthorized", ">failed<", ">current<", "Last confirmed current", "Last upload by this process"} {
		if !strings.Contains(body, want) {
			t.Errorf("storage is missing %q", want)
		}
	}
}

func TestStorageRendersLastCompletedSnapshotCheck(t *testing.T) {
	t.Parallel()
	member := memberSnapshot()
	member.ObservedAt = testNow
	checkedAt := testNow.Add(-time.Minute)
	member.KVSnapshots = &observability.KVSnapshotView{State: "current", IntervalSeconds: 3600, LastCheckAt: checkedAt}
	body := renderHTML(t, snapshotStorage(view{Local: &member, Now: testNow}))
	_, lastCheck, found := strings.Cut(body, "Last completed check:")
	if !found || !strings.Contains(lastCheck, `<ts-time datetime="`+rfc3339(checkedAt)+`"`) || strings.Contains(body, "@ago(") {
		t.Fatalf("last completed check did not render its timestamp: %s", body)
	}
}

func TestStorageSnapshotStatePreservesExplicitOverdueAndFailure(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, state, want string
		observedAt        time.Time
	}{
		{name: "overdue producer", state: "unknown", want: "overdue", observedAt: testNow},
		{name: "failed producer", state: "failed", want: "failed", observedAt: testNow},
		{name: "stale controller", state: "unknown", want: "stale", observedAt: testNow.Add(-10 * time.Minute)},
	} {
		t.Run(test.name, func(t *testing.T) {
			member := memberSnapshot()
			member.ObservedAt = test.observedAt
			member.KVSnapshots = &observability.KVSnapshotView{State: test.state, Overdue: true,
				IntervalSeconds: 60, CheckTimeoutSeconds: 120, LastCheckAt: testNow.Add(-4 * time.Minute)}
			current := view{Local: &member, Now: testNow}
			if got := current.snapshotState(member); got != test.want {
				t.Fatalf("snapshot state = %q, want %q", got, test.want)
			}
			body := renderHTML(t, snapshotStorage(current))
			if !strings.Contains(body, `class="pill s-`+snapshotStatus(test.want)+`">`+test.want+`<`) {
				t.Fatalf("snapshot state did not render its severity: %s", body)
			}
		})
	}
}

func TestStorageDoesNotPresentOldSnapshotEvidenceAsCurrent(t *testing.T) {
	member := memberSnapshot()
	member.ObservedAt = testNow
	member.KVSnapshots = &observability.KVSnapshotView{State: "current", IntervalSeconds: 60, CheckTimeoutSeconds: 120,
		LastCheckAt: testNow.Add(-4 * time.Minute), Buckets: []observability.KVSnapshotBucketView{
			{Bucket: "TS_CONFIG", State: "current", Sequence: 42, LastCurrentAt: testNow.Add(-4 * time.Minute)},
		}}
	current := view{Local: &member, Now: testNow}
	body := renderHTML(t, snapshotStorage(current))
	for _, want := range []string{">overdue<", ">stale<", "snapshot check is overdue"} {
		if !strings.Contains(body, want) {
			t.Errorf("old snapshot coverage missing %q", want)
		}
	}
	member.KVSnapshots.State = "follower"
	body = renderHTML(t, snapshotStorage(current))
	if !strings.Contains(body, ">follower<") || strings.Contains(body, "snapshot check is overdue") {
		t.Fatal("a follower was reported as a failing uploader")
	}
	member.KVSnapshots.State = "paused"
	if body = renderHTML(t, snapshotStorage(current)); !strings.Contains(body, ">paused<") {
		t.Fatal("paused snapshot schedule is hidden")
	}
	member.ObservedAt = testNow.Add(-10 * time.Minute)
	member.KVSnapshots.LastCheckAt = testNow
	member.KVSnapshots.Buckets[0].LastCurrentAt = testNow
	member.KVSnapshots.State = "current"
	if body = renderHTML(t, snapshotStorage(current)); !strings.Contains(body, ">stale<") {
		t.Fatal("old controller observation looked current")
	}
	member.KVSnapshots = nil
	if body = renderHTML(t, snapshotStorage(current)); !strings.Contains(body, ">unavailable<") {
		t.Fatal("missing snapshot provider looked healthy")
	}
}
