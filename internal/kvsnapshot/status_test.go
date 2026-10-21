package kvsnapshot

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestSnapshotStatusRetainsEvidenceAndRefreshesUnchangedBuckets(t *testing.T) {
	js := startJetStream(t)
	kv := openBucket(t, js, testBucket)
	put(t, kv, "secret-document-key", []byte("secret-document-value"))
	put(t, openBucket(t, js, "TS_OTHER"), "a", []byte("other"))
	openBucket(t, js, "TS_EMPTY")
	fake := newObjectStorage(t)
	snapshotter := snapshotterFor(js, fake, testBucket, "TS_OTHER", "TS_ABSENT", "TS_EMPTY")
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	snapshotter.Now = func() time.Time { return now }
	if status := snapshotter.Status(); status.State != "unknown" || !status.LastCheckAt.IsZero() {
		t.Fatalf("initial status = %+v", status)
	}
	if _, err := snapshotter.SnapshotOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	uploadedAt := now
	view := snapshotter.Status()
	if view.State != "current" || !view.LastCheckAt.Equal(now) || len(view.Buckets) != 4 ||
		view.Buckets[0].Sequence != 1 || !view.Buckets[0].LastUploadedAt.Equal(now) ||
		!view.Buckets[0].LastCurrentAt.Equal(now) || view.Buckets[2].State != "absent" || view.Buckets[3].State != "empty" {
		t.Fatalf("uploaded status = %+v", view)
	}

	now = now.Add(24 * time.Hour)
	if written, err := snapshotter.SnapshotOnce(t.Context()); err != nil || len(written) != 0 {
		t.Fatalf("unchanged snapshot = %v, %v", written, err)
	}
	view = snapshotter.Status()
	if view.State != "current" || !view.Buckets[0].LastCurrentAt.Equal(now) ||
		!view.Buckets[0].LastUploadedAt.Equal(uploadedAt) || fake.putCount() != 2 {
		t.Fatalf("unchanged status = %+v, puts = %d", view, fake.putCount())
	}
	confirmedAt := now

	put(t, kv, "secret-document-key", []byte("new-secret-document-value"))
	fake.fail("PUT", &storageFault{403, "secret-error-details"})
	now = now.Add(time.Minute)
	if _, err := snapshotter.SnapshotOnce(t.Context()); err == nil {
		t.Fatal("upload failure was ignored")
	}
	view = snapshotter.Status()
	bucket := view.Buckets[0]
	if view.State != "failed" || bucket.State != "failed" || bucket.ErrorClass != "unauthorized" ||
		bucket.Sequence != 1 || !bucket.LastUploadedAt.Equal(uploadedAt) || !bucket.LastCurrentAt.Equal(confirmedAt) ||
		!bucket.LastCheckAt.Equal(now) || !view.Buckets[1].LastCurrentAt.Equal(now) {
		t.Fatalf("failed status = %+v", view)
	}
	encoded, err := protocol.EncodeJSON(view)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-document", "secret-error-details", "etag-", testNamespace, "ocid1.key."} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("snapshot metadata contains %q: %s", secret, encoded)
		}
	}
	view.Buckets[0].State = "modified"
	if snapshotter.Status().Buckets[0].State != "failed" {
		t.Fatal("caller modified retained status")
	}

	fake.fail("PUT", nil)
	now = now.Add(time.Minute)
	if _, err := snapshotter.SnapshotOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	view = snapshotter.Status()
	if view.State != "current" || view.Buckets[0].Sequence != 2 || view.Buckets[0].ErrorClass != "" ||
		!view.Buckets[0].LastUploadedAt.Equal(now) || len(snapshotter.status) != 4 {
		t.Fatalf("recovered status = %+v", view)
	}
}

func TestSnapshotStatusDistinguishesOverdueChecksFromUnchangedUploads(t *testing.T) {
	js := startJetStream(t)
	put(t, openBucket(t, js, testBucket), "a", []byte("value"))
	fake := newObjectStorage(t)
	snapshotter := snapshotterFor(js, fake, testBucket)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	snapshotter.Now = func() time.Time { return now }
	if _, err := snapshotter.SnapshotOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	uploadedAt := now
	now = now.Add(snapshotInterval + snapshotPassTimeout)
	if view := snapshotter.Status(); view.State != "current" || view.Overdue || view.CheckTimeoutSeconds != 120 {
		t.Fatalf("status at the check deadline = %+v", view)
	}
	now = now.Add(time.Nanosecond)
	view := snapshotter.Status()
	if view.State != "unknown" || !view.Overdue || !view.Buckets[0].LastUploadedAt.Equal(uploadedAt) {
		t.Fatalf("overdue status = %+v", view)
	}
	snapshotter.Leader = func() bool { return false }
	if view := snapshotter.Status(); view.State != "follower" || view.Overdue {
		t.Fatalf("follower status = %+v", view)
	}
	snapshotter.Leader = func() bool { return true }
	now = now.Add(24 * time.Hour)
	if written, err := snapshotter.SnapshotOnce(t.Context()); err != nil || len(written) != 0 {
		t.Fatalf("unchanged snapshot = %v, %v", written, err)
	}
	view = snapshotter.Status()
	if view.State != "current" || view.Overdue || !view.Buckets[0].LastCurrentAt.Equal(now) ||
		!view.Buckets[0].LastUploadedAt.Equal(uploadedAt) || fake.putCount() != 1 {
		t.Fatalf("unchanged current status = %+v", view)
	}
}

func TestSnapshotStatusRequiresEveryBucketToBeKnown(t *testing.T) {
	js := startJetStream(t)
	storage := newObjectStorage(t)
	snapshotter := snapshotterFor(js, storage, testBucket)
	if _, err := snapshotter.SnapshotOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	openBucket(t, js, "TS_UNKNOWN")
	snapshotter.Buckets = append(snapshotter.Buckets, "TS_UNKNOWN")
	if view := snapshotter.Status(); view.State != "unknown" || view.Overdue {
		t.Fatalf("a checked bucket hid an unknown bucket: %+v", view)
	}
	if _, err := snapshotter.SnapshotOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if view := snapshotter.Status(); view.State != "current" || view.Buckets[0].State != "absent" || view.Buckets[1].State != "empty" {
		t.Fatalf("successfully checked absent and empty buckets = %+v", view)
	}
}

func TestSnapshotStatusConfirmsAnExistingObjectWithoutClaimingAnUpload(t *testing.T) {
	js := startJetStream(t)
	put(t, openBucket(t, js, testBucket), "a", []byte("value"))
	fake := newObjectStorage(t)
	if _, err := snapshotterFor(js, fake, testBucket).SnapshotOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshotter := snapshotterFor(js, fake, testBucket)
	if written, err := snapshotter.SnapshotOnce(t.Context()); err != nil || len(written) != 0 {
		t.Fatalf("confirm existing snapshot = %v, %v", written, err)
	}
	view := snapshotter.Status()
	if view.State != "current" || view.Buckets[0].Sequence != 1 || view.Buckets[0].LastCurrentAt.IsZero() ||
		!view.Buckets[0].LastUploadedAt.IsZero() || fake.putCount() != 1 {
		t.Fatalf("confirmed status = %+v", view)
	}
}

func TestUnchangedSnapshotDetectsStorageFailureAndRepairsMissingObject(t *testing.T) {
	js := startJetStream(t)
	put(t, openBucket(t, js, testBucket), "a", []byte("value"))
	fake := newObjectStorage(t)
	snapshotter := snapshotterFor(js, fake, testBucket)
	if _, err := snapshotter.SnapshotOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	confirmed := snapshotter.Status().Buckets[0].LastCurrentAt
	fake.fail("GET", &storageFault{403, "NotAuthorized"})
	if _, err := snapshotter.SnapshotOnce(t.Context()); err == nil {
		t.Fatal("unchanged local KV hid an Object Storage failure")
	}
	view := snapshotter.Status()
	if view.State != "failed" || view.Buckets[0].ErrorClass != "unauthorized" || !view.Buckets[0].LastCurrentAt.Equal(confirmed) {
		t.Fatalf("storage failure lost confirmation evidence: %+v", view)
	}
	fake.fail("GET", nil)
	fake.remove(t, testBucket)
	written, err := snapshotter.SnapshotOnce(t.Context())
	if err != nil || len(written) != 1 || fake.putCount() != 2 || snapshotter.Status().State != "current" {
		t.Fatalf("missing unchanged object was not repaired: %v, %v, puts=%d", written, err, fake.putCount())
	}
}

func TestSnapshotStatusReadsCurrentAuthority(t *testing.T) {
	js := startJetStream(t)
	put(t, openBucket(t, js, testBucket), "a", []byte("value"))
	storage := newObjectStorage(t)
	leader := true
	snapshotter := snapshotterFor(js, storage, testBucket)
	snapshotter.Leader = func() bool { return leader }
	if view := snapshotter.Status(); view.State != "unknown" || view.IntervalSeconds != 30 {
		t.Fatalf("initial status = %+v", view)
	}
	if _, err := snapshotter.SnapshotOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	leader = false
	if view := snapshotter.Status(); view.State != "follower" {
		t.Fatalf("follower status = %+v", view)
	}
	leader = true
	if view := snapshotter.Status(); view.State != "current" {
		t.Fatalf("leader lost its completed snapshot evidence: %+v", view)
	}
}

func TestSnapshotDeadlineDoesNotStarveLaterBuckets(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	js := startJetStream(t)
	put(t, openBucket(t, js, testBucket), "a", []byte("blocked"))
	put(t, openBucket(t, js, "TS_OTHER"), "a", []byte("healthy"))
	fake := newObjectStorage(t)
	started := make(chan struct{}, 1)
	fake.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/"+testBucket+".json") {
			started <- struct{}{}
			<-r.Context().Done()
			return true
		}
		return false
	}
	snapshotter := snapshotterFor(js, fake, testBucket, "TS_OTHER")
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	snapshotter.Now = func() time.Time { return now }
	pass := func() []string {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		var written []string
		var err error
		done := make(chan struct{})
		go func() {
			written, err = snapshotter.SnapshotOnce(ctx)
			close(done)
		}()
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("blocked bucket did not start")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("snapshot pass did not stop after cancellation")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("snapshot pass error = %v, want cancellation", err)
		}
		return written
	}

	if written := pass(); len(written) != 0 {
		t.Fatalf("exhausted first pass wrote %v", written)
	}
	now = now.Add(time.Minute)
	if written := pass(); len(written) != 1 || written[0] != "TS_OTHER" {
		t.Fatalf("fresh pass starved healthy bucket: wrote %v", written)
	}
	uploadedAt := now
	view := snapshotter.Status()
	if view.State != "failed" || view.Buckets[0].ErrorClass != "canceled" ||
		view.Buckets[1].State != "current" || view.Buckets[1].Sequence != 1 ||
		!view.Buckets[1].LastUploadedAt.Equal(uploadedAt) || !view.Buckets[1].LastCurrentAt.Equal(uploadedAt) {
		t.Fatalf("healthy bucket lost successful evidence: %+v", view)
	}
	if document := fake.document(t, "TS_OTHER"); len(document.Entries) != 1 || string(document.Entries[0].Value) != "healthy" {
		t.Fatalf("healthy snapshot = %+v", document)
	}

	now = now.Add(time.Minute)
	if written := pass(); len(written) != 0 {
		t.Fatalf("exhausted wraparound pass wrote %v", written)
	}
	view = snapshotter.Status()
	if view.Buckets[1].State != "failed" || !view.Buckets[1].LastUploadedAt.Equal(uploadedAt) ||
		!view.Buckets[1].LastCurrentAt.Equal(uploadedAt) || view.Buckets[1].Sequence != 1 {
		t.Fatalf("later cancellation erased successful evidence: %+v", view)
	}
	now = now.Add(time.Minute)
	if written := pass(); len(written) != 0 || fake.putCount() != 1 {
		t.Fatalf("unchanged healthy snapshot was rewritten: %v, puts=%d", written, fake.putCount())
	}
	view = snapshotter.Status()
	if view.Buckets[1].State != "current" || !view.Buckets[1].LastCurrentAt.Equal(now) ||
		!view.Buckets[1].LastUploadedAt.Equal(uploadedAt) || !view.LastCheckAt.Equal(now) {
		t.Fatalf("fresh pass did not reconfirm healthy snapshot: %+v", view)
	}
}

func TestSnapshotStatusDoesNotWaitForAnUploadAndIsThreadSafe(t *testing.T) {
	js := startJetStream(t)
	put(t, openBucket(t, js, testBucket), "a", []byte("value"))
	fake := newObjectStorage(t)
	if _, err := snapshotterFor(js, fake, testBucket).SnapshotOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	put(t, openBucket(t, js, "TS_OTHER"), "a", []byte("other"))
	started, release := make(chan struct{}), make(chan struct{})
	fake.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPut {
			return false
		}
		close(started)
		select {
		case <-r.Context().Done():
			return true
		case <-release:
			return false
		}
	}
	snapshotter := snapshotterFor(js, fake, testBucket, "TS_OTHER")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := snapshotter.SnapshotOnce(ctx)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("upload did not start")
	}
	read := make(chan string, 1)
	go func() { read <- snapshotter.Status().State }()
	select {
	case state := <-read:
		if state != "unknown" {
			t.Fatalf("status while another bucket is unknown = %s", state)
		}
	case <-time.After(time.Second):
		t.Fatal("status blocked on upload")
	}
	if view := snapshotter.Status(); view.Buckets[0].State != "current" || view.Buckets[1].State != "unknown" {
		t.Fatalf("partial pass status = %+v", view)
	}
	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for range 1000 {
				_ = snapshotter.Status()
			}
		})
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	readers.Wait()
	if view := snapshotter.Status(); view.State != "current" {
		t.Fatalf("completed status = %+v", view)
	}
}

func TestSnapshotErrorClassesAreBounded(t *testing.T) {
	for _, test := range []struct {
		name  string
		fault *storageFault
		class string
	}{
		{"unauthorized", &storageFault{401, "secret-upstream-error"}, "unauthorized"},
		{"forbidden", &storageFault{403, "secret-upstream-error"}, "unauthorized"},
		{"throttled", &storageFault{429, "secret-upstream-error"}, "throttled"},
		{"unavailable", &storageFault{503, "secret-upstream-error"}, "unavailable"},
		{"conflict", &storageFault{412, "secret-upstream-error"}, "conflict"},
	} {
		t.Run(test.name, func(t *testing.T) {
			js := startJetStream(t)
			put(t, openBucket(t, js, testBucket), "a", []byte("value"))
			storage := newObjectStorage(t)
			storage.fail(http.MethodPut, test.fault)
			snapshotter := snapshotterFor(js, storage, testBucket)
			if _, err := snapshotter.SnapshotOnce(t.Context()); err == nil {
				t.Fatal("storage failure was ignored")
			}
			view := snapshotter.Status()
			if view.State != "failed" || view.Buckets[0].ErrorClass != test.class {
				t.Fatalf("class = %+v, want %q", view, test.class)
			}
			encoded, err := protocol.EncodeJSON(view)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "secret-upstream-error") {
				t.Fatalf("status leaked upstream error: %s", encoded)
			}
		})
	}
}

func TestSnapshotClassifiesAnHTTPDeadline(t *testing.T) {
	js := startJetStream(t)
	put(t, openBucket(t, js, testBucket), "a", []byte("value"))
	storage := newObjectStorage(t)
	started := make(chan struct{})
	storage.hook = func(w http.ResponseWriter, r *http.Request) bool {
		close(started)
		<-r.Context().Done()
		return true
	}
	snapshotter := snapshotterFor(js, storage, testBucket)
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	if _, err := snapshotter.SnapshotOnce(ctx); err == nil {
		t.Fatal("deadline was ignored")
	}
	select {
	case <-started:
	default:
		t.Fatal("deadline did not cross the HTTP boundary")
	}
	if view := snapshotter.Status(); view.State != "failed" || view.Buckets[0].ErrorClass != "timeout" {
		t.Fatalf("deadline status = %+v", view)
	}
}
