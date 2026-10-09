package kvsnapshot

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func TestSnapshotStatusRetainsEvidenceAndRefreshesUnchangedBuckets(t *testing.T) {
	js := startJetStream(t)
	kv := openBucket(t, js, testBucket)
	put(t, kv, "secret-document-key", []byte("secret-document-value"))
	put(t, openBucket(t, js, "TS_OTHER"), "a", []byte("other"))
	openBucket(t, js, "TS_EMPTY")
	fake := newFakeObjects()
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
		!view.Buckets[0].LastUploadedAt.Equal(uploadedAt) || fake.puts != 2 {
		t.Fatalf("unchanged status = %+v, puts = %d", view, fake.puts)
	}
	confirmedAt := now

	put(t, kv, "secret-document-key", []byte("new-secret-document-value"))
	fake.putErr = fakeError{403, "secret-error-details"}
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
	for _, secret := range []string{"secret-document", "secret-error-details", "etag-", testConfig.Namespace, testConfig.KMSKeyID} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("snapshot metadata contains %q: %s", secret, encoded)
		}
	}
	view.Buckets[0].State = "modified"
	if snapshotter.Status().Buckets[0].State != "failed" {
		t.Fatal("caller modified retained status")
	}

	fake.putErr = nil
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
	fake := newFakeObjects()
	snapshotter := snapshotterFor(js, fake, testBucket)
	snapshotter.Interval = time.Minute
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	snapshotter.Now = func() time.Time { return now }
	if _, err := snapshotter.SnapshotOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	uploadedAt := now
	now = now.Add(snapshotter.Interval + snapshotPassTimeout)
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
	snapshotter.Schedule = func() (time.Duration, bool) { return time.Minute, true }
	if view := snapshotter.Status(); view.State != "paused" || view.Overdue {
		t.Fatalf("paused status = %+v", view)
	}
	snapshotter.Schedule = func() (time.Duration, bool) { return 10 * time.Minute, false }
	if view := snapshotter.Status(); view.State != "current" || view.Overdue {
		t.Fatalf("extended schedule status = %+v", view)
	}
	snapshotter.Schedule = nil
	now = now.Add(24 * time.Hour)
	if written, err := snapshotter.SnapshotOnce(t.Context()); err != nil || len(written) != 0 {
		t.Fatalf("unchanged snapshot = %v, %v", written, err)
	}
	view = snapshotter.Status()
	if view.State != "current" || view.Overdue || !view.Buckets[0].LastCurrentAt.Equal(now) ||
		!view.Buckets[0].LastUploadedAt.Equal(uploadedAt) || fake.puts != 1 {
		t.Fatalf("unchanged current status = %+v", view)
	}
}

func TestSnapshotStatusRequiresEveryBucketToBeKnown(t *testing.T) {
	now := time.Now()
	snapshotter := &Snapshotter{Buckets: []string{testBucket, "TS_UNKNOWN"}, Interval: time.Minute,
		Leader: func() bool { return true }, Now: func() time.Time { return now }, lastCheckAt: now}
	snapshotter.recordCheck(testBucket, false, "absent", nil)
	if view := snapshotter.Status(); view.State != "unknown" || view.Overdue {
		t.Fatalf("a checked bucket hid an unknown bucket: %+v", view)
	}
	snapshotter.recordCheck("TS_UNKNOWN", false, "empty", nil)
	if view := snapshotter.Status(); view.State != "current" {
		t.Fatalf("successfully checked absent and empty buckets = %+v", view)
	}
}

func TestSnapshotStatusConfirmsAnExistingObjectWithoutClaimingAnUpload(t *testing.T) {
	js := startJetStream(t)
	put(t, openBucket(t, js, testBucket), "a", []byte("value"))
	fake := newFakeObjects()
	if _, err := snapshotterFor(js, fake, testBucket).SnapshotOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshotter := snapshotterFor(js, fake, testBucket)
	if written, err := snapshotter.SnapshotOnce(t.Context()); err != nil || len(written) != 0 {
		t.Fatalf("confirm existing snapshot = %v, %v", written, err)
	}
	view := snapshotter.Status()
	if view.State != "current" || view.Buckets[0].Sequence != 1 || view.Buckets[0].LastCurrentAt.IsZero() ||
		!view.Buckets[0].LastUploadedAt.IsZero() || fake.puts != 1 {
		t.Fatalf("confirmed status = %+v", view)
	}
}

func TestUnchangedSnapshotDetectsStorageFailureAndRepairsMissingObject(t *testing.T) {
	js := startJetStream(t)
	put(t, openBucket(t, js, testBucket), "a", []byte("value"))
	fake := newFakeObjects()
	snapshotter := snapshotterFor(js, fake, testBucket)
	if _, err := snapshotter.SnapshotOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	confirmed := snapshotter.Status().Buckets[0].LastCurrentAt
	fake.getErr = fakeError{403, "NotAuthorized"}
	if _, err := snapshotter.SnapshotOnce(t.Context()); err == nil {
		t.Fatal("unchanged local KV hid an Object Storage failure")
	}
	view := snapshotter.Status()
	if view.State != "failed" || view.Buckets[0].ErrorClass != "unauthorized" || !view.Buckets[0].LastCurrentAt.Equal(confirmed) {
		t.Fatalf("storage failure lost confirmation evidence: %+v", view)
	}
	fake.getErr = nil
	fake.mu.Lock()
	clear(fake.objects)
	fake.mu.Unlock()
	written, err := snapshotter.SnapshotOnce(t.Context())
	if err != nil || len(written) != 1 || fake.puts != 2 || snapshotter.Status().State != "current" {
		t.Fatalf("missing unchanged object was not repaired: %v, %v, puts=%d", written, err, fake.puts)
	}
}

func TestSnapshotStatusReadsCurrentAuthorityAndSchedule(t *testing.T) {
	var leader, paused atomic.Bool
	leader.Store(true)
	snapshotter := &Snapshotter{Buckets: []string{testBucket}, Interval: time.Minute,
		Leader: leader.Load, Schedule: func() (time.Duration, bool) { return 2 * time.Minute, paused.Load() }}
	if view := snapshotter.Status(); view.State != "unknown" || view.IntervalSeconds != 120 {
		t.Fatalf("initial status = %+v", view)
	}
	leader.Store(false)
	if view := snapshotter.Status(); view.State != "follower" {
		t.Fatalf("follower status = %+v", view)
	}
	paused.Store(true)
	if view := snapshotter.Status(); view.State != "paused" {
		t.Fatalf("paused status = %+v", view)
	}
	leader.Store(true)
	paused.Store(false)
	if view := snapshotter.Status(); view.State != "unknown" {
		t.Fatalf("resumed status without evidence = %+v", view)
	}
}

type blockedSnapshotClient struct {
	*fakeObjects
	started  chan struct{}
	release  chan struct{}
	deadline chan time.Time
}

type blockedBucketSnapshotClient struct {
	*fakeObjects
	object  string
	started chan time.Time
}

func (client blockedBucketSnapshotClient) GetObject(ctx context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	if *request.ObjectName == client.object {
		deadline, _ := ctx.Deadline()
		client.started <- deadline
		<-ctx.Done()
		return objectstorage.GetObjectResponse{}, ctx.Err()
	}
	return client.fakeObjects.GetObject(ctx, request)
}

func TestSnapshotDeadlineDoesNotStarveLaterBuckets(t *testing.T) {
	js := startJetStream(t)
	put(t, openBucket(t, js, testBucket), "a", []byte("blocked"))
	put(t, openBucket(t, js, "TS_OTHER"), "a", []byte("healthy"))
	fake := newFakeObjects()
	client := blockedBucketSnapshotClient{fakeObjects: fake, object: testConfig.objectName(testCell, testBucket),
		started: make(chan time.Time, 1)}
	snapshotter := snapshotterFor(js, fake, testBucket, "TS_OTHER")
	snapshotter.Objects.Client = client
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
		case deadline := <-client.started:
			if deadline.IsZero() || time.Until(deadline) > snapshotPassTimeout {
				t.Fatalf("snapshot deadline = %s, want at most %s", deadline, snapshotPassTimeout)
			}
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
	if written := pass(); len(written) != 0 || fake.puts != 1 {
		t.Fatalf("unchanged healthy snapshot was rewritten: %v, puts=%d", written, fake.puts)
	}
	view = snapshotter.Status()
	if view.Buckets[1].State != "current" || !view.Buckets[1].LastCurrentAt.Equal(now) ||
		!view.Buckets[1].LastUploadedAt.Equal(uploadedAt) || !view.LastCheckAt.Equal(now) {
		t.Fatalf("fresh pass did not reconfirm healthy snapshot: %+v", view)
	}
}

func (client blockedSnapshotClient) PutObject(ctx context.Context, request objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	deadline, _ := ctx.Deadline()
	client.deadline <- deadline
	close(client.started)
	select {
	case <-ctx.Done():
		return objectstorage.PutObjectResponse{}, ctx.Err()
	case <-client.release:
		return client.fakeObjects.PutObject(ctx, request)
	}
}

func TestSnapshotStatusDoesNotWaitForAnUploadAndIsThreadSafe(t *testing.T) {
	js := startJetStream(t)
	put(t, openBucket(t, js, testBucket), "a", []byte("value"))
	fake := newFakeObjects()
	if _, err := snapshotterFor(js, fake, testBucket).SnapshotOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	put(t, openBucket(t, js, "TS_OTHER"), "a", []byte("other"))
	client := blockedSnapshotClient{fakeObjects: fake, started: make(chan struct{}), release: make(chan struct{}),
		deadline: make(chan time.Time, 1)}
	snapshotter := snapshotterFor(js, fake, testBucket, "TS_OTHER")
	snapshotter.Objects.Client = client
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := snapshotter.SnapshotOnce(ctx)
		done <- err
	}()
	select {
	case <-client.started:
	case <-time.After(5 * time.Second):
		t.Fatal("upload did not start")
	}
	if deadline := <-client.deadline; deadline.IsZero() || time.Until(deadline) > snapshotPassTimeout {
		t.Fatalf("snapshot upload deadline = %s, want at most %s", deadline, snapshotPassTimeout)
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
	close(client.release)
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
		err   error
		class string
	}{
		{context.DeadlineExceeded, "timeout"}, {context.Canceled, "canceled"},
		{ErrNewerLineage, "newer_lineage"}, {ErrConflict, "conflict"},
		{fakeError{401, "secret"}, "unauthorized"}, {fakeError{429, "secret"}, "throttled"},
		{errors.New("secret upstream error"), "unavailable"},
	} {
		if got := snapshotErrorClass(fmt.Errorf("wrapped: %w", test.err)); got != test.class {
			t.Errorf("class = %q, want %q", got, test.class)
		}
	}
}
