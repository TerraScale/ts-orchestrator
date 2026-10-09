package kvsnapshot

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const (
	testCell   = "gru-1"
	testBucket = "TS_SERVICE_SET"
)

var testConfig = Config{Enabled: true, Region: "sa-saopaulo-1", Namespace: "terrascale", Bucket: "gru-1-head",
	KMSKeyID: "ocid1.key.oc1.sa-saopaulo-1.head"}

// startJetStream starts one empty single-server cell; a second call stands in
// for a controller set rebuilt with an empty store.
func startJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go broker.Start()
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("embedded NATS did not start")
	}
	t.Cleanup(func() {
		broker.Shutdown()
		broker.WaitForShutdown()
	})
	conn, err := nats.Connect(broker.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	return js
}

type fakeError struct {
	status int
	code   string
}

func (err fakeError) Error() string           { return fmt.Sprintf("%d %s", err.status, err.code) }
func (err fakeError) GetHTTPStatusCode() int  { return err.status }
func (err fakeError) GetMessage() string      { return err.code }
func (err fakeError) GetCode() string         { return err.code }
func (err fakeError) GetOpcRequestID() string { return "request" }

type fakeObject struct {
	data []byte
	etag string
}

// fakeObjects follows Object Storage's conditional write and checksum rules.
type fakeObjects struct {
	mu      sync.Mutex
	objects map[string]fakeObject
	puts    int // successful PutObject calls
	etags   int
	getErr  error
	putErr  error
	lastKMS string
}

func newFakeObjects() *fakeObjects { return &fakeObjects{objects: map[string]fakeObject{}} }

func (fake *fakeObjects) GetObject(_ context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.getErr != nil {
		return objectstorage.GetObjectResponse{}, fake.getErr
	}
	object, ok := fake.objects[*request.ObjectName]
	if !ok {
		return objectstorage.GetObjectResponse{}, fakeError{404, "ObjectNotFound"}
	}
	return objectstorage.GetObjectResponse{Content: io.NopCloser(bytes.NewReader(object.data)),
		ContentLength: new(int64(len(object.data))), ETag: new(object.etag)}, nil
}

func (fake *fakeObjects) PutObject(_ context.Context, request objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.putErr != nil {
		return objectstorage.PutObjectResponse{}, fake.putErr
	}
	data, err := io.ReadAll(request.PutObjectBody)
	if err != nil {
		return objectstorage.PutObjectResponse{}, err
	}
	digest := sha256.Sum256(data)
	if request.OpcContentSha256 == nil || *request.OpcContentSha256 != base64.StdEncoding.EncodeToString(digest[:]) ||
		*request.ContentLength != int64(len(data)) {
		return objectstorage.PutObjectResponse{}, fakeError{400, "InvalidChecksum"}
	}
	current, exists := fake.objects[*request.ObjectName]
	if request.IfMatch != nil && !exists {
		return objectstorage.PutObjectResponse{}, fakeError{404, "ObjectNotFound"}
	}
	if request.IfNoneMatch != nil && exists || request.IfMatch != nil && current.etag != *request.IfMatch {
		return objectstorage.PutObjectResponse{}, fakeError{412, "PreconditionFailed"}
	}
	fake.puts++
	fake.etags++
	if request.OpcSseKmsKeyId != nil {
		fake.lastKMS = *request.OpcSseKmsKeyId
	}
	etag := fmt.Sprintf("etag-%d", fake.etags)
	fake.objects[*request.ObjectName] = fakeObject{data: data, etag: etag}
	return objectstorage.PutObjectResponse{ETag: new(etag)}, nil
}

func (fake *fakeObjects) set(t *testing.T, document Document) {
	t.Helper()
	data, err := encodeDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	fake.setRaw(document.Bucket, data)
}

func (fake *fakeObjects) setRaw(bucket string, data []byte) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.etags++
	fake.objects[testConfig.objectName(testCell, bucket)] = fakeObject{data: data, etag: fmt.Sprintf("etag-%d", fake.etags)}
}

func (fake *fakeObjects) document(t *testing.T, bucket string) Document {
	t.Helper()
	fake.mu.Lock()
	object := fake.objects[testConfig.objectName(testCell, bucket)]
	fake.mu.Unlock()
	document, err := decodeDocument(object.data, testCell, bucket)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func objectsFor(fake *fakeObjects) *Objects {
	return &Objects{Client: fake, Config: testConfig, Cell: testCell}
}

func snapshotterFor(js jetstream.JetStream, fake *fakeObjects, buckets ...string) *Snapshotter {
	return &Snapshotter{JS: js, Objects: objectsFor(fake), Buckets: buckets,
		Leader: func() bool { return true }, Interval: time.Second}
}

func openBucket(t *testing.T, js jetstream.JetStream, bucket string) jetstream.KeyValue {
	t.Helper()
	kv, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: bucket, Description: "test bucket",
		History: 4, MaxValueSize: 4096, MaxBytes: 1 << 20, TTL: time.Hour, Compression: true,
		Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	return kv
}

func put(t *testing.T, kv jetstream.KeyValue, key string, value []byte) {
	t.Helper()
	if _, err := kv.Put(t.Context(), key, value); err != nil {
		t.Fatal(err)
	}
}

func value(t *testing.T, kv jetstream.KeyValue, key string) ([]byte, bool) {
	t.Helper()
	entry, err := kv.Get(t.Context(), key)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return entry.Value(), true
}

func restore(t *testing.T, js jetstream.JetStream, fake *fakeObjects, buckets ...string) RestoreReport {
	t.Helper()
	report, err := Restore(t.Context(), js, objectsFor(fake), buckets, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return report
}

// A rebuilt cell gets back every live value byte for byte, so a signed
// value verifies without being signed again, and deleted keys stay gone.
func TestRestoreRebuildsSignedValuesInAnEmptyCell(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed := []byte(`{"generation":7,"services":["ts-auth"]}`)
	signature := ed25519.Sign(private, signed)
	binary := []byte{0, 0xff, 0xfe, '\n', 0x80}

	old := startJetStream(t)
	kv := openBucket(t, old, testBucket)
	put(t, kv, "set.current", append(signature, signed...))
	put(t, kv, "binary", binary)
	put(t, kv, "deleted", []byte("gone"))
	put(t, kv, "binary", binary) // a second revision of one key
	if err := kv.Delete(t.Context(), "deleted"); err != nil {
		t.Fatal(err)
	}
	fake := newFakeObjects()
	written, err := snapshotterFor(old, fake, testBucket, "TS_ABSENT").SnapshotOnce(t.Context())
	if err != nil || len(written) != 1 || written[0] != testBucket {
		t.Fatalf("snapshot = %v, %v", written, err)
	}
	if fake.lastKMS != testConfig.KMSKeyID {
		t.Fatalf("snapshot KMS key = %q", fake.lastKMS)
	}

	rebuilt := startJetStream(t)
	if done, err := RestoreComplete(t.Context(), rebuilt, 1); err != nil || done {
		t.Fatalf("fresh cell restore complete = %v, %v", done, err)
	}
	report := restore(t, rebuilt, fake, testBucket, "TS_ABSENT")
	if len(report.Buckets) != 1 || report.Written != 2 || report.Kept != 0 {
		t.Fatalf("restore report = %+v", report)
	}
	restored, err := rebuilt.KeyValue(t.Context(), testBucket)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := value(t, restored, "set.current")
	if !ed25519.Verify(public, got[ed25519.SignatureSize:], got[:ed25519.SignatureSize]) {
		t.Fatal("restored signed value no longer verifies")
	}
	if got, _ := value(t, restored, "binary"); !bytes.Equal(got, binary) {
		t.Fatalf("binary value = %x", got)
	}
	if _, ok := value(t, restored, "deleted"); ok {
		t.Fatal("deleted key was restored")
	}
	status, err := restored.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	config := status.Config()
	if config.History != 4 || config.MaxValueSize != 4096 || config.MaxBytes != -1 || config.TTL != 0 ||
		!config.Compression || config.Description != "test bucket" {
		t.Fatalf("restored bucket config = %+v", config)
	}
	if done, err := RestoreComplete(t.Context(), rebuilt, 1); err != nil || !done {
		t.Fatalf("restore complete = %v, %v", done, err)
	}

	// A later boot never restores again: a key deleted after the restore
	// stays deleted, even when it is purged.
	if err := restored.Purge(t.Context(), "binary"); err != nil {
		t.Fatal(err)
	}
	if report := restore(t, rebuilt, fake, testBucket); len(report.Buckets) != 0 || report.Written != 0 {
		t.Fatalf("second restore = %+v", report)
	}
	if _, ok := value(t, restored, "binary"); ok {
		t.Fatal("a completed restore ran again")
	}
}

// While a plan runs, a value written, updated or deleted by a controller
// that already finished it always wins over the snapshot.
func TestRestoreNeverOverwritesOrResurrectsKeys(t *testing.T) {
	fake := newFakeObjects()
	fake.set(t, Document{Version: 1, Cell: testCell, Bucket: testBucket, StreamCreated: time.Now().Add(-time.Hour),
		Sequence: 9, TakenAt: time.Now(), Config: BucketConfig{History: 4, MaxValueSize: 4096},
		Entries: []Entry{{Key: "deleted", Value: []byte("old")}, {Key: "missing", Value: []byte("old")},
			{Key: "updated", Value: []byte("old")}}})
	js := startJetStream(t)
	plans, err := openPlans(t.Context(), js, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plans.Create(t.Context(), restorePlanKey, []byte(`{"version":1,"state":"running","buckets":["`+
		testBucket+`"],"decided_at":"2026-10-05T00:00:00Z"}`)); err != nil {
		t.Fatal(err)
	}
	kv := openBucket(t, js, testBucket)
	put(t, kv, "updated", []byte("live"))
	put(t, kv, "deleted", []byte("live"))
	if err := kv.Delete(t.Context(), "deleted"); err != nil {
		t.Fatal(err)
	}

	report := restore(t, js, fake, testBucket)
	if report.Written != 1 || report.Kept != 2 {
		t.Fatalf("restore report = %+v", report)
	}
	if got, _ := value(t, kv, "updated"); string(got) != "live" {
		t.Fatalf("live value replaced by %q", got)
	}
	if _, ok := value(t, kv, "deleted"); ok {
		t.Fatal("deleted key was resurrected")
	}
	if got, _ := value(t, kv, "missing"); string(got) != "old" {
		t.Fatalf("missing key = %q", got)
	}
}

// Without a plan, a bucket that already holds values is live: it is left out
// of the plan, as is a bucket without a snapshot.
func TestRestorePlanSkipsWrittenBuckets(t *testing.T) {
	fake := newFakeObjects()
	for _, bucket := range []string{testBucket, "TS_ROLLOUTS"} {
		fake.set(t, Document{Version: 1, Cell: testCell, Bucket: bucket, StreamCreated: time.Now(), Sequence: 1,
			TakenAt: time.Now(), Config: BucketConfig{History: 1, MaxValueSize: -1},
			Entries: []Entry{{Key: "a", Value: []byte("snapshot")}}})
	}
	js := startJetStream(t)
	live := openBucket(t, js, testBucket)
	put(t, live, "b", []byte("live"))
	report := restore(t, js, fake, testBucket, "TS_ROLLOUTS", "TS_OCI_DESIRED")
	if len(report.Buckets) != 1 || report.Buckets[0] != "TS_ROLLOUTS" || report.Written != 1 {
		t.Fatalf("restore report = %+v", report)
	}
	if _, ok := value(t, live, "a"); ok {
		t.Fatal("a live bucket received snapshot values")
	}
}

// A cell whose authority log holds records kept its JetStream state: its
// first boot with snapshots enabled restores nothing and reads no OCI, even
// before the controllers are granted the prefix.
func TestRestoreLeavesALiveCellAlone(t *testing.T) {
	js := startJetStream(t)
	if _, err := js.CreateStream(t.Context(), jetstream.StreamConfig{Name: authority.ControlStreamName,
		Subjects: []string{"control.test"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(t.Context(), "control.test", []byte("lease")); err != nil {
		t.Fatal(err)
	}
	fake := newFakeObjects()
	fake.getErr = fakeError{404, "NotAuthorizedOrNotFound"}
	if report := restore(t, js, fake, testBucket); len(report.Buckets) != 0 {
		t.Fatalf("live cell restore = %+v", report)
	}
	if _, err := js.KeyValue(t.Context(), testBucket); !errors.Is(err, jetstream.ErrBucketNotFound) {
		t.Fatalf("live cell got a restored bucket: %v", err)
	}
	if done, err := RestoreComplete(t.Context(), js, 1); err != nil || !done {
		t.Fatalf("live cell restore complete = %v, %v", done, err)
	}
}

// A controller that finds another controller's plan follows it.
func TestRestoreFollowsAnExistingPlan(t *testing.T) {
	fake := newFakeObjects()
	for _, bucket := range []string{testBucket, "TS_ROLLOUTS"} {
		fake.set(t, Document{Version: 1, Cell: testCell, Bucket: bucket, StreamCreated: time.Now(), Sequence: 1,
			TakenAt: time.Now(), Config: BucketConfig{History: 1, MaxValueSize: -1},
			Entries: []Entry{{Key: "a", Value: []byte("snapshot")}}})
	}
	js := startJetStream(t)
	plans, err := openPlans(t.Context(), js, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plans.Create(t.Context(), restorePlanKey,
		[]byte(`{"version":1,"state":"running","buckets":["TS_ROLLOUTS"],"decided_at":"2026-10-05T00:00:00Z"}`)); err != nil {
		t.Fatal(err)
	}
	if report := restore(t, js, fake, testBucket, "TS_ROLLOUTS"); len(report.Buckets) != 1 || report.Written != 1 {
		t.Fatalf("restore report = %+v", report)
	}
	if _, err := js.KeyValue(t.Context(), testBucket); !errors.Is(err, jetstream.ErrBucketNotFound) {
		t.Fatalf("an unplanned bucket was restored: %v", err)
	}
}

// A snapshot that is not exactly this cell's bucket, or that cannot be read,
// fails the restore before any plan is recorded, so the next boot retries.
func TestRestoreRejectsTamperedOrUnreadableSnapshots(t *testing.T) {
	valid := Document{Version: 1, Cell: testCell, Bucket: testBucket, StreamCreated: time.Now(), Sequence: 3,
		TakenAt: time.Now(), Config: BucketConfig{History: 2, MaxValueSize: 8},
		Entries: []Entry{{Key: "a", Value: []byte("1")}, {Key: "b", Value: []byte("2")}}}
	encoded, err := encodeDocument(valid)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Document){
		"other cell":   func(document *Document) { document.Cell = "fra-1" },
		"other bucket": func(document *Document) { document.Bucket = "TS_ROLLOUTS" },
		"version":      func(document *Document) { document.Version = 2 },
		"no lineage":   func(document *Document) { document.StreamCreated = time.Time{} },
		"no sequence":  func(document *Document) { document.Sequence = 0 },
		"unsorted": func(document *Document) {
			document.Entries[0], document.Entries[1] = document.Entries[1], document.Entries[0]
		},
		"duplicate key":    func(document *Document) { document.Entries[1].Key = "a" },
		"invalid key":      func(document *Document) { document.Entries[0].Key = "a b" },
		"dot key":          func(document *Document) { document.Entries[0].Key = ".a" },
		"oversized value":  func(document *Document) { document.Entries[0].Value = []byte("123456789") },
		"history":          func(document *Document) { document.Config.History = 0 },
		"zero value limit": func(document *Document) { document.Config.MaxValueSize = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			document := valid
			document.Entries = append([]Entry(nil), valid.Entries...)
			mutate(&document)
			data, err := encodeDocument(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeDocument(data, testCell, testBucket); err == nil {
				t.Fatal("tampered snapshot was accepted")
			}
		})
	}
	for name, data := range map[string][]byte{
		"unknown field": bytes.Replace(encoded, []byte(`{"version"`), []byte(`{"extra":1,"version"`), 1),
		"truncated":     encoded[:len(encoded)/2],
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeDocument(data, testCell, testBucket); err == nil {
				t.Fatal("malformed snapshot was accepted")
			}
		})
	}

	js := startJetStream(t)
	tampered := valid
	tampered.Cell = "fra-1"
	data, err := encodeDocument(tampered)
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeObjects()
	fake.setRaw(testBucket, data)
	if _, err := Restore(t.Context(), js, objectsFor(fake), []string{testBucket}, 1, time.Now()); err == nil {
		t.Fatal("restore accepted another cell's snapshot")
	}
	fake = newFakeObjects()
	fake.getErr = fakeError{404, "BucketNotFound"}
	if _, err := Restore(t.Context(), js, objectsFor(fake), []string{testBucket}, 1, time.Now()); err == nil {
		t.Fatal("restore treated an unreadable Object Storage bucket as an empty snapshot")
	}
	if done, err := RestoreComplete(t.Context(), js, 1); err != nil || done {
		t.Fatalf("failed restore recorded a plan: %v, %v", done, err)
	}
	plans, err := openPlans(t.Context(), js, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plans.Get(t.Context(), restorePlanKey); !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatalf("failed restore left a plan: %v", err)
	}

	// A truncated download is refused even when its prefix would decode.
	fake = newFakeObjects()
	fake.setRaw(testBucket, encoded)
	client := truncatingClient{fake}
	if _, _, _, err := (&Objects{Client: client, Config: testConfig, Cell: testCell}).Get(t.Context(), testBucket); err == nil {
		t.Fatal("a download shorter than its content length was accepted")
	}
}

type truncatingClient struct{ *fakeObjects }

func (client truncatingClient) GetObject(ctx context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	response, err := client.fakeObjects.GetObject(ctx, request)
	if err == nil {
		*response.ContentLength++
	}
	return response, err
}

// Snapshots upload only on change, never roll back a newer stream's snapshot
// or a higher sequence, and survive an ETag that moved underneath them.
func TestSnapshotUploadsOnlyForwardChanges(t *testing.T) {
	js := startJetStream(t)
	kv := openBucket(t, js, testBucket)
	put(t, kv, "a", []byte("1"))
	fake := newFakeObjects()
	snapshotter := snapshotterFor(js, fake, testBucket)
	snapshot := func() []string {
		t.Helper()
		written, err := snapshotter.SnapshotOnce(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return written
	}
	if written := snapshot(); len(written) != 1 {
		t.Fatalf("first snapshot wrote %v", written)
	}
	if written := snapshot(); len(written) != 0 || fake.puts != 1 {
		t.Fatalf("unchanged bucket wrote %v (%d puts)", written, fake.puts)
	}

	// Another leader already uploaded this stream's newer state.
	put(t, kv, "b", []byte("2"))
	ahead := fake.document(t, testBucket)
	ahead.Sequence = 2
	ahead.Entries = append(ahead.Entries, Entry{Key: "b", Value: []byte("2")})
	fake.set(t, ahead)
	if written := snapshot(); len(written) != 0 || fake.puts != 1 {
		t.Fatalf("snapshot rewrote a current object: %v (%d puts)", written, fake.puts)
	}

	// An older stream's object is superseded once the ETag moved.
	behind := fake.document(t, testBucket)
	behind.StreamCreated = behind.StreamCreated.Add(-time.Hour)
	behind.Sequence = 1000
	fake.set(t, behind)
	put(t, kv, "c", []byte("3"))
	if written := snapshot(); len(written) != 1 {
		t.Fatalf("newer stream did not supersede an older one: %v", written)
	}
	current := fake.document(t, testBucket)
	if current.Sequence != 3 || len(current.Entries) != 3 || string(current.Entries[2].Value) != "3" {
		t.Fatalf("snapshot = %+v", current)
	}

	// A newer stream's object is never overwritten by this older one.
	newer := current
	newer.StreamCreated = newer.StreamCreated.Add(time.Hour)
	newer.Sequence = 1
	fake.set(t, newer)
	put(t, kv, "d", []byte("4"))
	if _, err := snapshotter.SnapshotOnce(t.Context()); !errors.Is(err, ErrNewerLineage) {
		t.Fatalf("older stream overwrite error = %v", err)
	}
	if got := fake.document(t, testBucket); !got.StreamCreated.Equal(newer.StreamCreated) {
		t.Fatal("newer stream's snapshot was overwritten")
	}
}

// A snapshot object deleted behind the leader's cached ETag is written
// again on the next change instead of failing every pass.
func TestSnapshotRewritesADeletedObject(t *testing.T) {
	js := startJetStream(t)
	kv := openBucket(t, js, testBucket)
	put(t, kv, "a", []byte("1"))
	fake := newFakeObjects()
	snapshotter := snapshotterFor(js, fake, testBucket)
	if _, err := snapshotter.SnapshotOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	clear(fake.objects)
	fake.mu.Unlock()
	put(t, kv, "b", []byte("2"))
	if written, err := snapshotter.SnapshotOnce(t.Context()); err != nil || len(written) != 1 {
		t.Fatalf("rewrite = %v, %v", written, err)
	}
	if document := fake.document(t, testBucket); len(document.Entries) != 2 {
		t.Fatalf("rewritten snapshot = %+v", document)
	}
}

// A follower never uploads; the leader check gates every pass.
func TestSnapshotRunsOnlyOnTheLeader(t *testing.T) {
	js := startJetStream(t)
	put(t, openBucket(t, js, testBucket), "a", []byte("1"))
	fake := newFakeObjects()
	snapshotter := snapshotterFor(js, fake, testBucket)
	snapshotter.Leader = func() bool { return false }
	snapshotter.Interval = 10 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if err := snapshotter.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("run = %v", err)
	}
	if fake.puts != 0 {
		t.Fatalf("follower wrote %d snapshots", fake.puts)
	}
}

// The schedule is read while Run runs: a pause stops uploads and resuming
// starts them again, without a restart.
func TestSnapshotRunFollowsTheSchedule(t *testing.T) {
	js := startJetStream(t)
	put(t, openBucket(t, js, testBucket), "a", []byte("1"))
	fake := newFakeObjects()
	snapshotter := snapshotterFor(js, fake, testBucket)
	snapshotter.Interval = 10 * time.Millisecond
	var paused atomic.Bool
	paused.Store(true)
	snapshotter.Schedule = func() (time.Duration, bool) { return 10 * time.Millisecond, paused.Load() }
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- snapshotter.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	fake.mu.Lock()
	pausedPuts := fake.puts
	fake.mu.Unlock()
	if pausedPuts != 0 {
		t.Fatalf("paused schedule wrote %d snapshots", pausedPuts)
	}
	paused.Store(false)
	deadline := time.Now().Add(5 * time.Second)
	for {
		fake.mu.Lock()
		puts := fake.puts
		fake.mu.Unlock()
		if puts > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("resumed schedule wrote no snapshot")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run = %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	if err := (Config{}).Validate(); err != nil {
		t.Fatalf("disabled config = %v", err)
	}
	if err := testConfig.Validate(); err != nil {
		t.Fatalf("valid config = %v", err)
	}
	if name := testConfig.objectName(testCell, testBucket); name != "kv-snapshot/v1/gru-1/TS_SERVICE_SET.json" {
		t.Fatalf("object name = %s", name)
	}
	for name, mutate := range map[string]func(*Config){
		"region":         func(config *Config) { config.Region = "mars-1" },
		"namespace":      func(config *Config) { config.Namespace = "Tera Scale" },
		"bucket":         func(config *Config) { config.Bucket = "a/b" },
		"kms key":        func(config *Config) { config.KMSKeyID = "ocid1.vault.x" },
		"short interval": func(config *Config) { config.IntervalSeconds = 1 },
		"long interval":  func(config *Config) { config.IntervalSeconds = 3601 },
		"prefix escape":  func(config *Config) { config.Prefix = "kv/../x" },
		"prefix slash":   func(config *Config) { config.Prefix = "/kv" },
	} {
		t.Run(name, func(t *testing.T) {
			config := testConfig
			mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	for _, buckets := range [][]string{{planBucket}, {testBucket, testBucket}, {"KV.x"}, {strings.Repeat("A", 65)}} {
		if err := validBuckets(buckets); err == nil {
			t.Fatalf("bucket list %v accepted", buckets)
		}
	}
	if err := validBuckets(Buckets); err != nil {
		t.Fatal(err)
	}
}
