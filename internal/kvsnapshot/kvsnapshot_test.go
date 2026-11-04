package kvsnapshot

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	testCell   = "gru"
	testBucket = "TS_SERVICE_SET"
)

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

func objectsFor(storage *objectStorageServer) *Objects {
	return &Objects{Client: storage.client, Namespace: testNamespace, Bucket: testObjectBucket, Cell: testCell}
}

func snapshotterFor(js jetstream.JetStream, storage *objectStorageServer, buckets ...string) *Snapshotter {
	return &Snapshotter{JS: js, Objects: objectsFor(storage), Buckets: buckets,
		Leader: func() bool { return true }}
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

func restore(t *testing.T, js jetstream.JetStream, fake *objectStorageServer, buckets ...string) RestoreReport {
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
	fake := newObjectStorage(t)
	written, err := snapshotterFor(old, fake, testBucket, "TS_ABSENT").SnapshotOnce(t.Context())
	if err != nil || len(written) != 1 || written[0] != testBucket {
		t.Fatalf("snapshot = %v, %v", written, err)
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
		"other cell": func(document *Document) { document.Cell = "fra-1" },
	} {
		t.Run(name, func(t *testing.T) {
			document := valid
			document.Entries = append([]Entry(nil), valid.Entries...)
			mutate(&document)
			data, err := encodeDocument(document)
			if err != nil {
				t.Fatal(err)
			}
			assertRestoreRejected(t, data)
		})
	}
	for name, data := range map[string][]byte{
		"unknown field": bytes.Replace(encoded, []byte(`{"version"`), []byte(`{"extra":1,"version"`), 1),
		"truncated":     encoded[:len(encoded)/2],
	} {
		t.Run(name, func(t *testing.T) {
			assertRestoreRejected(t, data)
		})
	}

	for _, fault := range []*storageFault{{404, "BucketNotFound"}} {
		t.Run(fault.code, func(t *testing.T) {
			storage := newObjectStorage(t)
			storage.fail("GET", fault)
			assertRestoreFailsBeforePlan(t, startJetStream(t), storage)
		})
	}
	t.Run("content length", func(t *testing.T) {
		storage := newObjectStorage(t)
		storage.setRaw(t, testBucket, encoded)
		storage.hook = func(w http.ResponseWriter, r *http.Request) bool {
			w.Header().Set("Content-Length", strconv.Itoa(len(encoded)+1))
			w.Header().Set("ETag", "truncated")
			_, _ = w.Write(encoded)
			return true
		}
		assertRestoreFailsBeforePlan(t, startJetStream(t), storage)
	})
}

func assertRestoreRejected(t *testing.T, data []byte) {
	t.Helper()
	storage := newObjectStorage(t)
	storage.setRaw(t, testBucket, data)
	assertRestoreFailsBeforePlan(t, startJetStream(t), storage)
}

func assertRestoreFailsBeforePlan(t *testing.T, js jetstream.JetStream, storage *objectStorageServer) {
	t.Helper()
	if _, err := Restore(t.Context(), js, objectsFor(storage), []string{testBucket}, 1, time.Now()); err == nil {
		t.Fatal("restore accepted an unreadable or invalid snapshot")
	}
	plans, err := openPlans(t.Context(), js, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plans.Get(t.Context(), restorePlanKey); !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatalf("failed restore left a plan: %v", err)
	}
}
