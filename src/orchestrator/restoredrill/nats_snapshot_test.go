package restoredrill

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/s2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

type snapshotCaptureStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func (s *snapshotCaptureStore) Put(_ context.Context, region, bucket, object string, body []byte) error {
	s.mu.Lock()
	s.objects[region+"/"+bucket+"/"+object] = append([]byte(nil), body...)
	s.mu.Unlock()
	return nil
}

func (s *snapshotCaptureStore) Head(_ context.Context, region, bucket, object string) (delivery.ObjectIdentity, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, found := s.objects[region+"/"+bucket+"/"+object]
	if !found {
		return delivery.ObjectIdentity{}, false, nil
	}
	return delivery.ObjectIdentity{
		Digest: delivery.SHA256Digest(body), Size: int64(len(body)), ETag: "etag-snapshot", Version: "version-1",
	}, true, nil
}

func (s *snapshotCaptureStore) GetSnapshot(_ context.Context, region, bucket, object string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, found := s.objects[region+"/"+bucket+"/"+object]
	return append([]byte(nil), body...), found, nil
}

func (s *snapshotCaptureStore) body(region, bucket, object string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.objects[region+"/"+bucket+"/"+object]...)
}

func TestNATSJetStreamSnapshotterUploadsRestorableBinaryArchive(t *testing.T) {
	server, err := natsserver.NewServer(&natsserver.Options{
		Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	server.Start()
	if !server.ReadyForConnections(5 * time.Second) {
		t.Fatal("embedded JetStream did not become ready")
	}
	t.Cleanup(func() {
		server.Shutdown()
		server.WaitForShutdown()
	})
	connection, err := nats.Connect(server.ClientURL(), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	js, err := jetstream.New(connection)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{
		Name: "CONTROL_STATE", Subjects: []string{"control.>"}, Storage: jetstream.FileStorage,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(ctx, "control.estate", []byte(`{"generation":9,"regions":["gru","sfo","fra"]}`)); err != nil {
		t.Fatal(err)
	}
	store := &snapshotCaptureStore{objects: map[string][]byte{}}
	snapshotter, err := NewNATSJetStreamSnapshotter(NATSJetStreamSnapshotterConfig{
		Connection: connection, Stream: "CONTROL_STATE", Store: store,
		Region: "gru", Bucket: "control-snapshots", MaxBytes: 8 << 20, Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := SnapshotRequest{
		RunID: "restore-drill-2026-09-04", ObjectKey: "jetstream/control/restore-drill-2026-09-04.epoch-9.snapshot",
		IdempotencyKey: "restore-drill-2026-09-04", ControlEpoch: 9, RestoreEpoch: 9,
	}
	snapshot, err := snapshotter.Snapshot(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	body := store.body("gru", "control-snapshots", request.ObjectKey)
	if snapshot.Size != int64(len(body)) || snapshot.Size == 0 || !delivery.SameDigest(snapshot.Checksum, delivery.SHA256Digest(body)) {
		t.Fatalf("snapshot identity = %+v, bytes=%d", snapshot, len(body))
	}

	archive := tar.NewReader(s2.NewReader(bytes.NewReader(body)))
	entries := 0
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("decode JetStream snapshot: %v", err)
		}
		if header.Name == "" {
			t.Fatal("JetStream snapshot contains an unnamed archive entry")
		}
		if _, err := io.Copy(io.Discard, archive); err != nil {
			t.Fatal(err)
		}
		entries++
	}
	if entries < 3 {
		t.Fatalf("JetStream snapshot archive entries = %d", entries)
	}
	store.mu.Lock()
	store.objects["gru/control-snapshots/"+request.ObjectKey] = []byte(`{"marker":"not-a-jetstream-snapshot"}`)
	store.mu.Unlock()
	if _, err := snapshotter.Snapshot(ctx, request); !errors.Is(err, ErrSnapshotVerification) {
		t.Fatalf("JSON marker snapshot error = %v", err)
	}
}
