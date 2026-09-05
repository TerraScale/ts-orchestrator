package restoredrill

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
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
	stream, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "CONTROL_STATE", Subjects: []string{"control.>"}, Storage: jetstream.FileStorage, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range []struct {
		subject string
		body    []byte
		header  nats.Header
	}{
		{"control.estate", []byte(`{"generation":9,"regions":["gru","sfo","fra"]}`), nats.Header{"X-Control-Epoch": []string{"9"}, "X-Record-Kind": []string{"estate", "admitted"}}},
		{"control.receipt", []byte{0, 1, 2, 0xff, 0x00}, nats.Header{"X-Receipt": []string{"durable-operation-9"}}},
		{"control.pending", []byte("next-unconsumed-record"), nats.Header{"X-Resume": []string{"after-checkpoint"}}},
	} {
		if _, err := js.PublishMsg(ctx, &nats.Msg{Subject: record.subject, Data: record.body, Header: record.header}); err != nil {
			t.Fatal(err)
		}
	}
	originals := make([]*jetstream.RawStreamMsg, 3)
	for index := range originals {
		record, err := stream.GetMsg(ctx, uint64(index+1))
		if err != nil {
			t.Fatal(err)
		}
		originals[index] = record
	}
	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{Durable: "CONTROL_CHECKPOINT", AckPolicy: jetstream.AckExplicitPolicy, AckWait: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := consumer.Fetch(2, jetstream.FetchMaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	delivered := 0
	for message := range batch.Messages() {
		if err := message.DoubleAck(ctx); err != nil {
			t.Fatal(err)
		}
		delivered++
	}
	if err := batch.Error(); err != nil || delivered != 2 {
		t.Fatalf("prepare durable checkpoint delivered=%d: %v", delivered, err)
	}
	checkpoint, err := consumer.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.AckFloor.Stream != 2 || checkpoint.AckFloor.Consumer != 2 || checkpoint.NumPending != 1 || checkpoint.NumAckPending != 0 {
		t.Fatalf("fixture checkpoint not committed: %+v", checkpoint)
	}
	before, err := stream.Info(ctx)
	if err != nil {
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
		IdempotencyKey: "restore-drill-2026-09-04", ControlEpoch: 9,
	}
	snapshot, err := snapshotter.Snapshot(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	body := store.body("gru", "control-snapshots", request.ObjectKey)
	if snapshot.Size != int64(len(body)) || snapshot.Size == 0 || !delivery.SameDigest(snapshot.Checksum, delivery.SHA256Digest(body)) {
		t.Fatalf("snapshot identity = %+v, bytes=%d", snapshot, len(body))
	}

	manifest, inner, err := decodeJetStreamSnapshotEnvelope(body, "CONTROL_STATE", 8<<20)
	if err != nil || manifest.Request != request || manifest.State.Msgs != before.State.Msgs {
		t.Fatalf("snapshot envelope: %+v %v", manifest, err)
	}
	archive := tar.NewReader(s2.NewReader(bytes.NewReader(inner)))
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
	// Restore the exact uploaded object into a separate broker/store. Parsing
	// tar alone cannot prove NATS accepts the archive or preserves its checkpoint.
	restoreSnapshotAndVerify(t, ctx, inner, before, originals, checkpoint)
	if retry, err := snapshotter.Snapshot(ctx, request); err != nil || retry != snapshot {
		t.Fatalf("uploaded snapshot readback retry: %+v %v", retry, err)
	}
	store.mu.Lock()
	store.objects["gru/control-snapshots/"+request.ObjectKey] = []byte(`{"marker":"not-a-jetstream-snapshot"}`)
	store.mu.Unlock()
	if _, err := snapshotter.Snapshot(ctx, request); !errors.Is(err, ErrSnapshotVerification) {
		t.Fatalf("JSON marker snapshot error = %v", err)
	}
}

func restoreSnapshotAndVerify(t *testing.T, ctx context.Context, archive []byte, before *jetstream.StreamInfo, originals []*jetstream.RawStreamMsg, checkpoint *jetstream.ConsumerInfo) {
	t.Helper()
	broker, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("restore broker did not start")
	}
	nc, err := nats.Connect(broker.ClientURL(), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Stream(ctx, before.Config.Name); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("restore target was not empty: %v", err)
	}
	// Config/State are the original server-observed snapshot boundary. The
	// archive is streamed through the pinned server's public restore API only.
	payload, err := json.Marshal(struct {
		Config jetstream.StreamConfig `json:"config"`
		State  jetstream.StreamState  `json:"state"`
	}{before.Config, before.State})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := nc.RequestWithContext(ctx, fmt.Sprintf(natsserver.JSApiStreamRestoreT, before.Config.Name), payload)
	if err != nil {
		t.Fatal(err)
	}
	var response natsserver.JSApiStreamRestoreResponse
	if err := json.Unmarshal(reply.Data, &response); err != nil || response.Error != nil || response.DeliverSubject == "" {
		t.Fatalf("public restore admission: %+v %v", response, err)
	}
	for offset := 0; offset < len(archive); offset += 32 << 10 {
		end := offset + (32 << 10)
		if end > len(archive) {
			end = len(archive)
		}
		ack, err := nc.RequestWithContext(ctx, response.DeliverSubject, archive[offset:end])
		if err != nil {
			t.Fatal(err)
		}
		if len(ack.Data) != 0 {
			t.Fatalf("restore chunk rejected: %s", ack.Data)
		}
	}
	reply, err = nc.RequestWithContext(ctx, response.DeliverSubject, nil)
	if err != nil {
		t.Fatal(err)
	}
	var completed natsserver.JSApiStreamCreateResponse
	if err := json.Unmarshal(reply.Data, &completed); err != nil || completed.Error != nil {
		t.Fatalf("public restore completion: %+v %v", completed, err)
	}
	stream, err := js.Stream(ctx, before.Config.Name)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if restored.State.Msgs != before.State.Msgs || restored.State.FirstSeq != before.State.FirstSeq || restored.State.LastSeq != before.State.LastSeq || restored.State.Consumers != 1 {
		t.Fatalf("restored stream state differs: before=%+v restored=%+v", before.State, restored.State)
	}
	for _, original := range originals {
		got, err := stream.GetMsg(ctx, original.Sequence)
		if err != nil {
			t.Fatal(err)
		}
		if got.Subject != original.Subject || got.Sequence != original.Sequence || !bytes.Equal(got.Data, original.Data) || !reflect.DeepEqual(got.Header, original.Header) || !got.Time.Equal(original.Time) {
			t.Fatalf("restored raw record changed: original=%+v restored=%+v", original, got)
		}
	}
	consumer, err := stream.Consumer(ctx, checkpoint.Name)
	if err != nil {
		t.Fatalf("durable consumer absent from archive: %v", err)
	}
	actual, err := consumer.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual.Config, checkpoint.Config) || actual.Delivered.Consumer != checkpoint.Delivered.Consumer || actual.Delivered.Stream != checkpoint.Delivered.Stream || actual.AckFloor.Consumer != checkpoint.AckFloor.Consumer || actual.AckFloor.Stream != checkpoint.AckFloor.Stream || actual.NumAckPending != checkpoint.NumAckPending || actual.NumPending != checkpoint.NumPending || actual.NumRedelivered != checkpoint.NumRedelivered {
		t.Fatalf("durable checkpoint changed: before=%+v restored=%+v", checkpoint, actual)
	}
	next, err := consumer.Next(jetstream.FetchMaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := next.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Sequence.Stream != 3 || metadata.Sequence.Consumer != 3 || next.Subject() != originals[2].Subject || !bytes.Equal(next.Data(), originals[2].Data) {
		t.Fatalf("consumer did not resume after acknowledged checkpoint: %+v", metadata)
	}
	if err := next.DoubleAck(ctx); err != nil {
		t.Fatal(err)
	}
	ack, err := js.Publish(ctx, "control.after-restore", []byte("new record"))
	if err != nil || ack.Sequence != before.State.LastSeq+1 {
		t.Fatalf("restored stream did not retain sequence allocator: %+v %v", ack, err)
	}
}
