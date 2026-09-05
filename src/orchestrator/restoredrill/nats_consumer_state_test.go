package restoredrill

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/s2"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

func TestConsumerStateRejectsMalformedInput(t *testing.T) {
	// Format 2: floors 0/0, delivered 2/2, one pending entry at 1/1,
	// timestamp base 100 minus delta 0, one redelivery for stream 1.
	valid := []byte{22, 2, 0, 0, 2, 2, 1, 200, 1, 1, 1, 0, 1, 1, 1}
	expected := &SnapshotConsumerEvidence{DeliveredConsumer: 2, DeliveredStream: 2, AckPending: 1, Redelivered: 1}
	if !validConsumerState(valid, expected) {
		t.Fatal("valid format-2 checkpoint rejected")
	}
	for length := range len(valid) {
		if validConsumerState(valid[:length], expected) {
			t.Fatalf("truncated checkpoint accepted at %d", length)
		}
	}
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return append(b, 0) },
		func(b []byte) []byte { b[0] = 0; return b },
		func(b []byte) []byte { b[1] = 1; return b },
		func(b []byte) []byte { b[4] = 3; return b },
		func(b []byte) []byte { b[9] = 0; return b },
		func(b []byte) []byte { b[10] = 3; return b },
		func(b []byte) []byte { b[14] = 0; return b },
		func(b []byte) []byte { b[14] = 3; return b },
		func(b []byte) []byte {
			return append(append(b[:6:6], binary.AppendUvarint(nil, ^uint64(0))...), b[7:]...)
		},
		func(b []byte) []byte { return append(append(b[:2:2], 128, 0), b[3:]...) },
	} {
		if validConsumerState(mutate(bytes.Clone(valid)), expected) {
			t.Fatal("malformed checkpoint accepted")
		}
	}
	duplicate := []byte{22, 2, 0, 0, 2, 2, 2, 200, 1, 1, 1, 0, 1, 1, 0, 0}
	if validConsumerState(duplicate, &SnapshotConsumerEvidence{DeliveredConsumer: 2, DeliveredStream: 2, AckPending: 2}) {
		t.Fatal("duplicate pending stream accepted")
	}
	duplicate = []byte{22, 2, 0, 0, 2, 2, 0, 2, 1, 1, 1, 1}
	if validConsumerState(duplicate, &SnapshotConsumerEvidence{DeliveredConsumer: 2, DeliveredStream: 2, Redelivered: 2}) {
		t.Fatal("duplicate redelivery stream accepted")
	}
	overflow := append([]byte{22, 2, 0, 0, 2, 2, 1}, binary.AppendVarint(nil, math.MaxInt64)...)
	overflow = append(overflow, 1, 1)
	overflow = binary.AppendVarint(overflow, math.MinInt64)
	overflow = append(overflow, 1, 1, 1)
	if validConsumerState(overflow, expected) {
		t.Fatal("overflowing pending timestamp accepted")
	}
	if _, ok := stateSequence(math.MaxUint64, 1, 2); ok {
		t.Fatal("overflowing pending sequence accepted")
	}
}

func TestSnapshotRestoresOutstandingAcknowledgementsAndRedelivery(t *testing.T) {
	nc, js := snapshotTestBroker(t)
	ctx := t.Context()
	stream, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "PENDING", Subjects: []string{"pending"}, Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := js.Publish(ctx, "pending", []byte("pending source record")); err != nil {
			t.Fatal(err)
		}
	}
	consumer, err := stream.CreateConsumer(ctx, jetstream.ConsumerConfig{Durable: "DURABLE", AckPolicy: jetstream.AckExplicitPolicy, AckWait: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := consumer.Fetch(3, jetstream.FetchMaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var first jetstream.Msg
	for msg := range batch.Messages() {
		meta, err := msg.Metadata()
		if err != nil {
			t.Fatal(err)
		}
		if meta.Sequence.Stream == 1 {
			first = msg
		}
		if meta.Sequence.Stream == 2 {
			if err := msg.DoubleAck(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	if batch.Error() != nil || first == nil {
		t.Fatal("pending fixture did not deliver")
	}
	if err := first.Nak(); err != nil {
		t.Fatal(err)
	}
	redelivery, err := consumer.Fetch(1, jetstream.FetchMaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	redelivered := false
	for msg := range redelivery.Messages() {
		meta, err := msg.Metadata()
		if err != nil || meta.Sequence.Stream != 1 || meta.NumDelivered != 2 {
			t.Fatal("redelivery fixture differs")
		}
		redelivered = true
	}
	if redelivery.Error() != nil || !redelivered {
		t.Fatal("redelivery was not observed")
	}
	store := &snapshotCaptureStore{objects: map[string][]byte{}}
	snapshotter, err := NewNATSJetStreamSnapshotter(NATSJetStreamSnapshotterConfig{Connection: nc, Stream: "PENDING", Store: store, Region: "gru", Bucket: "snapshots"})
	if err != nil {
		t.Fatal(err)
	}
	request := SnapshotRequest{RunID: "pending", IdempotencyKey: "pending", ObjectKey: "pending.epoch-1.snapshot", ControlEpoch: 1}
	if _, err := snapshotter.Snapshot(ctx, request); err != nil {
		t.Fatal(err)
	}
	target := privateRestoreBroker(t)
	evidence, err := RestorePreliminarySnapshot(ctx, target, "PENDING", store.body("gru", "snapshots", request.ObjectKey), defaultJetStreamSnapshotBytes)
	if err != nil || len(evidence.Consumers) != 1 || evidence.Consumers[0].AckPending != 2 || evidence.Consumers[0].Redelivered != 1 {
		t.Fatalf("outstanding acknowledgement state was not preserved: %+v %v", evidence, err)
	}
	targetJS, err := jetstream.New(target)
	if err != nil {
		t.Fatal(err)
	}
	// After verifying unchanged recovery evidence, shorten the retry timer to
	// observe the restored pending set without a one-minute test delay.
	recovered, err := targetJS.UpdateConsumer(ctx, "PENDING", jetstream.ConsumerConfig{Durable: "DURABLE", AckPolicy: jetstream.AckExplicitPolicy, AckWait: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := recovered.Fetch(2, jetstream.FetchMaxWait(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uint64]bool{}
	for msg := range replayed.Messages() {
		meta, err := msg.Metadata()
		if err != nil || meta.Sequence.Stream == 2 || seen[meta.Sequence.Stream] || meta.NumDelivered < 2 {
			t.Fatal("recovered pending delivery differs")
		}
		seen[meta.Sequence.Stream] = true
		if err := msg.DoubleAck(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if replayed.Error() != nil || len(seen) != 2 || !seen[1] || !seen[3] {
		t.Fatal("original pending set was not redelivered")
	}
	final, err := recovered.Info(ctx)
	if err != nil || final.NumAckPending != 0 || final.AckFloor.Stream != 3 {
		t.Fatalf("recovered acknowledgements did not commit: %+v %v", final, err)
	}
}

func FuzzConsumerStateValidation(f *testing.F) {
	f.Add([]byte{22, 2, 0, 0, 2, 2, 0, 0})
	f.Add([]byte{22, 2, 0, 0, 2, 2, 1, 200, 1, 1, 1, 0, 1, 1, 1})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = validConsumerState(raw, &SnapshotConsumerEvidence{DeliveredConsumer: 2, DeliveredStream: 2, AckPending: 1, Redelivered: 1})
	})
}

func TestMalformedConsumerStateRefusedBeforeRestore(t *testing.T) {
	nc, js := snapshotTestBroker(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	stream, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "STATE", Subjects: []string{"state"}, Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.CreateConsumer(ctx, jetstream.ConsumerConfig{Durable: "DURABLE", AckPolicy: jetstream.AckExplicitPolicy}); err != nil {
		t.Fatal(err)
	}
	snapshotter := &NATSJetStreamSnapshotter{connection: nc, stream: "STATE", maxBytes: 1 << 20}
	archive, response, err := snapshotter.streamSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(s2.NewReader(bytes.NewReader(archive)))
	var changed bytes.Buffer
	compressed := s2.NewWriter(&changed)
	writer := tar.NewWriter(compressed)
	mutated := false
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(header.Name, "/o.dat") {
			body = append(body, 0)
			header.Size = int64(len(body))
			mutated = true
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if writer.Close() != nil || compressed.Close() != nil || !mutated {
		t.Fatal("checkpoint mutation failed")
	}
	manifest := jetStreamSnapshotManifest{Version: 4, Stream: "STATE", RecordsSHA256: response.RecordsSHA256, CreatedAt: time.Now().UTC(), Config: response.Config, State: response.State, Consumers: response.Consumers, ArchiveSHA256: delivery.SHA256Digest(changed.Bytes()), ArchiveSize: int64(changed.Len())}
	envelope, err := encodeJetStreamSnapshotEnvelope(manifest, changed.Bytes(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	target := privateRestoreBroker(t)
	if _, err := RestorePreliminarySnapshot(ctx, target, "STATE", envelope, 1<<20); !errors.Is(err, ErrSnapshotVerification) {
		t.Fatalf("malformed checkpoint reached restore: %v", err)
	}
	targetJS, err := jetstream.New(target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := targetJS.Stream(ctx, "STATE"); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("invalid archive created target state: %v", err)
	}
}
