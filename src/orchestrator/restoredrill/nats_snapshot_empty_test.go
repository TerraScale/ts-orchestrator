package restoredrill

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/s2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

func TestNATSSnapshotEmptyStreamsPreserveAllocatorAndConsumer(t *testing.T) {
	for _, purged := range []bool{false, true} {
		name := "fresh"
		if purged {
			name = "purged"
		}
		t.Run(name, func(t *testing.T) {
			nc, js := snapshotTestBroker(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			stream, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "EMPTY", Subjects: []string{"empty"}, Storage: jetstream.FileStorage})
			if err != nil {
				t.Fatal(err)
			}
			consumer, err := stream.CreateConsumer(ctx, jetstream.ConsumerConfig{Name: "CHECKPOINT", Durable: "CHECKPOINT", AckPolicy: jetstream.AckExplicitPolicy})
			if err != nil {
				t.Fatal(err)
			}
			if purged {
				for range 3 {
					if _, err := js.Publish(ctx, "empty", []byte("data")); err != nil {
						t.Fatal(err)
					}
				}
				for range 2 {
					m, err := consumer.Next(jetstream.FetchMaxWait(time.Second))
					if err != nil {
						t.Fatal(err)
					}
					if err := m.DoubleAck(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if err := stream.Purge(ctx); err != nil {
					t.Fatal(err)
				}
			}
			before, err := stream.Info(ctx)
			if err != nil {
				t.Fatal(err)
			}
			checkpoint, err := consumer.Info(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if before.State.Msgs != 0 || (purged && before.State.LastSeq != 3) {
				t.Fatalf("empty fixture: %+v", before.State)
			}
			store := &snapshotCaptureStore{objects: map[string][]byte{}}
			created := time.Now().UTC()
			snapshotter, err := NewNATSJetStreamSnapshotter(NATSJetStreamSnapshotterConfig{Connection: nc, Stream: "EMPTY", Store: store, Region: "gru", Bucket: "snapshots", Now: func() time.Time { return created }})
			if err != nil {
				t.Fatal(err)
			}
			request := SnapshotRequest{RunID: "empty", IdempotencyKey: "empty", ObjectKey: "empty.epoch-1.snapshot", ControlEpoch: 1}
			snapshot, err := snapshotter.Snapshot(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			created = created.Add(time.Hour)
			retry, err := snapshotter.Snapshot(ctx, request)
			if err != nil || retry != snapshot {
				t.Fatalf("retry: %+v %v", retry, err)
			}
			stored := store.body("gru", "snapshots", request.ObjectKey)
			manifest, inner, err := decodeJetStreamSnapshotEnvelope(stored, "EMPTY", defaultJetStreamSnapshotBytes)
			if err != nil {
				t.Fatal(err)
			}
			if manifest.State.FirstSeq != before.State.FirstSeq || manifest.State.LastSeq != before.State.LastSeq {
				t.Fatalf("allocator metadata changed: %+v", manifest.State)
			}
			_, restoredJS := snapshotTestBroker(t)
			// Public protocol restore is exercised against another independent broker.
			restoredNC := restoredJS.Conn()
			requestBody, err := json.Marshal(struct {
				Config json.RawMessage    `json:"config"`
				State  *natsSnapshotState `json:"state"`
			}{manifest.Config, manifest.State})
			if err != nil {
				t.Fatal(err)
			}
			reply, err := restoredNC.RequestWithContext(ctx, "$JS.API.STREAM.RESTORE.EMPTY", requestBody)
			if err != nil {
				t.Fatal(err)
			}
			var admission natsserver.JSApiStreamRestoreResponse
			if json.Unmarshal(reply.Data, &admission) != nil || admission.Error != nil || admission.DeliverSubject == "" {
				t.Fatalf("restore admission: %s", reply.Data)
			}
			reply, err = restoredNC.RequestWithContext(ctx, admission.DeliverSubject, inner)
			if err != nil || len(reply.Data) != 0 {
				t.Fatalf("restore chunk: %+v %v", reply, err)
			}
			reply, err = restoredNC.RequestWithContext(ctx, admission.DeliverSubject, nil)
			if err != nil {
				t.Fatal(err)
			}
			var final natsserver.JSApiStreamCreateResponse
			if json.Unmarshal(reply.Data, &final) != nil || final.Error != nil {
				t.Fatalf("restore complete: %s", reply.Data)
			}
			restored, err := restoredJS.Stream(ctx, "EMPTY")
			if err != nil {
				t.Fatal(err)
			}
			info, err := restored.Info(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if info.State.Msgs != 0 || info.State.FirstSeq != before.State.FirstSeq || info.State.LastSeq != before.State.LastSeq || info.State.Consumers != 1 {
				t.Fatalf("restored allocator: %+v", info.State)
			}
			restoredConsumer, err := restored.Consumer(ctx, "CHECKPOINT")
			if err != nil {
				t.Fatal(err)
			}
			actual, err := restoredConsumer.Info(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(actual.Config, checkpoint.Config) || actual.Delivered.Consumer != checkpoint.Delivered.Consumer || actual.Delivered.Stream != checkpoint.Delivered.Stream || actual.AckFloor.Consumer != checkpoint.AckFloor.Consumer || actual.AckFloor.Stream != checkpoint.AckFloor.Stream || actual.NumAckPending != checkpoint.NumAckPending || actual.NumPending != checkpoint.NumPending {
				t.Fatalf("checkpoint changed: before=%+v after=%+v", checkpoint, actual)
			}
			ack, err := restoredJS.Publish(ctx, "empty", []byte("next"))
			if err != nil || ack.Sequence != before.State.LastSeq+1 {
				t.Fatalf("allocator resume: %+v %v", ack, err)
			}
			next, err := restoredConsumer.Next(jetstream.FetchMaxWait(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			metadata, err := next.Metadata()
			if err != nil || metadata.Sequence.Stream != ack.Sequence || metadata.Sequence.Consumer != checkpoint.Delivered.Consumer+1 {
				t.Fatalf("consumer resume: %+v %v", metadata, err)
			}
			if err := next.DoubleAck(ctx); err != nil {
				t.Fatal(err)
			}
			for _, mutate := range []func(*jetStreamSnapshotManifest){func(m *jetStreamSnapshotManifest) { m.State.Msgs = 1 }, func(m *jetStreamSnapshotManifest) { m.State.Consumers++ }} {
				changed := manifest
				state := *manifest.State
				changed.State = &state
				mutate(&changed)
				altered, err := encodeJetStreamSnapshotEnvelope(changed, inner, defaultJetStreamSnapshotBytes)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := decodeJetStreamSnapshotEnvelope(altered, "EMPTY", defaultJetStreamSnapshotBytes); !errors.Is(err, ErrSnapshotVerification) {
					t.Fatalf("inconsistent state accepted: %v", err)
				}
			}
		})
	}
}

func TestSnapshotEnvelopeRejectsIncompleteNonemptyArchive(t *testing.T) {
	nc, js := snapshotTestBroker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "STATE", Subjects: []string{"state"}, Storage: jetstream.FileStorage}); err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(ctx, "state", []byte("required payload")); err != nil {
		t.Fatal(err)
	}
	snapshotter, err := NewNATSJetStreamSnapshotter(NATSJetStreamSnapshotterConfig{Connection: nc, Stream: "STATE", Store: &snapshotCaptureStore{objects: map[string][]byte{}}, Region: "gru", Bucket: "snapshots"})
	if err != nil {
		t.Fatal(err)
	}
	inner, response, err := snapshotter.streamSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var incomplete bytes.Buffer
	compressed := s2.NewWriter(&incomplete)
	writer := tar.NewWriter(compressed)
	reader := tar.NewReader(s2.NewReader(bytes.NewReader(inner)))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(header.Name, ".blk") {
			continue
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(writer, reader); err != nil {
			t.Fatal(err)
		}
	}
	if writer.Close() != nil || compressed.Close() != nil {
		t.Fatal("archive close")
	}
	manifest := jetStreamSnapshotManifest{Version: 2, Stream: "STATE", CreatedAt: time.Now().UTC(), Config: response.Config, State: response.State, Consumers: response.Consumers, ArchiveSize: int64(incomplete.Len()), ArchiveSHA256: delivery.SHA256Digest(incomplete.Bytes())}
	envelope, err := encodeJetStreamSnapshotEnvelope(manifest, incomplete.Bytes(), defaultJetStreamSnapshotBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeJetStreamSnapshotEnvelope(envelope, "STATE", defaultJetStreamSnapshotBytes); !errors.Is(err, ErrSnapshotVerification) {
		t.Fatalf("missing payload accepted: %v", err)
	}
}

func TestSnapshotEnvelopeRejectsMissingConsumerAndTrailingData(t *testing.T) {
	nc, js := snapshotTestBroker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "STATE", Subjects: []string{"state"}, Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.CreateConsumer(ctx, jetstream.ConsumerConfig{Name: "CHECKPOINT", Durable: "CHECKPOINT", AckPolicy: jetstream.AckExplicitPolicy}); err != nil {
		t.Fatal(err)
	}
	snapshotter, err := NewNATSJetStreamSnapshotter(NATSJetStreamSnapshotterConfig{Connection: nc, Stream: "STATE", Store: &snapshotCaptureStore{objects: map[string][]byte{}}, Region: "gru", Bucket: "snapshots"})
	if err != nil {
		t.Fatal(err)
	}
	inner, response, err := snapshotter.streamSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Real empty stream contains no message blocks; its only retained payload is
	// the durable consumer, which must not disappear during validation.
	for _, omit := range []string{"obs/CHECKPOINT/meta.inf", "obs/CHECKPOINT/meta.sum", "obs/CHECKPOINT/o.dat", "all-consumers"} {
		t.Run(omit, func(t *testing.T) {
			var changed bytes.Buffer
			compressed := s2.NewWriter(&changed)
			writer := tar.NewWriter(compressed)
			reader := tar.NewReader(s2.NewReader(bytes.NewReader(inner)))
			for {
				header, err := reader.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if header.Name == omit || (omit == "all-consumers" && len(header.Name) > 4 && header.Name[:4] == "obs/") {
					continue
				}
				if err := writer.WriteHeader(header); err != nil {
					t.Fatal(err)
				}
				if _, err := io.Copy(writer, reader); err != nil {
					t.Fatal(err)
				}
			}
			if writer.Close() != nil || compressed.Close() != nil {
				t.Fatal("archive close")
			}
			if err := validateJetStreamSnapshot(changed.Bytes(), "STATE", defaultJetStreamSnapshotBytes, response.Config, response.State, response.Consumers); !errors.Is(err, ErrSnapshotVerification) {
				t.Fatalf("missing consumer payload accepted: %v", err)
			}
		})
	}
	manifest := jetStreamSnapshotManifest{Version: 2, Stream: "STATE", CreatedAt: time.Now().UTC(), Config: response.Config, State: response.State, Consumers: response.Consumers, ArchiveSize: int64(len(inner)), ArchiveSHA256: delivery.SHA256Digest(inner)}
	envelope, err := encodeJetStreamSnapshotEnvelope(manifest, inner, defaultJetStreamSnapshotBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeJetStreamSnapshotEnvelope(envelope, "STATE", defaultJetStreamSnapshotBytes); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{append(append([]byte(nil), envelope...), 0), append(append([]byte(nil), envelope...), envelope...), envelope[:len(envelope)-1]} {
		if _, _, err := decodeJetStreamSnapshotEnvelope(data, "STATE", defaultJetStreamSnapshotBytes); !errors.Is(err, ErrSnapshotVerification) {
			t.Fatalf("outer trailing/truncated data accepted: %v", err)
		}
	}
	for _, data := range [][]byte{append(append([]byte(nil), inner...), 1, 2, 3), append(append([]byte(nil), inner...), inner...), inner[:len(inner)-1]} {
		if err := validateJetStreamSnapshot(data, "STATE", defaultJetStreamSnapshotBytes, response.Config, response.State, response.Consumers); !errors.Is(err, ErrSnapshotVerification) {
			t.Fatalf("inner trailing/truncated data accepted: %v", err)
		}
	}
	// Canonical ordering and exact tar headers prohibit duplicate entries.
	duplicated := append(append([]byte(nil), envelope[:len(envelope)-1024]...), envelope...)
	if _, _, err := decodeJetStreamSnapshotEnvelope(duplicated, "STATE", defaultJetStreamSnapshotBytes); !errors.Is(err, ErrSnapshotVerification) {
		t.Fatalf("duplicate entries accepted: %v", err)
	}
	if _, _, err := decodeJetStreamSnapshotEnvelope(envelope, "STATE", int64(len(envelope)-1)); !errors.Is(err, ErrSnapshotVerification) {
		t.Fatalf("oversize accepted: %v", err)
	}
	manifest.State = nil
	data, err := encodeJetStreamSnapshotEnvelope(manifest, inner, defaultJetStreamSnapshotBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeJetStreamSnapshotEnvelope(data, "STATE", defaultJetStreamSnapshotBytes); !errors.Is(err, ErrSnapshotVerification) {
		t.Fatalf("missing API state accepted: %v", err)
	}
}
