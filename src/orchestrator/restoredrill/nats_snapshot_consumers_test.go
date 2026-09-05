package restoredrill

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestSnapshotRejectsMemoryBackedDurableCheckpoint(t *testing.T) {
	nc, js := snapshotTestBroker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "STATE", Subjects: []string{"state"}, Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.CreateConsumer(ctx, jetstream.ConsumerConfig{Name: "DURABLE", Durable: "DURABLE", MemoryStorage: true, AckPolicy: jetstream.AckExplicitPolicy}); err != nil {
		t.Fatal(err)
	}
	store := &snapshotCaptureStore{objects: map[string][]byte{}}
	snapshotter, err := NewNATSJetStreamSnapshotter(NATSJetStreamSnapshotterConfig{Connection: nc, Stream: "STATE", Store: store, Region: "gru", Bucket: "snapshots"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotter.Snapshot(ctx, SnapshotRequest{RunID: "memory", IdempotencyKey: "memory", ObjectKey: "memory.epoch-1.snapshot", ControlEpoch: 1}); !errors.Is(err, ErrSnapshotVerification) {
		t.Fatalf("unrestorable durable checkpoint accepted: %v", err)
	}
	if len(store.objects) != 0 {
		t.Fatal("failed snapshot was published")
	}
}

func TestSnapshotEnvelopeRequiresExplicitConsumerInventory(t *testing.T) {
	nc, js := snapshotTestBroker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "STATE", Subjects: []string{"state"}, Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []jetstream.ConsumerConfig{{Name: "FILE", Durable: "FILE", AckPolicy: jetstream.AckExplicitPolicy}, {Name: "MEMORY", MemoryStorage: true, AckPolicy: jetstream.AckExplicitPolicy, InactiveThreshold: time.Minute}} {
		if _, err := stream.CreateConsumer(ctx, config); err != nil {
			t.Fatal(err)
		}
	}
	store := &snapshotCaptureStore{objects: map[string][]byte{}}
	snapshotter, err := NewNATSJetStreamSnapshotter(NATSJetStreamSnapshotterConfig{Connection: nc, Stream: "STATE", Store: store, Region: "gru", Bucket: "snapshots"})
	if err != nil {
		t.Fatal(err)
	}
	request := SnapshotRequest{RunID: "inventory", IdempotencyKey: "inventory", ObjectKey: "inventory.epoch-1.snapshot", ControlEpoch: 1}
	if _, err := snapshotter.Snapshot(ctx, request); err != nil {
		t.Fatal(err)
	}
	manifest, inner, err := decodeJetStreamSnapshotEnvelope(store.body("gru", "snapshots", request.ObjectKey), "STATE", defaultJetStreamSnapshotBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*jetStreamSnapshotManifest){
		func(m *jetStreamSnapshotManifest) { m.Version = 1 },
		func(m *jetStreamSnapshotManifest) { m.Consumers = nil },
		func(m *jetStreamSnapshotManifest) { m.Consumers = m.Consumers[:1] },
		func(m *jetStreamSnapshotManifest) { m.Consumers[1].Durable = "MEMORY" },
		func(m *jetStreamSnapshotManifest) { m.Consumers[0].Name = "OTHER" },
		func(m *jetStreamSnapshotManifest) { m.Consumers[0].Durable = "OTHER" },
		func(m *jetStreamSnapshotManifest) { m.Consumers[0], m.Consumers[1] = m.Consumers[1], m.Consumers[0] },
	} {
		encoded, _ := json.Marshal(manifest)
		var altered jetStreamSnapshotManifest
		if err := json.Unmarshal(encoded, &altered); err != nil {
			t.Fatal(err)
		}
		mutate(&altered)
		envelope, err := encodeJetStreamSnapshotEnvelope(altered, inner, defaultJetStreamSnapshotBytes)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := decodeJetStreamSnapshotEnvelope(envelope, "STATE", defaultJetStreamSnapshotBytes); !errors.Is(err, ErrSnapshotVerification) {
			t.Fatalf("consumer obligation removed or changed: %v", err)
		}
	}
}

func TestSnapshotRequiresStableAndCompleteConsumerAPIIdentity(t *testing.T) {
	for _, mode := range []string{"null-config", "changed-identity", "missing-total", "oversized-inventory"} {
		t.Run(mode, func(t *testing.T) {
			broker, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
			if err != nil {
				t.Fatal(err)
			}
			broker.Start()
			t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
			if !broker.ReadyForConnections(time.Second) {
				t.Fatal("broker unavailable")
			}
			nc, err := nats.Connect(broker.ClientURL())
			if err != nil {
				t.Fatal(err)
			}
			defer nc.Close()
			var namesCalls atomic.Int32
			var snapshots atomic.Int32
			_, err = nc.Subscribe("$JS.API.>", func(m *nats.Msg) {
				switch {
				case m.Subject == "$JS.API.CONSUMER.NAMES.STATE":
					call := namesCalls.Add(1)
					name := "WATCH"
					if mode == "changed-identity" && call > 1 {
						name = "NEW"
					}
					response := map[string]any{"type": "io.nats.jetstream.api.v1.consumer_names_response", "offset": 0, "total": 1, "consumers": []string{name}}
					if mode == "missing-total" {
						delete(response, "total")
					}
					if mode == "oversized-inventory" {
						response["total"] = maximumSnapshotConsumers + 1
					}
					raw, _ := json.Marshal(response)
					_ = m.Respond(raw)
				case strings.HasPrefix(m.Subject, "$JS.API.CONSUMER.INFO.STATE."):
					name := strings.TrimPrefix(m.Subject, "$JS.API.CONSUMER.INFO.STATE.")
					response := map[string]any{"type": "io.nats.jetstream.api.v1.consumer_info_response", "stream_name": "STATE", "name": name, "created": "2026-01-01T00:00:00Z", "config": map[string]any{"mem_storage": true}}
					if mode == "null-config" {
						response["config"] = nil
					}
					raw, _ := json.Marshal(response)
					_ = m.Respond(raw)
				case m.Subject == "$JS.API.STREAM.SNAPSHOT.STATE":
					snapshots.Add(1)
					var request natsSnapshotRequest
					if json.Unmarshal(m.Data, &request) != nil {
						return
					}
					_ = m.Respond([]byte(`{"type":"io.nats.jetstream.api.v1.stream_snapshot_response","config":{"name":"STATE"},"state":{"consumer_count":1}}`))
					_ = nc.Publish(request.DeliverSubject, []byte("a short transfer whose changing inventory must fail"))
					_ = nc.Publish(request.DeliverSubject, nil)
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := nc.Flush(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			snapshotter := NATSJetStreamSnapshotter{connection: nc, stream: "STATE", maxBytes: 1 << 20}
			if _, _, err := snapshotter.streamSnapshot(ctx); !errors.Is(err, ErrSnapshotVerification) || ctx.Err() != nil {
				t.Fatalf("malformed/changing inventory was not rejected immediately: %v", err)
			}
			if mode == "changed-identity" {
				if namesCalls.Load() != 2 || snapshots.Load() != 1 {
					t.Fatal("fixture did not cross capture boundary")
				}
			} else if snapshots.Load() != 0 {
				t.Fatal("invalid initial consumer evidence reached snapshot API")
			}
		})
	}
}
