package restoredrill

import (
	"context"
	"errors"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func snapshotTestBroker(t *testing.T) (*nats.Conn, jetstream.JetStream) {
	t.Helper()
	broker, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("broker not ready")
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
	return nc, js
}

type snapshotReadbackFailure struct {
	*snapshotCaptureStore
	failure error
	missing bool
}

func (s *snapshotReadbackFailure) GetSnapshot(ctx context.Context, region, bucket, object string) ([]byte, bool, error) {
	if s.failure != nil {
		return nil, false, s.failure
	}
	if s.missing {
		return nil, false, nil
	}
	body, found, err := s.snapshotCaptureStore.GetSnapshot(ctx, region, bucket, object)
	if len(body) > 0 {
		body[len(body)/2] ^= 1
	}
	return body, found, err
}

func TestSnapshotRequiresDurableBodyReadback(t *testing.T) {
	nc, js := snapshotTestBroker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "STATE", Subjects: []string{"state"}, Storage: jetstream.FileStorage}); err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(ctx, "state", []byte("retained")); err != nil {
		t.Fatal(err)
	}
	providerErr := errors.New("object reader unavailable")
	for _, tc := range []struct {
		name    string
		failure error
		missing bool
		want    error
	}{
		{"unavailable", providerErr, false, providerErr},
		{"missing", nil, true, ErrSnapshotVerification},
		{"corrupt", nil, false, ErrSnapshotVerification},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &snapshotReadbackFailure{snapshotCaptureStore: &snapshotCaptureStore{objects: map[string][]byte{}}, failure: tc.failure, missing: tc.missing}
			snapshotter, err := NewNATSJetStreamSnapshotter(NATSJetStreamSnapshotterConfig{Connection: nc, Stream: "STATE", Store: store, Region: "gru", Bucket: "snapshots"})
			if err != nil {
				t.Fatal(err)
			}
			result, err := snapshotter.Snapshot(ctx, SnapshotRequest{RunID: "readback", IdempotencyKey: "readback", ObjectKey: "readback.epoch-1.snapshot", ControlEpoch: 1})
			if !errors.Is(err, tc.want) || result != (ControlStateSnapshot{}) {
				t.Fatalf("result=%+v error=%v", result, err)
			}
		})
	}
}
