package restoredrill

import (
	"context"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func privateRestoreBroker(t *testing.T) *nats.Conn {
	t.Helper()
	s, err := natsserver.NewServer(&natsserver.Options{DontListen: true, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	t.Cleanup(func() { s.Shutdown(); s.WaitForShutdown() })
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("private restore broker failed to start")
	}
	nc, err := nats.Connect("", nats.InProcessServer(s), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func verifyPreliminaryRestore(t *testing.T, ctx context.Context, body []byte) {
	t.Helper()
	reference := privateRestoreBroker(t)
	target := privateRestoreBroker(t)
	a, err := RestorePreliminarySnapshot(ctx, reference, "CONTROL_STATE", body, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RestorePreliminarySnapshot(ctx, target, "CONTROL_STATE", body, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !SameSnapshotRestoreEvidence(a, b) {
		t.Fatalf("independent restore differs: %+v %+v", a, b)
	}
	replay, err := RestorePreliminarySnapshot(ctx, target, "CONTROL_STATE", body, 8<<20)
	if err != nil || !SameSnapshotRestoreEvidence(a, replay) {
		t.Fatalf("restore replay differs: %+v %v", replay, err)
	}
	js, err := jetstream.New(target)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := js.Stream(ctx, "CONTROL_STATE")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := stream.Consumer(ctx, "CONTROL_CHECKPOINT")
	if err != nil {
		t.Fatal(err)
	}
	batch, err := consumer.Fetch(1, jetstream.FetchMaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for msg := range batch.Messages() {
		if err := msg.DoubleAck(ctx); err != nil {
			t.Fatal(err)
		}
	}
	changed, err := RestorePreliminarySnapshot(ctx, target, "CONTROL_STATE", body, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	if SameSnapshotRestoreEvidence(a, changed) {
		t.Fatal("changed consumer checkpoint accepted")
	}
	if _, err := js.Publish(ctx, "control.extra", []byte("conflict")); err != nil {
		t.Fatal(err)
	}
	if _, err := RestorePreliminarySnapshot(ctx, target, "CONTROL_STATE", body, 8<<20); err == nil {
		t.Fatal("conflicting target accepted")
	}
	info, err := stream.Info(ctx)
	if err != nil || info.State.Msgs != 4 {
		t.Fatalf("conflicting target was altered: %+v %v", info, err)
	}
}
