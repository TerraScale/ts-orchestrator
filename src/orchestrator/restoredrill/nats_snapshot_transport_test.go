package restoredrill

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const snapshotTestNonce = "0123456789ABCDEFGHIJKL"

func snapshotTestChunk(index int) *nats.Msg {
	return &nats.Msg{Data: make([]byte, snapshotChunkBytes), Reply: fmt.Sprintf("$JS.SNAPSHOT.ACK.STATE.%s.%d.%d", snapshotTestNonce, snapshotChunkBytes, index)}
}

func TestSnapshotTransferRequiresOrderedBoundedChunksAndSuccess(t *testing.T) {
	for _, fullChunks := range []int{0, 1, 10} {
		for _, tail := range []bool{false, true} {
			if fullChunks == 0 && !tail {
				continue
			}
			s := snapshotTransfer{stream: "STATE"}
			for i := 1; i <= fullChunks; i++ {
				if done, err := s.accept(snapshotTestChunk(i)); done || err != nil {
					t.Fatalf("chunk %d: done=%v error=%v", i, done, err)
				}
			}
			if tail {
				if done, err := s.accept(&nats.Msg{Data: []byte("tail")}); done || err != nil {
					t.Fatalf("tail: done=%v error=%v", done, err)
				}
			}
			terminal := &nats.Msg{}
			if fullChunks > 0 {
				terminal.Header = nats.Header{"Status": {"204"}}
			}
			if done, err := s.accept(terminal); !done || err != nil {
				t.Fatalf("completion: done=%v error=%v", done, err)
			}
			if _, err := s.accept(terminal); err == nil {
				t.Fatal("accepted data after completion")
			}
		}
	}
}

func TestSnapshotTransferRejectsReplySubstitutionAndMalformedChunks(t *testing.T) {
	valid := snapshotTestChunk(1).Reply
	for _, reply := range []string{
		"", "control.write", strings.Replace(valid, "STATE", "OTHER", 1),
		strings.Replace(valid, snapshotTestNonce, "*", 1), strings.Replace(valid, snapshotTestNonce, "short", 1),
		strings.Replace(valid, ".1048576.", ".01.", 1), valid + ".extra",
		strings.TrimSuffix(valid, ".1") + ".0", strings.TrimSuffix(valid, ".1") + ".2",
		strings.TrimSuffix(valid, ".1") + ".01", strings.TrimSuffix(valid, ".1") + ".-1",
	} {
		s := snapshotTransfer{stream: "STATE"}
		message := snapshotTestChunk(1)
		message.Reply = reply
		if _, err := s.accept(message); err == nil {
			t.Fatalf("accepted invalid ACK %q", reply)
		}
	}
	for _, mutation := range []func(*nats.Msg){
		func(m *nats.Msg) { m.Data = m.Data[:1] },
		func(m *nats.Msg) { m.Data = append(m.Data, 0) },
		func(m *nats.Msg) { m.Header = nats.Header{"Status": {"204"}} },
		func(m *nats.Msg) { m.Reply = strings.Replace(m.Reply, snapshotTestNonce, strings.Repeat("z", 22), 1) },
		func(m *nats.Msg) { m.Reply = valid },
	} {
		s := snapshotTransfer{stream: "STATE"}
		if _, err := s.accept(snapshotTestChunk(1)); err != nil {
			t.Fatal(err)
		}
		message := snapshotTestChunk(2)
		mutation(message)
		if _, err := s.accept(message); err == nil {
			t.Fatal("accepted malformed later chunk")
		}
	}
	for _, status := range []string{"", "200", "408", "500"} {
		s := snapshotTransfer{stream: "STATE"}
		_, _ = s.accept(snapshotTestChunk(1))
		if _, err := s.accept(&nats.Msg{Header: nats.Header{"Status": {status}}}); err == nil {
			t.Fatalf("accepted completion status %q", status)
		}
	}
	for _, test := range []struct {
		name     string
		first    *nats.Msg
		terminal *nats.Msg
	}{
		{"empty", nil, &nats.Msg{}},
		{"terminal-reply", snapshotTestChunk(1), &nats.Msg{Reply: "control.write", Header: nats.Header{"Status": {"204"}}}},
		{"missing-status", snapshotTestChunk(1), &nats.Msg{}},
		{"extra-header", snapshotTestChunk(1), &nats.Msg{Header: nats.Header{"Status": {"204"}, "Other": {"value"}}}},
		{"multiple-status", snapshotTestChunk(1), &nats.Msg{Header: nats.Header{"Status": {"204", "500"}}}},
		{"short-with-status", &nats.Msg{Data: []byte("tail")}, &nats.Msg{Header: nats.Header{"Status": {"204"}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := snapshotTransfer{stream: "STATE"}
			if test.first != nil {
				if _, err := s.accept(test.first); err != nil {
					t.Fatal(err)
				}
			}
			if done, err := s.accept(test.terminal); done || err == nil {
				t.Fatalf("accepted malformed terminal: done=%v error=%v", done, err)
			}
		})
	}
	s := snapshotTransfer{stream: "STATE"}
	_, _ = s.accept(&nats.Msg{Data: []byte("tail")})
	if _, err := s.accept(&nats.Msg{Data: []byte("more")}); err == nil {
		t.Fatal("accepted data after short tail")
	}
}

func TestSnapshotterNeverAcknowledgesUnrelatedReply(t *testing.T) {
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
	trap, err := nc.SubscribeSync("control.write")
	if err != nil {
		t.Fatal(err)
	}
	_, err = nc.Subscribe("$JS.API.STREAM.SNAPSHOT.STATE", func(m *nats.Msg) {
		var request natsSnapshotRequest
		if json.Unmarshal(m.Data, &request) != nil {
			return
		}
		_ = m.Respond([]byte(`{"type":"io.nats.jetstream.api.v1.stream_snapshot_response","config":{"name":"STATE"},"state":{}}`))
		_ = nc.PublishMsg(&nats.Msg{Subject: request.DeliverSubject, Reply: "control.write", Data: bytes.Repeat([]byte{1}, snapshotChunkBytes)})
		_ = nc.Publish(request.DeliverSubject, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	s := NATSJetStreamSnapshotter{connection: nc, stream: "STATE", maxBytes: 2 * snapshotChunkBytes}
	if _, _, err := s.streamSnapshot(ctx); err == nil || ctx.Err() != nil {
		t.Fatalf("did not immediately reject reply substitution: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	if pending, _, err := trap.Pending(); err != nil || pending != 0 {
		t.Fatalf("snapshotter published an unrelated ACK: pending=%d error=%v", pending, err)
	}
}

func TestSnapshotterCrossesFlowWindowAndRestoresExactRecords(t *testing.T) {
	nc, js := snapshotTestBroker(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	stream, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "CONTROL_STATE", Subjects: []string{"control.>"}, Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := stream.CreateConsumer(ctx, jetstream.ConsumerConfig{Name: "CHECKPOINT", Durable: "CHECKPOINT", AckPolicy: jetstream.AckExplicitPolicy})
	if err != nil {
		t.Fatal(err)
	}
	var originals []*jetstream.RawStreamMsg
	for range 20 {
		body := make([]byte, 512<<10)
		if _, err := rand.Read(body); err != nil {
			t.Fatal(err)
		}
		ack, err := js.Publish(ctx, "control.state", body)
		if err != nil {
			t.Fatal(err)
		}
		original, err := stream.GetMsg(ctx, ack.Sequence)
		if err != nil {
			t.Fatal(err)
		}
		originals = append(originals, original)
	}
	for range 2 {
		message, err := consumer.Next(jetstream.FetchMaxWait(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if err := message.DoubleAck(ctx); err != nil {
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
	store := &snapshotCaptureStore{objects: map[string][]byte{}}
	s, err := NewNATSJetStreamSnapshotter(NATSJetStreamSnapshotterConfig{Connection: nc, Stream: "CONTROL_STATE", Store: store, Region: "gru", Bucket: "snapshots", Timeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	request := SnapshotRequest{RunID: "flow-window", IdempotencyKey: "flow-window", ObjectKey: "flow-window.epoch-1.snapshot", ControlEpoch: 1}
	identity, err := s.Snapshot(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	manifest, inner, err := decodeJetStreamSnapshotEnvelope(store.body("gru", "snapshots", request.ObjectKey), "CONTROL_STATE", defaultJetStreamSnapshotBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(inner) <= 8<<20 || manifest.State.Msgs != before.State.Msgs {
		t.Fatalf("fixture did not cross pinned server flow window: archive=%d messages=%d", len(inner), manifest.State.Msgs)
	}
	restoreSnapshotAndVerify(t, ctx, inner, before, originals, checkpoint)
	if retry, err := s.Snapshot(ctx, request); err != nil || retry != identity {
		t.Fatalf("large snapshot retry changed identity: %+v %v", retry, err)
	}
}
