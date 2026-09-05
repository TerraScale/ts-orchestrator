package restoredrill

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

type changingSnapshotStream struct {
	jetstream.Stream
	change func() error
}

func (s *changingSnapshotStream) GetMsg(ctx context.Context, sequence uint64, options ...jetstream.GetMsgOpt) (*jetstream.RawStreamMsg, error) {
	message, err := s.Stream.GetMsg(ctx, sequence, options...)
	if err == nil && s.change != nil {
		change := s.change
		s.change = nil
		err = change()
	}
	return message, err
}

func TestSnapshotSourceRecordsRejectConcurrentChange(t *testing.T) {
	for _, operation := range []string{"publish", "delete", "configuration"} {
		t.Run(operation, func(t *testing.T) {
			nc, js := snapshotTestBroker(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			stream, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "STATE", Subjects: []string{"state"}, Storage: jetstream.FileStorage})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := js.Publish(ctx, "state", []byte("retained source")); err != nil {
				t.Fatal(err)
			}
			snapshotter := &NATSJetStreamSnapshotter{connection: nc, stream: "STATE", maxBytes: 1 << 20}
			_, response, err := snapshotter.streamSnapshot(ctx)
			if err != nil || !snapshotRecordDigestValid(response.RecordsSHA256) {
				t.Fatalf("stable source capture: %v", err)
			}
			changing := &changingSnapshotStream{Stream: stream, change: func() error {
				switch operation {
				case "publish":
					_, err := js.Publish(ctx, "state", []byte("new source record"))
					return err
				case "delete":
					return stream.DeleteMsg(ctx, 1)
				default:
					_, err := js.UpdateStream(ctx, jetstream.StreamConfig{Name: "STATE", Subjects: []string{"state"}, Storage: jetstream.FileStorage, Description: "changed during verification"})
					return err
				}
			}}
			if _, err := observeSourceRecords(ctx, changing, response, 1<<20); !errors.Is(err, ErrSnapshotVerification) || ctx.Err() != nil {
				t.Fatalf("source mutation accepted or timed out: %v", err)
			}
		})
	}
}

func TestSnapshotRecordEvidenceBound(t *testing.T) {
	_, js := snapshotTestBroker(t)
	ctx := t.Context()
	stream, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "STATE", Subjects: []string{"state"}, Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(ctx, "state", []byte(strings.Repeat("x", 8192))); err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotRecordsDigest(ctx, stream, info.State, 1024); !errors.Is(err, ErrSnapshotVerification) {
		t.Fatalf("oversized record evidence accepted: %v", err)
	}
}
