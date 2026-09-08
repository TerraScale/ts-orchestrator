package snapshotfacts

import (
	"context"
	"errors"
	"fmt"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	"time"
)

func CaptureStreams(ctx context.Context, v controltransition.VerifiedPlan, connections map[string]*nats.Conn, store restoredrill.SnapshotObjectStore, epoch uint64) ([]controltransition.StreamEvidence, []controltransition.CaptureObject, error) {
	p, _ := v.Plan()
	var streams []controltransition.StreamEvidence
	var objects []controltransition.CaptureObject
	for _, a := range p.Accounts {
		nc := connections[a.SourceName]
		if nc == nil {
			return nil, nil, errors.New("finalcapture: admitted account connection missing")
		}
		if err := ExactInventory(ctx, nc, a); err != nil {
			return nil, nil, err
		}
		for _, stream := range a.Streams {
			if err := v.Check(time.Now()); err != nil {
				return nil, nil, err
			}
			key, _ := controltransition.CaptureObjectKey(v, a.Role, stream.Name, epoch)
			snapshotter, err := restoredrill.NewNATSJetStreamSnapshotter(restoredrill.NATSJetStreamSnapshotterConfig{Connection: nc, Stream: stream.Name, Store: store, Region: "gru", Bucket: a.SourceName, MaxBytes: p.Limits.MaxSnapshotBytes})
			if err != nil {
				return nil, nil, err
			}
			request := restoredrill.SnapshotRequest{RunID: p.TransitionID, ObjectKey: key, IdempotencyKey: key, ControlEpoch: epoch}
			if _, err := snapshotter.Snapshot(ctx, request); err != nil {
				return nil, nil, fmt.Errorf("finalcapture: snapshot %s/%s: %w", a.Role, stream.Name, err)
			}
			body, found, err := store.GetSnapshot(ctx, "gru", a.SourceName, key)
			if err != nil || !found {
				return nil, nil, errors.New("finalcapture: snapshot not readable")
			}
			evidence, err := EnvelopeEvidence(body, p.Limits.MaxSnapshotBytes, a.Role, a.SourceName, stream.Name)
			if err != nil {
				return nil, nil, err
			}
			streams = append(streams, evidence)
			objects = append(objects, controltransition.CaptureObject{ControlEpoch: epoch, Role: a.Role, Stream: stream.Name, Key: key, SHA256: controltransition.Digest(body), Size: int64(len(body))})
		}
	}
	if err := controltransition.ValidateStreamEvidence(v, streams); err != nil {
		return nil, nil, err
	}
	return streams, objects, nil
}
func ExactInventory(ctx context.Context, nc *nats.Conn, a controltransition.Account) error {
	js, err := jetstream.New(nc)
	if err != nil {
		return err
	}
	wanted := map[string]bool{}
	for _, s := range a.Streams {
		wanted[s.Name] = true
	}
	list := js.StreamNames(ctx)
	count := 0
	for name := range list.Name() {
		if !wanted[name] {
			return errors.New("finalcapture: unexpected stream")
		}
		delete(wanted, name)
		count++
	}
	if err := list.Err(); err != nil {
		return err
	}
	if len(wanted) != 0 || count != len(a.Streams) {
		return errors.New("finalcapture: incomplete stream inventory")
	}
	return nil
}
