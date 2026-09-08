package finalcapture

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type Config struct {
	Plan               controltransition.VerifiedPlan
	CutReceipt         []byte
	SourceStateReceipt []byte
	Signer             *security.CommandSignatureSigner
}

// Run opens only the admitted working copy, never Source.StoreDir. A completed
// retry reads the exact durable receipt and archive bytes without starting NATS.
// An interrupted broker that changed its copy requires a trusted fresh copy;
// capture cannot repair or recopy the sealed original itself.
func Run(ctx context.Context, c Config) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("finalcapture: context required")
	}
	if err := c.Plan.Check(time.Now()); err != nil {
		return nil, err
	}
	cut, err := controltransition.VerifyCutReceipt(c.Plan, c.CutReceipt)
	if err != nil {
		return nil, err
	}
	source, err := controltransition.VerifySourceStateReceipt(c.Plan, c.SourceStateReceipt)
	if err != nil {
		return nil, err
	}
	if cut.SourceStateReceiptSHA256 != controltransition.Digest(c.SourceStateReceipt) || source.ObservedAt.After(cut.StoppedAt) {
		return nil, errors.New("finalcapture: cut does not bind quiescent source evidence")
	}
	p, _ := c.Plan.Plan()
	// Validate the signing identity before opening the working copy.
	probe := source
	if _, err := controltransition.SignSourceStateReceipt(c.Signer, c.Plan, probe); err != nil {
		return nil, err
	}
	store, err := openArchives(ctx, c.Plan, uint64(source.GlobalElectionFloor))
	if err != nil {
		return nil, err
	}
	defer store.close()
	if raw, found, err := store.read("receipt.json", controltransition.MaximumBytes); err != nil {
		return nil, err
	} else if found {
		receipt, err := controltransition.VerifyCaptureReceipt(c.Plan, c.CutReceipt, c.SourceStateReceipt, raw)
		if err != nil {
			return nil, err
		}
		if err := verifyObjects(ctx, store, receipt); err != nil {
			return nil, err
		}
		final, found, err := store.read("copy-final.sha256", 64)
		if err != nil || !found {
			return nil, errors.New("finalcapture: final copy digest missing")
		}
		identity, err := hostagent.InspectStorageTransitionCopy(ctx, c.Plan)
		if err != nil || identity.SHA256 != string(final) {
			return nil, errors.New("finalcapture: completed capture copy changed")
		}
		return raw, nil
	}
	if err := hostagent.VerifyStorageTransitionCopy(ctx, c.Plan, c.CutReceipt); err != nil {
		return nil, err
	}
	broker, err := startBroker(ctx, c.Plan)
	if err != nil {
		return nil, err
	}
	defer broker.close()
	streams, objects, err := captureStreams(ctx, c.Plan, broker.connections, store, uint64(source.GlobalElectionFloor))
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(streams, source.Streams) {
		return nil, errors.New("finalcapture: copy differs from quiescent source records or checkpoints")
	}
	// Every account is checked again after the complete sequential capture.
	// This also rejects expiry that advanced a stream captured earlier.
	for _, a := range p.Accounts {
		if err := exactInventory(ctx, broker.connections[a.SourceName], a); err != nil {
			return nil, err
		}
	}
	for i, object := range objects {
		body, found, err := store.GetSnapshot(ctx, "gru", streams[i].Account, object.Key)
		if err != nil || !found {
			return nil, errors.New("finalcapture: captured archive unavailable")
		}
		if _, err := restoredrill.VerifySnapshotSource(ctx, broker.connections[streams[i].Account], object.Stream, body, p.Limits.MaxSnapshotBytes); err != nil {
			return nil, err
		}
	}
	broker.close()
	identity, err := hostagent.InspectStorageTransitionCopy(ctx, c.Plan)
	if err != nil {
		return nil, err
	}
	if err := store.publish(ctx, "copy-final.sha256", []byte(identity.SHA256)); err != nil {
		return nil, err
	}
	receipt := controltransition.CaptureReceipt{Version: 1, Phase: "final-capture", PlanSHA256: c.Plan.Digest(), CutReceiptSHA256: controltransition.Digest(c.CutReceipt), SourceStateReceiptSHA256: controltransition.Digest(c.SourceStateReceipt), NodeID: p.Source.NodeID, StoreSHA256: cut.StoreSHA256, CopySHA256: cut.CopySHA256, CapturedAt: time.Now().UTC(), GlobalElectionFloor: source.GlobalElectionFloor, RegionalElectionFloor: source.RegionalElectionFloor, Streams: streams, Objects: objects}
	raw, err := controltransition.SignCaptureReceipt(c.Signer, c.Plan, c.CutReceipt, c.SourceStateReceipt, receipt)
	if err != nil {
		return nil, err
	}
	if err := verifyObjects(ctx, store, receipt); err != nil {
		return nil, err
	}
	if err := store.publish(ctx, "receipt.json", raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func captureStreams(ctx context.Context, v controltransition.VerifiedPlan, connections map[string]*nats.Conn, store restoredrill.SnapshotObjectStore, epoch uint64) ([]controltransition.StreamEvidence, []controltransition.CaptureObject, error) {
	p, _ := v.Plan()
	var streams []controltransition.StreamEvidence
	var objects []controltransition.CaptureObject
	for _, a := range p.Accounts {
		nc := connections[a.SourceName]
		if nc == nil {
			return nil, nil, errors.New("finalcapture: admitted account connection missing")
		}
		if err := exactInventory(ctx, nc, a); err != nil {
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
func exactInventory(ctx context.Context, nc *nats.Conn, a controltransition.Account) error {
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
func verifyObjects(ctx context.Context, s *archiveStore, r controltransition.CaptureReceipt) error {
	for i, o := range r.Objects {
		e := r.Streams[i]
		body, found, err := s.GetSnapshot(ctx, "gru", e.Account, o.Key)
		if err != nil || !found || int64(len(body)) != o.Size || controltransition.Digest(body) != o.SHA256 {
			return errors.New("finalcapture: final archive changed")
		}
		actual, err := EnvelopeEvidence(body, s.maximum, e.Role, e.Account, e.Stream)
		if err != nil || !reflect.DeepEqual(actual, e) {
			return errors.New("finalcapture: final archive evidence differs")
		}
	}
	return ctx.Err()
}
