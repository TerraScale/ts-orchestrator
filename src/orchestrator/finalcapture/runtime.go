package finalcapture

import (
	"context"
	"errors"
	"reflect"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/snapshotfacts"
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
	streams, objects, err := snapshotfacts.CaptureStreams(ctx, c.Plan, broker.connections, store, uint64(source.GlobalElectionFloor))
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(streams, source.Streams) {
		return nil, errors.New("finalcapture: copy differs from quiescent source records or checkpoints")
	}
	// Every account is checked again after the complete sequential capture.
	// This also rejects expiry that advanced a stream captured earlier.
	for _, a := range p.Accounts {
		if err := snapshotfacts.ExactInventory(ctx, broker.connections[a.SourceName], a); err != nil {
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

func verifyObjects(ctx context.Context, s *archiveStore, r controltransition.CaptureReceipt) error {
	for i, o := range r.Objects {
		e := r.Streams[i]
		body, found, err := s.GetSnapshot(ctx, "gru", e.Account, o.Key)
		if err != nil || !found || int64(len(body)) != o.Size || controltransition.Digest(body) != o.SHA256 {
			return errors.New("finalcapture: final archive changed")
		}
		actual, err := snapshotfacts.EnvelopeEvidence(body, s.maximum, e.Role, e.Account, e.Stream)
		if err != nil || !reflect.DeepEqual(actual, e) {
			return errors.New("finalcapture: final archive evidence differs")
		}
	}
	return ctx.Err()
}
