package snapshotfacts

import (
	"context"
	"errors"
	"sync"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
)

// ObserveSource reads a caller-owned, already-quiescent source. It cannot
// revoke clients, quiesce workers or sign a source-state receipt. The trusted
// retirement owner must hold that fence through broker shutdown.
func ObserveSource(ctx context.Context, v controltransition.VerifiedPlan, connections map[string]*nats.Conn, globalElectionFloor uint64) ([]controltransition.StreamEvidence, error) {
	p, err := v.Plan()
	if err != nil {
		return nil, err
	}
	store := &memorySnapshots{objects: map[string][]byte{}, maximum: p.Limits.MaxSnapshotBytes, totalMaximum: p.Limits.MaxTransferBytes}
	streams, objects, err := CaptureStreams(ctx, v, connections, store, globalElectionFloor)
	if err != nil {
		return nil, err
	}
	for _, a := range p.Accounts {
		if err := ExactInventory(ctx, connections[a.SourceName], a); err != nil {
			return nil, err
		}
	}
	for i, o := range objects {
		body, _, err := store.GetSnapshot(ctx, "gru", streams[i].Account, o.Key)
		if err != nil {
			return nil, err
		}
		if _, err := restoredrill.VerifySnapshotSource(ctx, connections[streams[i].Account], o.Stream, body, p.Limits.MaxSnapshotBytes); err != nil {
			return nil, err
		}
	}
	return streams, nil
}

type memorySnapshots struct {
	mu                    sync.Mutex
	objects               map[string][]byte
	maximum, totalMaximum int64
}

func (s *memorySnapshots) GetSnapshot(ctx context.Context, region, account, key string) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	body, found := s.objects[region+"/"+account+"/"+key]
	return body, found, nil
}
func (s *memorySnapshots) Head(ctx context.Context, region, account, key string) (delivery.ObjectIdentity, bool, error) {
	body, found, err := s.GetSnapshot(ctx, region, account, key)
	if err != nil || !found {
		return delivery.ObjectIdentity{}, found, err
	}
	digest := delivery.SHA256Digest(body)
	return delivery.ObjectIdentity{Digest: digest, Size: int64(len(body)), ETag: digest}, true, nil
}
func (s *memorySnapshots) Put(ctx context.Context, region, account, key string, body []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if int64(len(body)) > s.maximum {
		return errors.New("finalcapture: source observation snapshot limit exceeded")
	}
	id := region + "/" + account + "/" + key
	if _, found := s.objects[id]; found {
		return errors.New("finalcapture: source observation duplicate key")
	}
	var total int64
	for _, b := range s.objects {
		total += int64(len(b))
	}
	if total > s.totalMaximum-int64(len(body)) {
		return errors.New("finalcapture: source observation total limit exceeded")
	}
	s.objects[id] = body
	return nil
}
