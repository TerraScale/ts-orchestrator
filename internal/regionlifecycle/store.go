package regionlifecycle

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

// Bucket is the replicated KV bucket holding one record per region cell. It
// lives in the global home region and is advanced only by the global leader.
const Bucket = "TS_REGION_LIFECYCLE"

const (
	maxRecordBytes = 256 << 10
	storeTimeout   = 5 * time.Second
)

var (
	ErrNotFound = errors.New("region lifecycle record not found")
	ErrConflict = errors.New("region lifecycle compare-and-set conflict")
)

// Store persists records with compare-and-set on the KV revision. Every write
// is guarded by the global-scope authority lease immediately beforehand.
type Store struct {
	kv     jetstream.KeyValue
	fencer authority.Fencer
}

// OpenStore creates or verifies the lifecycle bucket.
func OpenStore(ctx context.Context, js jetstream.JetStream, replicas int, fencer authority.Fencer) (*Store, error) {
	if js == nil || fencer == nil || replicas < 1 || replicas > 5 {
		return nil, errors.New("region lifecycle store needs JetStream, a fencer and 1 to 5 replicas")
	}
	createCtx, cancel := context.WithTimeout(ctx, storeTimeout)
	kv, err := js.CreateKeyValue(createCtx, jetstream.KeyValueConfig{
		Bucket: Bucket, Description: "Region lifecycle state machine records",
		MaxValueSize: maxRecordBytes, History: 16, Storage: jetstream.FileStorage, Replicas: replicas,
	})
	cancel()
	if err != nil {
		if !errors.Is(err, jetstream.ErrBucketExists) {
			return nil, fmt.Errorf("create region lifecycle bucket: %w", err)
		}
		lookupCtx, lookupCancel := context.WithTimeout(ctx, storeTimeout)
		defer lookupCancel()
		if kv, err = js.KeyValue(lookupCtx, Bucket); err != nil {
			return nil, fmt.Errorf("open region lifecycle bucket: %w", err)
		}
		status, err := kv.Status(lookupCtx)
		if err != nil {
			return nil, err
		}
		if config := status.Config(); config.Replicas != replicas || config.Storage != jetstream.FileStorage || config.History < 2 {
			return nil, errors.New("existing region lifecycle bucket has incompatible durability")
		}
	}
	return NewStore(kv, fencer)
}

// NewStore wraps a caller-provisioned durable bucket.
func NewStore(kv jetstream.KeyValue, fencer authority.Fencer) (*Store, error) {
	if kv == nil || fencer == nil {
		return nil, errors.New("region lifecycle store needs a bucket and a fencer")
	}
	return &Store{kv: kv, fencer: fencer}, nil
}

// Guard proves the global lease at epoch; the driver calls it immediately
// before every external effect.
func (s *Store) Guard(ctx context.Context, epoch uint64) error {
	if epoch == 0 {
		return authority.ErrFenced
	}
	return s.fencer.Guard(ctx, epoch)
}

// Get returns the record and its KV revision.
func (s *Store) Get(ctx context.Context, cell string) (Record, uint64, error) {
	if !cellToken.MatchString(cell) {
		return Record{}, 0, errors.New("region lifecycle cell is invalid")
	}
	readCtx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	entry, err := s.kv.Get(readCtx, cell)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return Record{}, 0, ErrNotFound
	}
	if err != nil {
		return Record{}, 0, err
	}
	var record Record
	if err := protocol.DecodeStrict(entry.Value(), &record, maxRecordBytes); err != nil {
		return Record{}, 0, fmt.Errorf("decode region lifecycle record: %w", err)
	}
	if err := record.Validate(); err != nil || record.Cell != cell {
		return Record{}, 0, errors.New("stored region lifecycle record is corrupt")
	}
	return record, entry.Revision(), nil
}

// List returns every region record; the planner and guards use it to count
// regions and committed spend.
func (s *Store) List(ctx context.Context) ([]Record, error) {
	keys, err := s.keys(ctx)
	if err != nil {
		return nil, err
	}
	var records []Record
	for _, key := range keys {
		record, _, err := s.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

// keys lists every record key. A key lister closes its channel both when the
// listing completes and when it fails or times out, so it cannot tell a
// truncated listing from a complete one; this watches directly and returns
// only after the end-of-initial-values marker. A truncated list would
// undercount regions and committed spend for the admission guards.
func (s *Store) keys(ctx context.Context) ([]string, error) {
	listCtx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	watcher, err := s.kv.WatchAll(listCtx, jetstream.IgnoreDeletes(), jetstream.MetaOnly())
	if err != nil {
		return nil, fmt.Errorf("list region lifecycle keys: %w", err)
	}
	defer func() { _ = watcher.Stop() }()
	seen := map[string]bool{}
	var keys []string
	for {
		select {
		case <-listCtx.Done():
			return nil, fmt.Errorf("list region lifecycle keys: %w", listCtx.Err())
		case entry, open := <-watcher.Updates():
			if !open {
				return nil, errors.New("list region lifecycle keys: listing was interrupted")
			}
			if entry == nil {
				return keys, nil
			}
			if !seen[entry.Key()] {
				seen[entry.Key()] = true
				keys = append(keys, entry.Key())
			}
		}
	}
}

// Create stores a new Proposed record; a second proposal for a cell that
// already has a record is a conflict.
func (s *Store) Create(ctx context.Context, epoch uint64, record Record) (uint64, error) {
	if record.Phase != Proposed || record.Generation != 1 || record.ProposalGeneration != 1 {
		return 0, ErrInvalidTransition
	}
	data, err := encode(record)
	if err != nil {
		return 0, err
	}
	if err := s.fencer.Guard(ctx, epoch); err != nil {
		return 0, err
	}
	writeCtx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	revision, err := s.kv.Create(writeCtx, record.Cell, data)
	if errors.Is(err, jetstream.ErrKeyExists) {
		return 0, ErrConflict
	}
	return revision, err
}

// Update replaces the record at revision. The new record must be the next
// generation of the same region.
func (s *Store) Update(ctx context.Context, epoch uint64, prior, next Record, revision uint64) (uint64, error) {
	if next.Cell != prior.Cell || next.Generation != prior.Generation+1 || next.Proposal.ID != prior.Proposal.ID ||
		next.ProposalGeneration != prior.ProposalGeneration {
		return 0, ErrInvalidTransition
	}
	// A record whose intent a newer leader claimed is that leader's; an
	// intent can never be stamped with an epoch other than the writer's.
	if prior.Pending != nil && prior.Pending.Epoch > epoch {
		return 0, authority.ErrFenced
	}
	if next.Pending != nil && next.Pending.Epoch > epoch {
		return 0, ErrInvalidTransition
	}
	return s.write(ctx, epoch, next, revision)
}

// Repropose replaces a terminal record with a new Proposed record built by
// Machine.Repropose.
func (s *Store) Repropose(ctx context.Context, epoch uint64, prior, next Record, revision uint64) (uint64, error) {
	if !prior.Phase.Terminal() || next.Phase != Proposed || next.Cell != prior.Cell ||
		next.Generation != prior.Generation+1 || next.ProposalGeneration != next.Generation ||
		next.Proposal.ID == prior.Proposal.ID {
		return 0, ErrInvalidTransition
	}
	return s.write(ctx, epoch, next, revision)
}

func (s *Store) write(ctx context.Context, epoch uint64, next Record, revision uint64) (uint64, error) {
	data, err := encode(next)
	if err != nil {
		return 0, err
	}
	if err := s.fencer.Guard(ctx, epoch); err != nil {
		return 0, err
	}
	writeCtx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	updated, err := s.kv.Update(writeCtx, next.Cell, data, revision)
	if errors.Is(err, jetstream.ErrKeyExists) || errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
		// A revision mismatch: another writer advanced the record.
		return 0, ErrConflict
	}
	return updated, err
}

func encode(record Record) ([]byte, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(record, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRecordBytes {
		return nil, errors.New("region lifecycle record is too large")
	}
	return data, nil
}
