package nodescale

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// Bucket holds each region's scaler record. A new leader reads it to resume the action in flight and to
// respect the cooldowns.
const Bucket = "TS_NODESCALE"

const (
	recordKey      = "state"
	maxRecordBytes = 64 << 10
)

// ErrRecordChanged reports a save over a record another leader wrote first.
var ErrRecordChanged = errors.New("node scaler record changed under the leader")

// Record is the scaler's durable state for one region.
type Record struct {
	LastChange time.Time `json:"last_change,omitzero"`
	Action     *InFlight `json:"action,omitempty"` // the action in flight, nil when idle
	From       int       `json:"from,omitzero"`    // pool size before a scale-up
	Status     Status    `json:"status"`           // last published status
}

// RecordStore is the scaler's durable record. Store is the JetStream one; tests fake it.
type RecordStore interface {
	Load(ctx context.Context) (Record, uint64, error)
	Save(ctx context.Context, record Record, revision uint64) (uint64, error)
}

// Store keeps the record in a replicated JetStream key-value bucket.
type Store struct{ kv jetstream.KeyValue }

// OpenStore creates or updates the bucket with replicas copies.
func OpenStore(ctx context.Context, js jetstream.JetStream, replicas int) (*Store, error) {
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: Bucket, History: 1, MaxValueSize: maxRecordBytes,
		Storage: jetstream.FileStorage, Replicas: replicas,
	})
	if err != nil {
		return nil, fmt.Errorf("open node scaler store: %w", err)
	}
	return &Store{kv: kv}, nil
}

// Load returns the record and its revision. A region that never saved has the zero record at revision 0.
func (s *Store) Load(ctx context.Context) (Record, uint64, error) {
	entry, err := s.kv.Get(ctx, recordKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return Record{}, 0, nil
	}
	if err != nil {
		return Record{}, 0, fmt.Errorf("read node scaler record: %w", err)
	}
	var record Record
	if err := protocol.DecodeStrict(entry.Value(), &record, maxRecordBytes); err != nil {
		return Record{}, 0, fmt.Errorf("decode node scaler record: %w", err)
	}
	return record, entry.Revision(), nil
}

// Save writes the record over revision: revision 0 creates it, any other revision must still be current.
// It returns the new revision.
func (s *Store) Save(ctx context.Context, record Record, revision uint64) (uint64, error) {
	data, err := protocol.EncodeJSON(record)
	if err != nil {
		return 0, err
	}
	var written uint64
	if revision == 0 {
		written, err = s.kv.Create(ctx, recordKey, data)
	} else {
		written, err = s.kv.Update(ctx, recordKey, data, revision)
	}
	if errors.Is(err, jetstream.ErrKeyExists) || errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
		return 0, ErrRecordChanged
	}
	if err != nil {
		return 0, fmt.Errorf("write node scaler record: %w", err)
	}
	return written, nil
}
