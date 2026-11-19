package selfheal

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	bucket         = "TS_ORCH_SELF_HEAL"
	maxRecordBytes = 64 << 10
)

var errRecordChanged = errors.New("self-heal record changed under this leader")

type Repair struct {
	Host     string    `json:"host"`
	Node     string    `json:"node"`
	Instance string    `json:"instance"`
	Reason   string    `json:"reason"`
	Step     string    `json:"step"`
	Started  time.Time `json:"started"`
	StepAt   time.Time `json:"step_at"`
	Sent     time.Time `json:"sent,omitzero"`
	Outcome  string    `json:"outcome,omitempty"`
	Finished time.Time `json:"finished,omitzero"`
}

type Record struct {
	Repair   *Repair   `json:"repair,omitempty"`
	Last     *Repair   `json:"last,omitempty"`
	Replaced time.Time `json:"replaced,omitzero"`
	Stopped  string    `json:"stopped,omitempty"`
	Nodes    int       `json:"nodes,omitzero"`
}

type store struct {
	kv     jetstream.KeyValue
	region string
}

func openStore(ctx context.Context, conn *nats.Conn, region string) (*store, error) {
	js, err := jetstream.New(conn)
	if err != nil {
		return nil, err
	}
	kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: bucket, Replicas: mesh.StoreReplicas(region), History: 1, MaxValueSize: maxRecordBytes, Storage: jetstream.FileStorage})
	if err != nil {
		return nil, fmt.Errorf("self-heal store: %w", err)
	}
	return &store{kv: kv, region: region}, nil
}

func (s *store) load(ctx context.Context) (Record, uint64, error) {
	entry, err := s.kv.Get(ctx, s.region)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return Record{}, 0, nil
	}
	if err != nil {
		return Record{}, 0, fmt.Errorf("read self-heal record: %w", err)
	}
	var record Record
	if err := protocol.DecodeStrict(entry.Value(), &record, maxRecordBytes); err != nil {
		return Record{}, 0, fmt.Errorf("decode self-heal record: %w", err)
	}
	return record, entry.Revision(), nil
}

func (s *store) save(ctx context.Context, record Record, revision uint64) (uint64, error) {
	data, err := protocol.EncodeJSON(record)
	if err != nil {
		return 0, err
	}
	if revision == 0 {
		revision, err = s.kv.Create(ctx, s.region, data)
	} else {
		revision, err = s.kv.Update(ctx, s.region, data, revision)
	}
	if errors.Is(err, jetstream.ErrKeyExists) || errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
		return 0, errRecordChanged
	}
	if err != nil {
		return 0, fmt.Errorf("write self-heal record: %w", err)
	}
	return revision, nil
}
