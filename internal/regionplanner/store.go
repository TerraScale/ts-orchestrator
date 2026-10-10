package regionplanner

import (
	"context"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// Bucket holds the planner's state: its memory and its latest decision.
const Bucket = "TS_REGION_PLANNER"

const (
	stateKey      = "state"
	maxStateBytes = 64 << 10
)

// ErrStateChanged reports a save over a state another leader wrote first.
var ErrStateChanged = errors.New("region planner state changed under the leader")

// State is the planner's durable record.
type State struct {
	Memory   Memory   `json:"memory"`
	Decision Decision `json:"decision"`
}

// Store keeps the planner's state in a replicated JetStream key-value bucket.
// Every write is guarded by the global-scope authority lease.
type Store struct {
	kv     jetstream.KeyValue
	fencer authority.Fencer
}

// OpenStore creates or updates the bucket with replicas copies.
func OpenStore(ctx context.Context, js jetstream.JetStream, replicas int, fencer authority.Fencer) (*Store, error) {
	if fencer == nil {
		return nil, errors.New("region planner store needs a fencer")
	}
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: Bucket, History: 1, MaxValueSize: maxStateBytes,
		Storage: jetstream.FileStorage, Replicas: replicas,
	})
	if err != nil {
		return nil, fmt.Errorf("open region planner store: %w", err)
	}
	return &Store{kv: kv, fencer: fencer}, nil
}

// Load returns the state and its revision. Before the first save it is the
// zero state at revision 0.
func (s *Store) Load(ctx context.Context) (State, uint64, error) {
	entry, err := s.kv.Get(ctx, stateKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return State{}, 0, nil
	}
	if err != nil {
		return State{}, 0, fmt.Errorf("read region planner state: %w", err)
	}
	var state State
	if err := protocol.DecodeStrict(entry.Value(), &state, maxStateBytes); err != nil {
		return State{}, 0, fmt.Errorf("decode region planner state: %w", err)
	}
	return state, entry.Revision(), nil
}

// Save writes state over revision: revision 0 creates it, any other revision
// must still be current. It returns the new revision.
func (s *Store) Save(ctx context.Context, epoch uint64, state State, revision uint64) (uint64, error) {
	if epoch == 0 {
		return 0, authority.ErrFenced
	}
	if err := s.fencer.Guard(ctx, epoch); err != nil {
		return 0, err
	}
	data, err := protocol.EncodeJSON(state)
	if err != nil {
		return 0, err
	}
	var written uint64
	if revision == 0 {
		written, err = s.kv.Create(ctx, stateKey, data)
	} else {
		written, err = s.kv.Update(ctx, stateKey, data, revision)
	}
	if errors.Is(err, jetstream.ErrKeyExists) || errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
		return 0, ErrStateChanged
	}
	if err != nil {
		return 0, fmt.Errorf("write region planner state: %w", err)
	}
	return written, nil
}

// Decision returns the latest saved decision, and false before the planner
// has saved one.
func (s *Store) Decision(ctx context.Context) (Decision, bool, error) {
	state, revision, err := s.Load(ctx)
	if err != nil || revision == 0 {
		return Decision{}, false, err
	}
	return state.Decision, true, nil
}
