package authority

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// uncertainLeaseStore simulates the lost-ack window: reads succeed while the
// lease write fails with a transport error that is not a CAS conflict.
type uncertainLeaseStore struct{}

func (uncertainLeaseStore) Get(context.Context, string) (jetstream.KeyValueEntry, error) {
	return nil, jetstream.ErrKeyNotFound
}

func (uncertainLeaseStore) GetRevision(context.Context, string, uint64) (jetstream.KeyValueEntry, error) {
	return nil, jetstream.ErrKeyNotFound
}

func (uncertainLeaseStore) Put(context.Context, string, []byte) (uint64, error) {
	return 0, nats.ErrTimeout
}

func (uncertainLeaseStore) PutString(context.Context, string, string) (uint64, error) {
	return 0, nats.ErrTimeout
}

func (uncertainLeaseStore) Create(context.Context, string, []byte, ...jetstream.KVCreateOpt) (uint64, error) {
	return 0, nats.ErrTimeout
}

func (uncertainLeaseStore) Update(context.Context, string, []byte, uint64) (uint64, error) {
	return 0, nats.ErrTimeout
}

func (uncertainLeaseStore) Delete(context.Context, string, ...jetstream.KVDeleteOpt) error {
	return nats.ErrTimeout
}

func (uncertainLeaseStore) Purge(context.Context, string, ...jetstream.KVDeleteOpt) error {
	return nats.ErrTimeout
}

func (uncertainLeaseStore) Watch(context.Context, string, ...jetstream.WatchOpt) (jetstream.KeyWatcher, error) {
	return nil, nats.ErrTimeout
}

func (uncertainLeaseStore) WatchAll(context.Context, ...jetstream.WatchOpt) (jetstream.KeyWatcher, error) {
	return nil, nats.ErrTimeout
}

func (uncertainLeaseStore) WatchFiltered(context.Context, []string, ...jetstream.WatchOpt) (jetstream.KeyWatcher, error) {
	return nil, nats.ErrTimeout
}

func (uncertainLeaseStore) Keys(context.Context, ...jetstream.WatchOpt) ([]string, error) {
	return nil, nats.ErrTimeout
}

func (uncertainLeaseStore) ListKeys(context.Context, ...jetstream.WatchOpt) (jetstream.KeyLister, error) {
	return nil, nats.ErrTimeout
}

func (uncertainLeaseStore) ListKeysFiltered(context.Context, ...string) (jetstream.KeyLister, error) {
	return nil, nats.ErrTimeout
}

func (uncertainLeaseStore) History(context.Context, string, ...jetstream.WatchOpt) ([]jetstream.KeyValueEntry, error) {
	return nil, nats.ErrTimeout
}

func (uncertainLeaseStore) Bucket() string { return "uncertain" }

func (uncertainLeaseStore) PurgeDeletes(context.Context, ...jetstream.KVPurgeOpt) error {
	return nats.ErrTimeout
}

func (uncertainLeaseStore) Status(context.Context) (jetstream.KeyValueStatus, error) {
	return nil, nats.ErrTimeout
}

// One transport failure during lease acquisition must not wedge the journal
// in a pending status no command accepts; the next tick must still be able
// to run the acquisition again.
func TestRegionalAuthorityUncertainLeaseCASResolvesPending(t *testing.T) {
	coordinator := &RegionalAuthorityCoordinator{
		leaseDuration: time.Minute,
		tickInterval:  time.Second,
		store:         uncertainLeaseStore{},
		authorityId:   "gru-regional",
		candidateId:   "candidate-1",
		leaseKey:      "lease",
		journalState:  AuthorityStateEmpty,
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := coordinator.tick(context.Background()); err == nil {
			t.Fatal("the synthetic transport failure must surface to the loop")
		}
		state := coordinator.currentState()
		if state.Status == AuthorityStatusAcquisitionPending || state.PendingSet != nil {
			t.Fatalf("attempt %d left the journal wedged in %s with a pending set", attempt, state.Status)
		}
		if state.Status != AuthorityStatusReadOnlyHeld {
			t.Fatalf("attempt %d: an uncertain acquisition must return to held, got %s", attempt, state.Status)
		}
	}
}
