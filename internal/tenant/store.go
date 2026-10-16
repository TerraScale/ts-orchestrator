package tenant

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Bucket is the cell's tenant KV bucket; each key is the tenant ULID.
const Bucket = "TS_TENANTS"

const (
	maxValueBytes = 8 << 10
	// clockSkew is how far past the store's clock a write may be stamped.
	clockSkew = time.Minute
)

var (
	ErrNotFound = errors.New("tenant not found")
	ErrExists   = errors.New("tenant already exists")
	ErrConflict = errors.New("tenant changed since it was read")
	ErrCorrupt  = errors.New("stored tenant is corrupt")
)

// Versioned is a stored tenant and the KV revision it was read at.
type Versioned struct {
	Tenant   Tenant
	Revision uint64
}

// Store keeps a cell's tenants. Every write is a compare-and-swap on the
// revision the writer read, so of two controllers that read one revision,
// for instance on either side of a partition, only the first write lands.
// Reads come from the stream leader: a KV Get may be served by a follower
// a moment behind, and a reconciler would act on its old state. A write
// stamped more than a minute past the store's clock is refused, so no caller
// purges a tenant before its retention ends by passing a later time.
type Store struct {
	kv     jetstream.KeyValue
	leader nats.JetStreamContext
	now    func() time.Time
}

// OpenStore opens or creates the bucket with replicas copies and refuses a
// bucket that keeps fewer.
func OpenStore(ctx context.Context, js jetstream.JetStream, replicas int) (*Store, error) {
	if js == nil || replicas < 1 || replicas > 5 {
		return nil, errors.New("tenant store requires JetStream and 1 to 5 replicas")
	}
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:       Bucket,
		Description:  "Dedicated tenants of the cell",
		History:      4,
		MaxValueSize: maxValueBytes,
		Storage:      jetstream.FileStorage,
		Replicas:     replicas,
	})
	if err != nil {
		return nil, fmt.Errorf("open tenant store: %w", err)
	}
	status, err := kv.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("read tenant store status: %w", err)
	}
	if got := status.Config().Replicas; got != replicas {
		return nil, fmt.Errorf("tenant store has %d replicas, requires %d", got, replicas)
	}
	leader, err := js.Conn().JetStream(legacyOptions(js.Options())...)
	if err != nil {
		return nil, err
	}
	return &Store{kv: kv, leader: leader, now: time.Now}, nil
}

// legacyOptions carry js's API namespace and timeout to the leader-read
// context, so both address the same JetStream.
func legacyOptions(options jetstream.JetStreamOptions) []nats.JSOpt {
	var legacy []nats.JSOpt
	switch {
	case options.Domain != "":
		legacy = append(legacy, nats.Domain(options.Domain))
	case options.APIPrefix != "":
		legacy = append(legacy, nats.APIPrefix(options.APIPrefix))
	}
	if options.DefaultTimeout > 0 {
		legacy = append(legacy, nats.MaxWait(options.DefaultTimeout))
	}
	return legacy
}

func (s *Store) checkStamp(t Tenant) error {
	if limit := s.now().Add(clockSkew); t.UpdatedAt.After(limit) {
		return fmt.Errorf("%w: tenant %s is stamped %s, after %s", ErrInvalid, t.ID,
			t.UpdatedAt.Format(time.RFC3339), limit.Format(time.RFC3339))
	}
	return nil
}

// Create stores generation 1 of a new tenant. It writes only a key that
// was never written, so no ID is taken twice, even after a purge.
func (s *Store) Create(ctx context.Context, t Tenant) (Versioned, error) {
	if err := CheckNew(t); err != nil {
		return Versioned{}, err
	}
	if err := s.checkStamp(t); err != nil {
		return Versioned{}, err
	}
	data, err := encode(t)
	if err != nil {
		return Versioned{}, err
	}
	revision, err := s.kv.Update(ctx, t.ID, data, 0)
	if errors.Is(err, jetstream.ErrKeyExists) || errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
		return Versioned{}, fmt.Errorf("%w: %s", ErrExists, t.ID)
	}
	if err != nil {
		return Versioned{}, err
	}
	return Versioned{Tenant: t, Revision: revision}, nil
}

// Update replaces the tenant stored at revision with its successor next. It
// checks next against the stored record, never against the caller's copy.
func (s *Store) Update(ctx context.Context, revision uint64, next Tenant) (Versioned, error) {
	current, err := s.Get(ctx, next.ID)
	if err != nil {
		return Versioned{}, err
	}
	if current.Revision != revision {
		return Versioned{}, fmt.Errorf("%w: %s", ErrConflict, next.ID)
	}
	if err := CheckSuccessor(current.Tenant, next); err != nil {
		return Versioned{}, err
	}
	if err := s.checkStamp(next); err != nil {
		return Versioned{}, err
	}
	data, err := encode(next)
	if err != nil {
		return Versioned{}, err
	}
	revision, err = s.kv.Update(ctx, next.ID, data, revision)
	if errors.Is(err, jetstream.ErrKeyExists) || errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
		return Versioned{}, fmt.Errorf("%w: %s", ErrConflict, next.ID)
	}
	if err != nil {
		return Versioned{}, err
	}
	return Versioned{Tenant: next, Revision: revision}, nil
}

// Get reads one tenant. Tenants are never removed, so a delete marker is
// tampering, not absence.
func (s *Store) Get(ctx context.Context, id string) (Versioned, error) {
	if !entityid.Valid(id) {
		return Versioned{}, fmt.Errorf("%w: id %q", ErrInvalid, id)
	}
	key := id
	msg, err := s.leader.GetLastMsg("KV_"+Bucket, "$KV."+Bucket+"."+key, nats.Context(ctx))
	if errors.Is(err, nats.ErrMsgNotFound) {
		return Versioned{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return Versioned{}, err
	}
	if operation := msg.Header.Get("KV-Operation"); operation != "" {
		return Versioned{}, fmt.Errorf("%w: %s has a %s marker", ErrCorrupt, key, operation)
	}
	return decode(key, msg.Data, msg.Sequence)
}

// List reads, sorted by ID, every tenant created before the call, each at
// its latest state; a tenant created during the call may be missing. Since
// tenants are never removed, a missing tenant is never a gone one: the
// tenant's state says when it is gone. A corrupt record or a delete marker
// fails the list, and so does a listing cut short, so a reconciler never
// takes a tampered or truncated bucket for tenants that are gone.
func (s *Store) List(ctx context.Context) ([]Versioned, error) {
	watcher, err := s.kv.WatchFiltered(ctx, []string{"*"}, jetstream.MetaOnly())
	if err != nil {
		return nil, err
	}
	defer watcher.Stop()
	var ids []string
	complete := false
	for entry := range watcher.Updates() {
		if entry == nil {
			complete = true
			break
		}
		ids = append(ids, entry.Key())
	}
	if !complete {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("tenant listing: %w", context.Cause(ctx))
		}
		return nil, errors.New("tenant listing ended before every tenant was read")
	}
	slices.Sort(ids)
	tenants := make([]Versioned, 0, len(ids))
	for _, id := range slices.Compact(ids) {
		t, err := s.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, t)
	}
	return tenants, nil
}

func encode(t Tenant) ([]byte, error) {
	data, err := json.Marshal(t)
	if err == nil && len(data) > maxValueBytes {
		err = fmt.Errorf("%w: tenant %s exceeds %d bytes", ErrInvalid, t.ID, maxValueBytes)
	}
	return data, err
}

// decode trusts a record only when it is valid and stored under its own ID.
func decode(key string, value []byte, revision uint64) (Versioned, error) {
	var t Tenant
	if err := json.Unmarshal(value, &t, json.RejectUnknownMembers(true)); err != nil {
		return Versioned{}, fmt.Errorf("%w: %s: %v", ErrCorrupt, key, err)
	}
	if err := t.Validate(); err != nil {
		return Versioned{}, fmt.Errorf("%w: %s: %v", ErrCorrupt, key, err)
	}
	if key != t.ID {
		return Versioned{}, fmt.Errorf("%w: %s holds tenant %s", ErrCorrupt, key, t.ID)
	}
	return Versioned{Tenant: t, Revision: revision}, nil
}
