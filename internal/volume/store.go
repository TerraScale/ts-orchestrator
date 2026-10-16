package volume

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

// Bucket is the replicated KV bucket of a cell's volume records, keyed by
// volume ID.
const Bucket = "TS_VOLUMES"

const (
	maxRecordBytes = 16 << 10
	maxListed      = 10000
)

// Store keeps one cell's volume records. Every write is a compare-and-set on
// the KV revision and is checked against the stored record. It performs no
// OCI effect; the reconciler fences its effects and stamps its epoch on the
// status it writes.
type Store struct {
	kv     jetstream.KeyValue
	region string
}

// OpenStore provisions or binds the volume bucket of one region's cell.
func OpenStore(ctx context.Context, js jetstream.JetStream, region string, replicas int) (*Store, error) {
	if js == nil || !validRegion(region) || replicas != 1 && replicas != 3 && replicas != 5 {
		return nil, fmt.Errorf("%w: volume store configuration", ErrInvalid)
	}
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: Bucket, Description: "Managed volume records", Storage: jetstream.FileStorage,
		Replicas: replicas, History: 8, MaxValueSize: maxRecordBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("volume store: %w", err)
	}
	return &Store{kv: kv, region: region}, nil
}

// Create stores a new volume of this cell in state creating, with no
// machine, destroy request or OCI volume yet. The record is the durable
// intent of the OCI create.
func (s *Store) Create(ctx context.Context, v Volume) (Volume, error) {
	if err := v.Validate(); err != nil {
		return Volume{}, err
	}
	if v.Region != s.region || v.MachineID != "" || v.Destroying() || v.Status != (Status{State: StateCreating}) {
		return Volume{}, fmt.Errorf("%w: a new volume of %s starts creating with no machine", ErrInvalid, s.region)
	}
	wire, err := protocol.EncodeJSON(v)
	if err != nil {
		return Volume{}, err
	}
	revision, err := s.kv.Create(ctx, v.ID, wire)
	if errors.Is(err, jetstream.ErrKeyExists) {
		return Volume{}, fmt.Errorf("%w: volume %s exists", ErrConflict, v.ID)
	}
	if err != nil {
		return Volume{}, fmt.Errorf("create volume %s: %w", v.ID, err)
	}
	v.Revision = revision
	return v, nil
}

// Get reads one volume. A record that does not match its key or this cell
// is refused rather than returned.
func (s *Store) Get(ctx context.Context, id string) (Volume, error) {
	if !entityid.Valid(id) {
		return Volume{}, fmt.Errorf("%w: id %q", ErrInvalid, id)
	}
	entry, err := s.kv.Get(ctx, id)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return Volume{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return Volume{}, fmt.Errorf("read volume %s: %w", id, err)
	}
	return s.decode(id, entry)
}

func (s *Store) decode(id string, entry jetstream.KeyValueEntry) (Volume, error) {
	var v Volume
	if err := protocol.DecodeStrict(entry.Value(), &v, maxRecordBytes); err != nil {
		return Volume{}, fmt.Errorf("%w: record %s: %w", ErrInvalid, id, err)
	}
	if err := v.Validate(); err != nil {
		return Volume{}, fmt.Errorf("record %s: %w", id, err)
	}
	if v.ID != id || v.Region != s.region {
		return Volume{}, fmt.Errorf("%w: record %s holds volume %s of %s", ErrInvalid, id, v.ID, v.Region)
	}
	v.Revision = entry.Revision()
	return v, nil
}

// List returns every volume of the cell, sorted by ID. One invalid record
// fails the list: callers schedule and reconcile only on a complete view.
func (s *Store) List(ctx context.Context) ([]Volume, error) {
	watcher, err := s.kv.WatchAll(ctx, jetstream.IgnoreDeletes())
	if err != nil {
		return nil, fmt.Errorf("list volumes: %w", err)
	}
	defer func() {
		_ = watcher.Stop()
		// A delivery blocked on the full channel finishes, and the closed
		// subscription then closes the channel and ends this drain.
		go func() {
			for range watcher.Updates() {
			}
		}()
	}()
	var volumes []Volume
	for {
		var entry jetstream.KeyValueEntry
		open := false
		select {
		case entry, open = <-watcher.Updates():
		case <-ctx.Done():
			return nil, fmt.Errorf("list volumes: %w", ctx.Err())
		}
		switch {
		case !open:
			// The subscription closed before the initial values ended, for
			// example on a lost connection: the list would be partial.
			return nil, errors.New("list volumes: the key watch ended early")
		case entry == nil:
			slices.SortFunc(volumes, func(a, b Volume) int { return strings.Compare(a.ID, b.ID) })
			return volumes, nil
		case len(volumes) == maxListed:
			return nil, errors.New("volume list exceeds its safety bound")
		}
		v, err := s.decode(entry.Key(), entry)
		if err != nil {
			return nil, err
		}
		volumes = append(volumes, v)
	}
}

// Update replaces the record read at v.Revision with v, after checking the
// change against the stored record. A record changed since then fails with
// ErrConflict.
func (s *Store) Update(ctx context.Context, v Volume) (Volume, error) {
	prev, err := s.Get(ctx, v.ID)
	if err != nil {
		return Volume{}, err
	}
	if prev.Revision != v.Revision {
		return Volume{}, fmt.Errorf("%w: volume %s is at revision %d, not %d", ErrConflict, v.ID, prev.Revision, v.Revision)
	}
	if err := checkUpdate(prev, v); err != nil {
		return Volume{}, err
	}
	wire, err := protocol.EncodeJSON(v)
	if err != nil {
		return Volume{}, err
	}
	revision, err := s.kv.Update(ctx, v.ID, wire, v.Revision)
	if errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
		return Volume{}, fmt.Errorf("%w: volume %s", ErrConflict, v.ID)
	}
	if err != nil {
		return Volume{}, fmt.Errorf("update volume %s: %w", v.ID, err)
	}
	v.Revision = revision
	return v, nil
}

// Claim gives the volume to machineID. It is idempotent, and fails while
// another machine holds the volume or it is destroying.
func (s *Store) Claim(ctx context.Context, id, machineID string) (Volume, error) {
	return s.setMachine(ctx, id, "", machineID)
}

// Release takes the volume back from machineID. It is idempotent, and a
// release by a machine that no longer holds the volume changes nothing, so
// a stale release never takes the volume from its new machine.
func (s *Store) Release(ctx context.Context, id, machineID string) (Volume, error) {
	return s.setMachine(ctx, id, machineID, "")
}

func (s *Store) setMachine(ctx context.Context, id, from, to string) (Volume, error) {
	if !entityid.Valid(from + to) {
		return Volume{}, fmt.Errorf("%w: machine %q", ErrInvalid, from+to)
	}
	v, err := s.Get(ctx, id)
	if err != nil {
		return Volume{}, err
	}
	switch {
	case v.MachineID == to:
		return v, nil
	case from != "" && v.MachineID != from:
		return v, nil
	case v.Destroying():
		return Volume{}, fmt.Errorf("%w: volume %s is destroying", ErrTransition, id)
	}
	v.MachineID = to
	return s.Update(ctx, v)
}

// RequestDestroy starts the destroy of an unclaimed volume. It is idempotent
// and final.
func (s *Store) RequestDestroy(ctx context.Context, id string, now time.Time) (Volume, error) {
	v, err := s.Get(ctx, id)
	if err != nil || v.Destroying() {
		return v, err
	}
	if v.MachineID != "" {
		return Volume{}, fmt.Errorf("%w: volume %s is held by machine %s", ErrTransition, id, v.MachineID)
	}
	if now.IsZero() {
		return Volume{}, fmt.Errorf("%w: a destroy request needs its time", ErrInvalid)
	}
	v.DestroyRequestedAt = now.UTC()
	return s.Update(ctx, v)
}

// Zone returns the availability domain a machine of app must run in to use
// mounts, or "" when it mounts nothing. Like Fly, a machine mounts at most
// one volume. The volume must belong to app, be unclaimed or claimed by
// machineID, and be neither destroying nor failed.
func (s *Store) Zone(ctx context.Context, app, machineID string, mounts []Mount) (string, error) {
	switch len(mounts) {
	case 0:
		return "", nil
	case 1:
	default:
		return "", fmt.Errorf("%w: a machine mounts at most one volume", ErrInvalid)
	}
	if err := mounts[0].validate(); err != nil {
		return "", err
	}
	v, err := s.Get(ctx, mounts[0].Volume)
	switch {
	case errors.Is(err, ErrNotFound) || err == nil && v.App != app:
		return "", fmt.Errorf("%w: volume %s of app %s", ErrNotFound, mounts[0].Volume, app)
	case err != nil:
		return "", err
	case v.Destroying() || v.Status.State == StateFailed:
		return "", fmt.Errorf("%w: volume %s is destroying or failed", ErrTransition, v.ID)
	case v.MachineID != "" && v.MachineID != machineID:
		return "", fmt.Errorf("%w: volume %s is held by machine %s", ErrTransition, v.ID, v.MachineID)
	}
	return v.Zone, nil
}
