package ociresource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"
	"uuid"

	"github.com/nats-io/nats.go/jetstream"
)

const (
	desiredBucket  = "TS_OCI_DESIRED"
	observedBucket = "TS_OCI_OBSERVED"
	maxRecordBytes = 64 << 10
	schemaVersion  = 2
	maxListedKeys  = 4096
)

var (
	// ErrConflict marks a lost compare-and-set race or a non-increasing generation.
	ErrConflict = errors.New("OCI desired state changed concurrently")
	// ErrNotFound marks a missing desired record.
	ErrNotFound = errors.New("OCI desired state record does not exist")
)

// Tombstone marks a desired resource for deletion. The controller deletes the
// owned cloud resource only at or after NotBefore, then purges the record.
type Tombstone struct {
	RequestedAt time.Time `json:"requestedAt"`
	NotBefore   time.Time `json:"notBefore"`
}

// Desired is one versioned desired-state record.
type Desired struct {
	SchemaVersion int            `json:"schemaVersion"`
	Key           Key            `json:"key"`
	Generation    uint64         `json:"generation"`
	Policy        DriftPolicy    `json:"policy"`
	Spec          jsontext.Value `json:"spec"`
	SpecDigest    string         `json:"specDigest"`
	Tombstone     *Tombstone     `json:"tombstone,omitempty"`
	Operation     *Operation     `json:"operation,omitempty"`
	// Revision is the KV revision the record was read at; it is not stored.
	Revision uint64 `json:"-"`
}

// NewDesired encodes spec and computes its digest.
func NewDesired(key Key, generation uint64, policy DriftPolicy, spec any) (Desired, error) {
	wire, err := json.Marshal(spec, json.Deterministic(true))
	if err != nil {
		return Desired{}, fmt.Errorf("encode OCI desired spec: %w", err)
	}
	desired := Desired{SchemaVersion: schemaVersion, Key: key, Generation: generation, Policy: policy,
		Spec: jsontext.Value(wire), SpecDigest: digest(wire)}
	return desired, desired.Validate()
}

func digest(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

// Validate checks the record shape and that the digest binds the spec bytes.
func (d Desired) Validate() error {
	if d.SchemaVersion != schemaVersion || d.Generation == 0 || !d.Policy.valid() || len(d.Spec) == 0 {
		return errors.New("OCI desired record has an unsupported version, generation, policy, or spec")
	}
	if err := d.Key.Validate(); err != nil {
		return err
	}
	if digest(d.Spec) != d.SpecDigest {
		return errors.New("OCI desired record spec does not match its digest")
	}
	if d.Tombstone != nil && (d.Tombstone.RequestedAt.IsZero() || d.Tombstone.NotBefore.Before(d.Tombstone.RequestedAt)) {
		return errors.New("OCI desired record tombstone is invalid")
	}
	if d.Operation != nil {
		return d.Operation.validate()
	}
	return nil
}

// Status is the last observation of one desired resource.
type Status struct {
	Key        Key       `json:"key"`
	Generation uint64    `json:"generation"`
	SpecDigest string    `json:"specDigest"`
	ObservedAt time.Time `json:"observedAt"`
	// Policy is the desired record's drift policy at this observation.
	Policy      DriftPolicy `json:"policy,omitempty"`
	Found       bool        `json:"found"`
	InSync      bool        `json:"inSync"`
	Foreign     bool        `json:"foreign,omitempty"`
	Drift       []Change    `json:"drift,omitempty"`
	Applied     bool        `json:"applied,omitempty"`
	Deleted     bool        `json:"deleted,omitempty"`
	Error       string      `json:"error,omitempty"`
	OperationID string      `json:"operationId,omitempty"`
}

// Store is the desired/observed state seam. KVStore is the replicated
// implementation used by production and integration scenarios.
type Store interface {
	List(ctx context.Context, region, kind string) ([]Desired, error)
	Get(ctx context.Context, key Key) (Desired, error)
	// Put creates the record or replaces it with a strictly higher generation.
	Put(ctx context.Context, desired Desired) (Desired, error)
	// MarkDeleted tombstones the record at its current revision.
	MarkDeleted(ctx context.Context, key Key, requestedAt, notBefore time.Time) (Desired, error)
	// Purge removes a tombstoned record only if it is still at desired.Revision.
	Purge(ctx context.Context, desired Desired) error
	PutStatus(ctx context.Context, status Status) error
	GetStatus(ctx context.Context, key Key) (Status, bool, error)
	// SaveOperation atomically claims or confirms an operation at the desired
	// revision. In-flight IDs survive retries and authority transfers.
	SaveOperation(ctx context.Context, desired Desired, epoch uint64, now time.Time, complete bool) (Desired, error)
}

func encode(value any) ([]byte, error) {
	wire, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	if len(wire) > maxRecordBytes {
		return nil, errors.New("OCI resource record exceeds its size bound")
	}
	return wire, nil
}

func decodeDesired(wire []byte, revision uint64) (Desired, error) {
	if len(wire) > maxRecordBytes {
		return Desired{}, errors.New("OCI desired record exceeds its size bound")
	}
	var desired Desired
	if err := json.Unmarshal(wire, &desired, json.RejectUnknownMembers(true)); err != nil {
		return Desired{}, fmt.Errorf("decode OCI desired record: %w", err)
	}
	if desired.SchemaVersion == 1 && (desired.Policy == PolicyEnforce || desired.Policy == "report") && desired.Operation == nil {
		// Migrate the old switch once; the operation CAS persists v2 before
		// effects. New publishers can only submit always-enforced records.
		desired.SchemaVersion = schemaVersion
		desired.Policy = PolicyEnforce
	}
	if err := desired.Validate(); err != nil {
		return Desired{}, err
	}
	desired.Revision = revision
	return desired, nil
}

// KVStore keeps desired state and observations in replicated JetStream KV.
type KVStore struct {
	desired  jetstream.KeyValue
	observed jetstream.KeyValue
}

// OpenKVStore creates or opens the regional desired and observed buckets.
// Replicas must match the regional controller quorum configuration.
func OpenKVStore(ctx context.Context, js jetstream.JetStream, replicas int) (*KVStore, error) {
	if js == nil || replicas < 1 || replicas > 5 {
		return nil, errors.New("OCI resource store requires JetStream and one to five replicas")
	}
	open := func(bucket, description string, history uint8) (jetstream.KeyValue, error) {
		kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: bucket, Description: description,
			MaxValueSize: maxRecordBytes, History: history, Storage: jetstream.FileStorage, Replicas: replicas, Compression: true})
		if err == nil {
			return kv, nil
		}
		if !errors.Is(err, jetstream.ErrBucketExists) {
			return nil, fmt.Errorf("create %s bucket: %w", bucket, err)
		}
		kv, err = js.KeyValue(ctx, bucket)
		if err != nil {
			return nil, fmt.Errorf("open %s bucket: %w", bucket, err)
		}
		status, err := kv.Status(ctx)
		if err != nil {
			return nil, fmt.Errorf("inspect %s bucket: %w", bucket, err)
		}
		config := status.Config()
		if config.Replicas != replicas || config.Storage != jetstream.FileStorage || config.MaxValueSize > maxRecordBytes {
			return nil, fmt.Errorf("existing %s bucket has incompatible durability limits", bucket)
		}
		return kv, nil
	}
	desired, err := open(desiredBucket, "Desired OCI regional resource specs", 5)
	if err != nil {
		return nil, err
	}
	observed, err := open(observedBucket, "Last observed OCI regional resource state and drift", 1)
	if err != nil {
		return nil, err
	}
	return &KVStore{desired: desired, observed: observed}, nil
}

// NewKVStore wraps existing buckets.
func NewKVStore(desired, observed jetstream.KeyValue) (*KVStore, error) {
	if desired == nil || observed == nil {
		return nil, errors.New("OCI resource store requires both buckets")
	}
	return &KVStore{desired: desired, observed: observed}, nil
}

func (s *KVStore) List(ctx context.Context, region, kind string) ([]Desired, error) {
	probe := Key{Region: region, Kind: kind, Name: "x"}
	if err := probe.Validate(); err != nil {
		return nil, err
	}
	lister, err := s.desired.ListKeysFiltered(ctx, region+"."+kind+".*")
	if err != nil {
		if errors.Is(err, jetstream.ErrNoKeysFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("list OCI desired keys: %w", err)
	}
	var keys []string
	seen := make(map[string]bool)
	for key := range lister.Keys() {
		if len(keys) >= maxListedKeys {
			_ = lister.Stop()
			return nil, errors.New("OCI desired key list exceeds its safety bound")
		}
		if !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	// The lister closes early without an error when ctx ends mid-listing;
	// a truncated listing must not look complete.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("list OCI desired keys: %w", err)
	}
	slices.Sort(keys)
	records := make([]Desired, 0, len(keys))
	for _, subject := range keys {
		entry, err := s.desired.Get(ctx, subject)
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read OCI desired record: %w", err)
		}
		desired, err := decodeDesired(entry.Value(), entry.Revision())
		if err != nil {
			return nil, err
		}
		if desired.Key.subject() != subject {
			return nil, errors.New("OCI desired record key differs from its bucket key")
		}
		records = append(records, desired)
	}
	return records, nil
}

func (s *KVStore) Get(ctx context.Context, key Key) (Desired, error) {
	if err := key.Validate(); err != nil {
		return Desired{}, err
	}
	entry, err := s.desired.Get(ctx, key.subject())
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return Desired{}, ErrNotFound
	}
	if err != nil {
		return Desired{}, fmt.Errorf("read OCI desired record: %w", err)
	}
	desired, err := decodeDesired(entry.Value(), entry.Revision())
	if err != nil {
		return Desired{}, err
	}
	if desired.Key != key {
		return Desired{}, errors.New("OCI desired record key differs from its bucket key")
	}
	return desired, nil
}

func (s *KVStore) Put(ctx context.Context, desired Desired) (Desired, error) {
	desired.Operation = nil
	if err := desired.Validate(); err != nil {
		return Desired{}, err
	}
	wire, err := encode(desired)
	if err != nil {
		return Desired{}, err
	}
	current, err := s.Get(ctx, desired.Key)
	switch {
	case errors.Is(err, ErrNotFound):
		revision, err := s.desired.Create(ctx, desired.Key.subject(), wire)
		if errors.Is(err, jetstream.ErrKeyExists) {
			return Desired{}, ErrConflict
		}
		if err != nil {
			return Desired{}, fmt.Errorf("create OCI desired record: %w", err)
		}
		desired.Revision = revision
		return desired, nil
	case err != nil:
		return Desired{}, err
	}
	if desired.Generation <= current.Generation {
		return Desired{}, fmt.Errorf("%w: generation %d does not supersede %d", ErrConflict, desired.Generation, current.Generation)
	}
	if current.Operation != nil && current.Operation.CompletedAt.IsZero() {
		return Desired{}, fmt.Errorf("%w: previous OCI operation awaits observation", ErrConflict)
	}
	desired.Operation = nil
	wire, err = encode(desired)
	if err != nil {
		return Desired{}, err
	}
	revision, err := s.desired.Update(ctx, desired.Key.subject(), wire, current.Revision)
	if err != nil {
		return Desired{}, fmt.Errorf("%w: %w", ErrConflict, err)
	}
	desired.Revision = revision
	return desired, nil
}

// SaveOperation uses the desired record's CAS as the write barrier, including
// retries in the same epoch. A stale follower read cannot pass this barrier.
func (s *KVStore) SaveOperation(ctx context.Context, desired Desired, epoch uint64, now time.Time, complete bool) (Desired, error) {
	if desired.Revision == 0 {
		return Desired{}, ErrConflict
	}
	desired, err := operationRecord(desired, epoch, now, complete)
	if err != nil {
		return Desired{}, err
	}
	wire, err := encode(desired)
	if err != nil {
		return Desired{}, err
	}
	revision, err := s.desired.Update(ctx, desired.Key.subject(), wire, desired.Revision)
	if err != nil {
		return Desired{}, fmt.Errorf("%w: persist OCI operation: %w", ErrConflict, err)
	}
	desired.Revision = revision
	return desired, nil
}

func operationRecord(desired Desired, epoch uint64, now time.Time, complete bool) (Desired, error) {
	if epoch == 0 || now.IsZero() {
		return Desired{}, errors.New("OCI operation requires an authority epoch and timestamp")
	}
	operation := Operation{ID: uuid.New().String(), Epoch: epoch, StartedAt: now.UTC()}
	if desired.Operation != nil && desired.Operation.CompletedAt.IsZero() {
		operation = *desired.Operation
		if epoch < operation.Epoch {
			return Desired{}, ErrFenced
		}
		operation.Epoch = epoch
	}
	if complete {
		operation.CompletedAt = now.UTC()
	}
	desired.Operation = &operation
	return desired, desired.Validate()
}

func (s *KVStore) MarkDeleted(ctx context.Context, key Key, requestedAt, notBefore time.Time) (Desired, error) {
	current, err := s.Get(ctx, key)
	if err != nil {
		return Desired{}, err
	}
	if current.Tombstone != nil {
		return current, nil
	}
	if current.Operation != nil && current.Operation.CompletedAt.IsZero() {
		return Desired{}, fmt.Errorf("%w: previous OCI operation awaits observation", ErrConflict)
	}
	current.Operation = nil
	current.Tombstone = &Tombstone{RequestedAt: requestedAt.UTC(), NotBefore: notBefore.UTC()}
	if err := current.Validate(); err != nil {
		return Desired{}, err
	}
	wire, err := encode(current)
	if err != nil {
		return Desired{}, err
	}
	revision, err := s.desired.Update(ctx, key.subject(), wire, current.Revision)
	if err != nil {
		return Desired{}, fmt.Errorf("%w: %w", ErrConflict, err)
	}
	current.Revision = revision
	return current, nil
}

func (s *KVStore) Purge(ctx context.Context, desired Desired) error {
	if desired.Tombstone == nil || desired.Revision == 0 {
		return errors.New("only a read tombstoned OCI desired record may be purged")
	}
	if err := s.desired.Purge(ctx, desired.Key.subject(), jetstream.LastRevision(desired.Revision)); err != nil {
		return fmt.Errorf("%w: %w", ErrConflict, err)
	}
	if err := s.observed.Purge(ctx, desired.Key.subject()); err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
		return fmt.Errorf("purge OCI observed record: %w", err)
	}
	return nil
}

func (s *KVStore) PutStatus(ctx context.Context, status Status) error {
	if err := status.Key.Validate(); err != nil {
		return err
	}
	wire, err := encode(status)
	if err != nil {
		return err
	}
	if _, err := s.observed.Put(ctx, status.Key.subject(), wire); err != nil {
		return fmt.Errorf("write OCI observed record: %w", err)
	}
	return nil
}

func (s *KVStore) GetStatus(ctx context.Context, key Key) (Status, bool, error) {
	if err := key.Validate(); err != nil {
		return Status{}, false, err
	}
	entry, err := s.observed.Get(ctx, key.subject())
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return Status{}, false, nil
	}
	if err != nil {
		return Status{}, false, fmt.Errorf("read OCI observed record: %w", err)
	}
	var status Status
	if err := json.Unmarshal(entry.Value(), &status); err != nil {
		return Status{}, false, fmt.Errorf("decode OCI observed record: %w", err)
	}
	return status, true, nil
}

// StatusLister lists the last observations of one region, for read-only
// views such as the dashboard's drift insights.
type StatusLister interface {
	ListStatus(ctx context.Context, region string) ([]Status, error)
}

// ListStatus returns every observation of region, sorted by key. A record
// that cannot be decoded fails the listing rather than hiding drift.
func (s *KVStore) ListStatus(ctx context.Context, region string) ([]Status, error) {
	if err := (Key{Region: region, Kind: "x", Name: "x"}).Validate(); err != nil {
		return nil, err
	}
	lister, err := s.observed.ListKeysFiltered(ctx, region+".*.*")
	if err != nil {
		if errors.Is(err, jetstream.ErrNoKeysFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("list OCI observed keys: %w", err)
	}
	var keys []string
	for key := range lister.Keys() {
		if len(keys) >= maxListedKeys {
			_ = lister.Stop()
			return nil, errors.New("OCI observed key list exceeds its safety bound")
		}
		keys = append(keys, key)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("list OCI observed keys: %w", err)
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)
	statuses := make([]Status, 0, len(keys))
	for _, subject := range keys {
		entry, err := s.observed.Get(ctx, subject)
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read OCI observed record: %w", err)
		}
		if len(entry.Value()) > maxRecordBytes {
			return nil, errors.New("OCI observed record exceeds its size bound")
		}
		var status Status
		if err := json.Unmarshal(entry.Value(), &status); err != nil {
			return nil, fmt.Errorf("decode OCI observed record: %w", err)
		}
		if status.Key.subject() != subject {
			return nil, errors.New("OCI observed record key differs from its bucket key")
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}
