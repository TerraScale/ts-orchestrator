package placement

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	stateBucketName = "TS_PLACEMENT_STATE"
	maxIntentCount  = 4096
	maxStateBytes   = 64 << 10
)

var (
	ErrStoreConflict  = errors.New("placement state compare-and-swap conflict")
	ErrStoreCorrupt   = errors.New("placement state is corrupt")
	ErrMemberNotFound = errors.New("placement member state not found")
)

// AdmittedIntentReader returns only placement intents committed by the
// regional authority path. It must not expose operator drafts or unauthenticated
// values from a mutable local file.
type AdmittedIntentReader interface {
	ListPlacementIntents(context.Context, string) ([]Intent, error)
	ReadTerminalIntent(context.Context, string, string) (authority.LogEntry, error)
}

type authorityIntentReader struct {
	store    authority.PlacementIntentStore
	terminal authority.TerminalIntentReader
	cell     string
	region   oci.Region
}

// NewAuthorityIntentReader adapts the ordered regional placement log.
func NewAuthorityIntentReader(store authority.PlacementIntentStore, cell string, region oci.Region) (AdmittedIntentReader, error) {
	if store == nil || !validToken(cell) || !knownRegion(region) {
		return nil, errors.New("placement intent reader requires an authority log, cell, and supported region")
	}
	terminal, ok := store.(authority.TerminalIntentReader)
	if !ok {
		return nil, errors.New("placement intent reader requires a terminal authority fence")
	}
	return authorityIntentReader{store: store, terminal: terminal, cell: cell, region: region}, nil
}

func (reader authorityIntentReader) ReadTerminalIntent(ctx context.Context, databaseID, partitionID string) (authority.LogEntry, error) {
	return reader.terminal.ReadTerminalIntent(ctx, databaseID, partitionID)
}

func (reader authorityIntentReader) ListPlacementIntents(ctx context.Context, cell string) ([]Intent, error) {
	if cell != reader.cell {
		return nil, errors.New("placement intent reader scope mismatch")
	}
	entries, err := reader.store.ListPlacementIntents(ctx)
	if err != nil {
		return nil, err
	}
	if len(entries) > maxIntentCount {
		return nil, errors.New("placement intent listing exceeds its bound")
	}
	result := make([]Intent, 0, len(entries))
	for _, entry := range entries {
		if entry.Kind != authority.MutationPlacementIntent || entry.Sequence == 0 || entry.Epoch == 0 || !validToken(entry.OperationID) {
			return nil, fmt.Errorf("%w: malformed ordered placement log identity", ErrInvalidIntent)
		}
		intent, err := DecodeCommittedIntent(entry.Payload)
		if err != nil || intent.DatabaseID+"."+intent.PartitionID != entry.SubjectKey ||
			intent.OperationID() != entry.OperationID || !slices.Contains(intent.ActiveRegions, reader.region) {
			return nil, fmt.Errorf("%w: ordered placement payload identity or region mismatch", ErrInvalidIntent)
		}
		result = append(result, intent)
	}
	return result, nil
}

type VersionedMemberState struct {
	State    MemberState
	Revision uint64
}

// MemberPinReader looks up one exact durable Go placement seat. It must not
// scan the state bucket or substitute a different member when the key is absent.
type MemberPinReader interface {
	ReadMember(context.Context, string, string, string) (VersionedMemberState, error)
}

type Store interface {
	MemberPinReader
	ListIntents(context.Context) ([]Intent, error)
	ReadTerminalIntent(context.Context, string, string) (authority.LogEntry, error)
	ListMembers(context.Context, string, string) ([]VersionedMemberState, error)
	CompareAndSwap(context.Context, uint64, MemberState) (uint64, error)
}

type jetStreamStore struct {
	cell    string
	state   jetstream.KeyValue
	intents AdmittedIntentReader
}

// NewJetStreamStore opens the durable member-state bucket for one regional
// control plane and fails if its existing replica count is weaker than the
// configured R3 quorum. Placement intents are supplied by an admitted reader.
func NewJetStreamStore(ctx context.Context, js jetstream.JetStream, cell string, replicas int, intents AdmittedIntentReader) (Store, error) {
	if !validToken(cell) || js == nil || intents == nil || replicas < 1 || replicas > 5 {
		return nil, errors.New("placement store requires cell, JetStream, admitted intent reader and valid replica count")
	}
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:       stateBucketName,
		Description:  "Durable regional TerraBase placement member state",
		History:      2,
		MaxValueSize: maxStateBytes,
		MaxBytes:     128 << 20,
		Storage:      jetstream.FileStorage,
		Replicas:     replicas,
	})
	if err != nil {
		return nil, fmt.Errorf("open placement member state: %w", err)
	}
	status, err := kv.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("read placement member state status: %w", err)
	}
	if status.Config().Replicas != replicas {
		return nil, fmt.Errorf("placement state has %d replicas, requires %d", status.Config().Replicas, replicas)
	}
	return &jetStreamStore{cell: cell, state: kv, intents: intents}, nil
}

func (store *jetStreamStore) ListIntents(ctx context.Context) ([]Intent, error) {
	intents, err := store.intents.ListPlacementIntents(ctx, store.cell)
	if err != nil {
		return nil, err
	}
	if len(intents) > maxIntentCount {
		return nil, errors.New("placement intent listing exceeds its bound")
	}
	seen := make(map[string]struct{}, len(intents))
	for _, intent := range intents {
		if err := intent.Validate(); err != nil {
			return nil, err
		}
		if !validLowerSHA256Digest(intent.PayloadDigest()) {
			return nil, fmt.Errorf("%w: admitted placement intent is missing its canonical committed payload digest", ErrInvalidIntent)
		}
		identity := intent.DatabaseID + "\x00" + intent.PartitionID
		if _, exists := seen[identity]; exists {
			return nil, fmt.Errorf("%w: duplicate database/partition intent %q/%q", ErrInvalidIntent, intent.DatabaseID, intent.PartitionID)
		}
		seen[identity] = struct{}{}
	}
	slices.SortFunc(intents, func(a, b Intent) int {
		if database := strings.Compare(a.DatabaseID, b.DatabaseID); database != 0 {
			return database
		}
		return strings.Compare(a.PartitionID, b.PartitionID)
	})
	return intents, nil
}

func (store *jetStreamStore) ReadTerminalIntent(ctx context.Context, databaseID, partitionID string) (authority.LogEntry, error) {
	return store.intents.ReadTerminalIntent(ctx, databaseID, partitionID)
}

func (store *jetStreamStore) ListMembers(ctx context.Context, databaseID, partitionID string) ([]VersionedMemberState, error) {
	if !validDatabaseKeyID(databaseID) || !validBoundedToken(partitionID, maxPartitionIDLength) {
		return nil, fmt.Errorf("%w: database or partition id", ErrInvalidIntent)
	}
	keys, err := store.state.Keys(ctx)
	if errors.Is(err, jetstream.ErrNoKeysFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	prefix := memberStatePrefix(databaseID, partitionID)
	result := make([]VersionedMemberState, 0)
	for _, key := range keys {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		entry, err := store.state.Get(ctx, key)
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if entry.Operation() != jetstream.KeyValuePut {
			return nil, fmt.Errorf("%w: tombstone at %s", ErrStoreCorrupt, key)
		}
		var state MemberState
		if err := json.Unmarshal(entry.Value(), &state, json.RejectUnknownMembers(true)); err != nil {
			return nil, fmt.Errorf("%w: decode %s: %v", ErrStoreCorrupt, key, err)
		}
		if err := state.Validate(); err != nil || state.DatabaseID != databaseID || state.PartitionID != partitionID || memberStateKey(state.DatabaseID, state.PartitionID, state.MemberID) != key {
			return nil, fmt.Errorf("%w: invalid state at %s", ErrStoreCorrupt, key)
		}
		result = append(result, VersionedMemberState{State: state, Revision: entry.Revision()})
	}
	slices.SortFunc(result, func(a, b VersionedMemberState) int {
		return strings.Compare(a.State.MemberID, b.State.MemberID)
	})
	return result, nil
}

func (store *jetStreamStore) ReadMember(ctx context.Context, databaseID, partitionID, seatID string) (VersionedMemberState, error) {
	if !validDatabaseKeyID(databaseID) || !validBoundedToken(partitionID, maxPartitionIDLength) ||
		!validToken(seatID) {
		return VersionedMemberState{}, fmt.Errorf("%w: database, partition, or seat id", ErrInvalidIntent)
	}
	key := memberStateKey(databaseID, partitionID, seatID)
	entry, err := store.state.Get(ctx, key)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return VersionedMemberState{}, ErrMemberNotFound
	}
	if err != nil {
		return VersionedMemberState{}, err
	}
	if entry.Operation() != jetstream.KeyValuePut {
		return VersionedMemberState{}, fmt.Errorf("%w: tombstone at %s", ErrStoreCorrupt, key)
	}
	var state MemberState
	if err := json.Unmarshal(entry.Value(), &state, json.RejectUnknownMembers(true)); err != nil {
		return VersionedMemberState{}, fmt.Errorf("%w: decode %s: %v", ErrStoreCorrupt, key, err)
	}
	if err := state.Validate(); err != nil || state.DatabaseID != databaseID || state.PartitionID != partitionID ||
		state.MemberID != seatID || memberStateKey(state.DatabaseID, state.PartitionID, state.MemberID) != key {
		return VersionedMemberState{}, fmt.Errorf("%w: invalid state at %s", ErrStoreCorrupt, key)
	}
	return VersionedMemberState{State: state, Revision: entry.Revision()}, nil
}

func (store *jetStreamStore) CompareAndSwap(ctx context.Context, expected uint64, state MemberState) (uint64, error) {
	if err := state.Validate(); err != nil {
		return 0, err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return 0, err
	}
	if len(data) > maxStateBytes {
		return 0, errors.New("placement member state exceeds size bound")
	}
	key := memberStateKey(state.DatabaseID, state.PartitionID, state.MemberID)
	var revision uint64
	if expected == 0 {
		revision, err = store.state.Create(ctx, key, data)
	} else {
		revision, err = store.state.Update(ctx, key, data, expected)
	}
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyExists) || errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
			return 0, fmt.Errorf("%w: %v", ErrStoreConflict, err)
		}
		return 0, err
	}
	return revision, nil
}

func memberStatePrefix(databaseID, partitionID string) string {
	return "member." + databaseID + "." + partitionID + "."
}

func memberStateKey(databaseID, partitionID, memberID string) string {
	return memberStatePrefix(databaseID, partitionID) + memberID
}

var _ Store = (*jetStreamStore)(nil)
