package placement

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

func TestMemberStateKeyIncludesPartitionIdentity(t *testing.T) {
	first := memberStateKey("0000000000JJVVW9EMWY1PE1VX", "0000000000Z3WK359G2W66CVT8", "00000000000E5NVMSGX0D07DPA")
	second := memberStateKey("0000000000JJVVW9EMWY1PE1VX", "00000000001WFHC56Q8NB0X6T8", "00000000000E5NVMSGX0D07DPA")
	if first == second {
		t.Fatalf("partition member keys collide: %q", first)
	}
	if !entityid.Valid(first) || !entityid.Valid(second) {
		t.Fatal("member keys must be plain ULIDs")
	}
}

func TestReadMemberUsesExactKeyAndReturnsExplicitAbsence(t *testing.T) {
	state := validMemberStateForPins(t)
	state.DatabaseID = "0000000000JJVVW9EMWY1PE1VX"
	data, err := protocol.EncodeJSON(state)
	if err != nil {
		t.Fatal(err)
	}
	entry := fixedMemberEntry{key: memberStateKey(state.DatabaseID, state.PartitionID, state.MemberID), value: data, revision: 9}
	kv := &exactLookupKV{entry: entry}
	store := &jetStreamStore{state: kv}
	got, err := store.ReadMember(context.Background(), state.DatabaseID, state.PartitionID, state.MemberID)
	if err != nil || got.Revision != entry.revision || !reflect.DeepEqual(got.State, state) {
		t.Fatalf("exact member lookup = %+v, %v; want revision %d and original state", got, err, entry.revision)
	}
	if kv.key != memberStateKey(state.DatabaseID, state.PartitionID, state.MemberID) {
		t.Fatalf("member lookup read key %q; want exact composite key", kv.key)
	}

	kv.err = jetstream.ErrKeyNotFound
	if _, err := store.ReadMember(context.Background(), state.DatabaseID, state.PartitionID, state.MemberID); !errors.Is(err, ErrMemberNotFound) {
		t.Fatalf("missing exact member lookup error = %v, want ErrMemberNotFound", err)
	}
}

type exactLookupKV struct {
	jetstream.KeyValue
	entry fixedMemberEntry
	key   string
	err   error
}

func (kv *exactLookupKV) Get(_ context.Context, key string) (jetstream.KeyValueEntry, error) {
	kv.key = key
	if kv.err != nil {
		return nil, kv.err
	}
	return kv.entry, nil
}

type fixedMemberEntry struct {
	key      string
	value    []byte
	revision uint64
}

func (entry fixedMemberEntry) Bucket() string                  { return stateBucketName }
func (entry fixedMemberEntry) Key() string                     { return entry.key }
func (entry fixedMemberEntry) Value() []byte                   { return entry.value }
func (entry fixedMemberEntry) Revision() uint64                { return entry.revision }
func (entry fixedMemberEntry) Created() time.Time              { return time.Unix(1, 0).UTC() }
func (entry fixedMemberEntry) Delta() uint64                   { return 0 }
func (entry fixedMemberEntry) Operation() jetstream.KeyValueOp { return jetstream.KeyValuePut }

func TestIntentListAllowsDifferentPartitionsButRejectsDuplicateCompositeIdentity(t *testing.T) {
	first := validIntent(oci.RegionGRU)
	first.PartitionID = "00000000001WFHC56Q8NB0X6T8"
	second := validIntent(oci.RegionGRU)
	second.PartitionID = "0000000000Z3WK359G2W66CVT8"
	first = committedIntentForTest(t, first)
	second = committedIntentForTest(t, second)
	reader := intentReaderFunc(func(context.Context, string) ([]Intent, error) {
		return []Intent{first, second}, nil
	})
	store := &jetStreamStore{cell: "gru", intents: reader}
	intents, err := store.ListIntents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []Intent{first, second}
	if !reflect.DeepEqual(intents, want) {
		t.Fatalf("partition intents = %#v, want %#v", intents, want)
	}

	store.intents = intentReaderFunc(func(context.Context, string) ([]Intent, error) {
		return []Intent{want[0], want[0]}, nil
	})
	if _, err := store.ListIntents(context.Background()); !errors.Is(err, ErrInvalidIntent) {
		t.Fatalf("duplicate composite identity error = %v, want ErrInvalidIntent", err)
	}
}

func TestIntentListRejectsUncommittedOrMalformedPayloadDigests(t *testing.T) {
	legacy := Intent{
		SchemaVersion: 1, DatabaseID: "0000000000AJ79CD84K5P2YR0E", PartitionID: "0000000000Z3WK359G2W66CVT8",
		ActiveRegions: []oci.Region{oci.RegionGRU}, Generation: 1,
	}
	managed := validIntent(oci.RegionGRU)
	malformedLegacy := legacy
	malformedLegacy.committedPayloadSHA = "not-a-digest"
	malformedManaged := managed
	malformedManaged.committedPayloadSHA = "not-a-digest"
	for _, test := range []struct {
		name   string
		intent Intent
	}{
		{name: "legacy missing digest", intent: legacy},
		{name: "managed missing digest", intent: managed},
		{name: "legacy malformed digest", intent: malformedLegacy},
		{name: "managed malformed digest", intent: malformedManaged},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &jetStreamStore{cell: "gru", intents: intentReaderFunc(func(context.Context, string) ([]Intent, error) {
				return []Intent{test.intent}, nil
			})}
			if _, err := store.ListIntents(context.Background()); !errors.Is(err, ErrInvalidIntent) {
				t.Fatalf("uncommitted placement intent list error = %v, want invalid intent", err)
			}
		})
	}
}

func committedIntentForTest(t *testing.T, intent Intent) Intent {
	t.Helper()
	payload, err := protocol.EncodeJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := DecodeCommittedIntent(payload)
	if err != nil {
		t.Fatal(err)
	}
	return committed
}

func (reader intentReaderFunc) ListPlacementIntents(ctx context.Context, cell string) ([]Intent, error) {
	return reader(ctx, cell)
}

func (intentReaderFunc) ReadTerminalIntent(context.Context, string, string) (authority.LogEntry, error) {
	return authority.LogEntry{}, authority.ErrNotFound
}

type intentReaderFunc func(context.Context, string) ([]Intent, error)
