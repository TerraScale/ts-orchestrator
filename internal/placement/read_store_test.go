package placement

import (
	"context"
	"reflect"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go/jetstream"
)

func TestPlacementListingOpensExistingStateWithoutWrites(t *testing.T) {
	runtime, err := natscell.Start(t.Context(), placementTestBrokerConfig(t, "listing-reader"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	js := runtime.JetStream()
	intents := intentReaderFunc(func(context.Context, string) ([]Intent, error) { return nil, nil })
	if _, err := OpenReadStore(t.Context(), js, "gru", 1, intents); err == nil {
		t.Fatal("listing opened an absent bucket")
	}
	if _, err := js.KeyValue(t.Context(), stateBucketName); err == nil {
		t.Fatal("listing created an absent bucket")
	}
	kv, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: stateBucketName, History: 2,
		MaxValueSize: maxStateBytes, Storage: jetstream.FileStorage, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	state := validMemberStateForPins(t)
	wire, err := protocol.EncodeJSON(state)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := kv.Put(t.Context(), memberStateKey(state.DatabaseID, state.PartitionID, state.MemberID), wire)
	if err != nil {
		t.Fatal(err)
	}
	before, err := kv.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenReadStore(t.Context(), js, "gru", 1, intents)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reader.(Store); ok {
		t.Fatal("listing exposes placement writes")
	}
	members, err := reader.ListMembers(t.Context(), state.DatabaseID, state.PartitionID)
	if err != nil || len(members) != 1 || members[0].Revision != revision || !reflect.DeepEqual(members[0].State, state) {
		t.Fatalf("retained placement listing = %+v, %v", members, err)
	}
	if _, err := OpenReadStore(t.Context(), js, "gru", 2, intents); err == nil {
		t.Fatal("listing accepted weaker replicas")
	}
	after, err := kv.Status(t.Context())
	if err != nil || !reflect.DeepEqual(before.Config(), after.Config()) || before.Values() != after.Values() {
		t.Fatalf("listing changed bucket configuration or values: %v", err)
	}
}
