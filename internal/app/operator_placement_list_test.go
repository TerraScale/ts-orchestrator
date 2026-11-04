package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

type placementListStore struct {
	entries   []authority.LogEntry
	err       error
	listCalls int
}

func (store *placementListStore) CommitPlacementIntent(context.Context, uint64, string, string, string, uint64, []byte) (uint64, error) {
	panic("placement-list must not commit an intent")
}

func (store *placementListStore) ReadPlacementIntent(context.Context, string, string) (authority.LogEntry, error) {
	panic("placement-list must use the authoritative current-intent listing")
}

func (store *placementListStore) ListPlacementIntents(context.Context) ([]authority.LogEntry, error) {
	store.listCalls++
	return store.entries, store.err
}

func placementListEntry(t *testing.T, intent placement.Intent, sequence uint64) (authority.LogEntry, string) {
	t.Helper()
	payload, err := protocol.EncodeJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	return authority.LogEntry{
		Kind: authority.MutationPlacementIntent, SubjectKey: intent.DatabaseID + "." + intent.PartitionID,
		OperationID: intent.OperationID(), Epoch: 7, Sequence: sequence, Payload: payload,
	}, hex.EncodeToString(digest[:])
}

func TestOperatorPlacementListSortsCurrentIdentityWithoutPayload(t *testing.T) {
	base := testManagedPlacementIntent()
	first := base
	first.DatabaseID, first.PartitionID, first.Generation = "0000000000ZYVVW9EMWY1PE1VX", "0000000000Z3WK359G2W66CVT8", 3
	second := base
	second.DatabaseID, second.PartitionID, second.Generation = "00000000001Y9Z8VKC1VV66J6B", "00000000001WFHC56Q8NB0X6T8", 8
	third := base
	third.DatabaseID, third.PartitionID, third.Generation = "00000000001Y9Z8VKC1VV66J6B", "0000000000Z3WK359G2W66CVT8", 9
	firstEntry, firstDigest := placementListEntry(t, first, 3)
	secondEntry, secondDigest := placementListEntry(t, second, 2)
	thirdEntry, thirdDigest := placementListEntry(t, third, 1)
	store := &placementListStore{entries: []authority.LogEntry{firstEntry, secondEntry, thirdEntry}}
	reader := admittedPlacementReader{cell: "gru", store: store}
	var output bytes.Buffer
	if err := writeOperatorPlacementList(t.Context(), "gru", reader, &output); err != nil {
		t.Fatal(err)
	}
	var got operatorPlacementListResult
	if err := json.Unmarshal(output.Bytes(), &got, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if got.Cell != "gru" || got.Count != 3 || len(got.Placements) != 3 || store.listCalls != 1 {
		t.Fatalf("current placement count or cell is wrong: %+v", got)
	}
	for index, want := range []struct {
		database, partition, operation, digest string
		generation                             uint64
	}{
		{"00000000001Y9Z8VKC1VV66J6B", "00000000001WFHC56Q8NB0X6T8", second.OperationID(), secondDigest, 8},
		{"00000000001Y9Z8VKC1VV66J6B", "0000000000Z3WK359G2W66CVT8", third.OperationID(), thirdDigest, 9},
		{"0000000000ZYVVW9EMWY1PE1VX", "0000000000Z3WK359G2W66CVT8", first.OperationID(), firstDigest, 3},
	} {
		row := got.Placements[index]
		if row.DatabaseID != want.database || row.PartitionID != want.partition ||
			row.Generation != want.generation || row.OperationID != want.operation ||
			row.PayloadSHA256 != want.digest ||
			row.SchemaVersion != placement.IntentSchemaVersion || len(row.ActiveRegions) != 1 ||
			row.ClusterID != base.CanonicalRoster.ClusterID || row.TenantID != base.CanonicalRoster.TenantID ||
			row.ShardID != base.CanonicalRoster.ShardID {
			t.Fatalf("sorted placement identity %d = %+v", index, row)
		}
	}
	for _, forbidden := range []string{"runtime_manifests", "signed-v2-s3-config", "ocid1.", "secret_access_key"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("placement listing disclosed %q", forbidden)
		}
	}
}
