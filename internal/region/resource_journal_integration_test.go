package region

import (
	"encoding/json/v2"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

func TestProtectedResourceJournalSharesFoundationCASAndByteBound(t *testing.T) {
	store, client, raw := foundationProtocolStore(t)
	now := time.Now().UTC()
	desired, err := ociresource.NewDesired(ociresource.Key{Region: "GRU", Kind: "nsg-rules", Name: "members"}, 1, ociresource.PolicyEnforce, struct {
		ID string `json:"id"`
	}{ID: "original"})
	if err != nil {
		t.Fatal(err)
	}
	desired, err = ociresource.OperationRecord(desired, 1, now, false)
	if err != nil {
		t.Fatal(err)
	}
	desired.Operation.WorkRequests = []string{"original-accepted-work-request"}
	desired.Operation.Requests = []ociresource.RequestAttempt{{Method: "PUT", URL: "https://iaas.example/owned", Body: []byte(`{"rules":[{"port":4222}]}`), RetryToken: "original-token", IfMatch: "original-etag", StartedAt: now, Deadline: now.Add(time.Minute)}}
	source := ociresource.ResourceSource{ControllerConfigSHA256: strings.Repeat("a", 64), GrantSHA256: strings.Repeat("b", 64)}
	record := FoundationRecord{SchemaVersion: 1, Cell: "GRU", OCIRegion: "sa-saopaulo-1", TenancyID: "ocid1.tenancy.oc1..test", ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Generation: 1, IntentDigest: strings.Repeat("c", 64), OperationID: entityid.New(), Epoch: 1, Stage: "reconciled", StartedAt: now, UpdatedAt: now, CompletedAt: now, ResourceIDs: map[string]string{"vault": "ocid1.vault.oc1.sa-saopaulo-1.original"}, OCIResources: &ociresource.ProtectedJournal{Revision: 1, Source: source, Resources: map[string]ociresource.ProtectedResource{desired.Key.String(): {Revision: 1, Source: source, Desired: desired}}}}
	etag, err := store.CompareAndSwap(t.Context(), record, "")
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewObjectFoundationStore(client, "ns", "heads")
	if err != nil {
		t.Fatal(err)
	}
	loaded, loadedETag, err := restarted.Load(t.Context(), "GRU")
	if err != nil || loadedETag != etag || !reflect.DeepEqual(loaded.OCIResources, record.OCIResources) || !reflect.DeepEqual(loaded.ResourceIDs, record.ResourceIDs) {
		t.Fatalf("protected original history changed: %+v %v", loaded, err)
	}
	stored := loaded.OCIResources.Resources[desired.Key.String()].Desired
	resumed, err := ociresource.OperationRecord(stored, 2, now.Add(time.Second), false)
	if err != nil || resumed.Operation.ID != desired.Operation.ID || !resumed.Operation.StartedAt.Equal(now) || !slices.Equal(resumed.Operation.WorkRequests, desired.Operation.WorkRequests) {
		t.Fatalf("restarted uncertain operation changed: %+v %v", resumed.Operation, err)
	}
	unsigned := loaded
	copyJournal := *loaded.OCIResources
	copyJournal.Resources = make(map[string]ociresource.ProtectedResource, len(loaded.OCIResources.Resources))
	for key, value := range loaded.OCIResources.Resources {
		copyJournal.Resources[key] = value
	}
	entryWithoutRemoval := copyJournal.Resources[desired.Key.String()]
	entryWithoutRemoval.Desired.Tombstone = &ociresource.Tombstone{RequestedAt: now, NotBefore: now.Add(time.Hour)}
	copyJournal.Resources[desired.Key.String()] = entryWithoutRemoval
	unsigned.OCIResources = &copyJournal
	if _, err := restarted.CompareAndSwap(t.Context(), unsigned, loadedETag); err == nil {
		t.Fatal("unsigned removal provenance entered protected object")
	}
	if err := loaded.OCIResources.Validate("SFO"); err == nil {
		t.Fatal("cross-cell protected journal accepted")
	}
	loaded.Epoch = 2
	if _, err := restarted.CompareAndSwap(t.Context(), loaded, loadedETag); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompareAndSwap(t.Context(), record, etag); !errors.Is(err, ErrFoundationConflict) {
		t.Fatalf("stale resource journal overwrote foundation: %v", err)
	}
	loaded, loadedETag, err = restarted.Load(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	entry := loaded.OCIResources.Resources[desired.Key.String()]
	operation := *entry.Desired.Operation
	request := operation.Requests[0]
	request.Body = make([]byte, 64<<10)
	operation.Requests = append(slices.Clone(operation.Requests), request, request)
	entry.Desired.Operation = &operation
	loaded.OCIResources.Resources[desired.Key.String()] = entry
	before, err := json.Marshal(loaded, json.Deterministic(true))
	if err != nil || len(before) <= foundationRecordLimit || len(before) >= foundationJournalLimit {
		t.Fatalf("journal regression must cross only the old object bound: bytes=%d err=%v", len(before), err)
	}
	loadedETag, err = restarted.CompareAndSwap(t.Context(), loaded, loadedETag)
	if err != nil {
		t.Fatal(err)
	}
	current, currentETag, err := restarted.Load(t.Context(), "GRU")
	if err != nil || currentETag != loadedETag || !reflect.DeepEqual(current, loaded) {
		t.Fatalf("journal above 128 KiB changed during CAS/reload: %v", err)
	}
	operation.Requests = append(slices.Clone(operation.Requests), request, request, request, request)
	operation.Failure = "boundary"
	entry.Desired.Operation = &operation
	loaded.OCIResources.Resources[desired.Key.String()] = entry
	oversized, err := json.Marshal(loaded, json.Deterministic(true))
	if err != nil || len(oversized) <= foundationJournalLimit+1 {
		t.Fatalf("journal regression did not reach the object bound: bytes=%d err=%v", len(oversized), err)
	}
	last := &operation.Requests[len(operation.Requests)-1]
	// Base64 moves in four-byte steps; the failure string fills the remainder.
	trim := 3 * ((len(oversized) - foundationJournalLimit - 1 + 3) / 4)
	if trim > len(last.Body) {
		t.Fatal("journal boundary adjustment exceeds one valid request body")
	}
	last.Body = last.Body[:len(last.Body)-trim]
	oversized, err = json.Marshal(loaded, json.Deterministic(true))
	if err != nil || len(oversized) > foundationJournalLimit+1 {
		t.Fatalf("could not size exact journal boundary: bytes=%d err=%v", len(oversized), err)
	}
	operation.Failure += strings.Repeat("x", foundationJournalLimit+1-len(oversized))
	if err := loaded.validate(); err != nil {
		t.Fatalf("oversize candidate must otherwise remain valid: %v", err)
	}
	operation.Failure = operation.Failure[:len(operation.Failure)-1]
	before, err = json.Marshal(loaded, json.Deterministic(true))
	if err != nil || len(before) != foundationJournalLimit {
		t.Fatalf("journal write candidate is not exactly at the object bound: bytes=%d err=%v", len(before), err)
	}
	loadedETag, err = restarted.CompareAndSwap(t.Context(), loaded, loadedETag)
	if err != nil {
		t.Fatalf("journal write at exact object byte bound was rejected: %v", err)
	}
	operation.Failure += "x"
	oversized, err = json.Marshal(loaded, json.Deterministic(true))
	if err != nil || len(oversized) != foundationJournalLimit+1 {
		t.Fatalf("journal write candidate is not one byte above object bound: bytes=%d err=%v", len(oversized), err)
	}
	if _, err := restarted.CompareAndSwap(t.Context(), loaded, loadedETag); err == nil || !strings.Contains(err.Error(), "foundation record exceeds size bound") {
		t.Fatalf("oversized valid journal bypassed object byte bound: %v", err)
	}
	current, _, err = restarted.Load(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(current, json.Deterministic(true))
	if err != nil || string(before) != string(after) {
		t.Fatal("oversized journal damaged original operation")
	}
	raw(foundationObjectPrefix+"GRU.json", append(slices.Clone(after), ' '))
	if _, _, err := restarted.Load(t.Context(), "GRU"); err == nil || !strings.Contains(err.Error(), "foundation record exceeds size bound") {
		t.Fatalf("journal one byte above object bound was accepted: %v", err)
	}
}
