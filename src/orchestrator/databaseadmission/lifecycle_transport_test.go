package databaseadmission

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
)

type lifecycleTransportJournal struct {
	calls int
	err   error
}

func (j *lifecycleTransportJournal) ApplyLifecycle(context.Context, databaselifecycle.Event) error {
	j.calls++
	return j.err
}
func (j *lifecycleTransportJournal) FreezeInventory(context.Context, string, time.Time, time.Time) (databaselifecycle.Snapshot, error) {
	j.calls++
	return databaselifecycle.Snapshot{}, j.err
}
func (j *lifecycleTransportJournal) LifecycleResources(context.Context) (uint64, []databaselifecycle.Resource, error) {
	j.calls++
	return 1, []databaselifecycle.Resource{}, j.err
}
func TestLifecycleTransportRejectsMalformedAndAdmissionCreate(t *testing.T) {
	for _, data := range []string{`{"kind":"create"}`, `{"kind":"delete","extra":1}`, `null`, `[]`} {
		journal := &lifecycleTransportJournal{}
		reply := handleLifecycle(t.Context(), journal, LifecycleEventSubject, []byte(data))
		if reply.Error != "invalid" || journal.calls != 0 {
			t.Fatalf("accepted %s: %+v calls=%d", data, reply, journal.calls)
		}
	}
}
func TestLifecycleTransportPreservesTypedErrors(t *testing.T) {
	for err, want := range map[error]string{databaselifecycle.ErrInvalid: "invalid", databaselifecycle.ErrConflict: "conflict", databaselifecycle.ErrClosed: "closed", databaselifecycle.ErrIncomplete: "incomplete", errors.New("storage internal detail"): "unavailable"} {
		journal := &lifecycleTransportJournal{err: err}
		reply := handleLifecycle(t.Context(), journal, LifecycleEventSubject, []byte(`{"kind":"streams"}`))
		if reply.Error != want || reply.Applied {
			t.Fatalf("%v: %+v", err, reply)
		}
	}
}
func TestLifecycleIngressRequiresRoleUID(t *testing.T) {
	mux := http.NewServeMux()
	registerLifecycleIngress(mux, &LifecycleIngressConfig{PublisherConnection: &nats.Conn{}, BillingConnection: &nats.Conn{}, PublisherUID: 101, BillingUID: 202})
	for path, wrongUID := range map[string]uint32{"/internal/v1/databases/lifecycle": 202, "/internal/v1/databases/inventory/freeze": 101, "/internal/v1/databases/inventory/resources": 101} {
		request := httptest.NewRequest(http.MethodPost, path, nil)
		request = request.WithContext(context.WithValue(request.Context(), peerUIDKey{}, wrongUID))
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("%s: %d", path, recorder.Code)
		}
	}
}
func TestLifecycleRoleGrantsAreDisjoint(t *testing.T) {
	publisher, _ := LifecyclePublisherPermissions()
	billing, _ := InventoryConsumerPermissions()
	if !slices.Equal(publisher, []string{LifecycleEventSubject}) || slices.Contains(billing, LifecycleEventSubject) || !slices.Contains(billing, InventoryFreezeSubject) {
		t.Fatal(publisher, billing)
	}
	if validateLifecycleIngress(&LifecycleIngressConfig{}) == nil {
		t.Fatal("empty config accepted")
	}
}
func TestLifecycleTransportResourcesReceipt(t *testing.T) {
	journal := &lifecycleTransportJournal{}
	reply := handleLifecycle(t.Context(), journal, InventoryResourcesSubject, []byte(`{}`))
	data, err := json.Marshal(reply)
	if err != nil || reply.Inventory == nil || reply.Inventory.Revision != 1 || reply.Error != "" {
		t.Fatalf("%s: %v", data, err)
	}
}
