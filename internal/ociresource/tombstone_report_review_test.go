package ociresource

import (
	"errors"
	"testing"
	"time"
)

// A tombstoned report-only record never deletes the cloud object; the
// pending delete is reported as drift. An object that is already gone is
// still purged, since that touches only the desired store (#127 12044).
func TestReportPolicyTombstoneNeverDeletes(t *testing.T) {
	store := NewMemoryStore()
	cloud := &fakeWidgets{cloud: map[string]widget{}}
	controller, now := newController(t, store, cloud, TagModeFreeform)
	enforced := put(t, store, "a", 1, PolicyEnforce, 3)
	if _, err := controller.Reconcile(t.Context(), 7); err != nil {
		t.Fatal(err)
	}
	if _, ok := cloud.cloud["a"]; !ok {
		t.Fatal("fixture did not create the object")
	}
	put(t, store, "a", 2, PolicyReport, 3)
	if _, err := store.MarkDeleted(t.Context(), enforced.Key, *now, *now); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Hour)
	result, err := controller.Reconcile(t.Context(), 7)
	if err != nil || cloud.deletes != 0 || result.Applied != 0 {
		t.Fatalf("report-only tombstone mutated the cloud: result=%+v err=%v deletes=%d", result, err, cloud.deletes)
	}
	status, _, _ := store.GetStatus(t.Context(), enforced.Key)
	if len(status.Drift) != 1 || status.Drift[0].Op != "delete" {
		t.Fatalf("pending delete not reported: %+v", status)
	}
	delete(cloud.cloud, "a")
	if _, err := controller.Reconcile(t.Context(), 7); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(t.Context(), enforced.Key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tombstone of a gone object survived: %v", err)
	}
}
