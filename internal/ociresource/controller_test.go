package ociresource

import (
	"context"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func integrationStore(t *testing.T) *KVStore {
	t.Helper()
	store, err := OpenKVStore(t.Context(), integrationJetStream(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// Keep this fixture local: ociresourcetest imports ociresource.
func integrationJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	token := rand.Text()
	broker, err := server.NewServer(new(server.Options{Host: "127.0.0.1", Port: -1, JetStream: true,
		StoreDir: filepath.Join(t.TempDir(), "jetstream"), Authorization: token}))
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("OCI integration broker did not become ready")
	}
	connection, err := nats.Connect(broker.ClientURL(), nats.Token(token))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	js, err := jetstream.New(connection)
	if err != nil {
		t.Fatal(err)
	}
	return js
}

type widgetSpec struct {
	Size int `json:"size"`
}

type widget struct {
	Size int
	Tags Tags
}

// fakeWidgets is an in-memory cloud of one resource kind keyed by name.
type fakeWidgets struct {
	cloud   map[string]widget
	applies int
	deletes int
	fail    error
}

func (f *fakeWidgets) Kind() string { return "widget" }

func (f *fakeWidgets) Observe(_ context.Context, target Target[widgetSpec]) (widget, bool, error) {
	object, ok := f.cloud[target.Key.Name]
	if !ok {
		return widget{}, false, nil
	}
	if !target.Ownership.Owns(target.Key, object.Tags) {
		return widget{}, true, ErrForeign
	}
	return object, true, nil
}

func (f *fakeWidgets) Diff(target Target[widgetSpec], observed widget, found bool) Plan {
	var plan Plan
	switch {
	case !found:
		plan.Add("create", "widget size %d", target.Spec.Size)
	case observed.Size != target.Spec.Size:
		plan.Add("update", "size %d -> %d", observed.Size, target.Spec.Size)
	case target.Ownership.Stale(observed.Tags, target.Generation, target.SpecDigest):
		plan.Add("tag", "restamp ownership")
	}
	return plan
}

func (f *fakeWidgets) Apply(_ context.Context, target Target[widgetSpec], observed widget, _ bool, _ Plan) error {
	if f.fail != nil {
		return f.fail
	}
	f.applies++
	f.cloud[target.Key.Name] = widget{Size: target.Spec.Size,
		Tags: observed.Tags.Merge(target.Ownership.Stamp(target.Key, target.Generation, target.SpecDigest))}
	return nil
}

func (f *fakeWidgets) Delete(_ context.Context, target Target[widgetSpec], _ widget) error {
	f.deletes++
	delete(f.cloud, target.Key.Name)
	return nil
}

type fakeAuthority struct {
	epoch uint64
	calls int
}

func (a *fakeAuthority) Guard(_ context.Context, epoch uint64) error {
	a.calls++
	if epoch != a.epoch {
		return errors.New("stale epoch")
	}
	return nil
}

func widgetKey(name string) Key { return Key{Region: "GRU", Kind: "widget", Name: name} }

func newController(t *testing.T, store Store, cloud *fakeWidgets, mode TagMode) (*Controller[widgetSpec, widget], *time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	return &Controller[widgetSpec, widget]{Region: "GRU", Resource: cloud, Store: store,
		Ownership: Ownership{Mode: mode, Owner: "cell-gru"}, Authority: &fakeAuthority{epoch: 7},
		Now: func() time.Time { return now }}, &now
}

func put(t *testing.T, store Store, name string, generation uint64, policy DriftPolicy, size int) Desired {
	t.Helper()
	desired, err := NewDesired(widgetKey(name), generation, policy, widgetSpec{Size: size})
	if err != nil {
		t.Fatal(err)
	}
	desired, err = store.Put(t.Context(), desired)
	if err != nil {
		t.Fatal(err)
	}
	return desired
}

func TestControllerCreatesDetectsAndCorrectsDrift(t *testing.T) {
	for _, mode := range []TagMode{TagModeFreeform} {
		t.Run(string(mode), func(t *testing.T) {
			store := integrationStore(t)
			cloud := &fakeWidgets{cloud: map[string]widget{}}
			controller, _ := newController(t, store, cloud, mode)
			put(t, store, "a", 1, PolicyEnforce, 3)

			result, err := controller.Reconcile(t.Context(), 7)
			if err != nil || result.Applied != 1 || cloud.cloud["a"].Size != 3 {
				t.Fatalf("result=%+v err=%v cloud=%v", result, err, cloud.cloud)
			}
			result, err = controller.Reconcile(t.Context(), 7)
			if err != nil || result.InSync != 1 || result.Applied != 0 {
				t.Fatalf("second pass result=%+v err=%v", result, err)
			}

			// Out-of-band drift is detected and corrected on the next pass.
			object := cloud.cloud["a"]
			object.Size = 9
			cloud.cloud["a"] = object
			result, err = controller.Reconcile(t.Context(), 7)
			if err != nil || result.Applied != 1 || cloud.cloud["a"].Size != 3 {
				t.Fatalf("drift pass result=%+v err=%v", result, err)
			}
			status, ok, _ := store.GetStatus(t.Context(), widgetKey("a"))
			if !ok || !status.Applied || len(status.Drift) != 1 || status.Drift[0].Op != "update" {
				t.Fatalf("status=%+v", status)
			}

			// A new generation waits until observation confirms the prior operation.
			if _, err := controller.Reconcile(t.Context(), 7); err != nil {
				t.Fatal(err)
			}
			// A new generation restamps ownership even when the shape matches.
			next := put(t, store, "a", 2, PolicyEnforce, 3)
			if result, err = controller.Reconcile(t.Context(), 7); err != nil || result.Applied != 1 {
				t.Fatalf("generation pass result=%+v err=%v", result, err)
			}
			tags := cloud.cloud["a"].Tags
			if controller.Ownership.Stale(tags, 2, next.SpecDigest) || !controller.Ownership.Stale(tags, 2, "0000000000V4MRM46HP1SNGDYW") ||
				!controller.Ownership.Owns(widgetKey("a"), tags) {
				t.Fatalf("ownership tags were not restamped: %+v", tags)
			}
		})
	}
}

func TestRetiredReportPolicyCannotEnterPersistentDesiredState(t *testing.T) {
	store := integrationStore(t)
	if _, err := Publish(t.Context(), store, widgetKey("a"), DriftPolicy("report"), testSpec{"3"}); err == nil {
		t.Fatal("accepted retired report policy")
	}
	records, err := store.List(t.Context(), "GRU", "widget")
	if err != nil || len(records) != 0 {
		t.Fatalf("records=%v err=%v", records, err)
	}
}

func TestForeignResourcesAreNeverTouched(t *testing.T) {
	for _, tags := range []Tags{
		{},
		{Freeform: map[string]string{freeformManagedBy: managedByValue, freeformOwner: "00000000005KBY8XNJ83MMCJWP", freeformResource: "GRU/widget/a"}},
		{Freeform: map[string]string{freeformManagedBy: managedByValue, freeformOwner: "cell-gru", freeformResource: "GRU/widget/b"}},
	} {
		store := integrationStore(t)
		cloud := &fakeWidgets{cloud: map[string]widget{"a": {Size: 1, Tags: tags}}}
		controller, now := newController(t, store, cloud, TagModeFreeform)
		desired := put(t, store, "a", 1, PolicyEnforce, 3)
		result, err := controller.Reconcile(t.Context(), 7)
		if err != nil || result.Foreign != 1 || cloud.applies != 0 {
			t.Fatalf("result=%+v err=%v", result, err)
		}
		if _, err := store.MarkDeleted(t.Context(), desired.Key, *now, *now); err != nil {
			t.Fatal(err)
		}
		if _, err := controller.Reconcile(t.Context(), 7); err != nil || cloud.deletes != 0 || cloud.cloud["a"].Size != 1 {
			t.Fatalf("foreign object was deleted: err=%v cloud=%v", err, cloud.cloud)
		}
		if _, err := store.Get(t.Context(), desired.Key); err != nil {
			t.Fatal("a tombstone for a foreign object was purged")
		}
	}

}

func TestTombstoneDeletesOnlyAfterNotBeforeAndPurgesAfterConfirmation(t *testing.T) {
	store := integrationStore(t)
	cloud := &fakeWidgets{cloud: map[string]widget{}}
	controller, now := newController(t, store, cloud, TagModeFreeform)
	desired := put(t, store, "a", 1, PolicyEnforce, 3)
	if _, err := controller.Reconcile(t.Context(), 7); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Reconcile(t.Context(), 7); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkDeleted(t.Context(), desired.Key, *now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Reconcile(t.Context(), 7); err != nil || cloud.deletes != 0 {
		t.Fatalf("deleted before not-before: err=%v", err)
	}
	*now = now.Add(2 * time.Hour)
	result, err := controller.Reconcile(t.Context(), 7)
	if err != nil || cloud.deletes != 1 || result.Applied != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, err := store.Get(t.Context(), desired.Key); err != nil {
		t.Fatal("purged before the delete was confirmed by observation")
	}
	result, err = controller.Reconcile(t.Context(), 7)
	if err != nil || result.Deleted != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, err := store.Get(t.Context(), desired.Key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("record survived purge: %v", err)
	}
}

func TestFencedControllerStopsBeforeMutation(t *testing.T) {
	store := integrationStore(t)
	cloud := &fakeWidgets{cloud: map[string]widget{}}
	controller, _ := newController(t, store, cloud, TagModeFreeform)
	put(t, store, "a", 1, PolicyEnforce, 3)
	desired := put(t, store, "b", 1, PolicyEnforce, 3)
	cloud.cloud["b"] = widget{Size: 3, Tags: controller.Ownership.Stamp(desired.Key, 1, desired.SpecDigest)}
	_, err := controller.Reconcile(t.Context(), 6)
	if !errors.Is(err, ErrFenced) || cloud.applies != 0 {
		t.Fatalf("err=%v applies=%d", err, cloud.applies)
	}
}

func TestApplyFailureIsRecordedAndOtherRecordsContinue(t *testing.T) {
	store := integrationStore(t)
	cloud := &fakeWidgets{cloud: map[string]widget{"b": {Size: 3}}, fail: errors.New("boom")}
	cloud.cloud["b"] = widget{Size: 3, Tags: Ownership{Mode: TagModeFreeform, Owner: "cell-gru"}.Stamp(widgetKey("b"), 1, "")}
	controller, _ := newController(t, store, cloud, TagModeFreeform)
	put(t, store, "a", 1, PolicyEnforce, 3)
	desired := put(t, store, "b", 1, PolicyEnforce, 3)
	cloud.cloud["b"] = widget{Size: 3, Tags: controller.Ownership.Stamp(desired.Key, 1, desired.SpecDigest)}
	result, err := controller.Reconcile(t.Context(), 7)
	if err == nil || !strings.Contains(err.Error(), "boom") || result.Failed != 1 || result.Observed != 2 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	status, _, _ := store.GetStatus(t.Context(), widgetKey("a"))
	if !strings.Contains(status.Error, "boom") {
		t.Fatalf("status=%+v", status)
	}
}

func TestDesiredRecordsAreValidatedAndGenerationsMonotonic(t *testing.T) {
	if _, err := NewDesired(Key{Region: "XXX", Kind: "widget", Name: "a"}, 1, PolicyEnforce, widgetSpec{}); err == nil {
		t.Fatal("accepted an uncatalogued region")
	}
	if _, err := NewDesired(Key{Region: "GRU", Kind: "Widget", Name: "a"}, 1, PolicyEnforce, widgetSpec{}); err == nil {
		t.Fatal("accepted an invalid kind token")
	}
	if _, err := NewDesired(widgetKey("a"), 1, "adopt", widgetSpec{}); err == nil {
		t.Fatal("accepted an unknown drift policy")
	}
	desired, err := NewDesired(widgetKey("a"), 1, PolicyEnforce, widgetSpec{Size: 1})
	if err != nil {
		t.Fatal(err)
	}
	tampered := desired
	tampered.Spec = []byte(`{"size":2}`)
	if tampered.Validate() == nil {
		t.Fatal("accepted a spec that differs from its digest")
	}
	store := integrationStore(t)
	if _, err := store.Put(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(t.Context(), desired); !errors.Is(err, ErrConflict) {
		t.Fatalf("accepted a non-increasing generation: %v", err)
	}
}

func TestKVStoreRoundTripAndCompareAndSet(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	js := integrationJetStream(t)
	store, err := OpenKVStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKVStore(ctx, js, 1); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	first := put(t, store, "a", 1, PolicyEnforce, 1)
	put(t, store, "b", 1, PolicyEnforce, 2)
	if _, err := store.Put(ctx, first); !errors.Is(err, ErrConflict) {
		t.Fatalf("accepted a stale generation: %v", err)
	}
	second := put(t, store, "a", 2, PolicyEnforce, 5)
	records, err := store.List(ctx, "GRU", "widget")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, record := range records {
		names = append(names, record.Key.Name)
	}
	if !slices.Equal(names, []string{"a", "b"}) || records[0].Generation != 2 || records[0].SpecDigest != second.SpecDigest {
		t.Fatalf("records=%+v", records)
	}
	if other, err := store.List(ctx, "SFO", "widget"); err != nil || len(other) != 0 {
		t.Fatalf("other region=%v err=%v", other, err)
	}

	// The full controller loop runs against the replicated store.
	cloud := &fakeWidgets{cloud: map[string]widget{}}
	controller, now := newController(t, store, cloud, TagModeFreeform)
	if result, err := controller.Reconcile(ctx, 7); err != nil || result.Applied != 2 || result.Drifted != 2 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	status, ok, err := store.GetStatus(ctx, widgetKey("b"))
	if err != nil || !ok || status.InSync {
		t.Fatalf("status=%+v ok=%v err=%v", status, ok, err)
	}

	if _, err := controller.Reconcile(ctx, 7); err != nil {
		t.Fatal(err)
	}
	tombstoned, err := store.MarkDeleted(ctx, widgetKey("a"), *now, *now)
	if err != nil {
		t.Fatal(err)
	}
	// A purge at a stale revision loses the compare-and-set.
	stale := tombstoned
	stale.Revision--
	if err := store.Purge(ctx, stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale purge: %v", err)
	}
	for range 2 {
		if _, err := controller.Reconcile(ctx, 7); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Get(ctx, widgetKey("a")); !errors.Is(err, ErrNotFound) || cloud.deletes != 1 {
		t.Fatalf("tombstoned record survived: %v deletes=%d", err, cloud.deletes)
	}
}

func TestLegacyPolicyMigratesDurablyBeforeAlwaysOnConvergence(t *testing.T) {
	store := integrationStore(t)
	legacy, err := NewDesired(widgetKey("a"), 1, PolicyEnforce, widgetSpec{Size: 3})
	if err != nil {
		t.Fatal(err)
	}
	legacy.SchemaVersion = 1
	legacy.Policy = "report"
	wire, err := encode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.desired.Create(t.Context(), legacy.Key.subject(), wire); err != nil {
		t.Fatal(err)
	}
	cloud := &fakeWidgets{cloud: map[string]widget{}}
	controller, _ := newController(t, store, cloud, TagModeFreeform)
	if result, err := controller.Reconcile(t.Context(), 7); err != nil || result.Applied != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	entry, err := store.desired.Get(t.Context(), legacy.Key.subject())
	if err != nil {
		t.Fatal(err)
	}
	var migrated Desired
	if err := json.Unmarshal(entry.Value(), &migrated); err != nil {
		t.Fatal(err)
	}
	if migrated.SchemaVersion != 2 || migrated.Policy != PolicyEnforce || migrated.Operation == nil || cloud.cloud["a"].Size != 3 {
		t.Fatalf("migrated=%+v cloud=%v", migrated, cloud.cloud)
	}
}
