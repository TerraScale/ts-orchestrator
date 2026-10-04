package bucket

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
)

var (
	key   = ociresource.Key{Region: "GRU", Kind: Kind, Name: "backups"}
	owner = ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}
)

type fakeAPI struct {
	bucket Bucket
	rules  []Rule
	calls  []string
	nextID int
}

func (f *fakeAPI) GetBucket(context.Context, string, string) (Bucket, error) { return f.bucket, nil }
func (f *fakeAPI) ListRetentionRules(context.Context, string, string) ([]Rule, error) {
	return slices.Clone(f.rules), nil
}
func (f *fakeAPI) UpdateBucket(_ context.Context, _, _, etag, versioning string, tags ociresource.Tags) error {
	if etag != f.bucket.ETag {
		return errors.New("etag mismatch")
	}
	if versioning == VersioningEnabled && len(f.rules) > 0 {
		return errors.New("versioning refused with retention rules")
	}
	f.calls = append(f.calls, "bucket "+versioning)
	if versioning != "" {
		f.bucket.Versioning = versioning
	}
	f.bucket.Tags, f.bucket.ETag = tags, etag+"'"
	return nil
}
func (f *fakeAPI) CreateRetentionRule(_ context.Context, _, _, name string, amount int64, unit string) error {
	if f.bucket.Versioning == VersioningEnabled {
		return errors.New("retention refused on a versioned bucket")
	}
	f.nextID++
	f.calls = append(f.calls, "create "+name)
	f.rules = append(f.rules, Rule{ID: fmt.Sprintf("r%d", f.nextID), DisplayName: name, ETag: "r", Amount: amount, Unit: unit})
	f.bucket.ETag += "+"
	return nil
}
func (f *fakeAPI) UpdateRetentionRule(_ context.Context, _, _, id, _ string, amount int64, unit string) error {
	f.calls = append(f.calls, "update "+id)
	for index := range f.rules {
		if f.rules[index].ID == id {
			if f.rules[index].Locked {
				return errors.New("locked")
			}
			f.rules[index].Amount, f.rules[index].Unit = amount, unit
		}
	}
	return nil
}
func (f *fakeAPI) DeleteRetentionRule(_ context.Context, _, _, id, _ string) error {
	f.calls = append(f.calls, "delete "+id)
	f.rules = slices.DeleteFunc(f.rules, func(rule Rule) bool { return rule.ID == id })
	f.bucket.ETag += "-"
	return nil
}

type allow struct{}

func (allow) Guard(context.Context, uint64) error { return nil }

func ownedBucket() Bucket {
	return Bucket{Namespace: "tenancy", Name: "backups", ETag: "b1", Versioning: VersioningDisabled,
		Tags: ociresource.Tags{Freeform: map[string]string{"team": "data"}}.Merge(owner.Stamp(key, 0, ""))}
}

func reconcile(t *testing.T, api API, store ociresource.Store, spec Spec, policy ociresource.DriftPolicy) (ociresource.Result, error) {
	t.Helper()
	if _, err := ociresource.Publish(t.Context(), store, key, policy, spec); err != nil {
		t.Fatal(err)
	}
	controller := &ociresource.Controller[Spec, Observed]{Region: "GRU", Resource: Reconciler{API: api}, Store: store,
		Ownership: owner, Authority: allow{}}
	return controller.Reconcile(t.Context(), 1)
}

func TestBucketRetentionConvergesAndLeavesOperatorRulesAlone(t *testing.T) {
	operator := Rule{ID: "op", DisplayName: "legal-hold", Amount: 7, Unit: UnitYears, Locked: true}
	api := &fakeAPI{bucket: ownedBucket(), rules: []Rule{operator}}
	store := ociresource.NewMemoryStore()
	spec := Spec{Namespace: "tenancy", Bucket: "backups", Versioning: VersioningSuspended,
		Retention: []Retention{{Name: "daily", Days: 30}}}
	if result, err := reconcile(t, api, store, spec, ociresource.PolicyEnforce); err != nil || result.Applied != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !slices.Contains(api.rules, operator) || len(api.rules) != 2 || api.rules[1].DisplayName != "terrascale-backups-daily" {
		t.Fatalf("rules=%+v", api.rules)
	}
	if api.bucket.Tags.Freeform["team"] != "data" || !owner.Owns(key, api.bucket.Tags) {
		t.Fatalf("tags=%v", api.bucket.Tags)
	}
	if result, err := reconcile(t, api, store, spec, ociresource.PolicyEnforce); err != nil || result.InSync != 1 {
		t.Fatalf("second pass=%+v err=%v calls=%v", result, err, api.calls)
	}

	// Someone shortens the managed rule; it is restored.
	api.rules[1].Amount = 1
	api.calls = nil
	if result, err := reconcile(t, api, store, spec, ociresource.PolicyEnforce); err != nil || result.Applied != 1 {
		t.Fatalf("drift=%+v err=%v", result, err)
	}
	if api.rules[1].Amount != 30 || !slices.Equal(api.calls, []string{"update r1"}) {
		t.Fatalf("rules=%+v calls=%v", api.rules, api.calls)
	}
}

func TestBucketSwitchesFromRetentionToVersioningInASafeOrder(t *testing.T) {
	api := &fakeAPI{bucket: ownedBucket()}
	store := ociresource.NewMemoryStore()
	retention := Spec{Namespace: "tenancy", Bucket: "backups", Retention: []Retention{{Name: "daily", Days: 30}}}
	if _, err := reconcile(t, api, store, retention, ociresource.PolicyEnforce); err != nil {
		t.Fatal(err)
	}
	api.calls = nil
	versioned := Spec{Namespace: "tenancy", Bucket: "backups", Versioning: VersioningEnabled}
	if result, err := reconcile(t, api, store, versioned, ociresource.PolicyEnforce); err != nil || result.Applied != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !slices.Equal(api.calls, []string{"delete r1", "bucket Enabled"}) || api.bucket.Versioning != VersioningEnabled {
		t.Fatalf("calls=%v bucket=%+v", api.calls, api.bucket)
	}
}

func TestBucketLockedManagedRuleBlocksInsteadOfChanging(t *testing.T) {
	api := &fakeAPI{bucket: ownedBucket(), rules: []Rule{{ID: "r9", DisplayName: "terrascale-backups-daily", Amount: 10,
		Unit: UnitDays, Locked: true}}}
	store := ociresource.NewMemoryStore()
	spec := Spec{Namespace: "tenancy", Bucket: "backups", Retention: []Retention{{Name: "daily", Days: 30}}}
	result, err := reconcile(t, api, store, spec, ociresource.PolicyEnforce)
	if err == nil || !strings.Contains(err.Error(), "locked") || result.Failed != 1 || len(api.calls) != 0 {
		t.Fatalf("result=%+v err=%v calls=%v", result, err, api.calls)
	}
	status, _, _ := store.GetStatus(t.Context(), key)
	if !slices.ContainsFunc(status.Drift, func(change ociresource.Change) bool { return change.Op == "blocked" }) {
		t.Fatalf("status=%+v", status)
	}
}

func TestBucketForeignAndTombstoneNeverMutate(t *testing.T) {
	foreign := &fakeAPI{bucket: Bucket{Namespace: "tenancy", Name: "backups", ETag: "b1"}}
	spec := Spec{Namespace: "tenancy", Bucket: "backups", Versioning: VersioningEnabled}
	if result, err := reconcile(t, foreign, ociresource.NewMemoryStore(), spec, ociresource.PolicyEnforce); err != nil ||
		result.Foreign != 1 || len(foreign.calls) != 0 {
		t.Fatalf("foreign=%+v err=%v", result, err)
	}
	api := &fakeAPI{bucket: ownedBucket()}
	store := ociresource.NewMemoryStore()
	if _, err := reconcile(t, api, store, Spec{Namespace: "tenancy", Bucket: "backups",
		Retention: []Retention{{Name: "daily", Days: 30}}}, ociresource.PolicyEnforce); err != nil {
		t.Fatal(err)
	}
	api.calls = nil
	now := time.Now()
	if _, err := store.MarkDeleted(t.Context(), key, now.Add(-time.Hour), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	controller := &ociresource.Controller[Spec, Observed]{Region: "GRU", Resource: Reconciler{API: api}, Store: store,
		Ownership: owner, Authority: allow{}}
	if result, err := controller.Reconcile(t.Context(), 1); err != nil || result.Deleted != 1 || len(api.calls) != 0 ||
		len(api.rules) != 1 {
		t.Fatalf("tombstone=%+v err=%v calls=%v", result, err, api.calls)
	}
}

func TestBucketSpecValidation(t *testing.T) {
	valid := Spec{Namespace: "tenancy", Bucket: "backups", Retention: []Retention{{Name: "daily", Days: 30}}}
	for name, mutate := range map[string]func(*Spec){
		"namespace":      func(s *Spec) { s.Namespace = "Ten ancy" },
		"bucket":         func(s *Spec) { s.Bucket = "a/b" },
		"versioning":     func(s *Spec) { s.Versioning = "Disabled" },
		"both":           func(s *Spec) { s.Versioning = VersioningEnabled },
		"two durations":  func(s *Spec) { s.Retention[0].Years = 1 },
		"no duration":    func(s *Spec) { s.Retention[0].Days = 0 },
		"too long":       func(s *Spec) { s.Retention[0].Days = maxDays + 1 },
		"repeat":         func(s *Spec) { s.Retention = append(s.Retention, s.Retention[0]) },
		"bad rule name":  func(s *Spec) { s.Retention[0].Name = "Daily" },
		"too many rules": func(s *Spec) { s.Retention = make([]Retention, maxRetentionRules+1) },
	} {
		value := valid
		value.Retention = slices.Clone(valid.Retention)
		mutate(&value)
		if err := value.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSDKRequestsCarryIfMatchAndNeverLock(t *testing.T) {
	var requests []string
	var created map[string]any
	factory, endpoint := ociresourcetest.Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		requests = append(requests, r.Method+" "+r.URL.Path+" if-match="+r.Header.Get("if-match"))
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/retentionRules"):
			_, _ = io.WriteString(w, `{"items":[{"id":"r1","displayName":"terrascale-backups-daily","etag":"re",`+
				`"timeCreated":"2026-01-01T00:00:00Z","timeModified":"2026-01-01T00:00:00Z",`+
				`"duration":{"timeAmount":30,"timeUnit":"DAYS"},"timeRuleLocked":"2027-01-01T00:00:00Z"}]}`)
		case r.Method == http.MethodGet:
			w.Header().Set("etag", "be")
			_, _ = io.WriteString(w, `{"namespace":"tenancy","name":"backups","compartmentId":"c","createdBy":"u",`+
				`"timeCreated":"2026-01-01T00:00:00Z","etag":"be","versioning":"Disabled","metadata":{}}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/retentionRules"):
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &created); err != nil {
				t.Errorf("decode: %v", err)
			}
			_, _ = io.WriteString(w, `{"id":"r2","displayName":"x","etag":"e","timeCreated":"2026-01-01T00:00:00Z","timeModified":"2026-01-01T00:00:00Z"}`)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			_, _ = io.WriteString(w, `{"namespace":"tenancy","name":"backups","compartmentId":"c","createdBy":"u","timeCreated":"2026-01-01T00:00:00Z","etag":"be2","metadata":{}}`)
		}
	})
	api, err := newSDKAPI(factory, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	bucket, err := api.GetBucket(t.Context(), "tenancy", "backups")
	if err != nil || bucket.ETag != "be" || bucket.Versioning != VersioningDisabled {
		t.Fatalf("bucket=%+v err=%v", bucket, err)
	}
	rules, err := api.ListRetentionRules(t.Context(), "tenancy", "backups")
	if err != nil || len(rules) != 1 || !rules[0].Locked || rules[0].Amount != 30 || rules[0].Unit != UnitDays {
		t.Fatalf("rules=%+v err=%v", rules, err)
	}
	if err := api.UpdateBucket(t.Context(), "tenancy", "backups", "be", VersioningSuspended, bucket.Tags); err != nil {
		t.Fatal(err)
	}
	if err := api.CreateRetentionRule(t.Context(), "tenancy", "backups", "terrascale-backups-weekly", 1, UnitYears); err != nil {
		t.Fatal(err)
	}
	if err := api.DeleteRetentionRule(t.Context(), "tenancy", "backups", "r1", "re"); err != nil {
		t.Fatal(err)
	}
	if err := api.UpdateBucket(t.Context(), "tenancy", "backups", "", "", bucket.Tags); err == nil {
		t.Fatal("unconditional bucket update accepted")
	}
	if _, locked := created["timeRuleLocked"]; locked || created["displayName"] != "terrascale-backups-weekly" {
		t.Fatalf("created=%v", created)
	}
	want := []string{"POST /n/tenancy/b/backups if-match=be", "DELETE /n/tenancy/b/backups/retentionRules/r1 if-match=re"}
	for _, line := range want {
		if !slices.Contains(requests, line) {
			t.Errorf("missing %q in %v", line, requests)
		}
	}
}
