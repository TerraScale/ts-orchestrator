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

	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

var (
	key   = ociresource.Key{Region: "GRU", Kind: Kind, Name: "backups"}
	owner = ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "cell-gru"}
)

type providerState struct {
	bucket       Bucket
	rules        []Rule
	calls        []string
	nextID       int
	api          API
	loseResponse bool
}

func (f *providerState) UpdateBucket(_ context.Context, _, _, etag, versioning string, tags ociresource.Tags) error {
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
func (f *providerState) CreateRetentionRule(_ context.Context, _, _, name string, amount int64, unit string) error {
	if f.bucket.Versioning == VersioningEnabled {
		return errors.New("retention refused on a versioned bucket")
	}
	f.nextID++
	f.calls = append(f.calls, "create "+name)
	f.rules = append(f.rules, Rule{ID: fmt.Sprintf("r%d", f.nextID), DisplayName: name, ETag: "r", Amount: amount, Unit: unit})
	f.bucket.ETag += "+"
	return nil
}
func (f *providerState) UpdateRetentionRule(_ context.Context, _, _, id, _ string, amount int64, unit string) error {
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
func (f *providerState) DeleteRetentionRule(_ context.Context, _, _, id, _ string) error {
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

func reconcile(t *testing.T, api *providerState, store ociresource.Store, spec Spec, policy ociresource.DriftPolicy) (ociresource.Result, error) {
	t.Helper()
	confirm(t, api, store)
	if _, err := ociresource.Publish(t.Context(), store, key, policy, spec); err != nil {
		t.Fatal(err)
	}
	controller := &ociresource.Controller[Spec, Observed]{Region: "GRU", Resource: Reconciler{API: api.client(t)}, Store: store,
		Ownership: owner, Authority: allow{}}
	return controller.Reconcile(t.Context(), 1)
}

func TestBucketRetentionConvergesAndLeavesOperatorRulesAlone(t *testing.T) {
	operator := Rule{ID: "op", DisplayName: "legal-hold", Amount: 7, Unit: UnitYears, Locked: true}
	api := &providerState{bucket: ownedBucket(), rules: []Rule{operator}}
	store := persistentStore(t)
	spec := Spec{Namespace: "tenancy", Bucket: "backups", Versioning: VersioningSuspended,
		Retention: []Retention{{Name: "daily", Days: 30}}}
	if result, err := reconcile(t, api, store, spec, ociresource.PolicyEnforce); err != nil || result.Applied != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !slices.Contains(api.rules, operator) || len(api.rules) != 2 || api.rules[1].DisplayName != "terrascale/backups/daily" {
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

func (f *providerState) client(t *testing.T) API {
	t.Helper()
	if f.api != nil {
		return f.api
	}
	factory, endpoint := ociresourcetest.Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var err error
		mutation := r.Method != http.MethodGet
		retention := strings.Contains(r.URL.Path, "/retentionRules")
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		if mutation {
			body, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				t.Error(readErr)
				w.WriteHeader(400)
				return
			}
			switch {
			case !retention && r.Method == http.MethodPost:
				var details objectstorage.UpdateBucketDetails
				if err = json.Unmarshal(body, &details); err == nil {
					err = f.UpdateBucket(r.Context(), "tenancy", "backups", r.Header.Get("if-match"), string(details.Versioning), ociresource.Tags{Freeform: details.FreeformTags, Defined: details.DefinedTags})
				}
			case retention && r.Method == http.MethodPost:
				var details objectstorage.CreateRetentionRuleDetails
				if err = json.Unmarshal(body, &details); err == nil {
					if details.TimeRuleLocked != nil {
						t.Error("controller attempted to lock retention")
					}
					if details.Duration == nil {
						err = errors.New("duration required")
					} else {
						err = f.CreateRetentionRule(r.Context(), "tenancy", "backups", deref(details.DisplayName), *details.Duration.TimeAmount, string(details.Duration.TimeUnit))
					}
				}
			case retention && (r.Method == http.MethodPut || r.Method == http.MethodDelete):
				found := false
				for _, rule := range f.rules {
					if rule.ID == id {
						found = true
						if rule.ETag != r.Header.Get("if-match") {
							err = errors.New("etag mismatch")
						}
						if rule.Locked {
							err = errors.New("locked")
						}
					}
				}
				if !found {
					err = errors.New("retention rule not found")
				}
				if err == nil && r.Method == http.MethodDelete {
					err = f.DeleteRetentionRule(r.Context(), "tenancy", "backups", id, r.Header.Get("if-match"))
				} else if err == nil {
					var details objectstorage.UpdateRetentionRuleDetails
					if err = json.Unmarshal(body, &details); err == nil {
						if details.TimeRuleLocked != nil {
							t.Error("controller attempted to lock retention")
						}
						if details.Duration == nil {
							err = errors.New("duration required")
						} else {
							err = f.UpdateRetentionRule(r.Context(), "tenancy", "backups", id, r.Header.Get("if-match"), *details.Duration.TimeAmount, string(details.Duration.TimeUnit))
						}
					}
				}
			default:
				t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
				w.WriteHeader(405)
				return
			}
			if err != nil {
				w.WriteHeader(http.StatusPreconditionFailed)
				body, _ := json.Marshal(map[string]string{"code": "NoEtagMatch", "message": err.Error()})
				_, _ = w.Write(body)
				return
			}
			if f.loseResponse {
				f.loseResponse = false
				connection, _, hijackErr := w.(http.Hijacker).Hijack()
				if hijackErr != nil {
					t.Error(hijackErr)
					return
				}
				_ = connection.Close()
				return
			}
		}
		timestamp := &common.SDKTime{Time: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		var response any
		if retention {
			rules := []objectstorage.RetentionRuleSummary{}
			for _, rule := range f.rules {
				item := objectstorage.RetentionRuleSummary{Id: new(rule.ID), DisplayName: new(rule.DisplayName), Etag: new(rule.ETag), Duration: duration(rule.Amount, rule.Unit), TimeCreated: timestamp, TimeModified: timestamp}
				if rule.Locked {
					item.TimeRuleLocked = timestamp
				}
				rules = append(rules, item)
			}
			if r.Method == http.MethodGet {
				response = map[string]any{"items": rules}
			} else if len(rules) > 0 {
				response = rules[len(rules)-1]
			} else {
				response = map[string]any{}
			}
		} else {
			w.Header().Set("etag", f.bucket.ETag)
			response = objectstorage.Bucket{Namespace: new(f.bucket.Namespace), Name: new(f.bucket.Name), Etag: new(f.bucket.ETag), Versioning: objectstorage.BucketVersioningEnum(f.bucket.Versioning), FreeformTags: f.bucket.Tags.Freeform, DefinedTags: f.bucket.Tags.Defined, TimeCreated: timestamp}
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		body, marshalErr := json.Marshal(response)
		if marshalErr != nil {
			t.Error(marshalErr)
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(body)
	})
	api, err := newSDKAPI(factory, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	f.api = api
	return api
}

func persistentStore(t *testing.T) *ociresource.KVStore {
	t.Helper()
	return ociresourcetest.Store(t)
}

func confirm(t *testing.T, api *providerState, store ociresource.Store) {
	t.Helper()
	current, err := store.Get(t.Context(), key)
	if errors.Is(err, ociresource.ErrNotFound) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if current.Operation == nil || !current.Operation.CompletedAt.IsZero() {
		return
	}
	controller := &ociresource.Controller[Spec, Observed]{Region: "GRU", Resource: Reconciler{API: api.client(t)}, Store: store, Ownership: owner, Authority: allow{}}
	result, err := controller.Reconcile(t.Context(), 1)
	if err != nil || result.InSync != 1 {
		t.Fatalf("confirm=%+v err=%v", result, err)
	}
}
