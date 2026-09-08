package reaper

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
)

type lifecycleSourceFixture struct {
	resources []databaselifecycle.Resource
	err       error
	calls     atomic.Int32
}

func (s *lifecycleSourceFixture) LifecycleResources(context.Context) (uint64, []databaselifecycle.Resource, error) {
	s.calls.Add(1)
	return 7, s.resources, s.err
}

func lifecycleCatalogPolicy(t *testing.T) *LifecyclePolicyClient {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			SchemaVersion int `json:"schemaVersion"`
			LifecyclePolicyScope
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode scope: %v", err)
		}
		now := time.Now().UTC()
		_ = json.NewEncoder(w).Encode(LifecyclePolicyFacts{Coverage: LifecycleBillingCoverage{UnpaidStorageInvoices: map[string]LifecycleBillingGrace{}}, SchemaVersion: 1, OrganizationID: request.OrganizationID, ProjectID: request.ProjectID, DatabaseID: request.DatabaseID, Revision: "revision-1", ObservedAt: now, Plan: "free", OwnerEmails: []string{"owner@example.com"}, DeletionReasons: []string{}})
	}))
	t.Cleanup(server.Close)
	client, err := NewLifecyclePolicyClient(LifecyclePolicyClientConfig{Endpoint: server.URL + "/api/internal/lifecycle/evaluate", ServiceKey: strings.Repeat("k", 32), Transport: server.Client().Transport, CheckEffectAuthority: func(context.Context) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func completeLifecycleFixture(id string) databaselifecycle.Resource {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return databaselifecycle.Resource{Identity: databaselifecycle.Identity{Environment: "production", OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAA", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAB", DatabaseID: id}, Regions: []string{"GRU"}, CreatedAt: created, RoutingComplete: true, Streams: []databaselifecycle.Stream{{Region: "GRU", Partition: "partition", Epoch: 1, StartedAt: created}}}
}

func TestLifecycleCatalogOrdersCursorAndExcludesIncompleteOrDeleted(t *testing.T) {
	first := "01ARZ3NDEKTSV4RRFFQ69G5FAA"
	second := "01ARZ3NDEKTSV4RRFFQ69G5FAB"
	deleted := completeLifecycleFixture("01ARZ3NDEKTSV4RRFFQ69G5FAC")
	deleted.DeletedAt = deleted.CreatedAt.Add(time.Hour)
	incomplete := completeLifecycleFixture("01ARZ3NDEKTSV4RRFFQ69G5FAD")
	incomplete.Streams = nil
	foreign := completeLifecycleFixture("01ARZ3NDEKTSV4RRFFQ69G5FAE")
	foreign.Environment = "staging"
	source := &lifecycleSourceFixture{resources: []databaselifecycle.Resource{completeLifecycleFixture(second), deleted, incomplete, foreign, completeLifecycleFixture(first)}}
	catalog, err := NewLifecycleCatalog(source, lifecycleCatalogPolicy(t), "production")
	if err != nil {
		t.Fatal(err)
	}
	if source.calls.Load() != 0 {
		t.Fatal("catalog construction performed an inventory read")
	}
	page, err := catalog.List(t.Context(), "", 1)
	if err != nil || len(page.Databases) != 1 || page.Databases[0].ID != first || page.NextCursor != first {
		t.Fatalf("first page=%+v err=%v", page, err)
	}
	page, err = catalog.List(t.Context(), page.NextCursor, 1)
	if err != nil || len(page.Databases) != 1 || page.Databases[0].ID != second || page.NextCursor != "" {
		t.Fatalf("cursor page=%+v err=%v", page, err)
	}
}

func TestLifecycleCatalogRejectsDuplicateIdentityAndPreservesUnavailable(t *testing.T) {
	duplicate := completeLifecycleFixture("01ARZ3NDEKTSV4RRFFQ69G5FAA")
	source := &lifecycleSourceFixture{resources: []databaselifecycle.Resource{duplicate, duplicate}}
	catalog, err := NewLifecycleCatalog(source, lifecycleCatalogPolicy(t), "production")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.List(t.Context(), "", 10); !errors.Is(err, ErrInvalidDatabase) {
		t.Fatalf("duplicate accepted: %v", err)
	}
	source.err = errors.New("journal quorum unavailable")
	if _, err := catalog.List(t.Context(), "", 10); !errors.Is(err, ErrLifecycleInventoryUnavailable) {
		t.Fatalf("unavailable source was not typed: %v", err)
	}
}

func TestLifecyclePolicyDenialSurvivesReaperTranslation(t *testing.T) {
	now := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	last := now.Add(-100 * 24 * time.Hour)
	facts := LifecyclePolicyFacts{DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Revision: "revision-1", Plan: "free", LastAuthorizedRequestAt: &last, PauseEligible: true, OwnerEmails: []string{"z@example.com", "a@example.com"}}
	database, err := policyDatabase(facts, now)
	if err != nil {
		t.Fatal(err)
	}
	if !database.Exemption.activeAt(now) || database.OwnerEmail != "a@example.com" || database.OwnershipProof != facts.Revision {
		t.Fatalf("policy denial lost: %+v", database)
	}
	facts.DeletionEligible = true
	database, err = policyDatabase(facts, now)
	if err != nil || database.Exemption.Active {
		t.Fatalf("eligible observation rejected: %+v %v", database, err)
	}
	facts.DeletionProtection = true
	database, err = policyDatabase(facts, now)
	if err != nil || !database.Exemption.Active {
		t.Fatalf("protection lost: %+v %v", database, err)
	}
}

func TestLifecyclePolicyUnknownActivityAndPaidPlansStaySafe(t *testing.T) {
	facts := LifecyclePolicyFacts{DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Revision: "revision-1", Plan: "pro", OwnerEmails: []string{"owner@example.com"}}
	database, err := policyDatabase(facts, time.Now())
	if err != nil || database.Plan != PlanPaid || !database.LastRequest.IsZero() {
		t.Fatalf("unknown activity or paid plan changed: %+v %v", database, err)
	}
	facts.OwnerEmails = nil
	if _, err := policyDatabase(facts, time.Now()); err == nil {
		t.Fatal("missing owner accepted")
	}
}

func TestLifecyclePolicyRecentActivityCanReachReactivation(t *testing.T) {
	now := time.Now()
	last := now.Add(-time.Minute)
	facts := LifecyclePolicyFacts{DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Revision: "revision-1", Plan: "free", LastAuthorizedRequestAt: &last, OwnerEmails: []string{"owner@example.com"}, DeletionProtection: true}
	database, err := policyDatabase(facts, now)
	if err != nil || database.Exemption.Active || !database.LastRequest.Equal(last) {
		t.Fatalf("recent activity cannot reach reactivation: %+v %v", database, err)
	}
}

func TestLifecyclePolicyBillingGraceFactsReachReaperDatabase(t *testing.T) {
	now := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	deadline := now.Add(-time.Hour)
	facts := LifecyclePolicyFacts{
		DatabaseID:              "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Revision:                "revision-1",
		Plan:                    "pro",
		OwnerEmails:             []string{"owner@example.com"},
		BillingGraceDeadline:    &deadline,
		BillingDeletionEligible: true,
		DeletionReasons:         []string{"uncovered-storage"},
		Coverage: LifecycleBillingCoverage{UncoveredStorage: &LifecycleBillingGrace{
			StartedAt: deadline.Add(-30 * 24 * time.Hour), Deadline: deadline,
		}},
	}
	database, err := policyDatabase(facts, now)
	if err != nil {
		t.Fatal(err)
	}
	if database.BillingGraceDeadline == nil || !database.BillingGraceDeadline.Equal(deadline) || !database.BillingDeletionEligible || database.SelectedGraceCondition != "uncovered-storage" {
		t.Fatalf("billing grace facts were dropped: %+v", database)
	}
}
