package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
	"terrascale.tech/orchestrator/src/orchestrator/reaper"
)

func TestPolicyDatabaseActivitySourceConstructorBindsAcceptedPolicy(t *testing.T) {
	policy, err := reaper.NewLifecyclePolicyClient(reaper.LifecyclePolicyClientConfig{
		Endpoint:             "https://dashboard.example/api/internal/lifecycle/evaluate",
		ServiceKey:           strings.Repeat("k", 32),
		CheckEffectAuthority: func(context.Context) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if newPolicyDatabaseActivitySource(policy) == nil {
		t.Fatal("policy activity source constructor returned nil for an accepted policy")
	}
}

func TestProductionLifecycleCatalogPreservesPolicyAndBillingFields(t *testing.T) {
	const organization = "01ARZ3NDEKTSV4RRFFQ69G5FAA"
	const project = "01ARZ3NDEKTSV4RRFFQ69G5FAB"
	const database = "01ARZ3NDEKTSV4RRFFQ69G5FAC"
	now := time.Now().UTC().Truncate(time.Millisecond)
	deadline := now.Add(-time.Hour)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			SchemaVersion int `json:"schemaVersion"`
			reaper.LifecyclePolicyScope
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode policy scope: %v", err)
		}
		_ = json.NewEncoder(w).Encode(reaper.LifecyclePolicyFacts{
			SchemaVersion: 1, OrganizationID: request.OrganizationID, ProjectID: request.ProjectID, DatabaseID: request.DatabaseID,
			Revision: "policy-revision", Plan: "pro", OwnerEmails: []string{"owner@example.com"},
			LastAuthorizedRequestAt: new(now.Add(-time.Hour)), DeletionEligible: true, DeletionReasons: []string{"card-loss"},
			BillingGraceDeadline: &deadline, BillingDeletionEligible: true,
			Coverage: reaper.LifecycleBillingCoverage{CardLoss: &reaper.LifecycleBillingGrace{StartedAt: deadline.Add(-31 * 24 * time.Hour), Deadline: deadline}},
		})
	}))
	t.Cleanup(server.Close)
	policy, err := reaper.NewLifecyclePolicyClient(reaper.LifecyclePolicyClientConfig{
		Endpoint: server.URL + "/api/internal/lifecycle/evaluate", ServiceKey: strings.Repeat("k", 32), Transport: server.Client().Transport,
		CheckEffectAuthority: func(context.Context) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	journal := databaseadmission.NewMemoryJournal()
	identity := databaselifecycle.Identity{Environment: "production", OrganizationID: organization, ProjectID: project, DatabaseID: database}
	if err := journal.ApplyLifecycle(t.Context(), databaselifecycle.Event{OperationID: "create-database", Kind: "create", Identity: identity, At: now.Add(-2 * time.Hour), Regions: []string{"GRU"}}); err != nil {
		t.Fatal(err)
	}
	if err := journal.ApplyLifecycle(t.Context(), databaselifecycle.Event{
		OperationID: "route-database", Kind: "streams", Identity: identity,
		At: now.Add(-2 * time.Hour), Streams: []databaselifecycle.Stream{{Region: "GRU", Partition: "partition", Epoch: 1, StartedAt: now.Add(-2 * time.Hour)}},
	}); err != nil {
		t.Fatal(err)
	}
	catalog, err := newProductionLifecycleCatalog(journal, policy, "production")
	if err != nil {
		t.Fatal(err)
	}
	page, err := catalog.List(t.Context(), "", 10)
	if err != nil || len(page.Databases) != 1 {
		t.Fatalf("catalog page=%+v err=%v", page, err)
	}
	got := page.Databases[0]
	if got.Plan != reaper.PlanPaid || got.OwnerEmail != "owner@example.com" || got.PolicyRevision != "policy-revision" || !got.BillingDeletionEligible || got.BillingGraceDeadline == nil || !got.BillingGraceDeadline.Equal(deadline) || got.SelectedGraceCondition != "card-loss" {
		t.Fatalf("production catalog dropped policy/billing fields: %+v", got)
	}
}

type activitySourceFixture map[string]*time.Time

func (s activitySourceFixture) LastAuthorizedRequest(_ context.Context, record databaseadmission.Record) (*time.Time, error) {
	return s[record.DatabaseID], nil
}

func activityRecord(id, state string, created time.Time) databaseadmission.Record {
	return databaseadmission.Record{DatabaseID: id, State: state, CreatedAt: created}
}

func TestPageDatabaseActivityRecordsUsesDurableActivity(t *testing.T) {
	created := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	busy := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	activity := activitySourceFixture{"db-a": &busy}
	page, err := pageDatabaseActivityRecords(t.Context(), []databaseadmission.Record{activityRecord("db-a", "accepted", created)}, "", 10, activity)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Databases) != 1 || !page.Databases[0].LastRequest.Equal(busy) {
		t.Fatalf("page = %+v, want durable activity %v", page, busy)
	}
	if page.Databases[0].LastRequest.Equal(created) {
		t.Fatal("catalog fell back to admission CreatedAt as activity")
	}
}

func TestPageDatabaseActivityRecordsPreservesRestartActivity(t *testing.T) {
	activityAt := time.Date(2026, time.March, 2, 3, 4, 5, 0, time.UTC)
	activity := activitySourceFixture{"db-a": &activityAt}
	records := []databaseadmission.Record{activityRecord("db-a", "ready", time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC))}
	page, err := pageDatabaseActivityRecords(t.Context(), records, "", 1, activity)
	if err != nil || len(page.Databases) != 1 || !page.Databases[0].LastRequest.Equal(activityAt) {
		t.Fatalf("restart activity was not retained: page=%+v err=%v", page, err)
	}
}

func TestPageDatabaseActivityRecordsUsesBoundedKeysetCursor(t *testing.T) {
	activityAt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	activity := activitySourceFixture{"db-a": &activityAt, "db-b": &activityAt, "db-c": &activityAt}
	records := []databaseadmission.Record{
		activityRecord("db-c", "accepted", activityAt),
		activityRecord("db-a", "accepted", activityAt),
		activityRecord("db-b", "accepted", activityAt),
	}
	first, err := pageDatabaseActivityRecords(t.Context(), records, "", 2, activity)
	if err != nil || first.NextCursor != "db-b" || len(first.Databases) != 2 {
		t.Fatalf("first page = %+v err=%v", first, err)
	}
	second, err := pageDatabaseActivityRecords(t.Context(), records, first.NextCursor, 2, activity)
	if err != nil || second.NextCursor != "" || len(second.Databases) != 1 || second.Databases[0].ID != "db-c" {
		t.Fatalf("second page = %+v err=%v", second, err)
	}
}

func TestScopeCatalogRecordsFiltersForeignAndIncompleteRecords(t *testing.T) {
	records, err := scopeCatalogRecords([]databaseadmission.Record{
		{DatabaseID: "foreign", Request: databaseadmission.Request{Environment: "sfo"}, State: "ready"},
		{DatabaseID: "incomplete", Request: databaseadmission.Request{Environment: "gru", TenantID: "tenant", ProjectID: "project"}, State: "ready"},
	}, "gru")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("scoped records = %+v, want no incomplete or foreign records", records)
	}
}

func TestScopeCatalogRecordsRejectsDuplicateAdmittedIdentity(t *testing.T) {
	_, err := scopeCatalogRecords([]databaseadmission.Record{
		{DatabaseID: "db", Request: databaseadmission.Request{Environment: "gru"}, State: "accepted"},
		{DatabaseID: "db", Request: databaseadmission.Request{Environment: "gru"}, State: "ready"},
	}, "gru")
	if err == nil || !strings.Contains(err.Error(), "duplicate database identity") {
		t.Fatalf("duplicate identity error = %v", err)
	}
}

func TestFilterDeletingCatalogRecordsExcludesOnlyScopedDeletion(t *testing.T) {
	records := []databaseadmission.Record{
		{DatabaseID: "db-a", Request: databaseadmission.Request{Environment: "gru", TenantID: "tenant-a", ProjectID: "project-a"}},
		{DatabaseID: "db-b", Request: databaseadmission.Request{Environment: "gru", TenantID: "tenant-b", ProjectID: "project-b"}},
		{DatabaseID: "db-c", Request: databaseadmission.Request{Environment: "sfo", TenantID: "tenant-a", ProjectID: "project-a"}},
	}
	deletions := []databaseadmission.Deletion{
		{Request: databaseadmission.DeleteRequest{Environment: "gru", TenantID: "tenant-a", ProjectID: "project-a", DatabaseID: "db-a"}, State: "preparing"},
		{Request: databaseadmission.DeleteRequest{Environment: "sfo", TenantID: "tenant-a", ProjectID: "project-a", DatabaseID: "db-c"}, State: "stopping"},
	}
	filtered := filterDeletingCatalogRecords(records, deletions, "gru")
	if len(filtered) != 2 || filtered[0].DatabaseID != "db-b" || filtered[1].DatabaseID != "db-c" {
		t.Fatalf("filtered records = %+v", filtered)
	}
}
