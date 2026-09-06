package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
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
