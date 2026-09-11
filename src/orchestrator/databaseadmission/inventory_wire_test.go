package databaseadmission

import (
	"bytes"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

// TestInventoryWireFixture captures the bytes emitted by NewInventoryHandler.
// The checked-in copy is consumed by Dashboard eligibility tests, so changes
// to either DTO or JSON tags fail here instead of silently drifting.
func TestInventoryWireFixture(t *testing.T) {
	const key = "inventory-wire-fixture-key-012345678901234567890123456789"
	const tenant = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
	const project = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
	const activeDatabase = "01ARZ3NDEKTSV4RRFFQ69G5FB0"
	const deletedDatabase = "01ARZ3NDEKTSV4RRFFQ69G5FB2"
	const createdAt = "2026-09-01T12:00:00Z"
	const deletedAt = "2026-09-02T12:00:00Z"

	journal := NewMemoryJournal()
	active := inventoryFixtureRecord(t, tenant, project, activeDatabase, "01ARZ3NDEKTSV4RRFFQ69G5FC0", createdAt)
	if _, err := journal.Save(t.Context(), ScopeKey(active.Request), 0, active); err != nil {
		t.Fatal(err)
	}
	// The journal's bounded admission reservation makes two full pending
	// records exceed its test envelope. Seed the second immutable record and
	// its lifecycle resource directly after the real Save path; deletion still
	// runs through the production journal workflow below.
	retired := inventoryFixtureRecord(t, tenant, project, deletedDatabase, "01ARZ3NDEKTSV4RRFFQ69G5FC1", createdAt)
	retiredKey := ScopeKey(retired.Request)
	if err := databaselifecycle.Apply(&journal.state.Lifecycle, admissionLifecycleEvent(retired)); err != nil {
		t.Fatal(err)
	}
	journal.state.Records[retiredKey] = retired
	retiredResource := journal.state.Lifecycle.Resources[databaselifecycle.Key(admissionLifecycleEvent(retired).Identity)]
	retiredResource.DeletedAt = parseInventoryTime(t, deletedAt)
	retiredResource.UsageStoppedAt = retiredResource.DeletedAt
	retiredResource.EffectsCompletedAt = retiredResource.DeletedAt
	retiredResource.RetainUntil = retiredResource.DeletedAt.Add(24 * time.Hour)
	retiredResource.AccessRevoked = true
	journal.state.Lifecycle.Resources[databaselifecycle.Key(retiredResource.Identity)] = retiredResource

	handler, err := NewInventoryHandler(journal, "production", key)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"environment":"production","tenant_id":"` + tenant + `","project_id":"` + project + `"}`)
	req := httptest.NewRequest(http.MethodPost, InventoryPath, bytes.NewReader(body))
	req.Header.Set(InventoryKeyHeader, key)
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("inventory status=%d body=%s", response.Code, response.Body.String())
	}
	fixturePath := dashboardFixturePath(t)
	expected, readErr := os.ReadFile(fixturePath)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		t.Fatal(readErr)
	}
	if os.Getenv("UPDATE_INVENTORY_WIRE_FIXTURE") == "1" {
		if err := os.MkdirAll(filepath.Dir(fixturePath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixturePath, response.Body.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		expected = response.Body.Bytes()
	}
	if !bytes.Equal(response.Body.Bytes(), expected) {
		t.Fatalf("captured handler body differs from Dashboard fixture %s", fixturePath)
	}

	var inventory AdmissionInventory
	if err := json.Unmarshal(response.Body.Bytes(), &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.ProjectID != project || len(inventory.Operations) != 1 || len(inventory.RetiredOperationIDs) != 1 || len(inventory.Resources) != 2 {
		t.Fatalf("unexpected scoped inventory: %+v", inventory)
	}
	if inventory.Resources[0].AdmissionState != "accepted" || !inventory.Resources[1].Deleted {
		t.Fatalf("fixture does not contain accepted and retired resources: %+v", inventory.Resources)
	}
}

func inventoryFixtureRecord(t *testing.T, tenant, project, database, operation, created string) Record {
	t.Helper()
	record := journalFixture(t)
	record.Request.TenantID = tenant
	record.Request.ProjectID = project
	record.Request.Name = "inventory-" + strings.ToLower(database[len(database)-2:])
	record.Request.OperationID = operation
	record.DatabaseID = database
	record.CreatedAt = parseInventoryTime(t, created)
	record.State = "accepted"
	for i := range record.Targets {
		record.Targets[i].Provision.Binding.TenantID = tenant
		record.Targets[i].Provision.Binding.ProjectID = project
		record.Targets[i].Provision.Binding.DatabaseID = database
		stage := new(pb.PlacementStageRequest)
		if err := proto.Unmarshal(record.Targets[i].Proposal, stage); err != nil {
			t.Fatal(err)
		}
		for _, assignment := range stage.Proposal.Assignments {
			assignment.Tenant = tenant
			assignment.Project = project
			assignment.Database = database
		}
		proposal, err := proto.Marshal(stage)
		if err != nil {
			t.Fatal(err)
		}
		record.Targets[i].Proposal = proposal
		record.PlacementTargets[i].Proposal = proposal
	}
	if err := ValidateRecord(record); err != nil {
		t.Fatal(err)
	}
	return record
}

func parseInventoryTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func dashboardFixturePath(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller unavailable")
	}
	return filepath.Join(filepath.Dir(source), "..", "..", "..", "..", "ts-dashboard", "tests", "testdata", "database-admission-inventory-wire.json")
}
