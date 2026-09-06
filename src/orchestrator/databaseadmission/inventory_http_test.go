package databaseadmission

import (
	"crypto/tls"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInventoryHTTPSAuthenticationScopeAndDeletion(t *testing.T) {
	j := NewMemoryJournal()
	record := journalFixture(t)
	if _, err := j.Save(t.Context(), ScopeKey(record.Request), 0, record); err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("k", 32)
	handler, err := NewInventoryHandler(j, "production", key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body, key string
		tls             bool
		status          int
	}{
		{"authorized", `{"environment":"production","tenant_id":"01ARZ3NDEKTSV4RRFFQ69G5FAY"}`, key, true, 200},
		{"wrong key", `{}`, "wrong", true, 401},
		{"plaintext", `{}`, key, false, 400},
		{"unscoped", `{"environment":"production"}`, key, true, 400},
		{"wrong environment", `{"environment":"staging","tenant_id":"01ARZ3NDEKTSV4RRFFQ69G5FAY"}`, key, true, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, InventoryPath, strings.NewReader(tc.body))
			req.Header.Set(InventoryKeyHeader, tc.key)
			if tc.tls {
				req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
			}
			out := httptest.NewRecorder()
			handler.ServeHTTP(out, req)
			if out.Code != tc.status {
				t.Fatalf("status %d: %s", out.Code, out.Body.String())
			}
			if out.Code == 200 {
				var view AdmissionInventory
				if err := json.Unmarshal(out.Body.Bytes(), &view); err != nil {
					t.Fatal(err)
				}
				if !view.Complete || len(view.Operations) != 1 || view.Operations[0].OperationID != record.Request.OperationID || len(view.Revision) != 64 {
					t.Fatalf("invalid inventory: %+v", view)
				}
			}
		})
	}
	scope := InventoryScope{Environment: "production", TenantID: record.Request.TenantID, ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FB2"}
	view, err := j.AdmissionInventory(t.Context(), scope)
	if err != nil || len(view.Resources) != 0 || len(view.Operations) != 0 {
		t.Fatalf("project isolation: %+v %v", view, err)
	}
	scope.ProjectID = ""
	before, err := j.AdmissionInventory(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	r := DeleteRequest{Environment: scope.Environment, TenantID: scope.TenantID, ProjectID: record.Request.ProjectID, DatabaseID: record.DatabaseID, OperationID: "delete-inventory"}
	at := time.Now().UTC().Add(time.Second)
	deletion, err := j.BeginDeletion(t.Context(), r, at, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	pending, err := j.AdmissionInventory(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending.Operations) != 1 || len(pending.RetiredOperationIDs) != 0 || !pending.Resources[0].Deleting || pending.Revision == before.Revision {
		t.Fatalf("pending deletion released count: %+v", pending)
	}
	for _, target := range deletion.Targets {
		if _, err := j.RecordDeletionStop(t.Context(), r, DeletionReceipt{DeletionStop: target.Stop, AccessRevoked: true, UsageStopped: true}); err != nil {
			t.Fatal(err)
		}
	}
	done, err := j.AdmissionInventory(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(done.Operations) != 0 || len(done.RetiredOperationIDs) != 1 || !done.Resources[0].Deleted || done.Revision == pending.Revision {
		t.Fatalf("confirmed deletion not retired: %+v", done)
	}
}
