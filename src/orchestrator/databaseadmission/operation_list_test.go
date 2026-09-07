package databaseadmission

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestOperationDiscoverySurvivesAuthorityRestartAndLostResponse(t *testing.T) {
	cluster := newAdmissionJournalCluster(t)
	connection := cluster.connect(t)
	store := openAdmissionLeaseStore(t, t.Context(), connection, true)
	putAdmissionLease(t, t.Context(), store, admissionLease(1, "global-controller-gru-one"))
	journal := newAdmissionJournalClient(t, connection, 1, "global-controller-gru-one")
	config := pipelineConfig(t, journal)
	pipeline, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	request := journalFixture(t).Request
	// Lose the accepted response before the client learns the database ID.
	if _, err := pipeline.Accept(t.Context(), request); err != nil {
		t.Fatal(err)
	}

	cluster.restart(t)
	connection = cluster.connect(t)
	store = openAdmissionLeaseStore(t, t.Context(), connection, false)
	putAdmissionLease(t, t.Context(), store, admissionLease(2, "global-controller-gru-two"))
	config.Journal = newAdmissionJournalClient(t, connection, 2, "global-controller-gru-two")
	pipeline, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := StartAuthority(t.Context(), connection, pipeline)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	socket := filepath.Join(filepath.Dir(config.CatalogPath), "discovery.sock")
	ingress, err := StartIngress(t.Context(), IngressConfig{Connection: connection, SocketPath: socket, AllowedUID: uint32(os.Geteuid())})
	if err != nil {
		t.Fatal(err)
	}
	defer ingress.Close()
	client := unixTestClient(socket)
	defer client.CloseIdleConnections()
	query := OperationListRequest{Environment: request.Environment, TenantID: request.TenantID, ProjectID: request.ProjectID, Limit: 1}
	post := func(query OperationListRequest) (int, OperationPage) {
		t.Helper()
		data, _ := json.Marshal(query)
		response, err := client.Post("http://unix/internal/v1/operations/list", "application/json", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"key_version", "Ciphertext", "targets", "Wrapped"} {
			if strings.Contains(string(body), secret) {
				t.Fatalf("internal material in projection: %s", secret)
			}
		}
		var page OperationPage
		if response.StatusCode == 200 {
			if err := json.Unmarshal(body, &page); err != nil {
				t.Fatal(err)
			}
		}
		return response.StatusCode, page
	}
	seen := map[string]bool{}
	for {
		code, page := post(query)
		if code != http.StatusOK || len(page.Operations) != 1 {
			t.Fatal(code, page)
		}
		op := page.Operations[0]
		if seen[op.OperationID] || op.State != "queued" || op.Cancellable || op.Revision != 1 {
			t.Fatal(op)
		}
		seen[op.OperationID] = true
		if page.NextCursor == "" {
			break
		}
		foreign := query
		foreign.ProjectID = "01ARZ3NDEKTSV4RRFFQ69G5FB9"
		foreign.After = page.NextCursor
		if code, _ := post(foreign); code != 400 {
			t.Fatal("cross-project cursor accepted", code)
		}
		query.After = page.NextCursor
	}
	if len(seen) != 1 {
		t.Fatal(seen)
	}
	query.After = ""
	query.TenantID = "01ARZ3NDEKTSV4RRFFQ69G5FB9"
	if code, page := post(query); code != 200 || len(page.Operations) != 0 {
		t.Fatal("foreign tenant discovered records", code, page)
	}
	query.TenantID = request.TenantID
	query.Limit = 51
	if code, _ := post(query); code != 400 {
		t.Fatal("unbounded page accepted", code)
	}
	records, err := config.Journal.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if record.Revision != 1 {
			t.Fatal("progress viewing wrote journal", record.Revision)
		}
	}
	config.Authorize = func(_ context.Context, _ Request) error { return ErrForbidden }
	denied, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	query.Limit = 1
	if _, err := denied.ListOperations(t.Context(), query); !errors.Is(err, ErrForbidden) {
		t.Fatal("authorization ignored", err)
	}
}

// Snapshot fixture only replaces the read contract; production remains NATS-backed.
type operationSnapshotJournal struct {
	Journal
	records []Record
}

func (j operationSnapshotJournal) List(context.Context) ([]Record, error) {
	return slices.Clone(j.records), nil
}
func TestOperationDiscoveryPaginationScopeAndCursor(t *testing.T) {
	records := []Record{}
	for _, name := range []string{"first", "second", "third"} {
		r := journalFixture(t)
		r.Request.Name = name
		r.Request.OperationID = name
		r.Revision = 1
		records = append(records, r)
	}
	config := pipelineConfig(t, operationSnapshotJournal{records: records})
	pipeline, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	r := records[0].Request
	query := OperationListRequest{Environment: r.Environment, TenantID: r.TenantID, ProjectID: r.ProjectID, Limit: 1}
	seen := map[string]bool{}
	for {
		page, err := pipeline.ListOperations(t.Context(), query)
		if err != nil || len(page.Operations) != 1 {
			t.Fatal(page, err)
		}
		id := page.Operations[0].OperationID
		if seen[id] {
			t.Fatal("duplicate", id)
		}
		seen[id] = true
		if page.NextCursor == "" {
			break
		}
		foreign := query
		foreign.ProjectID = "01ARZ3NDEKTSV4RRFFQ69G5FB9"
		foreign.After = page.NextCursor
		if _, err := pipeline.ListOperations(t.Context(), foreign); !errors.Is(err, ErrInvalid) {
			t.Fatal("foreign cursor accepted", err)
		}
		query.After = page.NextCursor
	}
	if len(seen) != 3 {
		t.Fatal(seen)
	}
}
