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
	"strings"
	"testing"
)

func restoreSourceFixture(t *testing.T, journal Journal) Record {
	t.Helper()
	r := journalFixture(t)
	var err error
	r.Revision, err = journal.Save(t.Context(), ScopeKey(r.Request), 0, r)
	if err != nil {
		t.Fatal(err)
	}
	r.State, r.Wrapped = "ready", journalWrapped(r)
	for i := range r.Targets {
		r.Targets[i].Installed = true
	}
	for i := range r.PlacementTargets {
		r.PlacementTargets[i].Proposed = true
	}
	r.ReadinessNonce = strings.Repeat("a", 64)
	r.ReadyEvidence, _, _ = readinessFixture(t, r, r.ReadinessNonce)
	r.Revision, err = journal.Save(t.Context(), ScopeKey(r.Request), r.Revision, r)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func restoreRequestFixture(source Record) RestoreRequest {
	return RestoreRequest{Environment: source.Request.Environment, TenantID: source.Request.TenantID, ProjectID: source.Request.ProjectID, SourceDatabaseID: source.DatabaseID, Name: "recovered", OperationID: "public-restore-1", Selection: RestoreSelection{Kind: "latest"}}
}
func restoreFactsFixture() RestoreAdmissionFacts {
	return RestoreAdmissionFacts{PointID: strings.Repeat("b", 64), Provider: "oci", JournalCut: "42", SourceDigest: strings.Repeat("b", 64), CapturedAtMillis: 1000, Checksum: strings.Repeat("c", 64), RowCount: 7}
}
func TestUnixRestoreAdmissionAndExactRetryOverAuthenticatedNATS(t *testing.T) {
	cluster := newAdmissionJournalCluster(t)
	connection := cluster.connect(t)
	journal := NewMemoryJournal()
	source := restoreSourceFixture(t, journal)
	config := pipelineConfig(t, journal)
	resolves := 0
	config.Restore = &RestoreConfig{Resolve: func(_ context.Context, r Record, selection RestoreSelection) (RestoreAdmissionFacts, error) {
		resolves++
		if r.DatabaseID != source.DatabaseID || selection.Kind != "latest" {
			t.Fatal("resolution escaped original source")
		}
		return restoreFactsFixture(), nil
	}, Restore: func(context.Context, Record) ([]byte, error) {
		t.Fatal("admission dispatched restore")
		return nil, nil
	}}
	pipeline, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := StartAuthority(t.Context(), connection, pipeline)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	socket := filepath.Join(filepath.Dir(config.CatalogPath), "restore.sock")
	ingress, err := StartIngress(t.Context(), IngressConfig{Connection: connection, SocketPath: socket, AllowedUID: uint32(os.Geteuid())})
	if err != nil {
		t.Fatal(err)
	}
	defer ingress.Close()
	client := unixTestClient(socket)
	defer client.CloseIdleConnections()
	post := func(path string, request any) (int, Result) {
		t.Helper()
		data, _ := json.Marshal(request)
		response, err := client.Post("http://unix/internal/v1/databases/"+path, "application/json", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err = io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		var result Result
		if response.StatusCode == http.StatusAccepted || response.StatusCode == http.StatusOK {
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
		}
		return response.StatusCode, result
	}
	request := restoreRequestFixture(source)
	code, first := post("restore", request)
	if code != 202 || first.DatabaseID == "" || first.State != "pending" {
		t.Fatal(code, first)
	}
	code, retry := post("restore", request)
	if code != 202 || retry.DatabaseID != first.DatabaseID || resolves != 1 {
		t.Fatal("retry resolved a new point", code, retry, resolves)
	}
	for _, change := range []func(*RestoreRequest){func(r *RestoreRequest) { r.Name = "other" }, func(r *RestoreRequest) {
		r.Selection = RestoreSelection{Kind: "point_id", PointID: restoreFactsFixture().PointID}
	}, func(r *RestoreRequest) { r.SourceDatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAX" }} {
		changed := request
		change(&changed)
		if code, _ := post("restore", changed); code != 409 {
			t.Fatal("immutable operation changed", code)
		}
	}
	lookup := Request{Environment: request.Environment, TenantID: request.TenantID, ProjectID: request.ProjectID, OperationID: request.OperationID}
	if code, polled := post("status", lookup); code != 200 || polled.DatabaseID != first.DatabaseID {
		t.Fatal(code, polled)
	}
	records, err := journal.List(t.Context())
	if err != nil || len(records) != 2 {
		t.Fatal("target not durably reserved once", len(records), err)
	}
	record, err := pipeline.LookupOperation(t.Context(), lookup)
	if err != nil {
		t.Fatal(err)
	}
	if record.RestoreFacts.Epoch != 1 || record.Request.Residency != source.Request.Residency || record.Request.Regions[0] != source.Request.Regions[0] {
		t.Fatal("server facts/placement lost", record)
	}
	if _, err := pipeline.Accept(t.Context(), record.Request); !errors.Is(err, ErrConflict) {
		t.Fatal("restore aliased create", err)
	}
	// A new process replays the durable original request even if the resolver is unavailable.
	config.Restore = nil
	restarted, _ := New(config)
	if replay, err := restarted.AcceptRestore(t.Context(), request); err != nil || replay.DatabaseID != first.DatabaseID {
		t.Fatal("restart lost accepted operation", err)
	}
}

func TestRestorePreAdmissionDenialLeavesNoTarget(t *testing.T) {
	for _, mode := range []string{"authority", "foreign", "point", "epoch"} {
		t.Run(mode, func(t *testing.T) {
			journal := NewMemoryJournal()
			source := restoreSourceFixture(t, journal)
			config := pipelineConfig(t, journal)
			request := restoreRequestFixture(source)
			if mode != "authority" {
				config.Restore = &RestoreConfig{Resolve: func(context.Context, Record, RestoreSelection) (RestoreAdmissionFacts, error) {
					if mode == "point" {
						return RestoreAdmissionFacts{}, errors.New("point unavailable")
					}
					facts := restoreFactsFixture()
					if mode == "epoch" {
						facts.Epoch = 99
					}
					return facts, nil
				}, Restore: func(context.Context, Record) ([]byte, error) { return nil, nil }}
			}
			if mode == "foreign" {
				request.ProjectID = "01ARZ3NDEKTSV4RRFFQ69G5FB9"
			}
			p, _ := New(config)
			if _, err := p.AcceptRestore(t.Context(), request); err == nil {
				t.Fatal("invalid restore accepted")
			}
			records, _ := journal.List(t.Context())
			if len(records) != 1 {
				t.Fatal("target created on denial")
			}
		})
	}
}

func TestValidateRequestRejectsIncompleteRestoreProvenance(t *testing.T) {
	base := Request{
		Environment: "production", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAW",
		Name: "recovered", OperationID: "restore-operation", Regions: []string{"GRU"},
	}
	for name, mutate := range map[string]func(*Request){
		"point-without-parent":   func(r *Request) { r.RecoveryPointID = "01ARZ3NDEKTSV4RRFFQ69G5FAX" },
		"cut-without-point":      func(r *Request) { r.JournalCut = "cut-1" },
		"epoch-without-parent":   func(r *Request) { r.RestoreEpoch = 1 },
		"provider-without-point": func(r *Request) { r.RestoreProvider = "oci" },
		"invalid-provider": func(r *Request) {
			r.ParentDatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
			r.RecoveryPointID, r.JournalCut, r.RestoreEpoch, r.RestoreProvider = "01ARZ3NDEKTSV4RRFFQ69G5FAY", "cut-1", 1, "s3"
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := base
			mutate(&request)
			if err := ValidateRequest(request); !errors.Is(err, ErrInvalid) {
				t.Fatalf("ValidateRequest = %v, want ErrInvalid", err)
			}
		})
	}
}
