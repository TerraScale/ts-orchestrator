package app

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

type operationObservationMissingTime struct{ netbirdStateReader }

func (source operationObservationMissingTime) ReadNetBirdState(ctx context.Context) (authority.LogEntry, error) {
	entry, err := source.netbirdStateReader.ReadNetBirdState(ctx)
	entry.CreatedAt = time.Time{}
	return entry, err
}

func TestOperationObservationAuthenticatedHTTP(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	auth := newAuthenticatedNATS(t, "gru")
	broker, err := auth.start(t, ctx, natscell.Config{Cell: "gru", Instance: "operation-observation", Replicas: 1,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "nats")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scope: "gru", CandidateID: "0000000000G3799641MSM6590R", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	token := strings.Repeat("t", 40)
	server, err := observability.NewTokenServer(observability.Config{}, token,
		observability.ServerDeps{Registry: observability.NewRegistry(false), Health: new(observability.Health)})
	if err != nil {
		t.Fatal(err)
	}
	api := &operationObservationAPI{cell: "gru"}
	api.mount(server)
	listener := httptest.NewServer(server)
	t.Cleanup(listener.Close)
	request := func(method, path, bearer string, want int) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, listener.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		response, err := listener.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != want {
			t.Fatalf("%s %s = %d, want %d; %s", method, path, response.StatusCode, want, body)
		}
		if bearer == token && method == http.MethodGet && want != http.StatusUnauthorized &&
			(response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff") {
			t.Fatal("operation response lacks private response headers")
		}
		return body
	}
	const path = "/v1/operations/netbird"
	request(http.MethodGet, path, "", http.StatusUnauthorized)
	request(http.MethodGet, path, "wrong", http.StatusUnauthorized)
	request(http.MethodPost, path, token, http.StatusMethodNotAllowed)
	request(http.MethodGet, path, token, http.StatusServiceUnavailable)
	api.sources.Store(&operationObservationSources{netbird: control, backup: &backupOperationRuntime{control: control}})
	request(http.MethodGet, path, token, http.StatusNotFound)
	request(http.MethodGet, path+"?operation_id=old", token, http.StatusBadRequest)
	request(http.MethodGet, "/v1/operations/backups/invalid/invalid", token, http.StatusBadRequest)
	request(http.MethodGet, "/v1/operations/backups/0000000000WVSMBJNMAWCDJBSK/0000000000Z3WK359G2W66CVT8", token, http.StatusNotFound)
	request(http.MethodGet, "/v1/operations/credentials/0000000000WVSMBJNMAWCDJBSK/0000000000Z3WK359G2W66CVT8", token, http.StatusServiceUnavailable)

	record := network.Record{ID: "7E5HKSCCJSQJGMM2DVVHCQDQFV", Node: "node-a", Phase: "install",
		StartedAt: time.Now().UTC().Add(-time.Minute), Deadline: time.Now().UTC().Add(time.Minute),
		Reason: "Bearer private-reason-secret", Previous: "private-previous-secret", Fence: []byte(`{"secret":"private-fence-secret"}`)}
	state := netbirdState{Record: record, Command: network.Command{Action: "private-command-secret"}}
	wire, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	const mutationID = "0000000000SQ81DF1FR1ZA1QQB"
	sequence, err := control.CommitNetBirdState(ctx, control.Current().Epoch, mutationID, 0, wire)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := control.ReadNetBirdState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	body := request(http.MethodGet, path, token, http.StatusOK)
	var observed netbirdOperationObservation
	if err := json.Unmarshal(body, &observed, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if observed.OperationID != record.ID || observed.Commit.MutationOperationID != mutationID ||
		observed.Commit.Sequence != sequence || !observed.Commit.RecordedAt.Equal(entry.CreatedAt) ||
		observed.Commit.Epoch != entry.Epoch || observed.Node != record.Node || observed.Phase != record.Phase ||
		!observed.StartedAt.Equal(record.StartedAt) || !observed.Deadline.Equal(record.Deadline) {
		t.Fatalf("operation and committed metadata differ: %+v", observed)
	}
	for _, forbidden := range []string{"private-", "target", "enrollment", "command", "fence", "reason"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("response exposed %q", forbidden)
		}
	}
	api.sources.Store(&operationObservationSources{netbird: operationObservationMissingTime{control}})
	request(http.MethodGet, path, token, http.StatusServiceUnavailable)
	api.sources.Store(&operationObservationSources{netbird: control})
	if _, err := control.CommitNetBirdState(ctx, control.Current().Epoch, "0000000000CBFCJRYSV24E2Z96", sequence,
		[]byte(`{"secret":"private-decode-error-secret"}`)); err != nil {
		t.Fatal(err)
	}
	body = request(http.MethodGet, path, token, http.StatusServiceUnavailable)
	if string(body) != `{"error":"operation_unavailable"}` {
		t.Fatalf("source error was not fixed and redacted: %s", body)
	}
}

func TestOperationObservationRejectsTokenlessLoopback(t *testing.T) {
	server, err := observability.NewServer(observability.Config{},
		observability.ServerDeps{Registry: observability.NewRegistry(false), Health: new(observability.Health)})
	if err != nil {
		t.Fatal(err)
	}
	api := &operationObservationAPI{cell: "gru"}
	api.mount(server)
	for _, path := range []string{"/v1/operations/netbird",
		"/v1/operations/backups/0000000000WVSMBJNMAWCDJBSK/0000000000Z3WK359G2W66CVT8",
		"/v1/operations/credentials/0000000000WVSMBJNMAWCDJBSK/0000000000Z3WK359G2W66CVT8"} {
		response := httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("tokenless %s = %d", path, response.Code)
		}
	}
}
