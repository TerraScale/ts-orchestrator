package app

import (
	"context"
	"encoding/json/v2"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// Exercise the production mount paths and retained reader, rather than mounting
// a handler directly on a test server.
func TestRuntimeMountedOperationObservations(t *testing.T) {
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	auth := newAuthenticatedNATS(t, "gru")
	broker, err := auth.start(t, ctx, natscell.Config{Cell: "gru", Instance: "mounted-observations", Replicas: 1,
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
	token := strings.Repeat("m", 40)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, err := startRuntimeObservability(ctx, Config{NATS: natscell.Config{Cell: "gru", Instance: "mounted-observations"},
		Observability: observability.Config{ListenAddress: freeLoopbackAddress(t), BearerTokenFile: tokenFile}},
		"controller", "mounted-observations")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.close)
	if runtime.server == nil {
		t.Fatal("ordinary runtime listener did not bind")
	}
	ordinary := "http://" + runtime.server.Addr().String()
	client := &http.Client{Timeout: 5 * time.Second}
	request := func(base, path, bearer string, want int) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != want {
			t.Fatalf("%s%s = %d, want %d; %s", base, path, response.StatusCode, want, body)
		}
		if bearer == token && strings.HasPrefix(path, "/v1/operations/") &&
			(response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff") {
			t.Fatal("operation response lacks private response headers")
		}
		return body
	}
	const operationPath = "/v1/operations/netbird"
	request(ordinary, operationPath, "", http.StatusUnauthorized)
	request(ordinary, operationPath, "wrong", http.StatusUnauthorized)
	request(ordinary, operationPath, token, http.StatusServiceUnavailable)
	if body := request(ordinary, "/readyz", token, http.StatusServiceUnavailable); !strings.Contains(string(body), "startup failing") {
		t.Fatalf("startup readiness did not report startup failure: %s", body)
	}
	if err := runtime.attachController(ctx, controllerObservation{nats: broker, replicas: 1,
		brokerIDs: []string{"mounted-observations"}, authority: control}, nil); err != nil {
		t.Fatal(err)
	}
	if runtime.providers.Load() == nil {
		t.Fatal("controller did not attach journal providers")
	}
	runtime.markStarted()
	request(ordinary, "/readyz", token, http.StatusOK)

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	originalPort := dashboardPort
	dashboardPort = uint16(probe.Addr().(*net.TCPAddr).Port)
	_ = probe.Close()
	t.Cleanup(func() { dashboardPort = originalPort })
	stop, _, err := runtime.startDashboard(ctx, dashboardListener{addresses: netbirdAddresses{netip.MustParseAddr("127.0.0.1")},
		token: vaultsecret.VersionedValue{Value: token, SecretID: "dashboard", Number: 1}, generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	secondary := "http://" + netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), dashboardPort).String()
	paths := []string{operationPath,
		"/v1/operations/credentials/0000000000WVSMBJNMAWCDJBSK/0000000000Z3WK359G2W66CVT8",
		"/v1/operations/backups/0000000000WVSMBJNMAWCDJBSK/0000000000Z3WK359G2W66CVT8",
		"/v1/regions/gru/foundation"}
	for _, base := range []string{ordinary, secondary} {
		request(base, "/readyz", token, http.StatusOK)
		for _, path := range paths {
			request(base, path, "", http.StatusUnauthorized)
			request(base, path, "wrong", http.StatusUnauthorized)
			request(base, path, token, http.StatusServiceUnavailable)
		}
	}

	// Sources attach after both listeners have already mounted the shared API.
	runtime.operationObservations.sources.Store(&operationObservationSources{netbird: control})
	for _, base := range []string{ordinary, secondary} {
		request(base, operationPath, token, http.StatusNotFound)
	}
	record := network.Record{ID: "7E5HKSCCJSQJGMM2DVVHCQDQFV", Node: "node-a", Phase: "install",
		StartedAt: time.Now().UTC().Add(-time.Minute), Deadline: time.Now().UTC().Add(time.Minute),
		Reason: "private-reason", Previous: "private-previous", Fence: []byte(`{"secret":"private-fence"}`)}
	var previous uint64
	for index, mutationID := range []string{"0000000000SQ81DF1FR1ZA1QQB", "0000000000CBFCJRYSV24E2Z96"} {
		if index == 1 {
			record.Phase = "complete"
		}
		wire, err := json.Marshal(netbirdState{Record: record, Command: network.Command{Action: "private-command"}})
		if err != nil {
			t.Fatal(err)
		}
		sequence, err := control.CommitNetBirdState(ctx, control.Current().Epoch, mutationID, previous, wire)
		if err != nil {
			t.Fatal(err)
		}
		entry, err := control.ReadNetBirdState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if sequence <= previous {
			t.Fatalf("journal sequence did not advance: %d <= %d", sequence, previous)
		}
		previous = sequence
		for _, base := range []string{ordinary, secondary} {
			body := request(base, operationPath, token, http.StatusOK)
			var observed netbirdOperationObservation
			if err := json.Unmarshal(body, &observed, json.RejectUnknownMembers(true)); err != nil {
				t.Fatal(err)
			}
			if observed.Cell != "gru" || observed.OperationID != record.ID || observed.Node != record.Node || observed.Phase != record.Phase ||
				!observed.StartedAt.Equal(record.StartedAt) || !observed.Deadline.Equal(record.Deadline) ||
				observed.Commit.MutationOperationID != mutationID || observed.Commit.Sequence != sequence ||
				observed.Commit.Epoch != entry.Epoch || !observed.Commit.RecordedAt.Equal(entry.CreatedAt) {
				t.Fatalf("mounted API lost current committed metadata: %+v", observed)
			}
			for _, forbidden := range []string{"private-", "command", "fence", "reason"} {
				if strings.Contains(string(body), forbidden) {
					t.Fatalf("mounted operation API exposed %q", forbidden)
				}
			}
		}
	}

	// The controller's sampler supplies real broker observations, without
	// injecting samples into the history store or shortening its interval.
	historyPath := "/v1/history?metric=" + observability.HistMembersAnswering + "&range=1m"
	for {
		body := request(ordinary, historyPath, token, http.StatusOK)
		var history observability.HistoryResult
		if err := json.Unmarshal(body, &history); err != nil {
			t.Fatal(err)
		}
		if len(history.Series) == 1 && len(history.Series[0].Points) > 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("actual controller sampler produced no broker history: %s", body)
		case <-time.After(50 * time.Millisecond):
		}
	}
	for _, base := range []string{ordinary, secondary} {
		request(base, historyPath, "", http.StatusUnauthorized)
		body := request(base, historyPath, token, http.StatusOK)
		var history observability.HistoryResult
		if err := json.Unmarshal(body, &history); err != nil || len(history.Series) != 1 || len(history.Series[0].Points) == 0 {
			t.Fatalf("mounted history lost controller samples: %s (%v)", body, err)
		}
		series := history.Series[0]
		last := series.Points[len(series.Points)-1]
		if series.Metric != observability.HistMembersAnswering || last.Value != 1 ||
			last.Time.IsZero() || last.Time.After(time.Now()) || !series.LastObservedAt.Equal(last.Time) {
			t.Fatalf("mounted history changed broker evidence: %+v", series)
		}
	}
}
