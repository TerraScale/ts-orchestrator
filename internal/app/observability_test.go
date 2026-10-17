package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/regionview"
)

func TestSignedObservabilityStaysOnLoopbackOrBrokerAddress(t *testing.T) {
	t.Parallel()
	base := Config{NATS: natscell.Config{Embedded: &natscell.Embedded{Host: "10.0.1.5"}}}
	for name, settings := range map[string]observability.Config{
		"default": {},
		"broker": {ListenAddress: "10.0.1.5:9464",
			BearerTokenFile: "/etc/terrascale-orchestrator/observability-token"},
	} {
		cfg := base
		cfg.Observability = settings
		if err := validateSignedObservability(cfg); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, settings := range map[string]observability.Config{
		"off switch": {ListenAddress: "off"},
		"other private address": {ListenAddress: "10.0.1.6:9464",
			BearerTokenFile: "/etc/terrascale-orchestrator/observability-token"},
		"wildcard":          {ListenAddress: "0.0.0.0:9464"},
		"no token":          {ListenAddress: "10.0.1.5:9464"},
		"token outside":     {ListenAddress: "10.0.1.5:9464", BearerTokenFile: "/tmp/token"},
		"token traversal":   {ListenAddress: "10.0.1.5:9464", BearerTokenFile: "/etc/terrascale-orchestrator/../shadow"},
		"invalid log level": {LogLevel: "trace"},
	} {
		cfg := base
		cfg.Observability = settings
		if err := validateSignedObservability(cfg); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestLoadConfigRejectsPublicObservabilityListener(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"version":2,"nats":{"cell":"lab"},"observability":{"listen_address":"8.8.8.8:9464"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "observability") {
		t.Fatalf("LoadConfig() error = %v", err)
	}
}

func TestLoadConfigRejectsObservabilitySwitches(t *testing.T) {
	t.Parallel()
	for _, version := range []int{0, ConfigVersion, ConfigVersion + 1} {
		for _, settings := range []string{
			`{"cluster_aggregation":false}`, `{"cluster_aggregation":true}`,
			`{"dashboard":false}`, `{"dashboard":true}`, `{"listen_address":"off"}`,
		} {
			path := filepath.Join(t.TempDir(), "config.json")
			wire := fmt.Sprintf(`{"version":%d,"observability":%s}`, version, settings)
			if err := os.WriteFile(path, []byte(wire), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Errorf("observability switch accepted: %s", wire)
			}
		}
	}
}

type observedAuthority struct{ snapshot authority.Snapshot }

func (fencer observedAuthority) Current() authority.Snapshot  { return fencer.snapshot }
func (observedAuthority) Guard(context.Context, uint64) error { return nil }

func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

// The controller wiring must expose readiness, metrics, its own snapshot and
// a cell-wide view through the private listener, plus broker decision and
// region queries, with the default observability settings.
func TestControllerObservabilityServesSnapshotAndCluster(t *testing.T) {
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	auth := newAuthenticatedNATS(t, "lab")
	nats, err := auth.start(t, ctx, natscell.Config{Cell: "lab", Instance: "one", Replicas: 1,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "js")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nats.Close() })
	address := freeLoopbackAddress(t)
	token := strings.Repeat("o", 40)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{NATS: natscell.Config{Cell: "lab", Instance: "one"},
		Observability: observability.Config{ListenAddress: address, BearerTokenFile: tokenFile, LogFormat: "logfmt"}}
	telemetry, err := startRuntimeObservability(ctx, cfg, "controller", "one")
	if err != nil {
		t.Fatal(err)
	}
	if telemetry.server == nil {
		t.Skipf("loopback port %s was taken before the listener bound", address)
	}
	t.Cleanup(telemetry.close)
	get := func(path string) (int, string) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}
	if status, body := get("/readyz"); status != http.StatusServiceUnavailable || !strings.Contains(body, "startup failing") {
		t.Fatalf("/readyz before startup = %d %q", status, body)
	}
	lease := observedAuthority{snapshot: authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Leader: true, Ready: true, Epoch: 3, Revision: 8,
		ExpiresAt: time.Now().Add(time.Minute)}}
	probeTime := time.Now().UTC().Add(-time.Minute)
	if err := telemetry.attachController(ctx, controllerObservation{nats: nats, replicas: 1,
		brokerIDs: []string{"one", "two"}, authority: lease, linkProbes: func() []regionview.LinkProbe {
			return []regionview.LinkProbe{{Region: "sfo", ObservedAt: probeTime, Reach: "not_linked", WAN: "unknown", Detail: "private-probe-detail"}}
		}}, nil); err != nil {
		t.Fatal(err)
	}
	telemetry.markStarted()
	if status, body := get("/readyz"); status != http.StatusOK {
		t.Fatalf("/readyz after startup = %d %q", status, body)
	}
	status, metrics := get("/metrics")
	if status != http.StatusOK || !strings.Contains(metrics, "ts_orch_authority_epoch 3") ||
		!strings.Contains(metrics, "ts_orch_js_meta_leader 1") || !strings.Contains(metrics, "go_goroutines") {
		t.Fatalf("/metrics = %d\n%s", status, metrics)
	}
	status, body := get("/v1/snapshot")
	var snapshot observability.MemberSnapshot
	if err := json.Unmarshal([]byte(body), &snapshot); err != nil || status != http.StatusOK ||
		snapshot.Member != "one" || snapshot.Authority == nil || !snapshot.Authority.CanMutate || snapshot.NATS == nil {
		t.Fatalf("/v1/snapshot = %d %s (%v)", status, body, err)
	}
	status, body = get("/v1/cluster")
	var cluster observability.ClusterSnapshot
	if err := json.Unmarshal([]byte(body), &cluster); err != nil || status != http.StatusOK ||
		len(cluster.Members) != 1 || cluster.Members[0].Member != "one" ||
		len(cluster.Missing) != 1 || cluster.Missing[0] != "two" {
		t.Fatalf("/v1/cluster = %d %s (%v)", status, body, err)
	}
	if len(cluster.Members[0].Links) != 1 || !cluster.Members[0].Links[0].ObservedAt.Equal(probeTime) ||
		strings.Contains(body, "private-probe-detail") {
		t.Fatalf("authenticated cluster snapshot lost or exposed probe evidence: %s", body)
	}
	if status, body = get("/members"); status != http.StatusOK || !strings.Contains(body, ">one</a></td>") {
		t.Fatalf("default dashboard /members = %d %s", status, body)
	}
	slog.Warn("synthetic warning", observability.ComponentKey, "test")
	status, body = get("/v1/events")
	if status != http.StatusOK || !strings.Contains(body, "synthetic warning") {
		t.Fatalf("/v1/events = %d %s", status, body)
	}

	// The decision journal records the lease this member holds, stores it
	// in the regional stream and serves it with the other journal providers.
	deadline := time.Now().Add(20 * time.Second)
	var decisions decisionlog.Result
	for {
		// The authority lease; the JetStream meta election is journaled too.
		status, body = get("/v1/decisions?kind=leader_changed&subject_kind=member&since=1h")
		decisions = decisionlog.Result{}
		_ = json.Unmarshal([]byte(body), &decisions)
		if status == http.StatusOK && len(decisions.Decisions) == 1 && telemetry.journal.Stats().Published > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("/v1/decisions = %d %s stats=%+v", status, body, telemetry.journal.Stats())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if leader := decisions.Decisions[0]; leader.Region != "lab" || leader.Epoch != 3 || leader.Actor.Member != "one" {
		t.Fatalf("leader decision = %+v", leader)
	}
	subject, err := protocol.ObservabilitySubject("lab", decisionlog.QueryLeaf)
	if err != nil {
		t.Fatal(err)
	}
	query, err := nats.Conn().RequestWithContext(ctx, subject,
		[]byte(`{"version":1,"query":{"kinds":["leader_changed"],"subject_kind":"member"}}`))
	if err != nil {
		t.Fatalf("default decision query responder: %v", err)
	}
	var reply struct {
		Version int                `json:"version"`
		Region  string             `json:"region"`
		Result  decisionlog.Result `json:"result"`
	}
	if err := json.Unmarshal(query.Data, &reply); err != nil || reply.Version != 1 || reply.Region != "lab" ||
		len(reply.Result.Decisions) != 1 || reply.Result.Decisions[0].ID != decisions.Decisions[0].ID {
		t.Fatalf("broker decision query = %s (%v)", query.Data, err)
	}
	if status, body = get("/v1/decisions/" + decisions.Decisions[0].ID); status != http.StatusOK ||
		!strings.Contains(body, decisions.Decisions[0].ID) {
		t.Fatalf("/v1/decisions/{id} = %d %s", status, body)
	}
	if status, _ = get("/v1/decisions?since=yesterday"); status != http.StatusBadRequest {
		t.Fatalf("bad since = %d", status)
	}
	status, body = get("/v1/regions")
	var regions []globalview.Region
	if err := json.Unmarshal([]byte(body), &regions); err != nil || status != http.StatusOK || len(regions) != 1 ||
		regions[0].Cell != "lab" || regions[0].Rollup == nil || regions[0].Rollup.Controllers.Leader != "one" {
		t.Fatalf("/v1/regions = %d %s (%v)", status, body, err)
	}
	subject, err = protocol.ObservabilitySubject("lab", regionview.SummaryLeaf)
	if err != nil {
		t.Fatal(err)
	}
	region, err := nats.Conn().RequestWithContext(ctx, subject, []byte(`{"version":1}`))
	if err != nil {
		t.Fatalf("default region summary responder: %v", err)
	}
	var summary regionview.Summary
	if err := json.Unmarshal(region.Data, &summary); err != nil || summary.Region != "lab" ||
		summary.Leaders.Authority != "one" {
		t.Fatalf("broker region summary = %s (%v)", region.Data, err)
	}
	if status, body = get("/v1/insights"); status != http.StatusOK || !strings.Contains(body, `"insights"`) {
		t.Fatalf("/v1/insights = %d %s", status, body)
	}
	if status, body = get("/v1/summary?window=24h"); status != http.StatusOK ||
		!strings.Contains(body, "leader change") {
		t.Fatalf("/v1/summary = %d %s", status, body)
	}
	for {
		status, body = get("/v1/history/metrics")
		if status == http.StatusOK && strings.Contains(body, observability.HistMembersAnswering) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("/v1/history/metrics = %d %s", status, body)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if status, body = get("/v1/history?metric=" + observability.HistMembersAnswering + "&range=15m"); status != http.StatusOK ||
		!strings.Contains(body, `"points"`) {
		t.Fatalf("/v1/history = %d %s", status, body)
	}
	if !strings.Contains(metricsText(get), "ts_orch_decisions_recorded_total") {
		t.Fatal("decision journal metrics are not registered")
	}
}

func metricsText(get func(string) (int, string)) string {
	_, body := get("/metrics")
	return body
}
