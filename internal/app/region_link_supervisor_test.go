package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/regionlink"
	"github.com/TerraScale/ts-orchestrator/internal/regionview"
)

func wanTestSummary(region string, now time.Time) regionview.Summary {
	return regionview.Summary{Version: 1, Region: region, ObservedAt: now, TerraBase: regionview.TerraBase{NativeRegion: region + "-1"},
		Nodes: []regionview.Node{{Name: region + "-1", Services: []regionview.Service{{Role: "terrabase"}}},
			{Name: region + "-2", Services: []regionview.Service{{Role: "terrabase"}}}}}
}

func TestLinkRecoveryRequiresFreshWANAndPublishesMetrics(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	remote := wanTestSummary("sjc", now)
	recorder := new(linkTestRecorder)
	history := observability.NewHistory(observability.HistoryConfig{})
	provider := &regionview.Provider{Cell: "gru", Now: func() time.Time { return now }, History: history, NativeRegion: func() string { return "gru-1" },
		Nodes: func(context.Context) []regionview.Node { return wanTestSummary("gru", now).Nodes }}
	fail := true
	provider.Links = regionlink.Static{LocalRegion: "gru", All: []string{"gru", "sjc"},
		Handler: func(context.Context, string, string, []byte) ([]byte, error) {
			if fail {
				return nil, context.DeadlineExceeded
			}
			remote.ObservedAt = now
			return json.Marshal(remote)
		}}
	supervisor := &regionLinkSupervisor{cell: "gru", member: "a", source: provider, recorder: recorder,
		now: func() time.Time { return now }, reconnect: func(context.Context) (int, error) { return 1, nil }}
	supervisor.round(t.Context())
	failure := supervisor.failures["sjc"]
	fail = false
	now = now.Add(time.Minute)
	supervisor.round(t.Context())
	if supervisor.failures["sjc"] != failure || !supervisor.snapshot()[0].LastSuccessAt.IsZero() {
		t.Fatal("successful NATS with missing WAN claimed recovery")
	}
	for _, node := range remote.Nodes {
		remote.TerraBase.WAN = append(remote.TerraBase.WAN, regionview.WANPeer{SourceRegion: "gru-1",
			Node: node.Name, ObservedAt: now, Members: 2, StalenessSeconds: 1})
	}
	supervisor.round(t.Context())
	if supervisor.failures["sjc"] != "" || !supervisor.snapshot()[0].LastSuccessAt.Equal(now) {
		t.Fatal("fresh authenticated telemetry and complete WAN did not recover")
	}
	last := recorder.decisions[len(recorder.decisions)-1]
	if last.Kind != "region_link_recovered" || last.ParentID != failure || last.Status != decisionlog.StatusSucceeded {
		t.Fatalf("recovery has no causal journal chain: %+v", last)
	}
	var metrics bytes.Buffer
	supervisor.writeMetrics(&metrics)
	for _, want := range []string{`ts_orch_region_link_probe_success{peer="sjc",member="a"} 1`,
		`ts_orch_region_wan_healthy{peer="sjc",member="a"} 1`, `ts_orch_region_wan_lag_groups{peer="sjc",member="a"} 0`} {
		if !strings.Contains(metrics.String(), want) {
			t.Fatalf("metrics omit %q: %s", want, &metrics)
		}
	}
	now = now.Add(3 * time.Minute)
	metrics.Reset()
	supervisor.writeMetrics(&metrics)
	if strings.Contains(metrics.String(), "ts_orch_region_wan_lag_groups{") ||
		!strings.Contains(metrics.String(), `ts_orch_region_link_probe_success{peer="sjc",member="a"} 0`) {
		t.Fatalf("stopped probe metrics retained health: %s", &metrics)
	}
}

type linkTestRecorder struct {
	mu        sync.Mutex
	decisions []decisionlog.Decision
}

func (recorder *linkTestRecorder) Record(_ context.Context, decision decisionlog.Decision) string {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	decision.ID = decisionlog.NewID()
	recorder.decisions = append(recorder.decisions, decision)
	return decision.ID
}
