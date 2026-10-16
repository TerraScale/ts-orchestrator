package insights

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
)

func TestRegionWANFailurePersistsAndRecovers(t *testing.T) {
	now := time.Now().UTC()
	inputs := &Inputs{Now: now, Thresholds: (Thresholds{}).withDefaults(),
		Reachability: []RegionReach{{Region: "sfo", State: decisionlog.RegionOK, WAN: "failed", Detail: "WAN has conflicts"}},
		conditions:   map[string]time.Time{}, touched: map[string]struct{}{}}
	if got := regionUnreachable(inputs); len(got) != 0 {
		t.Fatal("WAN insight skipped its persistence window")
	}
	inputs.Now = now.Add(2 * time.Minute)
	got := regionUnreachable(inputs)
	if len(got) != 1 || !strings.Contains(got[0].Title, "TerraBase WAN") || got[0].Why != "WAN has conflicts" ||
		got[0].Evidence[0].Label != "Unhealthy for" {
		t.Fatalf("WAN failure was hidden or described as missing NATS: %+v", got)
	}
	inputs.Reachability[0].WAN = "ok"
	if got := regionUnreachable(inputs); len(got) != 0 {
		t.Fatalf("healthy link retained a WAN insight: %+v", got)
	}
}

func TestRegionWANTransientStatesDoNotRaiseCriticalInsights(t *testing.T) {
	now := time.Now().UTC()
	for _, reach := range []RegionReach{
		{Region: "sfo", State: decisionlog.RegionOK, WAN: "unknown"},
		{Region: "sfo", State: decisionlog.RegionOK, WAN: "catching_up"},
		{Region: "sfo", State: decisionlog.RegionOK, WAN: "ok"},
		{Region: "sfo", State: decisionlog.RegionNotLinked, WAN: "failed"},
	} {
		inputs := &Inputs{Now: now, Thresholds: (Thresholds{}).withDefaults(), Reachability: []RegionReach{reach},
			conditions: map[string]time.Time{"region:sfo": now.Add(-10 * time.Minute), "region-wan:sfo": now.Add(-10 * time.Minute)},
			touched:    map[string]struct{}{}}
		if got := regionUnreachable(inputs); len(got) != 0 {
			t.Fatalf("unobserved or normal replication became critical: %+v => %+v", reach, got)
		}
	}
}

type regionLinkInsightSource []RegionReach

func (source regionLinkInsightSource) Reachability(context.Context) []RegionReach { return source }

func TestRegionFailureTimersTrackCurrentCause(t *testing.T) {
	unreachable := RegionReach{Region: "sfo", State: decisionlog.RegionUnreachable}
	wanFailed := RegionReach{Region: "sfo", State: decisionlog.RegionOK, WAN: "failed", Detail: "WAN has conflicts"}
	for _, first := range []RegionReach{unreachable, wanFailed} {
		t.Run(first.State, func(t *testing.T) {
			now := time.Now().UTC()
			source := regionLinkInsightSource{first}
			engine := NewEngine(Config{Region: "gru", Reachability: source, Now: func() time.Time { return now },
				Rules: []Rule{{Name: "region_unreachable", Evaluate: regionUnreachable}}})
			engine.Evaluate(t.Context())
			now = now.Add(10 * time.Minute)
			if got := engine.Evaluate(t.Context()).Insights; len(got) != 1 || got[0].Evidence[0].Value != 600 {
				t.Fatalf("initial cause lost its duration: %+v", got)
			}
			source[0] = wanFailed
			if first.State == decisionlog.RegionOK {
				source[0] = unreachable
			}
			if got := engine.Evaluate(t.Context()).Insights; len(got) != 0 {
				t.Fatalf("new cause inherited the prior cause's timer: %+v", got)
			}
			now = now.Add(time.Minute)
			if got := engine.Evaluate(t.Context()).Insights; len(got) != 1 || got[0].Evidence[0].Value != 60 || got[0].Score != 60 {
				t.Fatalf("new cause has the wrong duration: %+v", got)
			}
			source[0] = first
			if got := engine.Evaluate(t.Context()).Insights; len(got) != 0 {
				t.Fatalf("reappearing cause retained an inactive timer: %+v", got)
			}
		})
	}
}
