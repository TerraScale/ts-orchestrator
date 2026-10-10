package regionview

import (
	"context"
	"encoding/json/v2"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlink"
)

func TestProbeRequiresFreshExactRegionReply(t *testing.T) {
	now := time.Now().UTC()
	for name, reply := range map[string]Summary{
		"fresh":         {Version: summaryVersion, Region: "sfo", ObservedAt: now},
		"wrong region":  {Version: summaryVersion, Region: "gru", ObservedAt: now},
		"wrong version": {Version: summaryVersion + 1, Region: "sfo", ObservedAt: now},
		"missing time":  {Version: summaryVersion, Region: "sfo"},
		"stale":         {Version: summaryVersion, Region: "sfo", ObservedAt: now.Add(-3 * time.Minute)},
		"future":        {Version: summaryVersion, Region: "sfo", ObservedAt: now.Add(2 * time.Minute)},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			provider := &Provider{Cell: "gru", Now: func() time.Time { return now }, Links: regionlink.Static{
				LocalRegion: "gru", All: []string{"gru", "sfo"},
				Handler: func(_ context.Context, region, leaf string, payload []byte) ([]byte, error) {
					if region != "sfo" || leaf != SummaryLeaf || string(payload) != string(summaryRequestPayload) {
						t.Fatalf("probe changed the authenticated telemetry contract: %s %s %s", region, leaf, payload)
					}
					calls++
					return json.Marshal(reply)
				},
			}}
			provider.Regions(t.Context())
			result := provider.Probe(t.Context(), "sfo")
			if calls != 2 {
				t.Fatalf("scheduled probe used cached reachability: requests=%d", calls)
			}
			if (result.Reach == decisionlog.RegionOK) != (name == "fresh") {
				t.Fatalf("probe accepted invalid telemetry: %+v", result)
			}
		})
	}
}

func TestProbeReachabilityPreservesAdmissionAndAuthenticatedWAN(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		reach, state, wan string
	}{
		{decisionlog.RegionNotLinked, decisionlog.RegionNotLinked, ""},
		{decisionlog.RegionUnreachable, decisionlog.RegionUnreachable, ""},
		{decisionlog.RegionError, decisionlog.RegionError, ""},
		{"stale", decisionlog.RegionError, ""},
		{decisionlog.RegionOK, decisionlog.RegionOK, "failed"},
	} {
		t.Run(test.reach, func(t *testing.T) {
			provider := &Provider{LinkProbes: func() []LinkProbe {
				return []LinkProbe{{Region: "sfo", Reach: test.reach, WAN: "failed", Detail: "WAN has conflicts", LastSuccessAt: now}}
			}}
			reach := provider.Reachability(t.Context())
			if len(reach) != 1 || reach[0].State != test.state || reach[0].WAN != test.wan || !reach[0].LastSeen.Equal(now) {
				t.Fatalf("probe admission or WAN provenance changed: %+v", reach)
			}
			if (reach[0].Detail != "") != (test.reach == decisionlog.RegionOK) {
				t.Fatalf("unauthenticated request forwarded WAN detail: %+v", reach)
			}
		})
	}
}
