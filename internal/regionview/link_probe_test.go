package regionview

import (
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
)

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
				return []LinkProbe{{Region: "sjc", Reach: test.reach, WAN: "failed", Detail: "WAN has conflicts", LastSuccessAt: now}}
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
