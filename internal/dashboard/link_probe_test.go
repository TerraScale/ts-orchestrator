package dashboard

import (
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionview"
)

func TestRegionLinkTableShowsDirectionUnitsAndUnknowns(t *testing.T) {
	t.Parallel()
	body := renderHTML(t, regionLinkProbes(regionview.Summary{Region: "gru", Links: []regionview.LinkProbe{
		{Region: "sfo", Reach: "ok", WAN: "catching_up", Lag: new(7.0), RoundTripMS: 150, ObservedAt: time.Now().UTC(),
			Detail: "WAN has unapplied change groups", Recovery: "awaiting a fresh authenticated probe"},
		{Region: "fra", Reach: "stale", WAN: "unknown", Detail: "scheduled probe is overdue"},
	}}))
	for _, want := range []string{"SFO", "FRA", "tested every minute", "150.0 ms", "lag 7 change groups", "catching_up",
		"unknown", "scheduled probe is overdue", "awaiting a fresh authenticated probe"} {
		if !strings.Contains(body, want) {
			t.Fatalf("link table omits %q: %s", want, body)
		}
	}
	if strings.Contains(body, "lag 0 change groups") {
		t.Fatal("missing WAN appeared as observed zero")
	}
}
