package releasepush

import (
	"encoding/json"
	"testing"
)

// ts-dashboard main on 2026-10-26: merges minutes apart failed 5 of 8
// releases with "release superseded during bake" or the floor refusal,
// although the newer run released the service.
func TestSupersededReleasesAreDoneAndRealFailuresAreNot(t *testing.T) {
	rows := func(rows ...map[string]any) json.RawMessage {
		data, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	bake := func(reason string) map[string]any {
		return map[string]any{"error": "x failed", "bake": map[string]any{"reason": reason}}
	}
	for name, test := range map[string]struct {
		result AppResult
		want   bool
	}{
		"older run refused at the floor": {AppResult{State: "failed", Error: "deployment is superseded by a newer signed run"}, true},
		"bake replaced, later regions waited": {AppResult{State: "failed", Error: "ts-auth failed in sjc, gru; succeeded in [fra]", Regions: rows(
			map[string]any{"result": "applied"}, bake("release superseded during bake"),
			map[string]any{"error": "an earlier region failed this rollout: sjc"})}, true},
		"real bake failure":           {AppResult{State: "failed", Error: "ts-auth failed in gru", Regions: rows(bake("bake ts-auth readiness: HTTP 503"))}, false},
		"replaced next to a real one": {AppResult{State: "failed", Regions: rows(bake("release superseded during bake"), map[string]any{"error": "not ready"})}, false},
		"changed approved run":        {AppResult{State: "failed", Error: "deployment changes an already approved run; release from a newer signed run"}, false},
		"only waiting regions":        {AppResult{State: "failed", Regions: rows(map[string]any{"error": "an earlier region failed this rollout: fra"})}, false},
		"no rows":                     {AppResult{State: "failed", Error: "no reply"}, false},
	} {
		if got := superseded(test.result); got != test.want {
			t.Errorf("%s: superseded = %v, want %v", name, got, test.want)
		}
	}
}
