package selfheal

import (
	"cmp"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func (s Status) Lines() []string {
	if s.Error != "" {
		return []string{"self-heal: observes nothing: " + s.Error}
	}
	line := fmt.Sprintf("self-heal: %d healthy, %d booting, %d unhealthy", s.Healthy, s.Booting, len(s.Unhealthy))
	if s.Blocked != "" {
		line += "; would refuse to act: " + s.Blocked
	}
	out := []string{line}
	for _, node := range s.Unhealthy {
		out = append(out, "self-heal unhealthy "+node)
	}
	if r := s.Repair; r != nil {
		out = append(out, fmt.Sprintf("self-heal repair: %s step %s since %s (started %s: %s)", r.Host, r.Step, stamp(r.StepAt), stamp(r.Started), r.Reason))
	}
	if r := s.Last; r != nil {
		out = append(out, fmt.Sprintf("self-heal last repair: %s %s at %s (started %s: %s)", r.Host, r.Outcome, stamp(r.Finished), stamp(r.Started), r.Reason))
	}
	return out
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func WriteMetrics(w io.Writer) {
	healers.Range(func(_, value any) bool {
		h := value.(*Healer)
		leading := h.leading()
		h.mu.Lock()
		defer h.mu.Unlock()
		if leading {
			observability.WriteGauge(w, observability.Series("ts_orch_self_heal_unhealthy_nodes", "region", h.region), float64(len(h.status.Unhealthy)))
			observability.WriteGauge(w, observability.Series("ts_orch_self_heal_stopped", "region", h.region), observability.Bool(h.status.Stopped != ""))
		}
		repairs := slices.SortedFunc(maps.Keys(h.repairs), func(a, b [2]string) int { return cmp.Compare(strings.Join(a[:], " "), strings.Join(b[:], " ")) })
		for _, key := range repairs {
			observability.WriteCounter(w, observability.Series("ts_orch_self_heal_repairs_total", "region", h.region, "step", key[0], "result", key[1]), float64(h.repairs[key]))
		}
		for _, reason := range slices.Sorted(maps.Keys(h.refusals)) {
			observability.WriteCounter(w, observability.Series("ts_orch_self_heal_refusals_total", "region", h.region, "reason", reason), float64(h.refusals[reason]))
		}
		return true
	})
}
