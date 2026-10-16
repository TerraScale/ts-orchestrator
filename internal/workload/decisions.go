package workload

import (
	"context"
	"fmt"
	"strconv"

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
)

// recordScale journals one applied autoscaling change. It is called only
// after every desired-state write of the step succeeded, so a step that a
// concurrent release or authority change interrupted is not journaled and the
// next tick records the change it actually applies.
func recordScale(ctx context.Context, cell string, spec ServiceSpec, epoch uint64, decision autoscale.Decision,
	readings []autoscale.Reading, generation uint64,
) {
	if !decision.Changed() {
		return
	}
	kind, verb := decisionlog.KindScaleUp, "up"
	if decision.To < decision.From {
		kind, verb = decisionlog.KindScaleDown, "down"
	}
	var signals []decisionlog.Signal
	if spec.Scaling != nil {
		for _, signal := range spec.Scaling.Signals {
			reading, found := findReading(readings, signal.Name)
			if !found {
				continue
			}
			comparison := "<="
			passed := reading.Value <= signal.Target
			signals = append(signals, decisionlog.Signal{Name: string(signal.Name), Value: reading.Value,
				Comparison: comparison, Threshold: decisionlog.Threshold(signal.Target), Passed: decisionlog.Passed(passed)})
		}
	}
	decisionlog.Record(ctx, decisionlog.Decision{
		Region:  cell,
		Actor:   decisionlog.Actor{Slice: "autoscale"},
		Kind:    kind,
		Subject: decisionlog.Subject{Kind: "service", ID: spec.Role, Name: spec.Environment + "/" + spec.Role},
		Summary: fmt.Sprintf("Scaled %s %s from %d to %d replicas", spec.Role, verb, decision.From, decision.To),
		Reason:  "Autoscaling decision " + decision.Reason + " passed its stabilization window and cooldown.",
		Rule:    "autoscale." + decision.Reason,
		Signals: signals,
		Status:  decisionlog.StatusInProgress,
		Epoch:   epoch,
		Attrs: map[string]string{"from": strconv.Itoa(decision.From), "to": strconv.Itoa(decision.To),
			"recommended": strconv.Itoa(decision.Recommended), "generation": strconv.FormatUint(generation, 10)},
	})
}

func findReading(readings []autoscale.Reading, name autoscale.SignalName) (autoscale.Reading, bool) {
	for _, reading := range readings {
		if reading.Signal == name && reading.Samples > 0 {
			return reading, true
		}
	}
	return autoscale.Reading{}, false
}
