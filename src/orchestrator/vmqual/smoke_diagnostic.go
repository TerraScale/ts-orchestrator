package vmqual

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Capture uses the immutable pre-create resource plan, including when startup
// failed before Inspect could return an observation. Cleanup retains its own
// independent context and proceeds even if either diagnostic cannot be read.
func collectSmokeFailureDiagnostic(ctx context.Context, target failureDiagnosticTarget) (FailureDiagnostic, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	report := FailureDiagnostic{VMID: target.id, Region: target.region, CapturedAt: time.Now().UTC()}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	report.Console, _ = captureFailureDiagnosticArtifact(target.root, target.console)
	report.Metrics, _ = captureFailureDiagnosticArtifact(target.root, target.metrics)
	var captureErr error
	for _, artifact := range []FailureDiagnosticArtifact{report.Console, report.Metrics} {
		if artifact.Observation != "" {
			captureErr = errors.Join(captureErr, fmt.Errorf("vm-smoke: observe %s diagnostic: %s", target.id, artifact.Observation))
		}
	}
	return report, errors.Join(captureErr, ctx.Err())
}

// WriteSmokeFailureDiagnostics emits retained bounded evidence after cleanup.
func WriteSmokeFailureDiagnostics(out io.Writer, report SmokeReport) error {
	if len(report.FailureDiagnostics) == 0 {
		return nil
	}
	return json.NewEncoder(out).Encode(struct {
		Diagnostics []FailureDiagnostic `json:"failureDiagnostics"`
	}{report.FailureDiagnostics})
}
