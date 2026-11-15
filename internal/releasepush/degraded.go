package releasepush

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

type SkippedWorker struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
}

type Degraded struct {
	SHA     string          `json:"sha"`
	RunID   string          `json:"run_id"`
	Skipped []SkippedWorker `json:"skipped"`
	At      time.Time       `json:"at"`
}

func degradedFile(state string) string { return filepath.Join(state, "nats", "release-degraded.json") }

func ReadDegraded(state string) (*Degraded, error) {
	var record Degraded
	present, err := readRecord(degradedFile(state), &record)
	if !present {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &record, nil
}

func (h *Handler) recordDegraded(admitted admission, skipped []HostVersion) {
	if len(skipped) == 0 {
		if err := removeIfExists(h.DegradedFile); err != nil {
			slog.Warn("release degraded record not cleared", "error", err)
		}
		return
	}
	record := Degraded{SHA: admitted.release.SHA, RunID: admitted.claims.RunID, At: time.Now().UTC()}
	for _, worker := range skipped {
		record.Skipped = append(record.Skipped, SkippedWorker{Host: worker.Host, Reason: worker.Error})
		slog.Error("release region degraded: a down worker was skipped and the manager installs anyway",
			"worker", worker.Host, "sha", admitted.release.SHA, "run", admitted.claims.RunID, "reason", worker.Error)
	}
	if err := writeJSON(h.DegradedFile, record); err != nil {
		slog.Error("release degraded record not saved", "error", err)
	}
}

func WriteReleaseMetrics(w io.Writer, state string) {
	record, err := ReadDegraded(state)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("release degraded record unreadable", "error", err)
	}
	degraded := record != nil && len(record.Skipped) != 0
	observability.WriteGauge(w, "ts_orch_release_region_degraded", observability.Bool(degraded))
	if !degraded {
		return
	}
	for _, worker := range record.Skipped {
		observability.WriteGauge(w, observability.Series("ts_orch_release_worker_skipped", "host", worker.Host, "sha", record.SHA, "run", record.RunID), 1)
	}
}
