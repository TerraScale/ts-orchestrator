package releasepush

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/releasegate"
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

func WriteReleaseMetrics(w io.Writer, state, binary string) {
	releasegate.WriteBlockedMetrics(w, releasegate.Receiver)
	admission, admissionErr := ReadAdmission(state, binary)
	if admissionErr != nil {
		slog.Warn("release admission record unreadable", "error", admissionErr)
	}
	if admission != nil && admission.RunID != "" {
		observability.WriteGauge(w, observability.Series("ts_orch_release_staging_admission", "region", admission.Region, "reason", "admitted_without_staging", "run", admission.RunID, "tag", admission.Tag), 1)
	}
	record, err := ReadDegraded(state)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("release degraded record unreadable", "error", err)
	}
	installed, channel, err := releaseSeqs(state, binary)
	if err != nil {
		slog.Warn("release seq records unreadable", "error", err)
	}
	observability.WriteGauge(w, "ts_orch_release_installed_seq", float64(installed))
	if channel != 0 {
		observability.WriteGauge(w, "ts_orch_release_channel_seq", float64(channel))
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
