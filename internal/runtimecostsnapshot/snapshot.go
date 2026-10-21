// Package runtimecostsnapshot exposes the dashboard's existing regional cost
// observation. Snapshots never authorize spending or price a benchmark window.
package runtimecostsnapshot

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
)

const Path = "/v1/cost"

var ErrPending = errors.New("regional cost observation is pending")

// Snapshot retains the source report's timestamp, including when pricing is
// pending. A missing cost or Cost.Missing leaves its amounts unqualified.
type Snapshot struct {
	SchemaVersion int           `json:"schema_version"`
	Region        string        `json:"region"`
	ObservedAt    time.Time     `json:"observed_at,omitzero"`
	Cost          *ocicost.View `json:"cost"`
}

func (s Snapshot) validate(region string) error {
	if s.SchemaVersion != 1 || s.Region != region {
		return errors.New("cost snapshot schema or region differs")
	}
	if s.Cost == nil {
		if !s.ObservedAt.IsZero() {
			return errors.New("cost snapshot has a timestamp without a source")
		}
		return ErrPending
	}
	if !strings.EqualFold(s.Cost.Cell, region) || !s.ObservedAt.Equal(s.Cost.Forecast.ObservedAt) {
		return errors.New("cost snapshot differs from its source")
	}
	if s.Cost.Missing != "" {
		return ErrPending
	}
	if s.ObservedAt.IsZero() || s.Cost.Forecast.Currency == "" {
		return errors.New("cost snapshot lacks source time or currency")
	}
	return nil
}

// Handler must be mounted behind the same authenticated boundary as /v1/usage.
// Partial observations remain visible with HTTP 200 and never become zero cost.
func Handler(region string, source func(context.Context) *ocicost.View) http.Handler {
	region = strings.ToLower(region)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "cost snapshots are read-only", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		snapshot := Snapshot{SchemaVersion: 1, Region: region}
		if source != nil {
			snapshot.Cost = source(ctx)
		}
		if snapshot.Cost != nil {
			snapshot.ObservedAt = snapshot.Cost.Forecast.ObservedAt
		}
		if err := snapshot.validate(region); err != nil && !errors.Is(err, ErrPending) {
			http.Error(w, "regional cost observation is unavailable", http.StatusServiceUnavailable)
			return
		}
		wire, err := json.Marshal(snapshot)
		if err != nil {
			http.Error(w, "regional cost observation is unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(wire)
	})
}
