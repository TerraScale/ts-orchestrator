// Package runtimecostsnapshot exposes the dashboard's existing regional cost
// observation. Snapshots never authorize spending or price a benchmark window.
package runtimecostsnapshot

import (
	"errors"
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
