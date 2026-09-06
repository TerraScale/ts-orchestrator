package main

import (
	"context"
	"errors"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
)

// Observe implements the autoscale observation boundary over the same
// authenticated host reports used by regional health. Resource pressure is
// never inferred from health or disk facts; reports without the typed metrics
// are unavailable and therefore hold the durable target.
func (s *observedKVHealthSource) Observe(ctx context.Context, region string) ([]autoscale.Observation, error) {
	if s == nil || ctx == nil || region == "" {
		return nil, autoscale.ErrUnavailable
	}
	config, err := s.configuration()
	if err != nil {
		return nil, err
	}
	for _, entry := range config.Regions {
		if entry.Code != region {
			continue
		}
		reports, err := s.sample(ctx, entry)
		if err != nil {
			return nil, err
		}
		result := make([]autoscale.Observation, 0, len(reports))
		for _, report := range reports {
			engine := report.Facts.Engine
			metrics := report.Facts.Metrics
			if !engine.Measured || !engine.Serving || report.State != hostagent.NodeStateServing || report.Quiesced || metrics.ObservationSequence <= 0 {
				return nil, autoscale.ErrUnavailable
			}
			result = append(result, autoscale.Observation{
				HostID: report.NodeId, EngineID: report.NodeId, Sequence: metrics.ObservationSequence,
				ObservedAt: time.UnixMilli(metrics.ObservedAtUnixMS), CPUPercent: metrics.CPUPercent,
				MemoryPercent: metrics.MemoryPercent, QueueDepth: metrics.QueueDepth,
				QueueCapacity: metrics.QueueCapacity, Healthy: true, Authenticated: true,
			})
		}
		if len(result) != len(entry.Members) {
			return nil, autoscale.ErrUnavailable
		}
		return result, nil
	}
	return nil, errors.New("autoscale: region is not admitted")
}
