package host

import (
	"context"
	"encoding/json/v2"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

// UsageObservations returns the retained hour of committed observations for
// this controller's existing regional host journal, including after restart.
func (c *Controller) UsageObservations(ctx context.Context) ([]CommittedUsage, error) {
	if c == nil || c.controlLog == nil {
		return nil, errors.New("committed host usage history is unavailable")
	}
	if err := c.lockControlLog(ctx); err != nil {
		return nil, err
	}
	defer func() { <-c.controlLogInfoGate }()
	info, err := c.controlLog.Info(ctx)
	if err != nil {
		return nil, err
	}
	entries, err := c.usageHistory.UsageWindow(ctx, c.controlLog, c.cell, info.State.LastSeq)
	if err != nil && !errors.Is(err, authority.ErrUsageHistoryTruncated) {
		return nil, err
	}
	result := make([]CommittedUsage, 0, len(entries))
	points := make(map[uint64]CommittedUsage, len(entries))
	for _, entry := range entries {
		var observation UsageObservation
		if err := json.Unmarshal(entry.Payload, &observation, json.RejectUnknownMembers(true)); err != nil {
			return nil, err
		}
		if err := validateUsageObservation(observation, c.cell); err != nil {
			return nil, err
		}
		if entry.Kind != authority.MutationUsageObservation || entry.Epoch != observation.Epoch ||
			entry.SubjectKey != registrationSubjectKey(c.cell, observation.Registration.Node) ||
			observation.PriorSequence >= entry.Sequence || observation.CoveredSequence >= entry.Sequence || entry.CreatedAt.IsZero() {
			return nil, errors.New("committed usage history differs from its host, epoch or predecessor")
		}
		if observation.CoveredSequence != 0 {
			first, firstOK := points[observation.PreviousSequence]
			last, lastOK := points[observation.CoveredSequence]
			if observation.CoveredSequence != observation.PriorSequence || firstOK && lastOK &&
				(first.Entry.SubjectKey != entry.SubjectKey || last.Entry.SubjectKey != entry.SubjectKey ||
					last.Observation.PriorSequence != first.Entry.Sequence || !sameUsageAllocation(first.Observation, last.Observation) ||
					!sameUsageAllocation(last.Observation, observation) || first.Observation.Source.Version > last.Observation.Source.Version ||
					last.Observation.Source.Version > observation.Source.Version || !first.Entry.CreatedAt.Before(last.Entry.CreatedAt) || !last.Entry.CreatedAt.Before(entry.CreatedAt)) {
				return nil, errors.New("committed usage coverage differs from its authenticated point records")
			}
		}
		value := CommittedUsage{Observation: observation, Entry: entry}
		points[entry.Sequence] = value
		result = append(result, value)
	}
	return result, err
}
