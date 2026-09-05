package vmqual

import (
	"context"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

// NewCleanupProbeStack admits one GRU service guest under its own durable run
// journal. It shares ownership validation with the six-guest qualification
// stack without relaxing the baseline topology constructor.
func NewCleanupProbeStack(config StackConfig) (*Stack, error) {
	if len(config.Guests) != 1 || config.Guests[0].Region != vmnet.GRU || !config.Guests[0].Control || config.JournalPath == "" || config.ResourceRoot == "" {
		return nil, errors.New("vmqual: cleanup probe requires one GRU control/service guest and owned journal roots")
	}
	return newStack(config, true)
}

func (s *Stack) StartCleanupProbe(ctx context.Context) error {
	if s == nil || !s.cleanupProbe {
		return errors.New("vmqual: cleanup probe stack is required")
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if err := s.initializeRun(ctx); err != nil {
		return err
	}
	if err := s.startSelectedGuests(ctx, map[vmnet.RegionCode]bool{vmnet.GRU: true}); err != nil {
		return err
	}
	s.mu.Lock()
	s.started = true
	s.mu.Unlock()
	return nil
}

// ReleaseCleanupProbeJournal models loss of the controller's journal lease.
// Only a dedicated fault-probe stack may abandon this lock without cleanup.
func (s *Stack) ReleaseCleanupProbeJournal() error {
	if s == nil || !s.cleanupProbe {
		return errors.New("vmqual: cleanup probe stack is required")
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.releaseJournalLock()
	return nil
}
