package execution

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"

	"github.com/moby/swarmkit/v2/api"
)

func (s *Source) ObserveReadiness(ctx context.Context, task *api.Task) error {
	key, err := TaskSHA256(task)
	if err != nil {
		return errors.Join(memberstatus.ErrReadinessUnobserved, err)
	}
	s.mu.Lock()
	entry := s.entries[key]
	if entry == nil || entry.revoked {
		s.mu.Unlock()
		return errors.Join(memberstatus.ErrReadinessUnobserved, ErrUnsafe)
	}
	member := entry.binding.Member
	s.mu.Unlock()
	return member.Readiness(ctx)
}
