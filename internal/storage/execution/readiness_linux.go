package execution

import (
	"context"

	"github.com/moby/swarmkit/v2/api"
)

func (s *Source) ObserveReadiness(ctx context.Context, task *api.Task) error {
	key, err := TaskSHA256(task)
	if err != nil {
		return err
	}
	s.mu.Lock()
	entry := s.entries[key]
	if entry == nil || entry.revoked {
		s.mu.Unlock()
		return ErrUnsafe
	}
	member := entry.binding.Member
	s.mu.Unlock()
	return member.Readiness(ctx)
}
