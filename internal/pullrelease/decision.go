package pullrelease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/nats-io/nats.go/jetstream"
)

type tagDecision struct {
	Admitted []string `json:"admitted,omitempty"`
	Failed   string   `json:"failed,omitempty"`
}

func (s *Store) decide(ctx context.Context, tag string, change func(*tagDecision) (string, bool)) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, askWait)
	defer cancel()
	key := "decision." + tag
	for {
		var decision tagDecision
		var revision uint64
		entry, err := s.kv.Get(ctx, key)
		switch {
		case errors.Is(err, jetstream.ErrKeyNotFound):
		case err != nil:
			return "", err
		default:
			if err := json.Unmarshal(entry.Value(), &decision); err != nil {
				return "", fmt.Errorf("rollout decision of %s damaged: %w", tag, err)
			}
			revision = entry.Revision()
		}
		reason, write := change(&decision)
		if !write {
			return reason, nil
		}
		data, err := json.Marshal(decision)
		if err != nil {
			return "", err
		}
		if revision == 0 {
			_, err = s.kv.Create(ctx, key, data)
		} else {
			_, err = s.kv.Update(ctx, key, data, revision)
		}
		if !errors.Is(err, jetstream.ErrKeyExists) {
			return reason, err
		}
	}
}

func (s *Store) failed(ctx context.Context, tag string) (string, error) {
	return s.decide(ctx, tag, func(decision *tagDecision) (string, bool) {
		if decision.Failed == "" {
			return "", false
		}
		return decision.Failed + ": failed the gate of " + tag + "; regions that have not started it hold it", false
	})
}

func (s *Store) admit(ctx context.Context, tag, region string) (string, error) {
	return s.decide(ctx, tag, func(decision *tagDecision) (string, bool) {
		switch {
		case slices.Contains(decision.Admitted, region):
			return "", false
		case decision.Failed != "":
			return decision.Failed + ": failed the gate of " + tag + "; regions that have not started it hold it", false
		}
		decision.Admitted = append(decision.Admitted, region)
		return "", true
	})
}

func (s *Store) fail(ctx context.Context, tag, region string) error {
	_, err := s.decide(ctx, tag, func(decision *tagDecision) (string, bool) {
		if decision.Failed != "" {
			return "", false
		}
		decision.Failed = region
		return "", true
	})
	return err
}

func (u *Updater) recordFailure(ctx context.Context) {
	tag := u.status.Target.Tag()
	if u.failed == tag {
		return
	}
	if err := u.store.fail(ctx, tag, u.Region); err != nil {
		slog.WarnContext(ctx, "gate failure not recorded in the rollout decision yet", "region", u.Region, "release", tag, "error", err)
		return
	}
	u.failed = tag
}
