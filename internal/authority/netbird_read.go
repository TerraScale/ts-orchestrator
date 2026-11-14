package authority

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nats.go/jetstream"
)

const NetBirdReadConsumer = "NET_ACCOUNT_READ"

func netBirdReadSubjects(scope string) []string {
	return []string{fmt.Sprintf("%s.%s.lease", controlSubjectRoot, scope),
		mutationSubject(scope, MutationNetBirdIntent, netbirdIntentKey)}
}

// OpenNetBirdRead replaces one bounded, inactive-expiring read cursor. The
// caller is the protected read-open service; manager credentials cannot call
// consumer administration APIs or choose filters, retention, or delivery mode.
func (r *Runtime) OpenNetBirdRead(ctx context.Context, nonce string) error {
	if !entityid.Valid(nonce) || r == nil {
		return ErrFenced
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.Current()
	if !current.CanMutate() {
		return ErrNotLeader
	}
	if err := r.guardLocked(ctx, current.Epoch); err != nil {
		return err
	}
	consumer, err := r.stream.Consumer(ctx, NetBirdReadConsumer)
	if err == nil {
		info, err := consumer.Info(ctx)
		if err != nil {
			return err
		}
		if info.Config.Metadata["terrascale-read-session"] == nonce {
			return verifyNetBirdConsumer(info, r.config.Scope, nonce)
		}
		if err := r.stream.DeleteConsumer(ctx, NetBirdReadConsumer); err != nil {
			return err
		}
	} else if !errors.Is(err, jetstream.ErrConsumerNotFound) {
		return err
	}
	_, err = r.stream.CreateConsumer(ctx, jetstream.ConsumerConfig{
		Name: NetBirdReadConsumer, Durable: NetBirdReadConsumer,
		DeliverPolicy: jetstream.DeliverAllPolicy, AckPolicy: jetstream.AckNonePolicy,
		ReplayPolicy: jetstream.ReplayInstantPolicy, FilterSubjects: netBirdReadSubjects(r.config.Scope),
		Replicas: r.config.Replicas, InactiveThreshold: 2 * time.Minute,
		Metadata: map[string]string{"terrascale-read-session": nonce},
	})
	return err
}

func verifyNetBirdConsumer(info *jetstream.ConsumerInfo, scope, nonce string) error {
	if info == nil {
		return ErrConflict
	}
	cfg := info.Config
	if info.Stream != ControlStreamName || info.Name != NetBirdReadConsumer ||
		cfg.Name != NetBirdReadConsumer || cfg.Durable != NetBirdReadConsumer ||
		cfg.DeliverPolicy != jetstream.DeliverAllPolicy || cfg.AckPolicy != jetstream.AckNonePolicy ||
		cfg.ReplayPolicy != jetstream.ReplayInstantPolicy || cfg.FilterSubject != "" ||
		!slices.Equal(cfg.FilterSubjects, netBirdReadSubjects(scope)) || cfg.HeadersOnly ||
		cfg.InactiveThreshold != 2*time.Minute || cfg.MemoryStorage ||
		(cfg.Replicas != 1 && cfg.Replicas != 3 && cfg.Replicas != 5) ||
		cfg.Metadata["terrascale-read-session"] != nonce || info.Paused {
		return errors.New("NetBird read consumer differs from its fixed source contract")
	}
	return nil
}
