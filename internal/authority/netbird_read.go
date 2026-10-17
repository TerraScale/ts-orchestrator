package authority

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
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

// NetBirdRead retains only public intent and lease observations. Every Read
// proves coverage against fresh leader counts; the consumed point grants no
// authority and is never persisted or restored as a task store.
type NetBirdRead struct {
	mu                  sync.Mutex
	stream              jetstream.Stream
	consumer            jetstream.Consumer
	scope               string
	nonce               string
	counts              [2]uint64
	delivered, sequence uint64
	lease, intent       *jetstream.RawStreamMsg
	failed              error
	created             time.Time
}

func ConnectNetBirdRead(ctx context.Context, js jetstream.JetStream, scope, nonce string) (*NetBirdRead, error) {
	if js == nil || !natsToken.MatchString(scope) || !entityid.Valid(nonce) {
		return nil, ErrFenced
	}
	stream, err := js.Stream(ctx, ControlStreamName)
	if err != nil {
		return nil, err
	}
	consumer, err := stream.Consumer(ctx, NetBirdReadConsumer)
	if err != nil {
		return nil, err
	}
	info, err := consumer.Info(ctx)
	if err != nil {
		return nil, err
	}
	if err := verifyNetBirdConsumer(info, scope, nonce); err != nil {
		return nil, err
	}
	if info.Delivered.Consumer != 0 {
		return nil, errors.New("NetBird read session has already been consumed")
	}
	return &NetBirdRead{stream: stream, consumer: consumer, scope: scope, nonce: nonce}, nil
}

// Read returns the latest committed intent and actual live lease after proving
// full filtered coverage at one unchanged stream-leader sequence. A partial
// delivery, consumer reset, retention change or lost reply requires a new session.
func (r *NetBirdRead) Read(ctx context.Context) (LogEntry, Snapshot, error) {
	if r == nil || ctx == nil {
		return LogEntry{}, Snapshot{}, ErrFenced
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for range 8 {
		if r.failed != nil {
			return LogEntry{}, Snapshot{}, r.failed
		}
		info, err := r.consumer.Info(ctx)
		if err != nil {
			return LogEntry{}, Snapshot{}, err
		}
		if err := verifyNetBirdConsumer(info, r.scope, r.nonce); err != nil {
			return LogEntry{}, Snapshot{}, err
		}
		if info.Delivered.Consumer != r.delivered {
			r.failed = errors.New("NetBird read cursor moved outside its original session")
			return LogEntry{}, Snapshot{}, r.failed
		}
		counts, head, err := r.currentCounts(ctx)
		if err != nil {
			if errors.Is(err, ErrConflict) {
				continue
			}
			return LogEntry{}, Snapshot{}, err
		}
		if r.counts[0] > counts[0] || r.counts[1] > counts[1] || r.sequence > head {
			return LogEntry{}, Snapshot{}, ErrConflict
		}
		if r.counts != counts {
			if err := r.drain(ctx, counts[0]-r.counts[0]+counts[1]-r.counts[1]); err != nil {
				r.failed = err
				return LogEntry{}, Snapshot{}, err
			}
			continue
		}
		if r.lease == nil || r.intent == nil {
			return LogEntry{}, Snapshot{}, ErrNotFound
		}
		lease, err := decodeLease(r.lease.Data)
		if err != nil || lease.Scope != r.scope {
			return LogEntry{}, Snapshot{}, ErrLeaseCorrupt
		}
		record, err := decodeControlRecord(r.intent.Data)
		if err != nil || record.Scope != r.scope || record.Kind != MutationNetBirdIntent || record.SubjectKey != netbirdIntentKey {
			return LogEntry{}, Snapshot{}, errors.New("NetBird intent record is corrupt")
		}
		expires := r.lease.Time.Add(time.Duration(lease.LeaseDuration))
		if lease.Released || !time.Now().Before(expires) || record.Epoch != lease.Epoch {
			return LogEntry{}, Snapshot{}, ErrFenced
		}
		return LogEntry{Kind: record.Kind, SubjectKey: record.SubjectKey, OperationID: record.OperationID,
				Epoch: record.Epoch, Sequence: r.intent.Sequence, CreatedAt: r.intent.Time, Payload: bytes.Clone(record.Payload)},
			Snapshot{Scope: lease.Scope, DeploymentID: lease.DeploymentID, CandidateID: lease.CandidateID,
				OwnerID: lease.OwnerID, Epoch: lease.Epoch, Revision: r.lease.Sequence, Ready: true,
				ExpiresAt: expires, ObservedAt: time.Now()}, ctx.Err()
	}
	return LogEntry{}, Snapshot{}, ErrConflict
}

func (r *NetBirdRead) currentCounts(ctx context.Context) ([2]uint64, uint64, error) {
	var counts [2]uint64
	var head uint64
	var leader string
	for index, subject := range netBirdReadSubjects(r.scope) {
		info, err := r.stream.Info(ctx, jetstream.WithSubjectFilter(subject))
		if err != nil {
			return counts, 0, err
		}
		if err := verifyControlStreamConfig(info.Config, info.Config.Replicas); err != nil {
			return counts, 0, err
		}
		if info.State.NumDeleted != 0 || info.State.Msgs != info.State.LastSeq ||
			(info.State.Msgs != 0 && info.State.FirstSeq != 1) {
			return counts, 0, errors.New("NetBird current read requires the complete immutable control log")
		}
		actualLeader := ""
		if info.Cluster != nil {
			actualLeader = info.Cluster.Leader
		}
		if info.Config.Replicas > 1 && actualLeader == "" {
			return counts, 0, ErrConflict
		}
		if r.created.IsZero() {
			r.created = info.Created
		}
		if info.Created != r.created {
			return counts, 0, ErrConflict
		}
		if index != 0 && (head != info.State.LastSeq || leader != actualLeader) {
			return counts, 0, ErrConflict
		}
		leader = actualLeader
		head, counts[index] = info.State.LastSeq, info.State.Subjects[subject]
	}
	return counts, head, nil
}

func (r *NetBirdRead) drain(ctx context.Context, remaining uint64) error {
	for remaining > 0 {
		batch, err := r.consumer.FetchNoWait(int(min(remaining, 128)))
		if err != nil {
			return err
		}
		var received uint64
		messages := batch.Messages()
		for messages != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case msg, ok := <-messages:
				if !ok {
					messages = nil
					continue
				}
				metadata, err := msg.Metadata()
				if err != nil || metadata.Stream != ControlStreamName || metadata.Consumer != NetBirdReadConsumer ||
					metadata.NumDelivered != 1 || metadata.Sequence.Consumer != r.delivered+1 || metadata.Sequence.Stream <= r.sequence {
					return errors.New("NetBird filtered read has an incomplete or repeated delivery")
				}
				subjects := netBirdReadSubjects(r.scope)
				index := slices.Index(subjects, msg.Subject())
				if index < 0 {
					return errors.New("NetBird read consumer delivered an unauthorized subject")
				}
				entry := &jetstream.RawStreamMsg{Subject: msg.Subject(), Sequence: metadata.Sequence.Stream,
					Time: metadata.Timestamp, Data: bytes.Clone(msg.Data())}
				if index == 0 {
					r.lease = entry
				} else {
					r.intent = entry
				}
				r.counts[index]++
				r.delivered, r.sequence = metadata.Sequence.Consumer, metadata.Sequence.Stream
				received++
			}
		}
		if err := batch.Error(); err != nil {
			return err
		}
		if received == 0 {
			return ErrConflict
		}
		remaining -= received
	}
	return nil
}
