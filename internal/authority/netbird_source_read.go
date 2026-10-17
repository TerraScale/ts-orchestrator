package authority

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	NetBirdServiceSetReadConsumer = "NET_SERVICE_SET_READ"
	NetBirdTrustRootReadConsumer  = "NET_TRUST_ROOT_READ"
)

type netBirdPublicSource struct{ stream, subject, consumer string }

var netBirdPublicSources = [...]netBirdPublicSource{
	{"KV_TS_SERVICE_SET", "$KV.TS_SERVICE_SET.current", NetBirdServiceSetReadConsumer},
	{"KV_TS_TRUST_ROOTS", "$KV.TS_TRUST_ROOTS.chain", NetBirdTrustRootReadConsumer},
}

// OpenNetBirdSourceRead exposes only the two public keys, never other bucket values.
func (r *Runtime) OpenNetBirdSourceRead(ctx context.Context, nonce string) error {
	if r == nil || !entityid.Valid(nonce) {
		return ErrFenced
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.Current()
	if !current.CanMutate() {
		return ErrNotLeader
	}
	if r.config.Replicas != 3 {
		return ErrFenced
	}
	if err := r.guardLocked(ctx, current.Epoch); err != nil {
		return err
	}
	for _, source := range netBirdPublicSources {
		stream, err := r.js.Stream(ctx, source.stream)
		if err != nil {
			return err
		}
		consumer, err := stream.Consumer(ctx, source.consumer)
		if err == nil {
			info, err := consumer.Info(ctx)
			if err != nil {
				return err
			}
			if info.Config.Metadata["terrascale-read-session"] == nonce {
				if err := verifyNetBirdSourceConsumer(info, source, nonce); err != nil {
					return err
				}
				continue
			}
			if err := stream.DeleteConsumer(ctx, source.consumer); err != nil {
				return err
			}
		} else if !errors.Is(err, jetstream.ErrConsumerNotFound) {
			return err
		}
		_, err = stream.CreateConsumer(ctx, jetstream.ConsumerConfig{
			Name: source.consumer, Durable: source.consumer, FilterSubject: source.subject,
			DeliverPolicy: jetstream.DeliverAllPolicy, AckPolicy: jetstream.AckNonePolicy,
			ReplayPolicy: jetstream.ReplayInstantPolicy, Replicas: 3, InactiveThreshold: 2 * time.Minute,
			Metadata: map[string]string{"terrascale-read-session": nonce},
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func verifyNetBirdSourceConsumer(info *jetstream.ConsumerInfo, source netBirdPublicSource, nonce string) error {
	if info == nil {
		return ErrConflict
	}
	cfg := info.Config
	if info.Stream != source.stream || info.Name != source.consumer || cfg.Name != source.consumer || cfg.Durable != source.consumer ||
		cfg.FilterSubject != source.subject || len(cfg.FilterSubjects) != 0 || cfg.HeadersOnly || cfg.MemoryStorage ||
		cfg.DeliverPolicy != jetstream.DeliverAllPolicy || cfg.AckPolicy != jetstream.AckNonePolicy ||
		cfg.ReplayPolicy != jetstream.ReplayInstantPolicy || cfg.Replicas != 3 || cfg.InactiveThreshold != 2*time.Minute ||
		cfg.Metadata["terrascale-read-session"] != nonce || info.Paused || info.Cluster == nil || info.Cluster.Leader == "" {
		return errors.New("NetBird public source consumer differs from its fixed contract")
	}
	return nil
}

// NetBirdSourceRecord is public signed material authenticated by its exact broker key.
type NetBirdSourceRecord struct {
	Created  time.Time
	Revision uint64
	Wire     []byte
}

type NetBirdSourceRead struct {
	mu      sync.Mutex
	readers [2]netBirdSourceCursor
	failed  error
}

type netBirdSourceCursor struct {
	source              netBirdPublicSource
	stream              jetstream.Stream
	consumer            jetstream.Consumer
	nonce               string
	created, cursorBorn time.Time
	delivered, sequence uint64
	latest              *jetstream.RawStreamMsg
}

func ConnectNetBirdSourceRead(ctx context.Context, js jetstream.JetStream, nonce string) (*NetBirdSourceRead, error) {
	if ctx == nil || js == nil || !entityid.Valid(nonce) {
		return nil, ErrFenced
	}
	r := &NetBirdSourceRead{}
	for index, source := range netBirdPublicSources {
		stream, err := js.Stream(ctx, source.stream)
		if err != nil {
			return nil, err
		}
		consumer, err := stream.Consumer(ctx, source.consumer)
		if err != nil {
			return nil, err
		}
		info, err := consumer.Info(ctx)
		if err != nil {
			return nil, err
		}
		if err := verifyNetBirdSourceConsumer(info, source, nonce); err != nil {
			return nil, err
		}
		if info.Delivered.Consumer != 0 {
			return nil, errors.New("NetBird public source session has already been consumed")
		}
		r.readers[index] = netBirdSourceCursor{source: source, stream: stream, consumer: consumer, nonce: nonce, cursorBorn: info.Created}
	}
	return r, nil
}

// Read proves currentness independently for each exact key. The caller checks
// both returned revision/bytes against its intent before every account effect.
func (r *NetBirdSourceRead) Read(ctx context.Context) (spec, roots NetBirdSourceRecord, err error) {
	if r == nil || ctx == nil {
		return spec, roots, ErrFenced
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed != nil {
		return spec, roots, r.failed
	}
	spec, err = r.readers[0].read(ctx)
	if err == nil {
		roots, err = r.readers[1].read(ctx)
	}
	if err != nil {
		r.failed = err
		return NetBirdSourceRecord{}, NetBirdSourceRecord{}, err
	}
	return spec, roots, nil
}

func (r *netBirdSourceCursor) state(ctx context.Context) (*jetstream.StreamInfo, error) {
	info, err := r.stream.Info(ctx, jetstream.WithSubjectFilter(r.source.subject), jetstream.WithDeletedDetails(true))
	if err != nil {
		return nil, err
	}
	cfg := info.Config
	if cfg.Name != r.source.stream || !slices.Equal(cfg.Subjects, []string{"$KV." + strings.TrimPrefix(r.source.stream, "KV_") + ".>"}) ||
		cfg.Replicas != 3 || cfg.Storage != jetstream.FileStorage || cfg.Retention != jetstream.LimitsPolicy ||
		cfg.MaxAge != 0 || cfg.MaxMsgsPerSubject != 4 || cfg.MaxMsgs != -1 || cfg.MaxBytes != -1 ||
		!cfg.DenyDelete || !cfg.AllowRollup || cfg.SubjectTransform != nil ||
		len(cfg.Sources) != 0 || cfg.Mirror != nil || info.Cluster == nil || info.Cluster.Leader == "" ||
		len(info.State.Deleted) != info.State.NumDeleted {
		return nil, errors.New("NetBird public source stream differs from its fixed retained contract")
	}
	if r.created.IsZero() {
		r.created = info.Created
	}
	if info.Created != r.created {
		return nil, ErrConflict
	}
	return info, nil
}

func sameNetBirdSourceState(a, b *jetstream.StreamInfo) bool {
	return a.Created == b.Created && a.Cluster.Leader == b.Cluster.Leader && reflect.DeepEqual(a.State, b.State)
}

func (r *netBirdSourceCursor) read(ctx context.Context) (NetBirdSourceRecord, error) {
	for range 8 {
		before, err := r.state(ctx)
		if err != nil {
			return NetBirdSourceRecord{}, err
		}
		if err := r.drain(ctx); err != nil {
			return NetBirdSourceRecord{}, err
		}
		cursor, err := r.consumer.Info(ctx)
		if err != nil {
			return NetBirdSourceRecord{}, err
		}
		if err := verifyNetBirdSourceConsumer(cursor, r.source, r.nonce); err != nil {
			return NetBirdSourceRecord{}, err
		}
		if cursor.Created != r.cursorBorn || cursor.Delivered.Consumer != r.delivered {
			return NetBirdSourceRecord{}, errors.New("NetBird public source cursor moved outside its original session")
		}
		after, err := r.state(ctx)
		if err != nil {
			return NetBirdSourceRecord{}, err
		}
		if !sameNetBirdSourceState(before, after) || cursor.Delivered.Stream < after.State.LastSeq {
			continue
		}
		if r.latest == nil || after.State.Subjects[r.source.subject] == 0 {
			return NetBirdSourceRecord{}, ErrNotFound
		}
		if r.latest.Sequence < after.State.FirstSeq || r.latest.Sequence > after.State.LastSeq || slices.Contains(after.State.Deleted, r.latest.Sequence) ||
			r.latest.Header.Get("KV-Operation") != "" || r.latest.Header.Get(jetstream.MarkerReasonHeader) != "" || len(r.latest.Data) == 0 {
			return NetBirdSourceRecord{}, ErrConflict
		}
		return NetBirdSourceRecord{Created: after.Created, Revision: r.latest.Sequence, Wire: bytes.Clone(r.latest.Data)}, ctx.Err()
	}
	return NetBirdSourceRecord{}, ErrConflict
}

func (r *netBirdSourceCursor) drain(ctx context.Context) error {
	for {
		// An ordinary pull forces a filtered store scan even when the broker's
		// asynchronous pending count is stale; no-wait can return before scanning.
		batch, err := r.consumer.Fetch(128, jetstream.FetchMaxWait(100*time.Millisecond))
		if err != nil {
			return err
		}
		var received int
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
				if err != nil || msg.Subject() != r.source.subject || metadata.Stream != r.source.stream || metadata.Consumer != r.source.consumer ||
					metadata.NumDelivered != 1 || metadata.Sequence.Consumer != r.delivered+1 || metadata.Sequence.Stream <= r.sequence {
					return errors.New("NetBird public source has an incomplete, repeated or unauthorized delivery")
				}
				r.latest = &jetstream.RawStreamMsg{Subject: msg.Subject(), Sequence: metadata.Sequence.Stream, Time: metadata.Timestamp,
					Header: maps.Clone(msg.Headers()), Data: bytes.Clone(msg.Data())}
				r.delivered, r.sequence = metadata.Sequence.Consumer, metadata.Sequence.Stream
				received++
			}
		}
		if err := batch.Error(); err != nil && !errors.Is(err, jetstream.ErrNoMessages) && !errors.Is(err, nats.ErrTimeout) {
			return err
		}
		if received < 128 {
			return nil
		}
	}
}
