package decisionlog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	// StreamName is the regional decision journal stream. Every cell has
	// its own JetStream, so the name carries no region.
	StreamName = "TS_DECISIONS"
	// JournalLeaf is the observability subject leaf decisions are stored on.
	JournalLeaf = "journal"
	// DefaultRetention keeps decisions for 30 days.
	DefaultRetention = 30 * 24 * time.Hour
	// DefaultStreamBytes bounds the stream on disk.
	DefaultStreamBytes = 256 << 20
	defaultStreamMsgs  = 500_000
	fetchBatch         = 256
)

// StreamConfig sizes the regional stream.
type StreamConfig struct {
	Cell     string
	Replicas int
	// Retention and MaxBytes default to DefaultRetention and
	// DefaultStreamBytes. The oldest decisions are discarded first.
	Retention time.Duration
	MaxBytes  int64
}

// Stream is the replicated regional decision stream. It implements Sink and
// Archive and tails new decisions into a Journal.
type Stream struct {
	stream  jetstream.Stream
	js      jetstream.JetStream
	subject string
}

// OpenStream creates or updates the regional stream. Its replica count
// follows the cell's quorum so a decision survives a controller loss.
func OpenStream(ctx context.Context, js jetstream.JetStream, config StreamConfig) (*Stream, error) {
	if js == nil {
		return nil, errors.New("decision stream requires JetStream")
	}
	if config.Replicas < 1 || config.Replicas > 5 {
		return nil, errors.New("decision stream replica count is out of range")
	}
	subject, err := protocol.ObservabilitySubject(config.Cell, JournalLeaf)
	if err != nil {
		return nil, err
	}
	if config.Retention <= 0 {
		config.Retention = DefaultRetention
	}
	if config.MaxBytes <= 0 {
		config.MaxBytes = DefaultStreamBytes
	}
	stream, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:        StreamName,
		Description: "Regional orchestrator decision journal",
		Subjects:    []string{subject},
		Storage:     jetstream.FileStorage,
		Replicas:    config.Replicas,
		Retention:   jetstream.LimitsPolicy,
		Discard:     jetstream.DiscardOld,
		MaxAge:      config.Retention,
		MaxBytes:    config.MaxBytes,
		MaxMsgs:     defaultStreamMsgs,
		MaxMsgSize:  MaxRecordBytes + 1024,
		Duplicates:  2 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("open decision stream: %w", err)
	}
	return &Stream{stream: stream, js: js, subject: subject}, nil
}

// Publish stores one decision, deduplicated by its ID.
func (stream *Stream) Publish(ctx context.Context, decision Decision) error {
	data, err := json.Marshal(decision)
	if err != nil {
		return err
	}
	if len(data) > MaxRecordBytes {
		return errors.New("decision record exceeds its size bound")
	}
	_, err = stream.js.Publish(ctx, stream.subject, data, jetstream.WithMsgID(decision.ID))
	return err
}

// Scan visits stored decisions from since, oldest first.
func (stream *Stream) Scan(ctx context.Context, since time.Time, maxScan int, visit func(Decision) bool) (bool, error) {
	info, err := stream.stream.Info(ctx)
	if err != nil {
		return false, err
	}
	if info.State.Msgs == 0 || info.State.LastTime.Before(since) {
		return true, nil
	}
	config := jetstream.OrderedConsumerConfig{DeliverPolicy: jetstream.DeliverAllPolicy}
	if !since.IsZero() && since.After(info.State.FirstTime) {
		start := since.UTC()
		config = jetstream.OrderedConsumerConfig{DeliverPolicy: jetstream.DeliverByStartTimePolicy,
			OptStartTime: &start}
	}
	return stream.consume(ctx, config, maxScan, info.State.LastSeq, visit)
}

// consume reads an ordered consumer until it reaches lastSeq, maxScan
// records, or visit stops it.
func (stream *Stream) consume(ctx context.Context, config jetstream.OrderedConsumerConfig, maxScan int,
	lastSeq uint64, visit func(Decision) bool,
) (bool, error) {
	consumer, err := stream.stream.OrderedConsumer(ctx, config)
	if err != nil {
		return false, err
	}
	scanned := 0
	for scanned < maxScan {
		batch, err := consumer.Fetch(min(fetchBatch, maxScan-scanned), jetstream.FetchMaxWait(time.Second))
		if err != nil {
			return false, err
		}
		received := 0
		for message := range batch.Messages() {
			received++
			scanned++
			metadata, err := message.Metadata()
			if err != nil {
				continue
			}
			var decision Decision
			if json.Unmarshal(message.Data(), &decision) == nil && decision.ID != "" && !visit(decision) {
				return true, nil
			}
			if metadata.Sequence.Stream >= lastSeq || metadata.NumPending == 0 {
				return true, nil
			}
		}
		if err := batch.Error(); err != nil && !errors.Is(err, jetstream.ErrNoMessages) {
			return false, err
		}
		if received == 0 {
			// Nothing more arrived within the wait: the stream end.
			return true, nil
		}
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
	}
	return false, nil
}

// Tail warms journal with the newest warm decisions and then ingests every
// new one until ctx ends, so this member can answer for the whole region.
// A broken consumer is recreated after a short backoff.
func (stream *Stream) Tail(ctx context.Context, journal *Journal, warm int) error {
	if warm <= 0 {
		warm = journal.config.Capacity
	}
	journal.beginReplay()
	defer journal.endReplay()
	backoff := time.Second
	// next is the sequence to resume from. caughtUp is the last sequence
	// the stream held when the tail started; it survives consumer restarts
	// so a replay broken half way still ends once that sequence is read.
	var next, caughtUp uint64
	for ctx.Err() == nil {
		err := stream.tailOnce(ctx, journal, warm, &next, &caughtUp)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		slog.DebugContext(ctx, "decision stream tail restarting", observability.ComponentKey, "decision", "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
	return ctx.Err()
}

func (stream *Stream) tailOnce(ctx context.Context, journal *Journal, warm int, next, caughtUp *uint64) error {
	// An empty stream is read from its start, so a decision stored between
	// the info call and the consumer is not missed.
	config := jetstream.OrderedConsumerConfig{DeliverPolicy: jetstream.DeliverAllPolicy}
	if *next == 0 {
		info, err := stream.stream.Info(ctx)
		if err != nil {
			return err
		}
		if info.State.Msgs == 0 {
			journal.endReplay()
		}
		*caughtUp = info.State.LastSeq
		if info.State.Msgs > 0 {
			start := info.State.FirstSeq
			if info.State.LastSeq >= uint64(warm) && info.State.LastSeq-uint64(warm)+1 > start {
				start = info.State.LastSeq - uint64(warm) + 1
			}
			if start > info.State.FirstSeq {
				// Older decisions stay in the stream for archive queries.
				if message, err := stream.stream.GetMsg(ctx, start); err == nil {
					journal.MarkCoveredFrom(message.Time)
				}
			}
			config = jetstream.OrderedConsumerConfig{DeliverPolicy: jetstream.DeliverByStartSequencePolicy,
				OptStartSeq: start}
		}
	} else {
		config = jetstream.OrderedConsumerConfig{DeliverPolicy: jetstream.DeliverByStartSequencePolicy,
			OptStartSeq: *next}
	}
	consumer, err := stream.stream.OrderedConsumer(ctx, config)
	if err != nil {
		return err
	}
	messages, err := consumer.Messages()
	if err != nil {
		return err
	}
	defer messages.Stop()
	stop := context.AfterFunc(ctx, messages.Stop)
	defer stop()
	for {
		message, err := messages.Next()
		if err != nil {
			return err
		}
		var sequence uint64
		if metadata, err := message.Metadata(); err == nil {
			sequence = metadata.Sequence.Stream
			*next = sequence + 1
		}
		var decision Decision
		if json.Unmarshal(message.Data(), &decision) == nil && decision.ID != "" {
			journal.Ingest(decision)
		}
		if *caughtUp > 0 && sequence >= *caughtUp {
			// Memory now holds what the stream held when the tail started.
			journal.endReplay()
			*caughtUp = 0
		}
	}
}

var (
	_ Sink    = (*Stream)(nil)
	_ Archive = (*Stream)(nil)
)
