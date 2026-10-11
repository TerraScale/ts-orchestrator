package logs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	StreamName      = "TS_LOG_SUMMARY"
	streamBytes     = 256 << 20
	streamMaxAge    = 25 * time.Hour
	maxMessageBytes = 64<<10 + 1<<10
	verdictTTL      = 5 * time.Minute
	retryFirst      = time.Second
	retryMax        = 30 * time.Second
)

// Stream holds the cell's node windows for the retention, so every controller
// can rebuild its view.
type Stream struct {
	stream jetstream.Stream
}

// OpenStream creates the stream or opens it. An existing stream is updated to
// this configuration: it holds only summaries, so a change is safe.
func OpenStream(ctx context.Context, js jetstream.JetStream, cell string, replicas int) (*Stream, error) {
	if js == nil {
		return nil, errors.New("log summary stream requires JetStream")
	}
	subject := protocol.AgentObservation(cell, "*", "logs")
	if subject == "" {
		return nil, errors.New("log summary subject is invalid")
	}
	config := jetstream.StreamConfig{
		Name:        StreamName,
		Description: "Regional log summary windows",
		Subjects:    []string{subject},
		Storage:     jetstream.FileStorage,
		Replicas:    replicas,
		Retention:   jetstream.LimitsPolicy,
		Discard:     jetstream.DiscardOld,
		MaxAge:      streamMaxAge,
		MaxBytes:    streamBytes,
		MaxMsgs:     -1,
		MaxMsgSize:  maxMessageBytes,
	}
	stream, err := js.CreateStream(ctx, config)
	if errors.Is(err, jetstream.ErrStreamNameAlreadyInUse) {
		stream, err = js.UpdateStream(ctx, config)
	}
	if err != nil {
		return nil, fmt.Errorf("open log summary stream: %w", err)
	}
	return &Stream{stream: stream}, nil
}

// Follow feeds view from the stream until ctx ends. It starts 24 hours back, so
// a restart or leader change rebuilds the view, and the view skips windows it
// already counted. verify must confirm that node is registered with nkey.
func (stream *Stream) Follow(ctx context.Context, view *View, verify func(ctx context.Context, node, nkey string) bool) {
	verdicts := &verdictCache{verify: verify, verdicts: make(map[nodeKey]verdict)}
	delay := retryFirst
	failing := false
	for {
		ctx := observability.StartTrace(ctx)
		started := time.Now()
		ready, err := stream.run(ctx, view, verdicts)
		if ready && failing {
			slog.InfoContext(ctx, "log summary follower recovered", observability.ComponentKey, "logs")
			failing = false
		}
		if ctx.Err() != nil {
			return
		}
		if failing {
			slog.DebugContext(ctx, "log summary follower still failing", observability.ComponentKey, "logs", "error", err)
		} else {
			slog.WarnContext(ctx, "log summary follower failed; retrying", observability.ComponentKey, "logs", "error", err)
			failing = true
		}
		// A consumer that lasted a while was healthy: its next failure starts over.
		if time.Since(started) >= retryMax {
			delay = retryFirst
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(2*delay, retryMax)
	}
}

// run follows the stream until the consumer fails or ctx ends. ready reports
// whether the consumer was created.
func (stream *Stream) run(ctx context.Context, view *View, verdicts *verdictCache) (bool, error) {
	start := time.Now().Add(-retention)
	consumer, err := stream.stream.OrderedConsumer(ctx, jetstream.OrderedConsumerConfig{
		DeliverPolicy: jetstream.DeliverByStartTimePolicy,
		OptStartTime:  &start,
	})
	if err != nil {
		return false, err
	}
	messages, err := consumer.Messages()
	if err != nil {
		return true, err
	}
	defer messages.Stop()
	stop := context.AfterFunc(ctx, messages.Stop)
	defer stop()
	for {
		msg, err := messages.Next()
		if err != nil {
			return true, err
		}
		accept(ctx, msg, view, verdicts)
	}
}

// accept counts one window whose node is verified for the NKey in its subject.
// A malformed or unverified window is dropped.
func accept(ctx context.Context, msg jetstream.Msg, view *View, verdicts *verdictCache) {
	var window Window
	if protocol.DecodeStrict(msg.Data(), &window, maxWindowBytes) != nil || window.Version != 1 {
		return
	}
	// The subject is ts.orch.v1.<cell>.agent.<nkey>.observation.logs.
	tokens := strings.Split(msg.Subject(), ".")
	if len(tokens) < 3 || !verdicts.allowed(ctx, window.Node, tokens[len(tokens)-3]) {
		return
	}
	view.Add(window, time.Now())
}

type nodeKey struct{ node, nkey string }

type verdict struct {
	ok bool
	at time.Time
}

// verdictCache remembers each node's verdict for verdictTTL, so a replay asks
// the registration once per node and key rather than once per window.
type verdictCache struct {
	verify   func(ctx context.Context, node, nkey string) bool
	verdicts map[nodeKey]verdict
}

func (c *verdictCache) allowed(ctx context.Context, node, nkey string) bool {
	key := nodeKey{node, nkey}
	if v, ok := c.verdicts[key]; ok && time.Since(v.at) < verdictTTL {
		return v.ok
	}
	ok := c.verify(ctx, node, nkey)
	c.verdicts[key] = verdict{ok: ok, at: time.Now()}
	return ok
}
