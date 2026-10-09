package observability

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	HostMetricStreamName            = "TS_HOST_METRIC_HISTORY"
	HostMetricStreamBytes     int64 = 1536 << 20
	HostMetricBatchBytes            = 64 << 10
	hostMetricHeaderBytes           = 128 // NATS framing and the uint64 expected-last-sequence header.
	HostMetricInterval              = time.Minute
	hostMetricDecodedBytes          = 1 << 20
	hostMetricPublishAttempts       = 8
	hostMetricReplayWait            = time.Second
)

// HostMetricBatch is one regional minute of telemetry. Epoch records its
// publisher's epoch; historical telemetry is never authority evidence.
type HostMetricBatch struct {
	At         time.Time `json:"at"`
	Epoch      uint64    `json:"epoch"`
	Samples    []Sample  `json:"samples"`
	Incomplete bool      `json:"incomplete"`
}

var errHostMetricBatchSize = errors.New("host metric batch exceeds payload size bound")

// BoundHostMetricBatch retains an ordered prefix that fits the sample and
// payload bounds, marking omissions and returning the number newly omitted.
// Nonempty valid batches retain at least one sample; encoder validation errors
// are returned.
func BoundHostMetricBatch(batch HostMetricBatch) (HostMetricBatch, uint64, error) {
	original := len(batch.Samples)
	if original > DefaultHistorySeries {
		batch.Samples = batch.Samples[:DefaultHistorySeries]
	}
	for {
		batch.Incomplete = batch.Incomplete || len(batch.Samples) < original
		_, err := encodeHostMetricBatch(batch)
		if err == nil {
			return batch, uint64(original - len(batch.Samples)), nil
		}
		if !errors.Is(err, errHostMetricBatchSize) || len(batch.Samples) <= 1 {
			return HostMetricBatch{}, 0, err
		}
		batch.Samples = batch.Samples[:len(batch.Samples)/2]
	}
}

// IsHostMetric selects the five host and service gauges persisted regionally.
func IsHostMetric(metric string) bool {
	switch metric {
	case HistHostCPUUtilization, HistHostMemoryRatio, HistHostDiskRatio,
		HistServiceCPUCores, HistServiceMemoryUsed:
		return true
	}
	return false
}

// HostMetricStream stores and replays regional host telemetry.
type HostMetricStream struct {
	streamMu          sync.Mutex // The NATS stream caches Info without synchronization.
	stream            jetstream.Stream
	js                jetstream.JetStream
	subject           string
	caughtUp          atomic.Bool
	archiveIncomplete atomic.Bool
	replayFailures    atomic.Uint64
	lastRejectedSeq   atomic.Uint64
}

// CaughtUp reports replay readiness, never controller or authority readiness.
func (stream *HostMetricStream) CaughtUp() bool {
	return stream.caughtUp.Load() && stream.js.Conn().IsConnected()
}

// ReplayFailures reports cumulative rejected batches on this stream handle.
// Cursor readiness does not imply complete history when this count is nonzero.
func (stream *HostMetricStream) ReplayFailures() uint64 {
	return stream.replayFailures.Load()
}

// ArchiveIncomplete reports whether replay observed a valid batch with omissions.
// It remains set for this handle; a new handle rebuilds from retained records.
func (stream *HostMetricStream) ArchiveIncomplete() bool {
	return stream.archiveIncomplete.Load()
}

func (stream *HostMetricStream) rejectReplayBatch(sequence uint64) {
	// Ordered replay can revisit old sequences after a new Tail call.
	for previous := stream.lastRejectedSeq.Load(); sequence > previous; previous = stream.lastRejectedSeq.Load() {
		if stream.lastRejectedSeq.CompareAndSwap(previous, sequence) {
			stream.replayFailures.Add(1)
			return
		}
	}
}

func OpenHostMetricStream(ctx context.Context, js jetstream.JetStream, cell string, replicas int) (*HostMetricStream, error) {
	if js == nil {
		return nil, errors.New("host metric stream requires JetStream")
	}
	if replicas < 1 || replicas > 5 {
		return nil, errors.New("host metric stream replica count is out of range")
	}
	subject, err := protocol.ObservabilitySubject(cell, "host-metrics")
	if err != nil {
		return nil, err
	}
	stream, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:        HostMetricStreamName,
		Description: "Regional host metric history",
		Subjects:    []string{subject},
		Storage:     jetstream.FileStorage,
		Replicas:    replicas,
		Retention:   jetstream.LimitsPolicy,
		Discard:     jetstream.DiscardNew,
		MaxAge:      HistoryRetention,
		MaxBytes:    HostMetricStreamBytes,
		MaxMsgs:     -1,
		MaxMsgSize:  HostMetricBatchBytes + hostMetricHeaderBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("open host metric stream: %w", err)
	}
	return &HostMetricStream{stream: stream, js: js, subject: subject}, nil
}

func (stream *HostMetricStream) info(ctx context.Context) (*jetstream.StreamInfo, error) {
	stream.streamMu.Lock()
	defer stream.streamMu.Unlock()
	return stream.stream.Info(ctx)
}

func (stream *HostMetricStream) message(ctx context.Context, sequence uint64) (*jetstream.RawStreamMsg, error) {
	stream.streamMu.Lock()
	defer stream.streamMu.Unlock()
	return stream.stream.GetMsg(ctx, sequence)
}

// Publish stores at most one batch per regional minute across all writers.
// It reports whether this normalized batch is confirmed stored, including retries
// after a lost acknowledgment. Skipped batches belonging to other writers are false.
// The caller must check publication authority before invoking it.
func (stream *HostMetricStream) Publish(ctx context.Context, batch HostMetricBatch) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	batch.At = batch.At.UTC().Truncate(HostMetricInterval)
	data, err := encodeHostMetricBatch(batch)
	if err != nil {
		return false, err
	}
	for range hostMetricPublishAttempts {
		info, err := stream.info(ctx)
		if err != nil {
			return false, err
		}
		lastSeq := info.State.LastSeq
		if info.State.Msgs > 0 {
			message, err := stream.message(ctx, lastSeq)
			if errors.Is(err, jetstream.ErrMsgNotFound) {
				continue // Retention may have expired the message after Info.
			}
			if err != nil {
				return false, err
			}
			last, err := decodeHostMetricBatch(message.Data)
			if err != nil {
				return false, fmt.Errorf("read latest host metric batch: %w", err)
			}
			if !batch.At.After(last.At) {
				return bytes.Equal(message.Data, data), nil
			}
		}
		_, err = stream.js.Publish(ctx, stream.subject, data, jetstream.WithExpectLastSequence(lastSeq))
		if err == nil {
			return true, nil
		}
		var apiErr *jetstream.APIError
		if !errors.As(err, &apiErr) || (apiErr.ErrorCode != jetstream.JSErrCodeStreamWrongLastSequence &&
			apiErr.ErrorCode != jetstream.JSErrCodeStreamWrongLastSequenceConstant) {
			return false, err
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return false, errors.New("host metric publish contention exceeded retry bound")
}

func validateHostMetricBatch(batch HostMetricBatch) error {
	_, offset := batch.At.Zone()
	if batch.At.IsZero() || offset != 0 || !batch.At.Equal(batch.At.Truncate(HostMetricInterval)) || batch.Epoch == 0 {
		return errors.New("host metric batch requires a UTC minute and positive epoch")
	}
	if len(batch.Samples) > DefaultHistorySeries {
		return errors.New("host metric batch exceeds sample bound")
	}
	seen := make(map[string]bool, len(batch.Samples))
	for _, sample := range batch.Samples {
		if !IsHostMetric(sample.Metric) || sample.Counter {
			return errors.New("host metric batch contains an unsupported gauge")
		}
		limit := 1.0
		service := sample.Metric == HistServiceCPUCores || sample.Metric == HistServiceMemoryUsed
		switch sample.Metric {
		case HistServiceCPUCores:
			limit = 1024
		case HistServiceMemoryUsed:
			limit = 1 << 44
		}
		if math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) || sample.Value < 0 || sample.Value > limit {
			return errors.New("host metric value is out of bounds")
		}
		member, serviceName := "", ""
		for _, label := range sample.Labels {
			if protocol.ValidateSubjectToken(label.Value) != nil {
				return errors.New("host metric label is not a valid token")
			}
			switch {
			case label.Name == "member" && member == "":
				member = label.Value
			case label.Name == "service" && service && serviceName == "":
				serviceName = label.Value
			default:
				return errors.New("host metric labels must be precisely member and, for service gauges, service")
			}
		}
		if member == "" || service && serviceName == "" {
			return errors.New("host metric required label is missing")
		}
		key := seriesKey(sample.Metric, sortedLabels(sample.Labels))
		if seen[key] {
			return errors.New("host metric batch contains a duplicate series")
		}
		seen[key] = true
	}
	return nil
}

func encodeHostMetricBatch(batch HostMetricBatch) ([]byte, error) {
	if err := validateHostMetricBatch(batch); err != nil {
		return nil, err
	}
	data, err := json.Marshal(batch)
	if err != nil {
		return nil, err
	}
	if len(data) > hostMetricDecodedBytes {
		return nil, fmt.Errorf("host metric batch exceeds decoded size bound: %w", errHostMetricBatchSize)
	}
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if buffer.Len() > HostMetricBatchBytes {
		return nil, fmt.Errorf("host metric batch exceeds compressed size bound: %w", errHostMetricBatchSize)
	}
	return buffer.Bytes(), nil
}

func decodeHostMetricBatch(data []byte) (HostMetricBatch, error) {
	var batch HostMetricBatch
	if len(data) > HostMetricBatchBytes {
		return batch, errors.New("host metric batch exceeds compressed size bound")
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return batch, err
	}
	defer reader.Close()
	decoded, err := io.ReadAll(io.LimitReader(reader, hostMetricDecodedBytes+1))
	if err != nil {
		return batch, err
	}
	if len(decoded) > hostMetricDecodedBytes {
		return batch, errors.New("host metric batch exceeds decoded size bound")
	}
	if err := json.Unmarshal(decoded, &batch); err != nil {
		return batch, err
	}
	return batch, validateHostMetricBatch(batch)
}

// Tail replays the whole retained stream, then follows new batches until
// cancellation. Consumer recreation resumes after the last handled sequence.
func (stream *HostMetricStream) Tail(ctx context.Context, history *History) error {
	stream.caughtUp.Store(false)
	defer stream.caughtUp.Store(false)
	if history == nil {
		return errors.New("host metric tail requires history")
	}
	var next uint64
	backoff := time.Second
	for ctx.Err() == nil {
		err := stream.tailHostMetricsOnce(ctx, history, &next)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		slog.Debug("host metric stream tail restarting", ComponentKey, "observability", "error", err)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		backoff = min(backoff*2, 30*time.Second)
	}
	return ctx.Err()
}

func (stream *HostMetricStream) tailHostMetricsOnce(ctx context.Context, history *History, next *uint64) error {
	stream.caughtUp.Store(false)
	defer stream.caughtUp.Store(false)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	connection := stream.js.Conn()
	statuses := connection.StatusChanged(nats.RECONNECTING, nats.DISCONNECTED, nats.CLOSED)
	defer connection.RemoveStatusListener(statuses)
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
		case <-statuses:
			stream.caughtUp.Store(false)
			cancel()
		}
	}()
	defer func() { cancel(); <-done }()
	info, err := stream.info(ctx)
	if err != nil {
		return err
	}
	caughtUp := info.State.LastSeq
	config := jetstream.OrderedConsumerConfig{DeliverPolicy: jetstream.DeliverAllPolicy}
	if *next != 0 {
		config = jetstream.OrderedConsumerConfig{DeliverPolicy: jetstream.DeliverByStartSequencePolicy, OptStartSeq: *next}
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
	if ctx.Err() == nil && (info.State.Msgs == 0 || *next > caughtUp) {
		stream.caughtUp.Store(true)
	}
	for {
		nextCtx := ctx
		cancelNext := func() {}
		if !stream.caughtUp.Load() {
			nextCtx, cancelNext = context.WithTimeout(ctx, hostMetricReplayWait)
		}
		message, err := messages.Next(jetstream.NextContext(nextCtx))
		cancelNext()
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			info, err := stream.info(ctx)
			if err != nil {
				return err
			}
			// Retention may remove the replay target before it can be delivered.
			if ctx.Err() == nil && (info.State.Msgs == 0 || *next > info.State.LastSeq) {
				stream.caughtUp.Store(true)
			}
			continue // NextContext deadlines leave the iterator usable.
		}
		if err != nil {
			return err
		}
		metadata, err := message.Metadata()
		if err != nil {
			return err
		}
		sequence := metadata.Sequence.Stream
		if sequence < *next {
			continue
		}
		if batch, err := decodeHostMetricBatch(message.Data()); err == nil {
			if batch.Incomplete {
				stream.archiveIncomplete.Store(true)
			}
			history.Append(batch.At, batch.Samples)
		} else {
			stream.rejectReplayBatch(sequence)
		}
		*next = sequence + 1
		if sequence >= caughtUp && ctx.Err() == nil {
			stream.caughtUp.Store(true)
		}
	}
}
