package observability

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Batch is an immutable snapshot handed to a BatchSender. Records are copied
// when they enter the batch and when they are handed to a sender.
type Batch struct {
	Signal  Signal
	Records [][]byte
	Bytes   int
}

func (b Batch) validate() error {
	if b.Signal != SignalMetrics && b.Signal != SignalLogs {
		return fmt.Errorf("unsupported telemetry signal %d", b.Signal)
	}
	if len(b.Records) < 1 || len(b.Records) > 10_000 {
		return errors.New("telemetry batch must contain 1..10000 records")
	}
	bytes := 0
	for _, record := range b.Records {
		if len(record) == 0 {
			return errors.New("telemetry batch contains an empty record")
		}
		if len(record) > 16*1024*1024 || bytes > 16*1024*1024-len(record) {
			return errors.New("telemetry batch exceeds 16 MiB")
		}
		bytes += len(record)
		if bytes > 16*1024*1024 {
			return errors.New("telemetry batch exceeds 16 MiB")
		}
	}
	if b.Bytes != 0 && b.Bytes != bytes {
		return errors.New("telemetry batch byte count is inconsistent")
	}
	return nil
}

// BatchSender is the transport boundary. Implementations may encode the
// records as OTLP or Prometheus remote-write; the batcher itself never makes a
// network call or assumes a wire format.
type BatchSender interface {
	SendBatch(ctx context.Context, batch Batch) error
}

// Batcher is a concurrency-safe, bounded telemetry batcher. A full batch is
// delivered synchronously on the Add call that fills it; callers can use Flush
// to force delivery by time or shutdown.
type Batcher struct {
	mu      sync.Mutex
	config  BatchConfig
	retry   RetryPolicy
	sender  BatchSender
	closed  bool
	signal  Signal
	records [][]byte
	bytes   int
}

// NewBatcher validates all bounds before constructing a batcher.
func NewBatcher(config BatchConfig, retry RetryPolicy, sender BatchSender) (*Batcher, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := retry.Validate(); err != nil {
		return nil, err
	}
	if sender == nil {
		return nil, errors.New("batch sender is required")
	}
	return &Batcher{config: config, retry: retry, sender: sender}, nil
}

// Add appends one pre-encoded OTLP or remote-write record. Oversize records
// are rejected rather than split, so payloads never exceed their source
// protocol's framing contract accidentally.
func (b *Batcher) Add(ctx context.Context, signal Signal, payload []byte) error {
	if b == nil {
		return errors.New("nil observability batcher")
	}
	if ctx == nil {
		return errors.New("batch context must not be nil")
	}
	if signal != SignalMetrics && signal != SignalLogs {
		return fmt.Errorf("unsupported telemetry signal %d", signal)
	}
	if len(payload) == 0 || len(payload) > b.config.MaxBytes {
		return fmt.Errorf("telemetry record must contain 1..%d bytes", b.config.MaxBytes)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return errors.New("observability batcher is closed")
	}
	if len(b.records) != 0 && (b.signal != signal || b.bytes+len(payload) > b.config.MaxBytes) {
		if err := b.flushLocked(ctx); err != nil {
			return err
		}
	}
	if len(b.records) == 0 {
		b.signal = signal
	}
	b.records = append(b.records, append([]byte(nil), payload...))
	b.bytes += len(payload)
	if len(b.records) == b.config.MaxItems {
		return b.flushLocked(ctx)
	}
	return nil
}

// Flush delivers the currently buffered records, if any.
func (b *Batcher) Flush(ctx context.Context) error {
	if b == nil {
		return errors.New("nil observability batcher")
	}
	if ctx == nil {
		return errors.New("batch context must not be nil")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return errors.New("observability batcher is closed")
	}
	return b.flushLocked(ctx)
}

// Close flushes pending records and prevents future writes. It is safe to call
// once; a failed final flush still closes the batcher so the caller cannot
// accidentally continue using a partially drained instance.
func (b *Batcher) Close(ctx context.Context) error {
	if b == nil {
		return errors.New("nil observability batcher")
	}
	if ctx == nil {
		return errors.New("batch context must not be nil")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	err := b.flushLocked(ctx)
	b.closed = true
	return err
}

func (b *Batcher) flushLocked(ctx context.Context) error {
	if len(b.records) == 0 {
		return nil
	}
	batch := Batch{Signal: b.signal, Records: make([][]byte, len(b.records)), Bytes: b.bytes}
	for index, record := range b.records {
		batch.Records[index] = append([]byte(nil), record...)
	}
	if err := batch.validate(); err != nil {
		return err
	}
	if err := Retry(ctx, b.retry, func(sendContext context.Context) error {
		return b.sender.SendBatch(sendContext, batch)
	}); err != nil {
		return err
	}
	b.records = nil
	b.bytes = 0
	b.signal = 0
	return nil
}
