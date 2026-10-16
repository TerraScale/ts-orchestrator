package ocicost

import (
	"context"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	// Bucket is the regional KV bucket holding the region's report.
	Bucket    = "TS_OCI_COST"
	reportKey = "report"
	// maxReportBytes bounds a stored report well above the largest one
	// Validate accepts, so a corrupt value cannot exhaust memory.
	maxReportBytes = 64 << 10
)

// ErrNoReport means no report has been written yet.
var ErrNoReport = errors.New("no OCI cost report yet")

// Store is the region's replicated report.
type Store struct{ kv jetstream.KeyValue }

// OpenStore opens the region's report bucket. Replicas keep the report
// readable through a leader failover, which is when the next read matters.
func OpenStore(ctx context.Context, js jetstream.JetStream, replicas int) (*Store, error) {
	if js == nil || replicas < 1 || replicas > 5 {
		return nil, errors.New("OCI cost store requires replicated JetStream")
	}
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: Bucket, History: 1,
		MaxValueSize: maxReportBytes, MaxBytes: 1 << 20, Storage: jetstream.FileStorage, Replicas: replicas})
	if err != nil {
		return nil, fmt.Errorf("open OCI cost store: %w", err)
	}
	return &Store{kv: kv}, nil
}

// Put replaces the report. An invalid report is refused before it reaches
// the bucket, so readers never see one.
func (s *Store) Put(ctx context.Context, report Report) error {
	if err := report.Validate(); err != nil {
		return fmt.Errorf("write OCI cost report: %w", err)
	}
	wire, err := protocol.EncodeJSON(report)
	if err == nil {
		_, err = s.kv.Put(ctx, reportKey, wire)
	}
	if err != nil {
		return fmt.Errorf("write OCI cost report: %w", err)
	}
	return nil
}

// Report returns the stored report, or ErrNoReport before the first Put.
func (s *Store) Report(ctx context.Context) (Report, error) {
	entry, err := s.kv.Get(ctx, reportKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return Report{}, ErrNoReport
	}
	if err != nil {
		return Report{}, fmt.Errorf("read OCI cost report: %w", err)
	}
	var report Report
	if err := protocol.DecodeStrict(entry.Value(), &report, maxReportBytes); err != nil {
		return Report{}, fmt.Errorf("read OCI cost report: %w", err)
	}
	if err := report.Validate(); err != nil {
		return Report{}, fmt.Errorf("read OCI cost report: %w", err)
	}
	return report, nil
}
