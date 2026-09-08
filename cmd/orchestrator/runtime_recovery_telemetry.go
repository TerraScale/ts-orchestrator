package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/observability"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
)

func newProductionRestoreTelemetryFromEnv(host, region string) (*productionRestoreTelemetry, error) {
	config, err := observabilityConfigFromEnv(os.LookupEnv)
	if err != nil {
		return nil, errors.Join(errors.New("restore telemetry: production observability configuration is required"), err)
	}
	encode := func(batch observability.Batch) (observability.EncodedBatch, error) {
		var body bytes.Buffer
		for _, record := range batch.Records {
			body.Write(record)
			body.WriteByte('\n')
		}
		return observability.EncodedBatch{Body: body.Bytes(), ContentType: "application/x-ndjson"}, nil
	}
	exporter, err := observability.NewHTTPExporter(config, nil, encode, encode, nil)
	if err != nil {
		return nil, err
	}
	telemetry, err := newProductionRestoreTelemetry(exporter, host, region)
	if err != nil {
		_ = exporter.Close(context.Background())
		return nil, err
	}
	return telemetry, nil
}

// productionRestoreTelemetry adapts aggregate restore outcomes to the
// bounded observability exporter. It has no access to database identities,
// checksums, provider errors, or branch names.
type productionRestoreTelemetry struct {
	exporter *observability.Exporter
	host     string
	region   string
}

func newProductionRestoreTelemetry(exporter *observability.Exporter, host, region string) (*productionRestoreTelemetry, error) {
	if exporter == nil || strings.TrimSpace(host) == "" || strings.TrimSpace(region) == "" {
		return nil, errors.New("restore telemetry: exporter, host, and region are required")
	}
	return &productionRestoreTelemetry{exporter: exporter, host: host, region: region}, nil
}

func (t *productionRestoreTelemetry) Record(ctx context.Context, facts restoredrill.RunTelemetry) error {
	if t == nil || t.exporter == nil {
		return errors.New("restore telemetry: exporter is unavailable")
	}
	if ctx == nil {
		return errors.New("restore telemetry: context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	statusName := "restore_drill.runs.failed"
	switch facts.Status {
	case restoredrill.RunSucceeded:
		statusName = "restore_drill.runs.succeeded"
	case restoredrill.RunRunning:
		statusName = "restore_drill.runs.pending"
	case restoredrill.RunCanceled:
		statusName = "restore_drill.runs.canceled"
	case restoredrill.RunFailed:
	default:
		return errors.New("restore telemetry: unknown run status")
	}
	for name, value := range map[string]float64{
		statusName:                       1,
		"restore_drill.databases":        float64(facts.DatabaseCount),
		"restore_drill.items.succeeded":  float64(facts.SucceededItems),
		"restore_drill.items.failed":     float64(facts.FailedItems),
		"restore_drill.items.pending":    float64(facts.PendingItems),
		"restore_drill.snapshot_regions": float64(facts.SnapshotRegions),
	} {
		if err := t.exporter.RecordCounter(ctx, name, t.host, t.region, "restore", value); err != nil {
			return err
		}
	}
	return nil
}

func (t *productionRestoreTelemetry) Close(ctx context.Context) error {
	if t == nil || t.exporter == nil {
		return nil
	}
	return t.exporter.Close(ctx)
}

var _ restoredrill.TelemetryPort = (*productionRestoreTelemetry)(nil)
