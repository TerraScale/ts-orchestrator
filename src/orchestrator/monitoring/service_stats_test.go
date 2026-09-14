package monitoring

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestServiceEndpointStatsRecordsBoundedSortedMeasurements(t *testing.T) {
	stats := NewNatsServiceEndpointStats()
	stats.Record(NatsServiceEndpointNameStats, NatsServiceRequestResultOk, 2*time.Millisecond)
	stats.Record(NatsServiceEndpointNameStats, NatsServiceRequestResultError, 5*time.Millisecond)
	stats.Record(NatsServiceEndpointNameHealth, NatsServiceRequestResultOk, time.Millisecond)

	snapshot := stats.Snapshot()
	if len(snapshot) != 2 || snapshot[0].Endpoint != NatsServiceEndpointNameHealth ||
		snapshot[1].Endpoint != NatsServiceEndpointNameStats {
		t.Fatalf("snapshot endpoints = %#v", snapshot)
	}
	measurement := snapshot[1]
	if measurement.Requests != 2 || measurement.Errors != 1 ||
		measurement.MinimumMilliseconds != 2 || measurement.MaximumMilliseconds != 5 ||
		measurement.P50Milliseconds != 2 || measurement.P95Milliseconds != 5 ||
		measurement.P99Milliseconds != 5 {
		t.Fatalf("stats measurement = %#v", measurement)
	}
}

func TestServiceEndpointStatsIsSafeForConcurrentRecording(t *testing.T) {
	stats := NewNatsServiceEndpointStats()
	const writers = 8
	const recordsPerWriter = 128
	var wait sync.WaitGroup
	for writer := 0; writer < writers; writer++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for record := 0; record < recordsPerWriter; record++ {
				stats.Record(NatsServiceEndpointNameHealth, NatsServiceRequestResultOk, time.Millisecond)
			}
		}()
	}
	wait.Wait()
	snapshot := stats.Snapshot()
	if len(snapshot) != 1 || snapshot[0].Requests != writers*recordsPerWriter {
		t.Fatalf("concurrent snapshot = %#v", snapshot)
	}
}

func TestServiceStatsDocumentCopiesAndCanonicalizesEndpoints(t *testing.T) {
	now := time.Date(2026, time.August, 31, 0, 0, 0, 0, time.UTC)
	endpoints := []NatsServiceEndpointMeasurement{
		NatsServiceEndpointMeasurementEmpty(NatsServiceEndpointNameStats),
		NatsServiceEndpointMeasurementEmpty(NatsServiceEndpointNameHealth),
	}
	document, err := NatsServiceStatsDocumentCreate("gru", "1.0.0", 2, true, now, endpoints)
	if err != nil {
		t.Fatal(err)
	}
	endpoints[0].Endpoint = NatsServiceEndpointNameHealth
	if document.Endpoints[0].Endpoint != NatsServiceEndpointNameHealth {
		t.Fatalf("document endpoints were not sorted: %#v", document.Endpoints)
	}
	if document.Endpoints[1].Endpoint != NatsServiceEndpointNameStats {
		t.Fatalf("document endpoints were aliased: %#v", document.Endpoints)
	}
	if err := document.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"SchemaVersion":1,"Cell":"gru","Service":"terrascale_orchestrator_gru","Version":"1.0.0","SchemaGeneration":2,"Healthy":true,"ObservedAt":"2026-08-31T00:00:00Z","Endpoints":[{"Endpoint":1,"Requests":0,"Errors":0,"MinimumMilliseconds":0,"P50Milliseconds":0,"P95Milliseconds":0,"P99Milliseconds":0,"MaximumMilliseconds":0},{"Endpoint":5,"Requests":0,"Errors":0,"MinimumMilliseconds":0,"P50Milliseconds":0,"P95Milliseconds":0,"P99Milliseconds":0,"MaximumMilliseconds":0}]}`
	if string(encoded) != want {
		t.Fatalf("document JSON = %s, want %s", encoded, want)
	}
}

func TestServiceEndpointStatsCapsReservoirAt256Samples(t *testing.T) {
	stats := NewNatsServiceEndpointStats()
	for sample := 1; sample <= 300; sample++ {
		stats.Record(NatsServiceEndpointNameHealth, NatsServiceRequestResultOk,
			time.Duration(sample)*time.Millisecond)
	}
	snapshot := stats.Snapshot()
	if len(snapshot) != 1 {
		t.Fatalf("snapshot length = %d, want 1", len(snapshot))
	}
	measurement := snapshot[0]
	if measurement.Requests != 300 || measurement.MinimumMilliseconds != 45 ||
		measurement.MaximumMilliseconds != 300 {
		t.Fatalf("capped measurement = %#v", measurement)
	}
}

func TestServiceStatsDocumentRejectsInvalidCellAndEndpoint(t *testing.T) {
	now := time.Date(2026, time.August, 31, 0, 0, 0, 0, time.UTC)
	if _, err := NatsServiceStatsDocumentCreate("GRU", "1.0.0", 2, true, now, nil); err == nil {
		t.Fatal("uppercase cell accepted")
	}
	if _, err := NatsServiceStatsDocumentCreate("gru", "1.0.0", 2, true, now,
		[]NatsServiceEndpointMeasurement{{Endpoint: 99}}); err == nil {
		t.Fatal("invalid endpoint accepted")
	}
}

func TestServiceEndpointMeasurementRejectsPercentileAboveMaximum(t *testing.T) {
	measurement := NatsServiceEndpointMeasurement{
		Endpoint:            NatsServiceEndpointNameHealth,
		Requests:            2,
		MinimumMilliseconds: 1,
		P50Milliseconds:     1,
		P95Milliseconds:     2,
		P99Milliseconds:     3,
		MaximumMilliseconds: 2,
	}
	if err := measurement.Validate(); err == nil {
		t.Fatal("measurement with P99 above maximum was accepted")
	}
}
