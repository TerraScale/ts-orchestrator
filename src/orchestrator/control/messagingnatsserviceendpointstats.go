// Port of src/TerraScale.Orchestrator/Messaging/NatsServiceEndpointStats.cs.
package control

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// NatsServiceEndpointName mirrors the C# enum: the closed endpoint-name domain
// of the regional control service.
type NatsServiceEndpointName int

const (
	NatsServiceEndpointNameHealth         NatsServiceEndpointName = 1
	NatsServiceEndpointNameInstanceHealth NatsServiceEndpointName = 2
	NatsServiceEndpointNameStatus         NatsServiceEndpointName = 3
	NatsServiceEndpointNameMembers        NatsServiceEndpointName = 4
	NatsServiceEndpointNameStats          NatsServiceEndpointName = 5
	NatsServiceEndpointNameDirectDelivery NatsServiceEndpointName = 6
)

func (n NatsServiceEndpointName) String() string {
	switch n {
	case NatsServiceEndpointNameHealth:
		return "Health"
	case NatsServiceEndpointNameInstanceHealth:
		return "InstanceHealth"
	case NatsServiceEndpointNameStatus:
		return "Status"
	case NatsServiceEndpointNameMembers:
		return "Members"
	case NatsServiceEndpointNameStats:
		return "Stats"
	case NatsServiceEndpointNameDirectDelivery:
		return "DirectDelivery"
	default:
		return fmt.Sprintf("%d", int(n))
	}
}

func natsServiceEndpointNameIsDefined(n NatsServiceEndpointName) bool {
	return n >= NatsServiceEndpointNameHealth && n <= NatsServiceEndpointNameDirectDelivery
}

// NatsServiceRequestResult mirrors the C# enum.
type NatsServiceRequestResult int

const (
	NatsServiceRequestResultOk    NatsServiceRequestResult = 1
	NatsServiceRequestResultError NatsServiceRequestResult = 2
)

func (r NatsServiceRequestResult) String() string {
	switch r {
	case NatsServiceRequestResultOk:
		return "Ok"
	case NatsServiceRequestResultError:
		return "Error"
	default:
		return fmt.Sprintf("%d", int(r))
	}
}

func natsServiceRequestResultIsDefined(r NatsServiceRequestResult) bool {
	return r >= NatsServiceRequestResultOk && r <= NatsServiceRequestResultError
}

// NatsServiceEndpointMeasurement mirrors the C# record: bounded latency
// statistics for one service endpoint. JSON tags mirror the C#
// source-generated context (default options: PascalCase names).
type NatsServiceEndpointMeasurement struct {
	Endpoint            NatsServiceEndpointName `json:"Endpoint"`
	Requests            int64                   `json:"Requests"`
	Errors              int64                   `json:"Errors"`
	MinimumMilliseconds int64                   `json:"MinimumMilliseconds"`
	P50Milliseconds     int64                   `json:"P50Milliseconds"`
	P95Milliseconds     int64                   `json:"P95Milliseconds"`
	P99Milliseconds     int64                   `json:"P99Milliseconds"`
	MaximumMilliseconds int64                   `json:"MaximumMilliseconds"`
}

// NatsServiceEndpointMeasurementEmpty mirrors the C# Empty factory.
func NatsServiceEndpointMeasurementEmpty(endpoint NatsServiceEndpointName) NatsServiceEndpointMeasurement {
	return NatsServiceEndpointMeasurement{Endpoint: endpoint}
}

// Validate mirrors the C# Validate.
func (m NatsServiceEndpointMeasurement) Validate() error {
	if !natsServiceEndpointNameIsDefined(m.Endpoint) || m.Requests < 0 || m.Errors < 0 ||
		m.Errors > m.Requests ||
		m.MinimumMilliseconds < 0 || m.P50Milliseconds < 0 || m.P95Milliseconds < 0 ||
		m.P99Milliseconds < 0 || m.MaximumMilliseconds < 0 ||
		m.P50Milliseconds > m.P95Milliseconds || m.P95Milliseconds > m.P99Milliseconds ||
		m.MinimumMilliseconds > m.MaximumMilliseconds ||
		(m.Requests > 0 && (m.P50Milliseconds < m.MinimumMilliseconds ||
			m.P99Milliseconds < m.MaximumMilliseconds)) {
		return errors.New("The NATS service endpoint measurement is invalid.")
	}

	return nil
}

// natsServiceEndpointSampleLimit mirrors the C# SampleLimit.
const natsServiceEndpointSampleLimit = 256

// NatsServiceEndpointStats mirrors the C# class: thread-safe recorder for
// service endpoint statistics — one bounded reservoir per endpoint.
type NatsServiceEndpointStats struct {
	mu        sync.Mutex
	recorders map[NatsServiceEndpointName]*natsServiceEndpointRecorder
}

// NewNatsServiceEndpointStats mirrors the C# constructor.
func NewNatsServiceEndpointStats() *NatsServiceEndpointStats {
	return &NatsServiceEndpointStats{recorders: map[NatsServiceEndpointName]*natsServiceEndpointRecorder{}}
}

// Record mirrors the C# Record.
func (s *NatsServiceEndpointStats) Record(
	endpoint NatsServiceEndpointName,
	result NatsServiceRequestResult,
	duration time.Duration,
) {
	if !natsServiceEndpointNameIsDefined(endpoint) {
		panic("Specified argument was out of the range of valid values. (Parameter 'endpoint')")
	}

	if !natsServiceRequestResultIsDefined(result) {
		panic("Specified argument was out of the range of valid values. (Parameter 'result')")
	}

	s.mu.Lock()
	recorder, exists := s.recorders[endpoint]
	if !exists {
		recorder = &natsServiceEndpointRecorder{}
		s.recorders[endpoint] = recorder
	}
	s.mu.Unlock()

	recorder.Record(result, duration)
}

// Snapshot mirrors the C# Snapshot.
func (s *NatsServiceEndpointStats) Snapshot() []NatsServiceEndpointMeasurement {
	s.mu.Lock()
	defer s.mu.Unlock()

	snapshot := make([]NatsServiceEndpointMeasurement, 0, len(s.recorders))
	for endpoint, recorder := range s.recorders {
		snapshot = append(snapshot, recorder.Measurement(endpoint))
	}

	sort.Slice(snapshot, func(i, j int) bool {
		return snapshot[i].Endpoint < snapshot[j].Endpoint
	})

	return snapshot
}

type natsServiceEndpointRecorder struct {
	mu          sync.Mutex
	samples     [natsServiceEndpointSampleLimit]int64
	requests    int64
	errors      int64
	sampleCount int
	sampleHead  int
}

func (r *natsServiceEndpointRecorder) Record(result NatsServiceRequestResult, duration time.Duration) {
	milliseconds := int64(math.Ceil(duration.Seconds() * 1000))
	if milliseconds < 0 {
		milliseconds = 0
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.requests++
	if result == NatsServiceRequestResultError {
		r.errors++
	}

	r.samples[r.sampleHead] = milliseconds
	r.sampleHead = (r.sampleHead + 1) % natsServiceEndpointSampleLimit
	if r.sampleCount < natsServiceEndpointSampleLimit {
		r.sampleCount++
	}
}

func (r *natsServiceEndpointRecorder) Measurement(endpoint NatsServiceEndpointName) NatsServiceEndpointMeasurement {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.requests == 0 {
		return NatsServiceEndpointMeasurementEmpty(endpoint)
	}

	window := make([]int64, r.sampleCount)
	copy(window, r.samples[:r.sampleCount])
	sort.Slice(window, func(i, j int) bool { return window[i] < window[j] })

	percentile := func(fraction float64) int64 {
		index := int(math.Ceil(fraction*float64(len(window)))) - 1
		if index < 0 {
			index = 0
		}

		if index >= len(window) {
			index = len(window) - 1
		}

		return window[index]
	}

	measurement := NatsServiceEndpointMeasurement{
		Endpoint:            endpoint,
		Requests:            r.requests,
		Errors:              r.errors,
		MinimumMilliseconds: window[0],
		P50Milliseconds:     percentile(0.50),
		P95Milliseconds:     percentile(0.95),
		P99Milliseconds:     percentile(0.99),
		MaximumMilliseconds: window[len(window)-1],
	}
	if err := measurement.Validate(); err != nil {
		panic(err)
	}

	return measurement
}

// NatsServiceStatsDocumentCurrentSchemaVersion mirrors the C# constant.
const NatsServiceStatsDocumentCurrentSchemaVersion = 1

// NatsServiceStatsDocument mirrors the C# record: the document served by the
// read-only stats service endpoint.
type NatsServiceStatsDocument struct {
	SchemaVersion    int                              `json:"SchemaVersion"`
	Cell             string                           `json:"Cell"`
	Service          string                           `json:"Service"`
	Version          string                           `json:"Version"`
	SchemaGeneration int                              `json:"SchemaGeneration"`
	Healthy          bool                             `json:"Healthy"`
	ObservedAt       time.Time                        `json:"ObservedAt"`
	Endpoints        []NatsServiceEndpointMeasurement `json:"Endpoints"`
}

// NatsServiceStatsDocumentCreate mirrors the C# Create.
func NatsServiceStatsDocumentCreate(
	cell string,
	version string,
	schemaGeneration int,
	healthy bool,
	observedAt time.Time,
	endpoints []NatsServiceEndpointMeasurement,
) (*NatsServiceStatsDocument, error) {
	if !messagingCellTokenIsValid(cell) {
		return nil, errors.New("The cell is not a bounded token. (Parameter 'cell')")
	}

	ordered := append([]NatsServiceEndpointMeasurement(nil), endpoints...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Endpoint < ordered[j].Endpoint })

	document := &NatsServiceStatsDocument{
		SchemaVersion:    NatsServiceStatsDocumentCurrentSchemaVersion,
		Cell:             cell,
		Service:          "terrascale_orchestrator_" + cell,
		Version:          version,
		SchemaGeneration: schemaGeneration,
		Healthy:          healthy,
		ObservedAt:       observedAt,
		Endpoints:        ordered,
	}

	if err := document.Validate(); err != nil {
		return nil, err
	}

	return document, nil
}

// Validate mirrors the C# Validate.
func (d *NatsServiceStatsDocument) Validate() error {
	if d.SchemaVersion != NatsServiceStatsDocumentCurrentSchemaVersion ||
		!messagingCellTokenIsValid(d.Cell) ||
		d.Service != "terrascale_orchestrator_"+d.Cell ||
		d.Version == "" || d.SchemaGeneration <= 0 || d.ObservedAt.IsZero() {
		return errors.New("The NATS service stats document is invalid.")
	}

	seen := map[NatsServiceEndpointName]struct{}{}
	for _, endpoint := range d.Endpoints {
		if _, duplicate := seen[endpoint.Endpoint]; duplicate {
			return errors.New("The NATS service stats document is invalid.")
		}

		seen[endpoint.Endpoint] = struct{}{}
		if err := endpoint.Validate(); err != nil {
			return err
		}
	}

	return nil
}
