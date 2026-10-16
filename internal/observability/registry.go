package observability

import (
	"bytes"
	"io"
	"slices"
	"sync"

	"github.com/VictoriaMetrics/metrics"
)

// MetricPrefix is the common namespace of every orchestrator metric.
const MetricPrefix = "ts_orch_"

// Registry composes the metric sets that feature slices own and scrape-time
// writers that render state only when scraped. It deliberately avoids the
// VictoriaMetrics global set, so tests and several in-process members do not
// double-register series. The sets that feature slices own (for example
// placement.Metrics, delivery.Metrics, oci.Metrics and LogMetrics) are still
// process-wide: several in-process members registering the same set share
// its counter values. A production process runs exactly one member.
type Registry struct {
	mu      sync.Mutex
	sets    []*metrics.Set
	writers []func(io.Writer)
	// processMetrics adds process_* and go_* series. Several in-process
	// members would repeat them; a test or secondary registry can omit them.
	processMetrics bool
}

// NewRegistry returns an empty registry. processMetrics adds the Go runtime
// and process series that VictoriaMetrics/metrics collects.
func NewRegistry(processMetrics bool) *Registry {
	metrics.ExposeMetadata(true)
	return &Registry{processMetrics: processMetrics}
}

// Register adds one slice's metric set. Registering the same set twice is a
// no-op.
func (registry *Registry) Register(set *metrics.Set) {
	if registry == nil || set == nil {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for _, existing := range registry.sets {
		if existing == set {
			return
		}
	}
	registry.sets = append(registry.sets, set)
}

// RegisterWriter adds a scrape-time writer. Writers must be fast or cached:
// a scrape and every cross-member snapshot call them synchronously.
func (registry *Registry) RegisterWriter(write func(io.Writer)) {
	if registry == nil || write == nil {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.writers = append(registry.writers, write)
}

// WritePrometheus renders every registered series in Prometheus text format.
func (registry *Registry) WritePrometheus(w io.Writer) {
	if registry == nil {
		return
	}
	registry.mu.Lock()
	sets := slices.Clone(registry.sets)
	writers := slices.Clone(registry.writers)
	process := registry.processMetrics
	registry.mu.Unlock()
	if process {
		metrics.WriteProcessMetrics(w)
	}
	for _, set := range sets {
		set.WritePrometheus(w)
	}
	for _, write := range writers {
		write(w)
	}
}

// Text returns the exposition bounded to limit bytes. A truncated exposition
// ends at the last complete line and reports truncated=true.
func (registry *Registry) Text(limit int) (string, bool) {
	var buffer bytes.Buffer
	registry.WritePrometheus(&buffer)
	data := buffer.Bytes()
	if limit <= 0 || len(data) <= limit {
		return string(data), false
	}
	data = data[:limit]
	if cut := bytes.LastIndexByte(data, '\n'); cut >= 0 {
		data = data[:cut+1]
	} else {
		data = nil
	}
	return string(data), true
}
