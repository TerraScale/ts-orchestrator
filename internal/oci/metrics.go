package oci

import (
	"cmp"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"github.com/VictoriaMetrics/metrics"
	"github.com/oracle/oci-go-sdk/v65/common"
)

// Metrics is the OCI slice's metric set. Every SDK client built by
// newSDKProvider records into it through instrumentedDispatcher.
var Metrics = metrics.NewSet()

// maxOperationsPerService bounds label cardinality. A raw path never
// becomes a label: OCIDs and names are templated, and unknown shapes past
// the bound collapse into "other".
const maxOperationsPerService = 64

var apiStats = &operationStats{byKey: map[apiOperationKey]*observability.OCIOperationView{},
	perService: map[string]int{}}

type apiOperationKey struct {
	service   string
	operation string
}

type operationStats struct {
	mu         sync.Mutex
	byKey      map[apiOperationKey]*observability.OCIOperationView
	perService map[string]int
}

// instrumentedDispatcher wraps one SDK client's HTTP dispatcher. It observes
// only the method, a templated route, the status and the latency; request
// and response bodies, headers and signatures are never read.
type instrumentedDispatcher struct {
	next    common.HTTPRequestDispatcher
	service string
	now     func() time.Time
}

func instrument(next common.HTTPRequestDispatcher, service string) common.HTTPRequestDispatcher {
	if next == nil {
		next = http.DefaultClient
	}
	return &instrumentedDispatcher{next: next, service: service, now: time.Now}
}

func (dispatcher *instrumentedDispatcher) Do(request *http.Request) (*http.Response, error) {
	started := dispatcher.now()
	response, err := dispatcher.next.Do(request)
	elapsed := dispatcher.now().Sub(started)
	status := 0
	if response != nil {
		status = response.StatusCode
	}
	apiStats.record(dispatcher.service, operationTemplate(request), status, err != nil, elapsed)
	return response, err
}

func (stats *operationStats) record(service, operation string, status int, transportError bool, elapsed time.Duration) {
	stats.mu.Lock()
	key := apiOperationKey{service: service, operation: operation}
	view, known := stats.byKey[key]
	if !known {
		if stats.perService[service] >= maxOperationsPerService {
			key.operation = "other"
			view, known = stats.byKey[key]
		}
		if !known {
			view = &observability.OCIOperationView{Service: service, Operation: key.operation}
			stats.byKey[key] = view
			stats.perService[service]++
		}
	}
	seconds := elapsed.Seconds()
	view.Calls++
	view.TotalSeconds += seconds
	view.MaxSeconds = max(view.MaxSeconds, seconds)
	view.LastStatus = status
	failed := transportError || status >= 400
	if failed {
		view.Errors++
		view.LastErrorCode = status
	}
	if status == http.StatusTooManyRequests {
		view.Throttled++
	}
	operation = key.operation
	stats.mu.Unlock()

	code := strconv.Itoa(status)
	if transportError {
		code = "transport_error"
	}
	labels := []string{"service", service, "operation", operation}
	Metrics.GetOrCreateCounter(observability.Series(observability.MetricPrefix+"oci_requests_total",
		slices.Concat(labels, []string{"code", code})...)).Inc()
	Metrics.GetOrCreatePrometheusHistogram(observability.Series(observability.MetricPrefix+"oci_request_duration_seconds",
		labels...)).Update(seconds)
	if status == http.StatusTooManyRequests {
		Metrics.GetOrCreateCounter(observability.Series(observability.MetricPrefix+"oci_throttled_total", labels...)).Inc()
	}
}

// APIView returns per-operation OCI API usage since process start and the
// latest fleet inventory by lifecycle state.
func APIView() observability.OCIView {
	fleet := FleetInventory()
	apiStats.mu.Lock()
	defer apiStats.mu.Unlock()
	view := observability.OCIView{Operations: make([]observability.OCIOperationView, 0, len(apiStats.byKey)),
		Fleet: fleet}
	for _, operation := range apiStats.byKey {
		view.Operations = append(view.Operations, *operation)
	}
	slices.SortFunc(view.Operations, func(a, b observability.OCIOperationView) int {
		return cmp.Or(cmp.Compare(a.Service, b.Service), cmp.Compare(a.Operation, b.Operation))
	})
	return view
}

// operationTemplate turns "GET /20160918/instances/ocid1.instance...?page=x"
// into "GET /instances/{id}". The API version segment is dropped, resource
// identifiers become {id}, and only a bounded action query is kept.
func operationTemplate(request *http.Request) string {
	if request == nil || request.URL == nil {
		return "unknown"
	}
	segments := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(segments) > 0 && apiVersionSegment(segments[0]) {
		segments = segments[1:]
	}
	if len(segments) > 8 {
		segments = append(segments[:8], "...")
	}
	for index, segment := range segments {
		if identifierSegment(segment) {
			segments[index] = "{id}"
		}
	}
	template := request.Method + " /" + strings.Join(segments, "/")
	if action := request.URL.Query().Get("action"); action != "" {
		if !boundedAction(action) {
			action = "{action}"
		}
		template += "?action=" + action
	}
	return template
}

func apiVersionSegment(segment string) bool {
	if len(segment) != 8 {
		return false
	}
	for _, character := range segment {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func identifierSegment(segment string) bool {
	if strings.HasPrefix(segment, "ocid1.") || len(segment) > 40 || strings.ContainsAny(segment, ".:@%=") {
		return true
	}
	digits := 0
	for _, character := range segment {
		if character >= '0' && character <= '9' {
			digits++
		}
	}
	return digits > 0 && digits*2 >= len(segment)
}

func boundedAction(action string) bool {
	if len(action) > 32 {
		return false
	}
	for _, character := range action {
		if (character < 'A' || character > 'Z') && character != '_' {
			return false
		}
	}
	return true
}
