package edge

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/VictoriaMetrics/metrics"
)

var durationBounds = [...]float64{.0001, .00025, .0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30}

type requestDurationKey struct{}

type transportDurationKey struct{}

type requestDuration struct{ upstream atomic.Int64 }

type durationLabels struct{ name, region string }

type durationHistogram struct {
	set             *metrics.Set
	total, upstream *metrics.PrometheusHistogram
}

func newDurationHistogram(labels durationLabels) *durationHistogram {
	set := metrics.NewSet()
	name := func(stage string) string {
		return observability.Series("ts_orch_edge_request_duration_seconds", "name", labels.name, "region", labels.region, "stage", stage)
	}
	return &durationHistogram{set, set.NewPrometheusHistogramExt(name("total"), durationBounds[:]), set.NewPrometheusHistogramExt(name("upstream"), durationBounds[:])}
}

func (e *Edge) measureRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		name := r.Host
		if host, _, err := net.SplitHostPort(name); err == nil {
			name = host
		}
		name = strings.ToLower(name)
		if _, served := (*e.routes.Load())[name]; !served {
			next.ServeHTTP(w, r)
			return
		}
		region := "local"
		if mesh := e.meshNode(); mesh != nil {
			region = mesh.Region()
		}
		labels := durationLabels{name, region}
		value, ok := e.requestDurations.Load(labels)
		if !ok {
			value, _ = e.requestDurations.LoadOrStore(labels, newDurationHistogram(labels))
		}
		histogram := value.(*durationHistogram)
		duration := new(requestDuration)
		defer func() {
			histogram.upstream.Update(time.Duration(duration.upstream.Load()).Seconds())
			histogram.total.UpdateDuration(start)
		}()
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestDurationKey{}, duration)))
	})
}

type durationTransport struct{ next http.RoundTripper }

func (t durationTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	duration, ok := r.Context().Value(requestDurationKey{}).(*requestDuration)
	if !ok || r.Context().Value(transportDurationKey{}) == true {
		return t.next.RoundTrip(r)
	}
	start := time.Now()
	response, err := t.next.RoundTrip(r.WithContext(context.WithValue(r.Context(), transportDurationKey{}, true)))
	duration.upstream.Add(int64(time.Since(start)))
	if response != nil && response.Body != nil {
		if response.Request != nil {
			response.Request = response.Request.WithContext(context.WithValue(response.Request.Context(), transportDurationKey{}, false))
		}
		body := durationBody{response.Body, duration}
		if writer, ok := response.Body.(io.Writer); ok {
			response.Body = durationDuplex{body, writer}
		} else {
			response.Body = body
		}
	}
	return response, err
}

type durationBody struct {
	io.ReadCloser
	duration *requestDuration
}

func (b durationBody) Read(p []byte) (int, error) {
	start := time.Now()
	n, err := b.ReadCloser.Read(p)
	b.duration.upstream.Add(int64(time.Since(start)))
	return n, err
}

type durationDuplex struct {
	durationBody
	io.Writer
}

func (b durationDuplex) CloseWrite() error {
	if writer, ok := b.ReadCloser.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (e *Edge) WriteRequestMetrics(w io.Writer) {
	observability.WriteGauge(w, "ts_orch_edge_upstream_connections", float64(e.upstreamSockets.count()))
	observability.WriteGauge(w, "ts_orch_edge_upstream_connection_limit", maxUpstreamConnections)
	e.requestDurations.Range(func(key, value any) bool {
		if _, served := (*e.routes.Load())[key.(durationLabels).name]; !served {
			e.requestDurations.Delete(key)
			return true
		}
		value.(*durationHistogram).set.WritePrometheus(w)
		return true
	})
}
