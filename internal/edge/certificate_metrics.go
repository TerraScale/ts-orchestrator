package edge

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

type orderTransport struct {
	success *atomic.Uint64
	failure *atomic.Uint64
	next    http.RoundTripper
}

func (t orderTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.next.RoundTrip(r)
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/new-order") {
		if err == nil && response.StatusCode == http.StatusCreated {
			t.success.Add(1)
		} else {
			t.failure.Add(1)
		}
	}
	return response, err
}

func WriteLocalCertificateMetrics(ctx context.Context, w io.Writer) {
	if e := localEdge.Load(); e != nil {
		e.WriteCertificateMetrics(ctx, w)
	}
}

func (e *Edge) WriteCertificateMetrics(ctx context.Context, w io.Writer) {
	inventory := e.Inventory(ctx)
	expiry := map[string]map[string]int64{}
	for _, cert := range inventory.Certificates {
		for _, name := range e.servedNames() {
			if !slicesContainsName(cert.Names, name) {
				continue
			}
			if expiry[name] == nil {
				expiry[name] = map[string]int64{}
			}
			previous, ok := expiry[name][cert.KeyType]
			if !ok || cert.NotAfter.Unix() < previous {
				expiry[name][cert.KeyType] = cert.NotAfter.Unix()
			}
		}
	}
	for name, types := range expiry {
		for keyType, until := range types {
			observability.WriteGauge(w, observability.Series("ts_edge_certificate_not_after", "name", name, "key_type", keyType), float64(until))
		}
	}
	observability.WriteGauge(w, "ts_edge_certificate_names_missing", float64(len(inventory.MissingNames)))
	observability.WriteCounter(w, "ts_edge_ecdsa_unsupported_handshakes_total", float64(e.certs.cache.unsupportedHandshakes.Load()))
	observability.WriteCounter(w, observability.Series("ts_edge_autocert_orders_total", "outcome", "success"), float64(e.certs.success.Load()))
	observability.WriteCounter(w, observability.Series("ts_edge_autocert_orders_total", "outcome", "error"), float64(e.certs.failure.Load()))
}

func slicesContainsName(names []string, name string) bool {
	name = strings.ToLower(name)
	for _, candidate := range names {
		if candidate == name {
			return true
		}
		if strings.HasPrefix(candidate, "*.") && strings.Count(name, ".") == strings.Count(candidate, ".") && strings.HasSuffix(name, candidate[1:]) {
			return true
		}
	}
	return false
}
