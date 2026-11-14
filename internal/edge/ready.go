package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

type ReadinessRoute struct {
	Host string
	Port int
	Path string
}

type Readiness struct {
	Ready        bool
	Missing      []string
	MissingNames []string
	NotDurable   []string
	infra        []string
}

func (r Readiness) InfraErr() error {
	if len(r.infra) == 0 {
		return nil
	}
	return fmt.Errorf("edge not ready: %s", strings.Join(r.infra, ", "))
}

func (e *Edge) Readiness(ctx context.Context) Readiness {
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	conditions, err := e.ready(bounded)
	cancel()
	if err != nil {
		conditions = append(conditions, err.Error())
	}
	e.readyStatus.Store(&readinessVerdict{len(conditions) == 0, time.Now(), conditions})
	return e.report()
}

func (e *Edge) report() Readiness {
	infra := e.infrastructure()
	pending, missingNames := e.certificateGaps()
	missing := append(slices.Clone(infra), pending...)
	return Readiness{Ready: len(missing) == 0 && len(missingNames) == 0, Missing: missing, MissingNames: missingNames, NotDurable: e.notDurable(), infra: infra}
}

func (e *Edge) SetReadinessRoutes(routes []ReadinessRoute) {
	e.readyRoutes.Store(&routes)
}

func listenerBit(protocol string) uint32 {
	return map[string]uint32{"http": 1, "https": 2, "postgres": 4, "terrabase": 8}[protocol]
}

func (e *Edge) serveReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	readiness := e.Readiness(r.Context())
	if readiness.Ready {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(struct {
		Ready        bool     `json:"ready"`
		Missing      []string `json:"missing"`
		MissingNames []string `json:"missing_names"`
		NotDurable   []string `json:"not_durable"`
	}{readiness.Ready, readiness.Missing, readiness.MissingNames, readiness.NotDurable})
}

func (e *Edge) readiness() (bool, []string, []string) {
	report := e.report()
	return report.Ready, report.Missing, report.MissingNames
}

func (e *Edge) infrastructure() []string {
	verdict := e.readyStatus.Load()
	missing := []string{}
	if verdict == nil || time.Since(verdict.at) > 10*time.Second {
		missing = append(missing, "edge readiness unavailable")
	}
	if verdict != nil {
		missing = append(missing, verdict.conditions...)
	}
	return missing
}

func (e *Edge) certificateGaps() ([]string, []string) {
	pending, missingNames := []string{}, []string{}
	for _, name := range e.servedNames() {
		if e.servesTrusted(name) == nil {
			continue
		}
		if e.certMissing(name) {
			missingNames = append(missingNames, name)
		} else {
			pending = append(pending, "certificate "+name+" pending")
		}
	}
	return pending, missingNames
}

func readinessHello(name string) *tls.ClientHelloInfo {
	suites := []uint16{}
	for _, suite := range tls.CipherSuites() {
		suites = append(suites, suite.ID)
	}
	return &tls.ClientHelloInfo{
		ServerName:        name,
		CipherSuites:      suites,
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		SupportedPoints:   []uint8{0},
		SupportedProtos:   []string{"h2", "http/1.1"},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.PSSWithSHA256, tls.PSSWithSHA384, tls.PSSWithSHA512, tls.PKCS1WithSHA256, tls.PKCS1WithSHA384, tls.PKCS1WithSHA512},
	}
}

func (e *Edge) servesTrusted(name string) error {
	cert, _, err := e.selectCertificate(readinessHello(name))
	if err != nil {
		return err
	}
	intermediates := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		intermediates.AddCert(parsed)
	}
	_, err = cert.Leaf.Verify(x509.VerifyOptions{DNSName: name, Intermediates: intermediates})
	return err
}

func (e *Edge) notDurable() []string {
	names := []string{}
	e.certs.cache.volatile.Range(func(key, _ any) bool { names = append(names, key.(string)); return true })
	slices.Sort(names)
	return names
}

func (e *Edge) certMissing(name string) bool {
	seen, _ := e.certSeen.Load(name)
	grace, ok := seen.(time.Time)
	if !ok || time.Since(grace) < issueTTL {
		return false
	}
	return true
}

func (e *Edge) ready(ctx context.Context) ([]string, error) {
	conditions := []string{}
	if e.listeners.Load() != 15 {
		conditions = append(conditions, "listeners unavailable")
	}
	if e.bootstrapErr != nil {
		return conditions, e.bootstrapErr
	}
	held, err := e.bootstrap.Ingress(ctx)
	if err != nil {
		return conditions, err
	}
	if held != nil {
		conditions = append(conditions, "ingress held")
	} else if router := e.regional.Load(); router != nil {
		router.ingressMu.Lock()
		draining := router.held != nil
		router.ingressMu.Unlock()
		if draining {
			conditions = append(conditions, "node draining")
		}
	}
	web, postgres := *e.routes.Load(), *e.postgres.Load()
	if len(web)+len(postgres) == 0 {
		conditions = append(conditions, "routes unavailable")
	}
	routes := *e.readyRoutes.Load()
	if len(routes) == 0 {
		conditions = append(conditions, "readiness routes unavailable")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, route := range routes {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(route.Port))+route.Path, nil)
		if err != nil {
			return conditions, err
		}
		req.Host = route.Host
		resp, err := client.Do(req)
		if err != nil {
			conditions = append(conditions, "backend unavailable")
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			conditions = append(conditions, "backend not ready")
		}
	}
	for _, port := range postgres {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			conditions = append(conditions, "postgres backend unavailable")
			continue
		}
		conn.Close()
	}
	return conditions, nil
}

type readinessVerdict struct {
	ok         bool
	at         time.Time
	conditions []string
}

func (e *Edge) reconcileReadiness(ctx context.Context) {
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	var reported *bool
	for {
		if readiness := e.Readiness(ctx); reported == nil || *reported != readiness.Ready {
			slog.InfoContext(ctx, "edge readiness changed", "ready", readiness.Ready, "missing", readiness.Missing, "missing_names", readiness.MissingNames)
			reported = &readiness.Ready
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (e *Edge) serveCertificateMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	e.WriteCertificateMetrics(r.Context(), w)
	e.certs.cache.failures.Range(func(key, value any) bool {
		name, variant := certificateVariant(key.(string))
		observability.WriteCounter(w, observability.Series("ts_orch_edge_certificate_order_failures_total", "name", name, "variant", variant), float64(value.(*atomic.Uint64).Load()))
		return true
	})
	e.certs.cache.memory.Range(func(key, value any) bool {
		name, variant := certificateVariant(key.(string))
		remaining := time.Until(value.(cachedCertificate).cert.Leaf.NotAfter).Seconds()
		_, _ = fmt.Fprintf(w, "%s %g\n", observability.Series("ts_orch_edge_certificate_expiry_seconds", "name", name, "variant", variant), remaining)
		return true
	})
	names := map[string]bool{}
	e.certs.cache.unsupported.Range(func(key, _ any) bool { names[certificateName(key.(string))] = true; return true })
	_, _ = fmt.Fprintf(w, "ts_orch_edge_certificate_blocked_names %d\n", len(names))
	count := 0
	e.certs.cache.unsupported.Range(func(_, _ any) bool { count++; return true })
	_, _ = io.WriteString(w, fmt.Sprintf("ts_orch_edge_certificate_unsupported %d\n", count))
	volatile := 0
	e.certs.cache.volatile.Range(func(_, _ any) bool { volatile++; return true })
	_, _ = fmt.Fprintf(w, "ts_orch_edge_certificate_not_durable %d\n", volatile)
}
