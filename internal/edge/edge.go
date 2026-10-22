// Package edge terminates public HTTPS on this host. It obtains certificates
// from Let's Encrypt with ACME HTTP-01 and proxies each hostname to the
// loopback port of the service that claims it. HTTP/1.1, websocket and SSE
// reach the backend over HTTP/1.1; gRPC reaches it over cleartext HTTP/2.
// A backend answer asking for a replay goes to the nearest region it names
// (replay.go).
package edge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

// Edge serves :80 and :443 for the hostnames in its route table.
type Edge struct {
	certs  *autocert.Manager
	routes atomic.Pointer[map[string]int]
	proxy  *httputil.ReverseProxy
	// challenges answers HTTP-01 for the tokens this edge holds.
	challenges http.Handler
	mesh       atomic.Pointer[Mesh]
	local      http.RoundTripper // to the loopback backends
	peers      http.RoundTripper // to other regions' edges
	// peerAddr is region's edge; tests replace it.
	peerAddr func(region string) string
}

// New returns an edge that caches certificates under stateDir/edge-certs.
func New(stateDir string) *Edge { return newEdge(stateDir, nil) }

// newEdge uses client as the ACME client; nil means Let's Encrypt.
func newEdge(stateDir string, client *acme.Client) *Edge {
	e := &Edge{peerAddr: func(region string) string { return net.JoinHostPort(region+"."+mesh.Domain, "443") }}
	e.peers = newPeerTransport(e)
	e.routes.Store(&map[string]int{})
	e.certs = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(filepath.Join(stateDir, "edge-certs")),
		HostPolicy: e.hostPolicy,
		Client:     client,
	}
	e.challenges = e.certs.HTTPHandler(nil)
	http1 := http.DefaultTransport.(*http.Transport).Clone()
	http1.Proxy = nil
	h2c := http1.Clone()
	h2c.Protocols = new(http.Protocols)
	h2c.Protocols.SetUnencryptedHTTP2(true)
	// gRPC streams may hold response headers back, so only HTTP/1.1 gets this.
	http1.ResponseHeaderTimeout = 30 * time.Second
	e.local = roundTripper(func(r *http.Request) (*http.Response, error) {
		if isGRPC(r) {
			return h2c.RoundTrip(r)
		}
		return http1.RoundTrip(r)
	})
	e.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			port, _ := e.port(pr.In.Host)
			pr.SetURL(&url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))})
			pr.Out.Host = pr.In.Host
			if fromPeer(pr.In) {
				// The source edge already set them from the client's connection.
				for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
					pr.Out.Header[h] = pr.In.Header[h]
				}
			} else {
				pr.SetXForwarded()
			}
			// Client-supplied address headers would spoof the X-Forwarded-For value.
			for _, h := range []string{"X-Real-IP", "True-Client-IP", "CF-Connecting-IP"} {
				pr.Out.Header.Del(h)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if err := e.replay(resp); err != nil {
				return err
			}
			if resp.Header.Get("Strict-Transport-Security") == "" {
				resp.Header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			return nil
		},
		Transport: e.local,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.WarnContext(r.Context(), "edge proxy error", "host", r.Host, "error", err)
			// A backend that refused the connection never saw the request, so
			// the source edge may try the next region.
			var op *net.OpError
			if fromPeer(r) && errors.As(err, &op) && op.Op == "dial" {
				w.Header().Set(replayDownHeader, "1")
			}
			w.WriteHeader(http.StatusBadGateway)
		},
		// gRPC and SSE streams must reach the client as each message arrives.
		FlushInterval: -1,
	}
	return e
}

// SetRoutes replaces the hostname -> 127.0.0.1 port table. Certificates are
// issued only for hostnames in the table.
func (e *Edge) SetRoutes(routes map[string]int) {
	table := make(map[string]int, len(routes))
	for host, port := range routes {
		table[strings.ToLower(host)] = port
	}
	e.routes.Store(&table)
}

// Run serves :80 and :443 until ctx ends.
func (e *Edge) Run(ctx context.Context) error {
	httpLn, err := net.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("edge: listen :80: %w", err)
	}
	tlsLn, err := net.Listen("tcp", ":443")
	if err != nil {
		httpLn.Close()
		return fmt.Errorf("edge: listen :443: %w", err)
	}
	return e.serve(ctx, httpLn, tlsLn)
}

func (e *Edge) serve(ctx context.Context, httpLn, tlsLn net.Listener) error {
	// :80 answers HTTP-01 challenges and redirects everything else to https.
	plain := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := e.port(r.Host); !ok {
				http.NotFound(w, r)
				return
			}
			if isChallenge(r) {
				e.serveChallenge(w, r)
				return
			}
			// GeoDNS health checks probe region IPs, where SNI cannot pick a
			// certificate; readiness carries no secrets, so :80 answers it.
			if r.URL.Path == "/readyz" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
				e.proxy.ServeHTTP(w, r)
				return
			}
			e.challenges.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	// No read or write timeout on :443: gRPC, SSE and websocket streams stay
	// open for hours.
	tlsConfig := e.certs.TLSConfig()
	tlsConfig.GetConfigForClient = e.meshTLS
	public := &http.Server{
		Handler:           http.HandlerFunc(e.serveHTTPS),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	errs := make(chan error, 2)
	go func() { errs <- plain.Serve(httpLn) }()
	go func() { errs <- public.ServeTLS(tlsLn, "", "") }()
	var err error
	select {
	case <-ctx.Done():
	case err = <-errs:
	}
	plain.Close()
	public.Close()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

const netbirdHost = "netbird.terrascale.tech"

func (e *Edge) serveHTTPS(w http.ResponseWriter, r *http.Request) {
	peer := fromPeer(r)
	if peer && isChallenge(r) {
		e.serveChallenge(w, r)
		return
	}
	if _, ok := e.port(r.Host); !ok {
		if peer {
			w.Header().Set(replayDownHeader, "1")
		}
		http.NotFound(w, r)
		return
	}
	// NetBird's unauthenticated owner claim is only for ts-orch on loopback
	// (manager.BootstrapServer); the public route never offers it.
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if strings.EqualFold(host, netbirdHost) && path.Clean("/"+r.URL.Path) == "/api/setup" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !peer {
		r.Header.Del(replaySrcHeader)
		r.Header.Del(replayFailedHeader)
	}
	if !isGRPC(r) {
		r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
		if !peer && r.Header.Get("Upgrade") == "" {
			if err := bufferBody(r); err != nil {
				http.Error(w, "bad request body", http.StatusBadRequest)
				return
			}
		}
	}
	e.proxy.ServeHTTP(w, r)
}

func (e *Edge) hostPolicy(_ context.Context, host string) error {
	if _, ok := e.port(host); !ok {
		return fmt.Errorf("edge: no route for host %q", host)
	}
	return nil
}

func (e *Edge) port(host string) (int, bool) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	port, ok := (*e.routes.Load())[strings.ToLower(host)]
	return port, ok
}

func isGRPC(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return r.ProtoMajor == 2 && (ct == "application/grpc" || strings.HasPrefix(ct, "application/grpc+"))
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
