// Package edge terminates public HTTPS on this host. It obtains certificates
// from Let's Encrypt with ACME HTTP-01 and proxies each hostname to the
// loopback port of the service that claims it. HTTP/1.1, websocket and SSE
// reach the backend over HTTP/1.1; gRPC reaches it over cleartext HTTP/2.
package edge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Edge serves :80 and :443 for the hostnames in its route table.
type Edge struct {
	certs  *autocert.Manager
	routes atomic.Pointer[map[string]int]
	proxy  *httputil.ReverseProxy
}

// New returns an edge that caches certificates under stateDir/edge-certs.
func New(stateDir string) *Edge { return newEdge(stateDir, nil) }

// newEdge uses client as the ACME client; nil means Let's Encrypt.
func newEdge(stateDir string, client *acme.Client) *Edge {
	e := &Edge{}
	e.routes.Store(&map[string]int{})
	e.certs = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(filepath.Join(stateDir, "edge-certs")),
		HostPolicy: e.hostPolicy,
		Client:     client,
	}
	http1 := http.DefaultTransport.(*http.Transport).Clone()
	http1.Proxy = nil
	h2c := http1.Clone()
	h2c.Protocols = new(http.Protocols)
	h2c.Protocols.SetUnencryptedHTTP2(true)
	// gRPC streams may hold response headers back, so only HTTP/1.1 gets this.
	http1.ResponseHeaderTimeout = 30 * time.Second
	e.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			port, _ := e.port(pr.In.Host)
			pr.SetURL(&url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))})
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
			// Client-supplied address headers would spoof the X-Forwarded-For value.
			for _, h := range []string{"X-Real-IP", "True-Client-IP", "CF-Connecting-IP"} {
				pr.Out.Header.Del(h)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.Header.Get("Strict-Transport-Security") == "" {
				resp.Header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			return nil
		},
		Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
			if isGRPC(r) {
				return h2c.RoundTrip(r)
			}
			return http1.RoundTrip(r)
		}),
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
	challenges := e.certs.HTTPHandler(nil)
	plain := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := e.port(r.Host); !ok {
				http.NotFound(w, r)
				return
			}
			challenges.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	// No read or write timeout on :443: gRPC, SSE and websocket streams stay
	// open for hours.
	public := &http.Server{
		Handler:           http.HandlerFunc(e.serveHTTPS),
		TLSConfig:         e.certs.TLSConfig(),
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

func (e *Edge) serveHTTPS(w http.ResponseWriter, r *http.Request) {
	if _, ok := e.port(r.Host); !ok {
		http.NotFound(w, r)
		return
	}
	if !isGRPC(r) {
		r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
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
