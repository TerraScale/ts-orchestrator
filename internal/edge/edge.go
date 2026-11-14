package edge

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/TerraScale/ts-orchestrator/internal/handoff"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	netbirddashboard "github.com/TerraScale/ts-orchestrator/internal/netbird/dashboard"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutmaintenance"
)

type Edge struct {
	bootstrap        *rolloutmaintenance.Store
	bootstrapErr     error
	bootstrapBarrier bootstrapBarrier
	listen           func(network, address string) (net.Listener, error) // net.Listen; tests use ephemeral ports.
	terrabase        func() (string, error)
	certs            *autocert.Manager
	certificateDir   string
	held             sync.Map
	listeners        atomic.Uint32
	readyRoutes      atomic.Pointer[[]ReadinessRoute]
	orderSuccess     atomic.Uint64
	orderFailure     atomic.Uint64
	unsupported      atomic.Uint64
	routes           atomic.Pointer[map[string]int]
	postgres         atomic.Pointer[map[string]int]
	pgKeys           postgresKeys
	pgHandshakes     chan struct{}
	pgHandshakeMu    sync.Mutex
	pgHandshakeN     map[string]int
	pgSessions       chan struct{}
	pgRelays         chan struct{}
	pgControl        chan struct{}
	serviceRoutes    atomic.Pointer[serviceRoutes]
	peerEdges        atomic.Pointer[func() []mesh.WorkerPeer]
	edgeTransports   sync.Map
	edgeNext         sync.Map
	proxy            *httputil.ReverseProxy
	// challenges answers HTTP-01 for the tokens this edge holds.
	challenges http.Handler
	mesh       atomic.Pointer[Mesh]
	regional   atomic.Pointer[regionalRouter]
	local      http.RoundTripper // to the loopback backends
	peers      http.RoundTripper // to other regions' edges
	// peerAddr is region's edge; tests replace it.
	peerAddr func(region string) string
	// spoolDir holds request bodies too large to keep in memory for a replay.
	spoolDir           string
	requestProofSecret atomic.Pointer[[]byte]
	netbirdDashboard   *netbirddashboard.Handler
	draining           atomic.Bool
	lastHealthProbe    atomic.Int64
}

// New returns an edge that caches certificates under stateDir/edge-certs.
func New(stateDir string) *Edge { return newEdge(stateDir, nil) }

// newEdge uses client as the ACME client; nil means Let's Encrypt.
func newEdge(stateDir string, client *acme.Client) *Edge {
	e := &Edge{
		pgRelays: make(chan struct{}, 32), pgControl: make(chan struct{}, 32),
		listen:       net.Listen,
		terrabase:    terrabaseInternal,
		pgHandshakes: make(chan struct{}, maxPostgresHandshakeAll), pgHandshakeN: map[string]int{},
		pgSessions:       make(chan struct{}, maxPostgresConns),
		peerAddr:         func(region string) string { return net.JoinHostPort(region+"."+mesh.Domain, "443") },
		spoolDir:         filepath.Join(stateDir, "edge-spool"),
		netbirdDashboard: netbirddashboard.New(stateDir),
	}
	e.bootstrap, e.bootstrapErr = rolloutmaintenance.Open(stateDir)
	e.peers = newPeerTransport(e)
	e.routes.Store(&map[string]int{})
	e.postgres.Store(&map[string]int{})
	e.certs = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(filepath.Join(stateDir, "edge-certs")),
		HostPolicy: e.hostPolicy,
		Client:     client,
	}
	e.certs.Cache = certificateObservation{Cache: e.certs.Cache, edge: e}
	e.certificateDir = filepath.Join(stateDir, "edge-certs")
	if client == nil {
		e.certs.Client = &acme.Client{DirectoryURL: autocert.DefaultACMEDirectory}
	}
	observed := *http.DefaultClient
	if e.certs.Client.HTTPClient != nil {
		observed = *e.certs.Client.HTTPClient
	}
	transport := observed.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	observed.Transport = orderTransport{edge: e, next: transport}
	e.certs.Client.HTTPClient = &observed
	e.challenges = e.certs.HTTPHandler(nil)
	localEdge.Store(e)
	http1 := http.DefaultTransport.(*http.Transport).Clone()
	http1.Proxy = nil
	http1.DialContext = dialHandoff
	h2c := http1.Clone()
	h2c.Protocols = new(http.Protocols)
	h2c.Protocols.SetUnencryptedHTTP2(true)
	// gRPC streams may hold response headers back, so only HTTP/1.1 gets this.
	http1.ResponseHeaderTimeout = 30 * time.Second
	e.local = roundTripper(func(r *http.Request) (*http.Response, error) {
		if target, ok := r.Context().Value(edgeTargetKey{}).(edgeTarget); ok {
			return e.peerEdgeRoundTrip(r, target)
		}
		r = traceBackend(r)
		if r.Context().Value(edgeHopKey{}) != nil {
			if isGRPC(r) {
				return h2c.RoundTrip(r)
			}
			return http1.RoundTrip(r)
		}
		if r.URL.Port() == "8080" {
			if response, err := e.regionalRoundTrip(r, false); response != nil || err != nil {
				return response, err
			}
		}
		if resp, err := e.failover(r); resp != nil || err != nil {
			return resp, err
		}
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
			pr.Out.Header.Del(edgeHopHeader)
			pr.Out.Header.Del(peerCredentialHeader)
			if websocketHandshake(pr.Out) {
				pr.Out.Header.Set("Upgrade", "websocket")
			}
			// Rewrite restores this even if Connection named it as hop-by-hop.
			pr.Out.Header.Set(requestIDHeader, pr.In.Header.Get(requestIDHeader))
			if proof := e.requestProof(pr.In.Header.Get(requestIDHeader)); proof != "" {
				pr.Out.Header.Set(requestProofHeader, proof)
			}
			if fromPeer(pr.In) || pr.In.Context().Value(edgeHopKey{}) != nil {
				// The source edge already set them from the client's connection.
				for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
					pr.Out.Header[h] = pr.In.Header[h]
				}
				pr.Out = traceWrite(pr.In, pr.Out)
			} else {
				pr.SetXForwarded()
			}
			// Client-supplied address headers would spoof the X-Forwarded-For value.
			for _, h := range []string{"X-Real-IP", "True-Client-IP", "CF-Connecting-IP"} {
				pr.Out.Header.Del(h)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.Request.Context().Value(edgeHopKey{}) == nil {
				if err := e.replay(resp); err != nil {
					return err
				}
			}
			locateDatabaseHome(resp)
			// The ingress response already carries the authoritative identity.
			resp.Header.Del(requestIDHeader)
			resp.Trailer.Del(requestIDHeader)
			resp.Header.Del(requestProofHeader)
			resp.Trailer.Del(requestProofHeader)
			if resp.StatusCode != http.StatusSwitchingProtocols {
				resp.Body = identityResponseBody{resp.Body, resp}
			}
			secureHeaders(resp.Header)
			return nil
		},
		Transport: e.local,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.WarnContext(r.Context(), "edge proxy error", append([]any{"host", r.Host, "request_id", r.Header.Get(requestIDHeader), "error", err}, proxyErrorContext(r)...)...)
			// A backend that never received the whole request did not run it,
			// so the source edge may try the next region.
			if fromPeer(r) && !wroteBackend(r) {
				w.Header().Set(replayDownHeader, "1")
			}
			secureHeaders(w.Header())
			w.WriteHeader(http.StatusBadGateway)
		},
		// gRPC and SSE streams must reach the client as each message arrives.
		FlushInterval: -1,
	}
	return e
}

// SetRoutes replaces the hostname -> 127.0.0.1 port tables for HTTPS (web)
// and Postgres. Certificates are issued only for hostnames in the tables.
func (e *Edge) SetRoutes(web, postgres map[string]int) {
	services := make(map[string]string, len(web))
	ready := make([]string, 0, len(web))
	for host := range web {
		services[host] = host
		ready = append(ready, host)
	}
	e.SetServiceRoutes(web, postgres, services, ready)
}

func (e *Edge) setRoutes(web, postgres map[string]int) {
	lower := func(routes map[string]int) *map[string]int {
		table := make(map[string]int, len(routes))
		for host, port := range routes {
			table[strings.ToLower(host)] = port
		}
		return &table
	}
	e.routes.Store(lower(web))
	e.postgres.Store(lower(postgres))
}

func (e *Edge) Drain() { e.draining.Store(true) }

func (e *Edge) drainingHealth(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" {
		return false
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
			e.lastHealthProbe.Store(time.Now().UnixNano())
		}
	}
	if !e.draining.Load() {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
	return true
}

func (e *Edge) Run(ctx context.Context) error {
	listeners, stop := context.WithCancel(context.WithoutCancel(ctx))
	defer stop()
	var running sync.WaitGroup
	running.Go(func() { e.reconcileNetBirdDashboard(ctx) })
	for _, protocol := range []string{"http", "https", "postgres", "terrabase"} {
		running.Go(func() { e.runListener(listeners, protocol) })
	}
	<-ctx.Done()
	e.Drain()
	if time.Since(time.Unix(0, e.lastHealthProbe.Load())) < time.Minute {
		timer := time.NewTimer(drainGrace)
		defer timer.Stop()
		<-timer.C
	}
	stop()
	running.Wait()
	return nil
}

const drainGrace = 20 * time.Second

const clientIdleTimeout = 120 * time.Second

// httpServers is shared by production startup and the complete proxy fixtures.
func (e *Edge) httpServers() (*http.Server, *http.Server) {
	// :80 answers HTTP-01 challenges and redirects everything else to https.
	plain := &http.Server{
		Handler: countResponses("http", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !e.authorizeEdgeHop(w, r) {
				return
			}
			e.identify(w, r)
			if r.URL.Path == "/edge/ready" {
				e.ServeReady(w, r)
				return
			}
			// A Postgres hostname needs :80 only for its certificate's challenge.
			if _, ok := e.port(r.Host); !ok && !(isChallenge(r) && e.postgresHost(r.Host)) {
				http.NotFound(w, r)
				return
			}
			if isChallenge(r) {
				e.serveChallenge(w, r)
				return
			}
			// GeoDNS health checks probe region IPs, where SNI cannot pick a
			// certificate; liveness and readiness carry no secrets, so :80 answers them.
			if (r.URL.Path == "/readyz" || r.URL.Path == "/healthz") && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
				if e.drainingHealth(w, r) {
					return
				}
				e.proxy.ServeHTTP(w, withBackendTrace(r))
				return
			}
			e.challenges.ServeHTTP(w, r)
		})),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       clientIdleTimeout,
		MaxHeaderBytes:    64 << 10,
	}
	// No read or write timeout on :443: gRPC, SSE and websocket streams stay
	// open for hours.
	tlsConfig := e.certificateTLSConfig()
	tlsConfig.GetConfigForClient = e.meshTLS
	public := &http.Server{
		Handler:           countResponses("https", http.HandlerFunc(e.serveHTTPS)),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       clientIdleTimeout,
		MaxHeaderBytes:    64 << 10,
		HTTP2:             &http.HTTP2Config{WriteByteTimeout: clientIdleTimeout},
	}
	return plain, public
}

const netbirdHost = "netbird.terrascale.tech"

func (e *Edge) serveHTTPS(w http.ResponseWriter, r *http.Request) {
	switch {
	case isExtendedConnect(r):
		w, r = upgradeExtendedConnect(w, r)
	case r.Header.Get("Upgrade") != "":
		w = hijackWriter{w, !websocketHandshake(r)}
	}
	if !e.authorizeEdgeHop(w, r) {
		return
	}
	e.identify(w, r)
	if e.drainingHealth(w, r) {
		return
	}
	peer := fromPeer(r) || r.Context().Value(edgeHopKey{}) != nil
	if strings.HasPrefix(r.URL.Path, postgresCancelPath) {
		e.servePostgresCancel(w, r)
		return
	}
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
	if e.serveRegions(w, r) {
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
	r = e.routePeerEdge(r)
	if strings.EqualFold(host, netbirdHost) && !netbirdBackend(r) && r.Context().Value(edgeTargetKey{}) == nil {
		secureHeaders(w.Header())
		e.netbirdDashboard.ServeHTTP(w, r)
		return
	}
	if peer {
		r = r.WithContext(context.WithValue(r.Context(), wroteKey{}, new(atomic.Bool)))
	} else {
		r.Header.Del(replaySrcHeader)
		r.Header.Del(replayFailedHeader)
	}
	if !isGRPC(r) {
		r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
		if !peer && r.Header.Get("Upgrade") == "" {
			release, err := bufferBody(r, e.spoolDir)
			if err != nil {
				http.Error(w, "bad request body", http.StatusBadRequest)
				return
			}
			defer release()
		}
	}
	e.proxy.ServeHTTP(w, withBackendTrace(r))
}

// secureHeaders adds the response header baseline every TerraScale surface
// sends, keeping any value the backend chose.
func secureHeaders(h http.Header) {
	for name, value := range map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
	} {
		if h.Get(name) == "" {
			h.Set(name, value)
		}
	}
	// A backend with its own Content-Security-Policy decides framing there.
	if h.Get("X-Frame-Options") == "" && h.Get("Content-Security-Policy") == "" {
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
	}
}

func (e *Edge) hostPolicy(_ context.Context, host string) error {
	if _, ok := e.port(host); !ok && !e.postgresHost(host) {
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

// handoffWait bounds how long a backend dial waits out a service update. The
// executor holds the port from the old task's SIGTERM until the new task answers
// its readyPath (stop grace, process start and first readiness check: ts-auth
// needs 3-6 s); a refused dial sent nothing, so retrying is safe for any method.
// It stays under the replay peers' 30 s ResponseHeaderTimeout, so a peer edge
// answers down before its source gives up; a held TerraBase fails over instead.
const handoffWait = 20 * time.Second

func dialHandoff(ctx context.Context, network, address string) (net.Conn, error) {
	return dialHandoffWithin(ctx, network, address, handoffWait)
}

func dialHandoffWithin(ctx context.Context, network, address string, wait time.Duration) (net.Conn, error) {
	var dialer net.Dialer
	deadline := time.Now().Add(wait)
	if _, p, err := net.SplitHostPort(address); err == nil {
		if port, err := strconv.ParseUint(p, 10, 16); err == nil {
			handoff.Wait(ctx, uint16(port), deadline)
		}
	}
	for {
		conn, err := dialer.DialContext(ctx, network, address)
		if err == nil || !errors.Is(err, syscall.ECONNREFUSED) || time.Now().After(deadline) {
			return conn, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (e *Edge) certificateTLSConfig() *tls.Config {
	config := e.certs.TLSConfig()
	config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := e.certs.GetCertificate(hello)
		if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acme.ALPNProto {
			return cert, err
		}
		if err == nil && cert != nil {
			e.rememberCertificate(hello.ServerName, cert)
		}
		if (err != nil || cert != nil && hello.SupportsCertificate(cert) != nil) && e.hostPolicy(hello.Context(), hello.ServerName) == nil {
			inventory := e.Inventory(hello.Context())
			valid := map[string]bool{}
			for _, held := range inventory.Certificates {
				if held.Valid && slicesContainsName(held.Names, hello.ServerName) {
					valid[held.Fingerprint] = true
				}
			}
			candidates, _ := e.heldCertificates(hello.Context())
			for _, candidate := range candidates {
				digest := sha256.Sum256(candidate.Certificate[0])
				if valid[hex.EncodeToString(digest[:])] && hello.SupportsCertificate(candidate) == nil {
					return cert, err
				}
			}
			if len(valid) > 0 {
				e.unsupported.Add(1)
			}
		}
		return cert, err
	}
	return config
}
