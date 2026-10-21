package observability

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ServerDeps are the read-only sources one listener exposes. Registry and
// Health are required; the JSON views are served only when present.
type ServerDeps struct {
	Registry  *Registry
	Health    ReadinessSource
	Snapshots SnapshotSource
	Cluster   ClusterSource
	Events    EventSource
	Sessions  *SessionStore
	// TokenVersion orders shared Vault-token registrations; local files omit it.
	TokenVersion TokenVersion
	// LocalSessions preserves browser login on hosts without KV permissions.
	// Controllers keep it false and attach the persistent regional store.
	LocalSessions bool
}

// Server is the private observability listener. Additional read-only routes,
// such as the dashboard, are mounted with Handle before or after Start.
type Server struct {
	mux           *http.ServeMux
	token         []byte
	deps          ServerDeps
	http          *http.Server
	listen        net.Listener
	sessions      *sessions
	reclaimCancel context.CancelFunc
	reclaimDone   chan struct{}
	// loginMounted enables session cookies as an alternative to the bearer
	// header. It is set only by HandleLogin, so a listener without the
	// dashboard keeps accepting the bearer header alone.
	loginMounted atomic.Bool
	// snapshots and cluster hold the current JSON view sources. Their routes
	// are mounted once; a later HandleSnapshots or HandleCluster replaces the
	// source instead of registering the pattern again, which would panic.
	snapshots    atomic.Pointer[SnapshotSource]
	cluster      atomic.Pointer[ClusterSource]
	snapshotOnce sync.Once
	clusterOnce  sync.Once
	catalog      *metricCatalog
	historyOnce  sync.Once
}

// NewServer validates config, reads the bearer token and builds the routes.
// It does not bind; Start does.
func NewServer(config Config, deps ServerDeps) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	var token []byte
	if config.BearerTokenFile != "" {
		var err error
		if token, err = readBearerToken(config.BearerTokenFile); err != nil {
			return nil, err
		}
	}
	return newServer(config, token, deps)
}

// NewTokenServer is NewServer with the bearer token itself instead of
// bearer_token_file, for a listener whose token is read from Vault. The
// token is required whatever the address.
func NewTokenServer(config Config, token string, deps ServerDeps) (*Server, error) {
	checked, err := checkBearerToken([]byte(token))
	if err != nil {
		return nil, err
	}
	// The token stands in for the file Validate requires off loopback.
	config.BearerTokenFile = "token"
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return newServer(config, checked, deps)
}

func newServer(config Config, token []byte, deps ServerDeps) (*Server, error) {
	if deps.Registry == nil || deps.Health == nil {
		return nil, errors.New("observability server requires a registry and health checks")
	}
	manager := &sessions{secure: config.TLSCertFile != ""}
	if deps.LocalSessions {
		manager.local = make(map[string]struct{})
	}
	server := &Server{mux: http.NewServeMux(), deps: deps, sessions: manager, token: token}
	server.catalog = &metricCatalog{registry: deps.Registry}
	if deps.Sessions != nil && token != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.SetSessionStore(ctx, deps.Sessions); err != nil {
			return nil, err
		}
	}
	server.mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writePlain(writer, http.StatusOK, "ok\n")
	})
	server.mux.HandleFunc("GET /readyz", server.readyz)
	server.Handle("GET /metrics", http.HandlerFunc(server.metrics))
	server.HandleAuthenticated("GET /v1/metrics/catalog", http.HandlerFunc(server.metricCatalogHTTP))
	if deps.Snapshots != nil {
		server.HandleSnapshots(deps.Snapshots)
	}
	if deps.Cluster != nil {
		server.HandleCluster(deps.Cluster)
	}
	if deps.Events != nil {
		server.Handle("GET /v1/events", http.HandlerFunc(server.events))
	}
	return server, nil
}

// HandleSnapshots mounts GET /v1/snapshot once a runtime finished wiring
// its providers. A listener started earlier serves health meanwhile. Calling
// it again replaces the source rather than mounting the route twice.
func (server *Server) HandleSnapshots(source SnapshotSource) {
	server.snapshots.Store(&source)
	server.snapshotOnce.Do(func() {
		server.Handle("GET /v1/snapshot", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			snapshot, err := (*server.snapshots.Load()).Snapshot(request.Context(),
				request.URL.Query().Get("metrics") == "1")
			if err != nil {
				writePlain(writer, http.StatusServiceUnavailable, "snapshot unavailable\n")
				return
			}
			writeJSON(writer, snapshot)
		}))
	})
}

// HandleCluster mounts GET /v1/cluster for a cell-wide aggregator. Calling it
// again replaces the aggregator.
func (server *Server) HandleCluster(source ClusterSource) {
	server.cluster.Store(&source)
	server.clusterOnce.Do(func() {
		server.Handle("GET /v1/cluster", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			snapshot, err := (*server.cluster.Load()).Cluster(request.Context(),
				request.URL.Query().Get("metrics") == "1")
			if err != nil {
				writePlain(writer, http.StatusServiceUnavailable, "cluster snapshot unavailable\n")
				return
			}
			writeJSON(writer, snapshot)
		}))
	})
}

// Handle mounts an authenticated read-only route. With a configured bearer
// token every request must present it, or a session cookie once HandleLogin
// mounted the dashboard login; on a tokenless loopback listener the loopback
// bind is the only control, as for the built-in routes.
func (server *Server) Handle(pattern string, handler http.Handler) {
	server.mux.Handle(pattern, server.authenticate(handler))
}

// HandleAuthenticated never grants tokenless loopback access to this API.
func (server *Server) HandleAuthenticated(pattern string, handler http.Handler) {
	server.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if server.token == nil {
			writePlain(w, http.StatusServiceUnavailable, "authenticated API requires a configured token\n")
			return
		}
		handler.ServeHTTP(w, r)
	}))
}

// HandleStatic mounts an unauthenticated route for public embedded files,
// such as the dashboard's stylesheet the login form needs. It must never
// serve cell state.
func (server *Server) HandleStatic(pattern string, handler http.Handler) {
	server.mux.Handle(pattern, handler)
}

// ServeHTTP lets tests and an embedding mux exercise the routes directly.
func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	// A proxy hop would make the bind address meaningless as an access
	// control, exactly as for the host enrollment listener.
	if request.Header.Get("Forwarded") != "" || request.Header.Get("X-Forwarded-For") != "" ||
		request.Header.Get("X-Real-IP") != "" {
		writePlain(writer, http.StatusBadRequest, "proxied requests are not accepted\n")
		return
	}
	// Without a token the loopback bind is the only control, and DNS
	// rebinding defeats it for any route reachable under a hostname. Every
	// route of a tokenless listener, not only the dashboard's, therefore
	// requires an IP literal or localhost as the Host.
	if server.token == nil && !LiteralHost(request.Host) {
		writePlain(writer, http.StatusMisdirectedRequest, "address this listener by IP or localhost\n")
		return
	}
	server.mux.ServeHTTP(writer, request)
}

// LiteralHost reports whether an HTTP Host header names an IP literal or
// localhost, which a DNS-rebinding page cannot present.
func LiteralHost(host string) bool {
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	} else if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if host == "localhost" {
		return true
	}
	_, err := netip.ParseAddr(host)
	return err == nil
}

func (server *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if server.token != nil && !bearerMatches(request.Header.Get("Authorization"), server.token) {
			authenticated := false
			if request.Header.Get("Authorization") == "" && server.loginMounted.Load() {
				var err error
				authenticated, err = server.sessions.authenticated(request)
				if err != nil {
					writePlain(writer, http.StatusServiceUnavailable, "session storage unavailable\n")
					return
				}
			}
			if !authenticated {
				if server.loginMounted.Load() && wantsLoginPage(request) {
					http.Redirect(writer, request, "/login?next="+url.QueryEscape(LocalRedirectPath(request.URL.RequestURI())),
						http.StatusSeeOther)
					return
				}
				writer.Header().Set("WWW-Authenticate", `Bearer realm="ts-orch"`)
				writePlain(writer, http.StatusUnauthorized, "unauthorized\n")
				return
			}
		}
		if server.token != nil && server.loginMounted.Load() && request.Header.Get("Authorization") == "" {
			if cookie, err := request.Cookie(SessionCookieName); err == nil {
				http.SetCookie(writer, server.sessions.cookie(cookie.Value))
			}
		}
		next.ServeHTTP(writer, request)
	})
}

// Start binds the validated address and serves until ctx ends or Close.
// The returned channel yields the terminal serve error, nil after Close.
func (server *Server) Start(ctx context.Context, config Config) (<-chan error, error) {
	address, err := ValidateListenAddress(config.Address())
	if err != nil {
		return nil, err
	}
	// The token was read by NewServer from its own config; never let a
	// different Start config widen a tokenless server onto a network address.
	if !address.Addr().IsLoopback() && server.token == nil {
		return nil, errors.New("a non-loopback observability listener requires bearer_token_file")
	}
	var tlsConfig *tls.Config
	if config.TLSCertFile != "" {
		certificate, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load observability TLS: %w", err)
		}
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address.String())
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	// No WriteTimeout: dashboard streams are long-lived. Headers and request
	// bodies are bounded as for the host enrollment listener.
	server.http = &http.Server{Handler: TraceHTTP(server), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 4096}
	server.listen = listener
	if server.token != nil {
		cleanupCtx, cancel := context.WithCancel(ctx)
		server.reclaimCancel, server.reclaimDone = cancel, make(chan struct{})
		go func() {
			defer close(server.reclaimDone)
			server.sessions.retryCleanup(cleanupCtx)
		}()
	}
	result := make(chan error, 1)
	go func() {
		err := server.http.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		result <- err
	}()
	context.AfterFunc(ctx, func() { _ = server.Close() })
	return result, nil
}

// Addr returns the bound address after Start.
func (server *Server) Addr() net.Addr {
	if server == nil || server.listen == nil {
		return nil
	}
	return server.listen.Addr()
}

// Close stops the listener and open connections.
func (server *Server) Close() error {
	if server == nil {
		return nil
	}
	if server.reclaimCancel != nil {
		server.reclaimCancel()
		<-server.reclaimDone
	}
	if server.http == nil {
		return nil
	}
	return server.http.Close()
}

func (server *Server) readyz(writer http.ResponseWriter, request *http.Request) {
	ready, results := server.deps.Health.Evaluate(request.Context())
	var body strings.Builder
	for _, result := range results {
		state := "ok"
		if !result.OK {
			state = "failing"
			if result.Detail != "" {
				state += ": " + result.Detail
			}
		}
		fmt.Fprintf(&body, "%s %s\n", result.Name, state)
	}
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writePlain(writer, status, body.String())
}

func (server *Server) metrics(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	server.deps.Registry.WritePrometheus(writer)
}

func (server *Server) events(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	after, _ := strconv.ParseUint(query.Get("after"), 10, 64)
	limit, err := strconv.Atoi(query.Get("limit"))
	if err != nil || limit <= 0 || limit > DefaultEventCapacity {
		limit = 200
	}
	writeJSON(writer, server.deps.Events.Since(after, limit))
}

func writePlain(writer http.ResponseWriter, status int, body string) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write([]byte(body))
}

func writeJSON(writer http.ResponseWriter, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		writePlain(writer, http.StatusInternalServerError, "encode failed\n")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = writer.Write(append(data, '\n'))
}
