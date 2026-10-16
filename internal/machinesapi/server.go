// Package machinesapi is the controllers' Machines-style REST API over the
// shared app and machine model (internal/machines), authenticated with
// ts-auth access tokens and scoped to the caller's organization. See
// docs/machines-api.md.
package machinesapi

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/machines"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/tenant"
	"golang.org/x/net/netutil"
)

// ScopeRead is the scope every read needs.
const ScopeRead = "orch:read"

// maxConnections bounds the connections one controller serves: the public
// load balancer sends the internet here, and these hosts also run the
// cell's NATS quorum and authority.
const maxConnections = 256

//go:embed openapi.json
var openAPI []byte

var (
	// appRE and machineRE are internal/machines' name and ID rules; a path
	// value becomes part of a KV key only after it matches.
	appRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Config is controller.machines_api of the controller config.
type Config struct {
	PlatformOrganizationID string `json:"platform_organization_id,omitempty"`
	// ListenAddress is the API's ip:port; the regional load balancer
	// forwards the public host to it. Anything but loopback needs TLS.
	ListenAddress string `json:"listen_address"`
	TLSCertFile   string `json:"tls_cert_file,omitempty"`
	TLSKeyFile    string `json:"tls_key_file,omitempty"`
	// Issuer is ts-auth's issuer exactly as tokens carry it, and Audience
	// the aud value tokens must hold for this API.
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	// JWKSURLs are where the controller fetches ts-auth's signing keys, in
	// order: the local replica first, then the other controllers'. Plain
	// http is allowed only to loopback and private addresses.
	JWKSURLs []string `json:"jwks_urls"`
	// Clients are the ts-auth client IDs whose tokens the API accepts.
	// Every ts-auth token carries every audience, so the client is what
	// keeps another service's tokens out.
	Clients []string `json:"clients"`
	// Members maps each organization ID to the ts-auth subjects (user ULIDs
	// or service client IDs) that act for it. ts-auth tokens carry no
	// organization yet, so this signed map is the tenancy.
	Members map[string][]string `json:"members"`
}

// Validate checks the configuration without binding or fetching anything.
func (c Config) Validate() error {
	listen, err := netip.ParseAddrPort(c.ListenAddress)
	if err != nil {
		return fmt.Errorf("machines_api listen_address: %w", err)
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("machines_api tls_cert_file and tls_key_file go together")
	}
	// Requests carry bearer tokens, so only a loopback listener, which no
	// network sees, may serve plain HTTP.
	if c.TLSCertFile == "" && !listen.Addr().IsLoopback() {
		return errors.New("machines_api needs tls_cert_file and tls_key_file unless it listens on loopback")
	}
	issuer, err := url.Parse(c.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.RawQuery != "" || issuer.Fragment != "" {
		return errors.New("machines_api issuer must be an https URL")
	}
	if c.Audience == "" || len(c.Clients) == 0 || slices.Contains(c.Clients, "") {
		return errors.New("machines_api audience and clients are required")
	}
	if len(c.JWKSURLs) == 0 {
		return errors.New("machines_api jwks_urls are required")
	}
	for _, raw := range c.JWKSURLs {
		keys, err := url.Parse(raw)
		if err != nil || keys.Host == "" || keys.User != nil {
			return fmt.Errorf("machines_api jwks_url %q is not a URL", raw)
		}
		address, notIP := netip.ParseAddr(keys.Hostname())
		if keys.Scheme != "https" && (keys.Scheme != "http" || notIP != nil || !address.IsLoopback() && !address.IsPrivate()) {
			return fmt.Errorf("machines_api jwks_url %q must be https, or http to a loopback or private address", raw)
		}
	}
	if c.PlatformOrganizationID != "" && !entityid.Valid(c.PlatformOrganizationID) {
		return errors.New("machines_api platform_organization_id must be a canonical ULID")
	}
	for _, client := range c.Clients {
		if !entityid.Valid(client) {
			return errors.New("machines_api clients must be canonical ULIDs")
		}
	}
	seen := map[string]bool{}
	for org, subjects := range c.Members {
		if !entityid.Valid(org) {
			return fmt.Errorf("machines_api members: organization %q", org)
		}
		for _, subject := range subjects {
			if !entityid.Valid(subject) || seen[subject] {
				return fmt.Errorf("machines_api members: subject %q is empty or in two organizations", subject)
			}
			seen[subject] = true
		}
	}
	return nil
}

// Server serves the API from the region's app store and the cell's tenants.
type Server struct {
	config   Config
	verifier *Verifier
	apps     *machines.Store
	tenants  *tenant.Store
	// orgs maps a subject to its organization.
	orgs      map[string]string
	links     observability.ClusterSource
	linkCache observability.Cache[observability.ClusterSnapshot]
	mux       *http.ServeMux
	http      *http.Server
}

// NewServer builds the routes. It does not bind; Start does.
func NewServer(config Config, apps *machines.Store, tenants *tenant.Store, links observability.ClusterSource) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if apps == nil || tenants == nil {
		return nil, errors.New("machines API requires the app and tenant stores")
	}
	s := &Server{config: config, apps: apps, tenants: tenants, mux: http.NewServeMux(), orgs: map[string]string{},
		links: links, linkCache: observability.Cache[observability.ClusterSnapshot]{TTL: 3 * time.Second},
		verifier: NewVerifier(config.Issuer, config.Audience, config.JWKSURLs)}
	for org, subjects := range config.Members {
		for _, subject := range subjects {
			s.orgs[subject] = org
		}
	}
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.HandleFunc("GET /v1/openapi.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(openAPI)
	})
	s.mux.HandleFunc("GET /v1/link-health", s.linkHealth)
	s.mux.Handle("GET /v1/apps", s.authorized(ScopeRead, s.listApps))
	s.mux.Handle("GET /v1/apps/{app}", s.authorized(ScopeRead, s.withApp(s.getApp)))
	s.mux.Handle("GET /v1/apps/{app}/machines", s.authorized(ScopeRead, s.withApp(s.listMachines)))
	s.mux.Handle("GET /v1/apps/{app}/machines/{id}", s.authorized(ScopeRead, s.withApp(s.getMachine)))
	return s, nil
}

// ServeHTTP lets tests and the controller exercise the routes directly.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.mux.ServeHTTP(w, r)
}

// Start binds the configured address and serves until ctx ends. The
// returned channel yields the terminal serve error.
func (s *Server) Start(ctx context.Context) (<-chan error, error) {
	var certificate tls.Certificate
	if s.config.TLSCertFile != "" {
		var err error
		if certificate, err = tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile); err != nil {
			return nil, fmt.Errorf("load machines API TLS: %w", err)
		}
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.config.ListenAddress)
	if err != nil {
		return nil, err
	}
	listener = netutil.LimitListener(listener, maxConnections)
	if s.config.TLSCertFile != "" {
		listener = tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}})
	}
	// No WriteTimeout: log streams (a later slice) are long-lived.
	s.http = &http.Server{Handler: observability.TraceHTTP(s), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10}
	result := make(chan error, 1)
	go func() {
		err := s.http.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		result <- err
	}()
	context.AfterFunc(ctx, func() { _ = s.http.Close() })
	return result, nil
}

// caller is a verified principal and the organization it acts for.
type caller struct {
	Principal
	Org string
}

// authorized verifies the bearer token, its client, the scope and the
// caller's organization before next runs.
func (s *Server) authorized(scope string, next func(http.ResponseWriter, *http.Request, caller)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		if !strings.EqualFold(scheme, "Bearer") || token == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ts-orch"`)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "a ts-auth bearer access token is required")
			return
		}
		principal, err := s.verifier.Verify(r.Context(), token)
		if err == nil && !slices.Contains(s.config.Clients, principal.ClientID) {
			err = fmt.Errorf("%w: client %q may not call this API", ErrUnauthenticated, principal.ClientID)
		}
		if err != nil {
			// Debug: the internet can send any number of bad tokens.
			slog.DebugContext(r.Context(), "machines API token rejected", observability.ComponentKey, "machinesapi", "error", err)
			w.Header().Set("WWW-Authenticate", `Bearer realm="ts-orch", error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "the access token was rejected")
			return
		}
		if !principal.HasScope(scope) {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="ts-orch", error="insufficient_scope", scope=%q`, scope))
			writeError(w, http.StatusForbidden, "insufficient_scope", "the token lacks scope "+scope)
			return
		}
		org, member := s.orgs[principal.Subject]
		if !member {
			writeError(w, http.StatusForbidden, "no_organization", "the caller is not a member of any organization")
			return
		}
		next(w, r, caller{Principal: principal, Org: org})
	})
}

// visible reports whether c may see app: the platform organization sees
// every app, a tenant organization only its own tenants' apps. owners
// caches tenant organizations for one request, so a listing reads each
// owning tenant once and never the whole tenant bucket. A missing tenant
// owns nothing a tenant organization can see.
func (s *Server) visible(ctx context.Context, c caller, app machines.App, owners map[string]string) (bool, error) {
	if c.Org == s.config.PlatformOrganizationID {
		return true, nil
	}
	if app.Class != machines.ClassTenant {
		return false, nil
	}
	owner, cached := owners[app.Tenant]
	if !cached {
		t, err := s.tenants.Get(ctx, app.Tenant)
		switch {
		case err == nil:
			owner = t.Tenant.Organization
		case !errors.Is(err, tenant.ErrNotFound):
			return false, err
		}
		owners[app.Tenant] = owner
	}
	return owner == c.Org, nil
}

func (s *Server) listApps(w http.ResponseWriter, r *http.Request, c caller) {
	apps, err := s.apps.Apps(r.Context())
	if err != nil {
		s.unavailable(w, err)
		return
	}
	owners := map[string]string{}
	visible := []machines.App{}
	for _, app := range apps {
		ok, err := s.visible(r.Context(), c, app, owners)
		if err != nil {
			s.unavailable(w, err)
			return
		}
		if ok {
			visible = append(visible, app)
		}
	}
	writeJSON(w, http.StatusOK, map[string][]machines.App{"apps": visible})
}

// withApp resolves the {app} path value to an app the caller may see. An
// app of another organization is reported missing, so names do not leak
// across tenants.
func (s *Server) withApp(next func(http.ResponseWriter, *http.Request, caller, machines.App)) func(http.ResponseWriter, *http.Request, caller) {
	return func(w http.ResponseWriter, r *http.Request, c caller) {
		name := r.PathValue("app")
		if !appRE.MatchString(name) {
			writeError(w, http.StatusBadRequest, "invalid_name", "app names are DNS labels")
			return
		}
		app, err := s.apps.App(r.Context(), name)
		if errors.Is(err, machines.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "app "+name+" not found")
			return
		}
		if err != nil {
			s.unavailable(w, err)
			return
		}
		ok, err := s.visible(r.Context(), c, app, map[string]string{})
		if err != nil {
			s.unavailable(w, err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, "not_found", "app "+name+" not found")
			return
		}
		next(w, r, c, app)
	}
}

func (s *Server) getApp(w http.ResponseWriter, _ *http.Request, _ caller, app machines.App) {
	writeJSON(w, http.StatusOK, app)
}

// MachineView is a machine with its observed status, absent until the
// orchestrator first observes it.
type MachineView struct {
	machines.Machine
	Status *machines.Status `json:"status,omitempty"`
}

func (s *Server) listMachines(w http.ResponseWriter, r *http.Request, _ caller, app machines.App) {
	list, err := s.apps.Machines(r.Context(), app.Name)
	if err != nil {
		s.unavailable(w, err)
		return
	}
	statuses, err := s.apps.Statuses(r.Context(), app.Name)
	if err != nil {
		s.unavailable(w, err)
		return
	}
	byID := make(map[string]*machines.Status, len(statuses))
	for index := range statuses {
		byID[statuses[index].ID] = &statuses[index]
	}
	views := make([]MachineView, 0, len(list))
	for _, machine := range list {
		views = append(views, MachineView{Machine: machine, Status: byID[machine.ID]})
	}
	writeJSON(w, http.StatusOK, map[string][]MachineView{"machines": views})
}

func (s *Server) getMachine(w http.ResponseWriter, r *http.Request, _ caller, app machines.App) {
	id := r.PathValue("id")
	if !entityid.Valid(id) {
		writeError(w, http.StatusBadRequest, "invalid_name", "machine IDs must be canonical uppercase ULIDs")
		return
	}
	machine, err := s.apps.Machine(r.Context(), app.Name, id)
	if errors.Is(err, machines.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "machine "+id+" not found")
		return
	}
	if err != nil {
		s.unavailable(w, err)
		return
	}
	view := MachineView{Machine: machine}
	status, err := s.apps.Status(r.Context(), app.Name, id)
	switch {
	case err == nil:
		view.Status = &status
	case !errors.Is(err, machines.ErrNotFound):
		s.unavailable(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) unavailable(w http.ResponseWriter, err error) {
	slog.Error("machines API store read failed", observability.ComponentKey, "machinesapi", "error", err)
	writeError(w, http.StatusServiceUnavailable, "unavailable", "the controller cannot read the cell state")
}

type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, apiError{Error: code, Message: message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	data, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		status, data = http.StatusInternalServerError, []byte(`{"error":"internal","message":"encode response"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}
