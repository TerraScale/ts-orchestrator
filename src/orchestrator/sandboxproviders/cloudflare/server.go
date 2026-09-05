// Package cloudflare provides a bounded, in-process Cloudflare HTTP endpoint
// for the Firecracker qualification stack. It intentionally has no provider
// credentials, network dialer, or orchestration hooks. The endpoint speaks the
// subset of the Cloudflare v4 contract used by the production reconciler.
package cloudflare

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config controls a local endpoint. IDs are deliberately explicit so tests
// can use the same paths as a production client without resolving anything.
type Config struct {
	ZoneID    string
	AccountID string
	ZoneName  string
	Faults    []Fault
}

// Options is an alias retained for callers that prefer the provider-neutral
// naming used by the other sandbox providers.
type Options = Config

// New creates an isolated endpoint. All mutable state is private to the
// returned value and is protected for concurrent httptest/race use.
func New(cfg Config) *Server { return NewServer(cfg) }

// NewServer creates an isolated endpoint.
func NewServer(cfg Config) *Server {
	if cfg.ZoneID == "" {
		cfg.ZoneID = "zone-local"
	}
	if cfg.AccountID == "" {
		cfg.AccountID = "account-local"
	}
	if cfg.ZoneName == "" {
		cfg.ZoneName = "terrascale.tech"
	}
	s := &Server{cfg: cfg, faults: newFaultBook(cfg.Faults), idem: map[string]idempotentResponse{}, nextID: 1,
		rules: map[string][]wireRule{}, snippets: map[string]snippet{}, snippetRules: []snippetRule{}, kv: map[string]map[string][]byte{}, workers: map[string]*workerScript{}, secrets: map[string]map[string]secret{}, secretStores: map[string]secretStore{}}
	s.settings = map[string]string{"ssl": "strict", "min_tls_version": "1.2", "tls_1_3": "on", "always_use_https": "on"}
	return s
}

// Server is an HTTP handler, not a cloud client. It should be used with
// httptest.NewServer in tests. It never starts a listener itself.
type Server struct {
	cfg Config
	mu  sync.Mutex

	dns          []dnsRecord
	rules        map[string][]wireRule
	snippets     map[string]snippet
	snippetRules []snippetRule
	routes       []workerRoute
	namespaces   []namespace
	kv           map[string]map[string][]byte
	settings     map[string]string
	totalTLS     bool
	tiered       bool
	purges       [][]string

	workers      map[string]*workerScript
	secrets      map[string]map[string]secret
	secretStores map[string]secretStore
	nextID       uint64
	idem         map[string]idempotentResponse
	faults       *faultBook
}

// Handler returns the endpoint as an http.Handler. Server itself implements
// http.Handler, so this is mainly useful when composing a larger local stack.
func (s *Server) Handler() http.Handler { return s }

// ServeHTTP implements the local Cloudflare API. Unknown routes fail closed.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s == nil {
		http.Error(w, "sandbox cloudflare: nil server", http.StatusInternalServerError)
		return
	}
	var body []byte
	var err error
	if r.Body != nil {
		body, err = io.ReadAll(io.LimitReader(r.Body, (8<<20)+1))
	}
	if err != nil {
		s.writeError(w, http.StatusBadRequest, 1001, "request body unreadable")
		return
	}
	if len(body) > 8<<20 {
		s.writeError(w, http.StatusRequestEntityTooLarge, 1010, "request body too large")
		return
	}
	if r.Body != nil {
		r.Body.Close()
	}
	if resp, ok := s.replayIdempotent(w, r, body); ok {
		_ = resp
		return
	}
	if fault, ok := s.faults.next(r.Method, r.URL.Path); ok {
		if fault.Delay > 0 {
			t := time.NewTimer(fault.Delay)
			select {
			case <-r.Context().Done():
				t.Stop()
				s.writeError(w, http.StatusRequestTimeout, 1008, "fault delay canceled")
				return
			case <-t.C:
			}
		}
		if fault.Commit {
			s.dispatch(w, r, body, fault)
			return
		}
		s.writeFault(w, fault)
		return
	}
	s.dispatch(w, r, body, FaultStep{})
}

func (s *Server) dispatch(w http.ResponseWriter, r *http.Request, body []byte, fault FaultStep) {
	path := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	if path == "zones" && r.Method == http.MethodGet {
		s.resolveZone(w, r)
		return
	}
	if len(parts) >= 2 && parts[0] == "zones" && parts[1] == s.cfg.ZoneID {
		s.zone(w, r, parts[2:], body, fault)
		return
	}
	if len(parts) >= 2 && parts[0] == "accounts" && parts[1] == s.cfg.AccountID {
		s.account(w, r, parts[2:], body, fault)
		return
	}
	s.writeError(w, http.StatusNotFound, 1000, "resource not found")
}

func (s *Server) resolveZone(w http.ResponseWriter, r *http.Request) {
	if name := r.URL.Query().Get("name"); name != "" && name != s.cfg.ZoneName {
		s.envelope(w, http.StatusOK, []any{}, nil)
		return
	}
	s.envelope(w, http.StatusOK, []map[string]any{{"id": s.cfg.ZoneID, "name": s.cfg.ZoneName, "account": map[string]string{"id": s.cfg.AccountID}}}, nil)
}

func (s *Server) zone(w http.ResponseWriter, r *http.Request, p []string, body []byte, fault FaultStep) {
	if len(p) == 0 {
		s.writeError(w, http.StatusNotFound, 1000, "zone resource not found")
		return
	}
	switch p[0] {
	case "dns_records":
		s.dnsEndpoint(w, r, p[1:], body, fault)
	case "rulesets":
		s.rulesetEndpoint(w, r, p[1:], body, fault)
	case "snippets":
		s.snippetEndpoint(w, r, p[1:], body, fault)
	case "workers":
		if len(p) < 2 || p[1] != "routes" {
			s.writeError(w, http.StatusNotFound, 1000, "Worker routes not found")
			return
		}
		s.routesEndpoint(w, r, p[2:], body, fault)
	case "cache":
		s.cacheEndpoint(w, r, p[1:], body, fault)
	case "purge_cache":
		s.purgeEndpoint(w, r, body, fault)
	case "settings":
		s.settingsEndpoint(w, r, body, fault)
	case "ssl":
		s.tlsEndpoint(w, r, p[1:], body, fault)
	default:
		s.writeError(w, http.StatusNotFound, 1000, "resource not found")
	}
}

func (s *Server) account(w http.ResponseWriter, r *http.Request, p []string, body []byte, fault FaultStep) {
	if len(p) == 0 {
		s.writeError(w, http.StatusNotFound, 1000, "account resource not found")
		return
	}
	if p[0] == "storage" && len(p) >= 3 && p[1] == "kv" && p[2] == "namespaces" {
		s.kvEndpoint(w, r, p[3:], body, fault)
		return
	}
	if p[0] == "workers" && len(p) >= 3 && p[1] == "scripts" {
		s.workerEndpoint(w, r, p[2:], body, fault)
		return
	}
	if p[0] == "secrets_store" {
		s.secretEndpoint(w, r, p[1:], body, fault)
		return
	}
	s.writeError(w, http.StatusNotFound, 1000, "resource not found")
}

// ClientConfig returns values suitable for cloudflare.NewClient. This helper
// does not install a transport or make a network request.
func (s *Server) ClientConfig() (zoneID, accountID string) { return s.cfg.ZoneID, s.cfg.AccountID }

func (s *Server) envelope(w http.ResponseWriter, status int, result any, fault *FaultStep) {
	if fault != nil && fault.Headers != nil {
		for k, v := range fault.Headers {
			w.Header().Set(k, v)
		}
	}
	if status == 0 {
		status = http.StatusOK
	}
	if result != nil {
		w.Header().Set("ETag", etag(result))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": status >= 200 && status < 300, "errors": []any{}, "messages": []any{}, "result": result})
}

func (s *Server) writeError(w http.ResponseWriter, status, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": code, "message": message}}, "messages": []any{}, "result": nil})
}

func (s *Server) writeFault(w http.ResponseWriter, f FaultStep) {
	status := f.Status
	if status == 0 {
		status = http.StatusServiceUnavailable
	}
	for k, v := range f.Headers {
		w.Header().Set(k, v)
	}
	if f.Drop {
		if h, ok := w.(http.Hijacker); ok {
			c, _, _ := h.Hijack()
			_ = c.Close()
			return
		}
	}
	if f.Body != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if raw, ok := f.Body.([]byte); ok {
			_, _ = w.Write(raw)
		} else {
			_ = json.NewEncoder(w).Encode(f.Body)
		}
		return
	}
	s.writeError(w, status, f.Code, f.Message)
}

func (s *Server) replayIdempotent(w http.ResponseWriter, r *http.Request, body []byte) (idempotentResponse, bool) {
	if strings.Contains(r.URL.Path, "/secrets_store/") {
		return idempotentResponse{}, false
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Header.Get("Idempotency-Key") == "" {
		return idempotentResponse{}, false
	}
	key := r.Header.Get("Idempotency-Key")
	fingerprint := r.Method + "\x00" + r.URL.RequestURI() + "\x00" + string(body)
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.idem[key]; ok {
		if old.fingerprint != fingerprint {
			s.writeError(w, http.StatusConflict, 1002, "idempotency key reused with different request")
			return old, true
		}
		for k, v := range old.headers {
			w.Header()[k] = append([]string(nil), v...)
		}
		w.WriteHeader(old.status)
		_, _ = w.Write(old.body)
		return old, true
	}
	// dispatch records the response through captureResponse. The marker is
	// kept in the request context only conceptually; handlers call remember.
	return idempotentResponse{}, false
}

type idempotentResponse struct {
	fingerprint string
	status      int
	headers     http.Header
	body        []byte
}

func (s *Server) remember(r *http.Request, requestBody []byte, status int, headers http.Header, body []byte) {
	if strings.Contains(r.URL.Path, "/secrets_store/") {
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		return
	}
	// Mutation handlers hold s.mu while emitting and recording the response.
	// Keeping this helper lock-free avoids recursively taking that mutex.
	s.idem[key] = idempotentResponse{fingerprint: r.Method + "\x00" + r.URL.RequestURI() + "\x00" + string(requestBody), status: status, headers: headers.Clone(), body: append([]byte(nil), body...)}
}

// writeMutation emits an enveloped mutation response and records it for an
// Idempotency-Key replay. raw is used for Cloudflare endpoints that return a
// non-envelope body.
func (s *Server) writeMutation(r *http.Request, w http.ResponseWriter, requestBody []byte, status int, result any, raw []byte, fault FaultStep) {
	if fault.Status != 0 {
		status = fault.Status
	}
	for k, v := range fault.Headers {
		w.Header().Set(k, v)
	}
	if fault.Drop {
		if h, ok := w.(http.Hijacker); ok {
			c, _, _ := h.Hijack()
			_ = c.Close()
			return
		}
	}
	if fault.Body != nil {
		s.writeFault(w, fault)
		return
	}
	if raw == nil {
		raw, _ = json.Marshal(map[string]any{"success": status >= 200 && status < 300, "errors": []any{}, "messages": []any{}, "result": result})
		raw = append(raw, '\n')
	}
	if result != nil {
		w.Header().Set("ETag", etag(result))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
	s.remember(r, requestBody, status, w.Header(), raw)
}

func etag(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return `"` + hex.EncodeToString(h[:]) + `"`
}
func checkMatch(r *http.Request, current string) bool {
	return r.Header.Get("If-Match") == "" || r.Header.Get("If-Match") == current
}
func id(prefix string, n *uint64) string { v := fmt.Sprintf("%s-%d", prefix, *n); *n++; return v }
func pathUnescape(v string) string {
	x, err := url.PathUnescape(v)
	if err == nil {
		return x
	}
	return v
}
func page(r *http.Request, length int) (start, end, number, total int) {
	number, _ = strconv.Atoi(r.URL.Query().Get("page"))
	if number < 1 {
		number = 1
	}
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if per < 1 {
		per = 20
	}
	if per > 1000 {
		per = 1000
	}
	total = (length + per - 1) / per
	start = (number - 1) * per
	if start > length {
		start = length
	}
	end = start + per
	if end > length {
		end = length
	}
	return
}
func resultInfo(page, per, total int) map[string]int {
	pages := (total + per - 1) / per
	if pages == 0 {
		pages = 1
	}
	return map[string]int{"page": page, "per_page": per, "total_count": total, "total_pages": pages}
}

// Reset clears provider state while retaining configuration and scripted
// faults. It is intentionally explicit; no production package can call it.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dns = nil
	s.rules = map[string][]wireRule{}
	s.snippets = map[string]snippet{}
	s.snippetRules = []snippetRule{}
	s.routes = nil
	s.namespaces = nil
	s.kv = map[string]map[string][]byte{}
	s.workers = map[string]*workerScript{}
	s.secrets = map[string]map[string]secret{}
	s.secretStores = map[string]secretStore{}
	s.idem = map[string]idempotentResponse{}
	s.purges = nil
	s.totalTLS = false
	s.tiered = false
	s.settings = map[string]string{"ssl": "strict", "min_tls_version": "1.2", "tls_1_3": "on", "always_use_https": "on"}
}

func init() {}
