// Package oci provides a bounded, in-process OCI REST endpoint for local
// qualification. It deliberately implements HTTP semantics (including
// retries and uncertain outcomes), rather than exposing orchestration state or
// a provider-specific test shortcut.
package oci

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultBodyLimit int64 = 16 << 20

// Config bounds the endpoint. Zero values select safe defaults.
type Config struct {
	Namespace          string
	Region             string
	ManagementEndpoint string
	MaxBodyBytes       int64
	MaxResources       int
	WorkRequestPolls   int
	// AsyncPolls is an alias convenient for shared sandbox fixtures.
	AsyncPolls int
	Faults     []Fault
}

type Options = Config

// FaultKind describes a scripted provider outcome.
type FaultKind string

const (
	FaultResponse      FaultKind = "response"
	FaultTimeout       FaultKind = "timeout"
	FaultIndeterminate FaultKind = "indeterminate"
)

// FaultStep is a deterministic response in a Fault script. Commit applies a
// mutation before returning the scripted outcome; Drop closes the connection
// after the mutation, modelling an accepted request whose response was lost.
type FaultStep struct {
	Status  int
	Code    any
	Body    any
	Delay   time.Duration
	Drop    bool
	Commit  bool
	Headers map[string]string
}

// Fault describes an ordered script matched by method and path. Calls limits
// how many times the step sequence is replayed (zero means once per step).
type Fault struct {
	Method   string
	Path     string
	Calls    int
	Steps    []FaultStep
	Response *FaultStep
}

type FaultScript = Fault

// FaultRule is consumed in order when method and path match. Count defaults to
// one. A blank method or path is a wildcard; path wildcards use a trailing *.
type FaultRule struct {
	Method  string
	Path    string
	Kind    FaultKind
	Status  int
	Code    string
	Body    any
	Delay   time.Duration
	Count   int
	Commit  bool
	Headers map[string]string
}

// Server is a bounded local OCI service endpoint. It is safe for concurrent
// requests and is intended for use with httptest.NewServer.
type Server struct {
	mu                 sync.Mutex
	cfg                Config
	managementEndpoint string
	seq                uint64
	resources          map[string]map[string]*resource
	objects            map[string]*object
	work               map[string]*workRequest
	idempotency        map[string]idempotentResult
	faults             []FaultRule
	closed             bool
}

type resource struct {
	ID             string         `json:"id"`
	CompartmentID  string         `json:"compartmentId,omitempty"`
	DisplayName    string         `json:"displayName,omitempty"`
	Name           string         `json:"name,omitempty"`
	LifecycleState string         `json:"lifecycleState"`
	ETag           string         `json:"etag"`
	Kind           string         `json:"-"`
	Values         map[string]any `json:"-"`
}
type object struct {
	Content                 []byte
	SHA256, ETag            string
	Namespace, Bucket, Name string
}
type workRequest struct {
	ID, Kind, ResourceID string
	polls, maxPolls      int
	failed               bool
}
type idempotentResult struct{ fingerprint, id string }

// Stats reports bounded endpoint state for qualification diagnostics.
type Stats struct {
	Resources    int
	Objects      int
	WorkRequests int
}

// New returns an endpoint. It implements http.Handler and can be passed to
// httptest.NewServer directly. NewServer is an alias retained for readability.
func New(cfg Config) *Server { return NewServer(cfg) }
func NewServer(cfg Config) *Server {
	if cfg.Namespace == "" {
		cfg.Namespace = "terrascale-local"
	}
	if cfg.Region == "" {
		cfg.Region = "sa-saopaulo-1"
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = defaultBodyLimit
	}
	if cfg.MaxResources <= 0 {
		cfg.MaxResources = 4096
	}
	if cfg.WorkRequestPolls <= 0 && cfg.AsyncPolls > 0 {
		cfg.WorkRequestPolls = cfg.AsyncPolls
	}
	if cfg.WorkRequestPolls <= 0 {
		cfg.WorkRequestPolls = 2
	}
	s := &Server{cfg: cfg, managementEndpoint: cfg.ManagementEndpoint, resources: map[string]map[string]*resource{}, objects: map[string]*object{}, work: map[string]*workRequest{}, idempotency: map[string]idempotentResult{}}
	for _, fault := range cfg.Faults {
		steps := fault.Steps
		if len(steps) == 0 && fault.Response != nil {
			steps = []FaultStep{*fault.Response}
		}
		for _, step := range steps {
			rule := FaultRule{Method: fault.Method, Path: fault.Path, Status: step.Status, Code: fmt.Sprint(step.Code), Body: step.Body, Delay: step.Delay, Count: 1, Commit: step.Commit, Headers: step.Headers}
			if step.Drop {
				rule.Kind = FaultIndeterminate
			} else if step.Status == 0 && step.Delay > 0 {
				rule.Kind = FaultTimeout
			} else {
				rule.Kind = FaultResponse
			}
			if fault.Calls > 0 {
				rule.Count = fault.Calls
			}
			s.faults = append(s.faults, rule)
		}
	}
	return s
}

// Handler returns the server as an http.Handler.
func (s *Server) Handler() http.Handler { return s }

// Close prevents future mutations. Existing reads remain safe and return a
// provider-style 503. It is idempotent and useful in cleanup paths.
func (s *Server) Close() error { s.mu.Lock(); s.closed = true; s.mu.Unlock(); return nil }

// SetFaultScript replaces the deterministic fault script. Rules are copied.
func (s *Server) SetFaultScript(script any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = nil
	s.appendFaultsLocked(script)
}
func (s *Server) AddFault(script any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appendFaultsLocked(script)
}
func (s *Server) ClearFaults() { s.mu.Lock(); s.faults = nil; s.mu.Unlock() }

func (s *Server) appendFaultsLocked(script any) {
	copyHeaders := func(in map[string]string) map[string]string {
		if len(in) == 0 {
			return nil
		}
		out := make(map[string]string, len(in))
		for k, v := range in {
			out[k] = v
		}
		return out
	}
	switch value := script.(type) {
	case FaultRule:
		rule := value
		if len(value.Headers) > 0 {
			rule.Headers = make(map[string]string, len(value.Headers))
			for k, v := range value.Headers {
				rule.Headers[k] = v
			}
		}
		s.faults = append(s.faults, rule)
	case []FaultRule:
		for _, rule := range value {
			s.appendFaultsLocked(rule)
		}
	case Fault:
		steps := value.Steps
		if len(steps) == 0 && value.Response != nil {
			steps = []FaultStep{*value.Response}
		}
		for _, step := range steps {
			kind := FaultResponse
			if step.Drop {
				kind = FaultIndeterminate
			} else if step.Status == 0 && step.Delay > 0 {
				kind = FaultTimeout
			}
			count := value.Calls
			if count <= 0 {
				count = 1
			}
			s.faults = append(s.faults, FaultRule{Method: value.Method, Path: value.Path, Kind: kind, Status: step.Status, Code: fmt.Sprint(step.Code), Body: step.Body, Delay: step.Delay, Count: count, Commit: step.Commit, Headers: copyHeaders(step.Headers)})
		}
	case []Fault:
		for _, item := range value {
			s.appendFaultsLocked(item)
		}
	}
}

// SetManagementEndpoint configures the endpoint advertised by newly created
// vaults. It is useful when a test server has a separately mounted KMS
// listener.
func (s *Server) SetManagementEndpoint(endpoint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.managementEndpoint = endpoint
}

// ResourceCount is a bounded diagnostic helper for tests and cleanup checks.
func (s *Server) ResourceCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.allResourcesLocked())
}

func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{Resources: len(s.allResourcesLocked()), Objects: len(s.objects), WorkRequests: len(s.work)}
}

// Reset removes only this endpoint's resource state while retaining its
// configuration and fault script.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resources = map[string]map[string]*resource{}
	s.objects = map[string]*object{}
	s.work = map[string]*workRequest{}
	s.idempotency = map[string]idempotentResult{}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "" || r.URL.Path[0] != '/' {
		writeError(w, http.StatusBadRequest, "InvalidParameter")
		return
	}
	if rule, ok := s.takeFault(r.Method, r.URL.Path); ok {
		if rule.Delay > 0 {
			timer := time.NewTimer(rule.Delay)
			select {
			case <-timer.C:
			case <-r.Context().Done():
				timer.Stop()
				return
			}
		}
		switch rule.Kind {
		case FaultTimeout:
			if rule.Delay <= 0 {
				rule.Delay = 100 * time.Millisecond
			}
			timer := time.NewTimer(rule.Delay)
			select {
			case <-timer.C:
			case <-r.Context().Done():
				timer.Stop()
				return
			}
			return
		case FaultIndeterminate:
			// Run the normal mutation against a response writer that discards
			// bytes, then close the connection. This models OCI accepting a
			// request while the client loses the response.
			s.dispatch(&discardWriter{ResponseWriter: w}, r)
			if h, ok := w.(http.Hijacker); ok {
				conn, _, err := h.Hijack()
				if err == nil {
					_ = conn.Close()
				}
			}
			return
		default:
			if rule.Commit {
				var raw []byte
				if r.Body != nil {
					raw, _ = io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxBodyBytes+1))
					_ = r.Body.Close()
				}
				r.Body = io.NopCloser(bytes.NewReader(raw))
				s.dispatch(&discardWriter{ResponseWriter: w}, r)
				r.Body = io.NopCloser(bytes.NewReader(raw))
			}
			for key, value := range rule.Headers {
				w.Header().Set(key, value)
			}
			status := rule.Status
			if status == 0 {
				status = http.StatusInternalServerError
			}
			if rule.Body == nil {
				rule.Body = map[string]string{"code": rule.Code}
			}
			writeJSON(w, status, rule.Body)
			return
		}
	}
	s.dispatch(w, r)
}

type discardWriter struct {
	http.ResponseWriter
	wrote bool
}

func (w *discardWriter) WriteHeader(int)           { w.wrote = true }
func (w *discardWriter) Write([]byte) (int, error) { w.wrote = true; return 0, nil }

func (s *Server) dispatch(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > s.cfg.MaxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "RequestTooLarge")
		return
	}
	if s.isClosed() {
		writeError(w, http.StatusServiceUnavailable, "EndpointClosed")
		return
	}
	parts := pathParts(r.URL.Path)
	if len(parts) > 0 && parts[0] == "n" {
		s.objectRoute(w, r, parts)
		return
	}
	if len(parts) >= 2 && parts[0] == "20160918" {
		s.coreRoute(w, r, parts[1:])
		return
	}
	if len(parts) >= 2 && parts[0] == "20180608" {
		s.vaultRoute(w, r, parts[1:])
		return
	}
	if len(parts) >= 2 && parts[0] == "20210224" {
		s.certificateRoute(w, r, parts[1:])
		return
	}
	writeError(w, http.StatusNotFound, "NotFound")
}

func (s *Server) isClosed() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.closed }
func pathParts(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	raw := strings.Split(p, "/")
	out := make([]string, len(raw))
	for i, v := range raw {
		out[i], _ = url.PathUnescape(v)
	}
	return out
}
func (s *Server) takeFault(method, path string) (FaultRule, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.faults {
		f := &s.faults[i]
		if f.Method != "" && !strings.EqualFold(f.Method, method) {
			continue
		}
		if f.Path != "" && !(strings.HasSuffix(f.Path, "*") && strings.HasPrefix(path, strings.TrimSuffix(f.Path, "*"))) && f.Path != path {
			continue
		}
		out := *f
		if f.Count <= 1 {
			s.faults = append(s.faults[:i], s.faults[i+1:]...)
		} else {
			f.Count--
		}
		return out, true
	}
	return FaultRule{}, false
}

func (s *Server) coreRoute(w http.ResponseWriter, r *http.Request, p []string) {
	if len(p) == 0 {
		writeError(w, http.StatusNotFound, "NotFound")
		return
	}
	if p[0] == "workRequests" {
		s.workRoute(w, r, p[1:])
		return
	}
	if p[0] == "availabilityDomains" {
		if r.Method == http.MethodGet {
			writeJSON(w, 200, []map[string]string{{"name": "AD-1"}, {"name": "AD-2"}})
			return
		}
		writeError(w, 405, "MethodNotAllowed")
		return
	}
	kind := map[string]string{"compartments": "compartment", "vcns": "vcn", "subnets": "subnet", "networkSecurityGroups": "networksecuritygroup", "instances": "instance", "volumes": "volume", "volumeAttachments": "volumeattachment"}[p[0]]
	if kind == "" {
		writeError(w, 404, "NotFound")
		return
	}
	if len(p) >= 3 && p[0] == "networkSecurityGroups" && p[2] == "securityRules" {
		s.rulesRoute(w, r, p[1])
		return
	}
	if len(p) >= 3 && p[0] == "instances" && p[2] == "actions" {
		s.instanceAction(w, r, p[1], p[3:])
		return
	}
	if len(p) == 1 && r.Method == http.MethodGet {
		s.listResources(w, r, kind)
		return
	}
	if len(p) == 1 && r.Method == http.MethodPost {
		s.createResource(w, r, kind, p[0])
		return
	}
	if len(p) == 2 {
		s.resourceRoute(w, r, kind, p[1])
		return
	}
	writeError(w, 404, "NotFound")
}

func (s *Server) vaultRoute(w http.ResponseWriter, r *http.Request, p []string) {
	if len(p) == 0 {
		writeError(w, 404, "NotFound")
		return
	}
	if p[0] == "vaults" {
		if len(p) == 1 && r.Method == http.MethodGet {
			s.listResources(w, r, "vault")
			return
		}
		if len(p) == 1 && r.Method == http.MethodPost {
			s.createResource(w, r, "vault", "vaults")
			return
		}
		if len(p) == 2 {
			s.resourceRoute(w, r, "vault", p[1])
			return
		}
	}
	if p[0] == "keys" {
		if len(p) == 1 && r.Method == http.MethodGet {
			s.listResources(w, r, "key")
			return
		}
		if len(p) == 1 && r.Method == http.MethodPost {
			s.createResource(w, r, "key", "keys")
			return
		}
		if len(p) == 2 {
			s.resourceRoute(w, r, "key", p[1])
			return
		}
	}
	writeError(w, 404, "NotFound")
}

func (s *Server) createResource(w http.ResponseWriter, r *http.Request, kind, collection string) {
	body, err := readJSON(r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, 400, "InvalidParameter")
		return
	}
	name := stringValue(body, "displayName")
	if name == "" {
		name = stringValue(body, "name")
	}
	comp := stringValue(body, "compartmentId")
	if kind == "compartment" {
		comp = stringValue(body, "compartmentId")
	}
	fingerprint := hashJSON(body)
	token := r.Header.Get("opc-retry-token")
	s.mu.Lock()
	defer s.mu.Unlock()
	if token != "" {
		if prior, ok := s.idempotency[token]; ok {
			if prior.fingerprint != fingerprint {
				writeError(w, 409, "IdempotencyConflict")
				return
			}
			s.respondResourceLocked(w, prior.id, kind, http.StatusAccepted)
			return
		}
	}
	if len(s.allResourcesLocked()) >= s.cfg.MaxResources {
		writeError(w, 429, "LimitExceeded")
		return
	}
	nameKey := kind + "/" + comp + "/" + name
	if token == "" {
		for _, x := range s.resources[kind] {
			if x.CompartmentID == comp && x.DisplayName == name && name != "" {
				s.respondResourceLocked(w, x.ID, kind, http.StatusConflict)
				return
			}
		}
	}
	id := s.newIDLocked(kind)
	etag := s.etagLocked()
	state := "CREATING"
	if kind == "compartment" {
		state = "ACTIVE"
	}
	x := &resource{ID: id, Kind: kind, CompartmentID: comp, DisplayName: name, Name: name, LifecycleState: state, ETag: etag, Values: body}
	if kind == "certificate" {
		x.LifecycleState = "ACTIVE"
		x.Values["subjectAlternativeNames"] = body["subjectAlternativeNames"]
		x.Values["timeExpiresAt"] = time.Now().UTC().AddDate(1, 0, 0).Format(time.RFC3339)
	}
	if kind == "vault" && s.managementEndpoint == "" {
		x.Values["managementEndpoint"] = "https://sandbox-management.kms." + s.cfg.Region + ".oci.oraclecloud.com"
	}
	if s.resources[kind] == nil {
		s.resources[kind] = map[string]*resource{}
	}
	s.resources[kind][id] = x
	if token != "" {
		s.idempotency[token] = idempotentResult{fingerprint, id}
	}
	if state != "ACTIVE" {
		workID := s.newIDLocked("workrequest")
		s.work[workID] = &workRequest{ID: workID, Kind: kind, ResourceID: id, maxPolls: s.cfg.WorkRequestPolls}
		w.Header().Set("opc-work-request-id", workID)
	}
	s.respondResourceLocked(w, id, kind, http.StatusAccepted)
	_ = nameKey
}

func (s *Server) listResources(w http.ResponseWriter, r *http.Request, kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := make([]*resource, 0, len(s.resources[kind]))
	for _, x := range s.resources[kind] {
		if !matchesQuery(x, r.URL.Query()) {
			continue
		}
		all = append(all, x)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	items, next := paginate(all, r.URL.Query())
	out := make([]map[string]any, 0, len(items))
	for _, x := range items {
		out = append(out, s.resourceMapLocked(x))
	}
	if next != "" {
		w.Header().Set("opc-next-page", next)
	}
	if kind != "certificate" {
		writeJSON(w, 200, out)
		return
	}
	writeJSON(w, 200, map[string]any{"items": out})
}
func matchesQuery(x *resource, q url.Values) bool {
	if c := q.Get("compartmentId"); c != "" && x.CompartmentID != c {
		return false
	}
	if n := q.Get("name"); n != "" && x.DisplayName != n {
		return false
	}
	if v := q.Get("vcnId"); v != "" && stringValue(x.Values, "vcnId") != v {
		return false
	}
	return true
}
func paginate(all []*resource, q url.Values) ([]*resource, string) {
	start, _ := strconv.Atoi(q.Get("page"))
	if start < 0 {
		start = 0
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	if start >= len(all) {
		return nil, ""
	}
	end := start + limit
	if end > len(all) {
		end = len(all)
	}
	next := ""
	if end < len(all) {
		next = strconv.Itoa(end)
	}
	return all[start:end], next
}

func (s *Server) resourceRoute(w http.ResponseWriter, r *http.Request, kind, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x := s.resources[kind][id]
	if x == nil {
		writeError(w, 404, "NotFound")
		return
	}
	if r.Method == http.MethodGet {
		s.respondResourceLocked(w, id, kind, 200)
		return
	}
	if r.Method == http.MethodPut {
		if !s.etagOK(x, r.Header.Get("If-Match")) {
			writeError(w, 412, "EtagMismatch")
			return
		}
		body, err := readJSON(r, s.cfg.MaxBodyBytes)
		if err != nil {
			writeError(w, 400, "InvalidParameter")
			return
		}
		for k, v := range body {
			x.Values[k] = v
		}
		if v, ok := body["versioning"]; ok {
			x.Values["versioning"] = v
		}
		x.ETag = s.etagLocked()
		x.LifecycleState = "AVAILABLE"
		if kind == "vault" {
			x.LifecycleState = "ACTIVE"
		}
		s.respondResourceLocked(w, id, kind, 200)
		return
	}
	if r.Method == http.MethodDelete {
		if got := r.Header.Get("If-Match"); got != "" && !s.etagOK(x, got) {
			writeError(w, 412, "EtagMismatch")
			return
		}
		delete(s.resources[kind], id)
		w.Header().Set("etag", x.ETag)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeError(w, 405, "MethodNotAllowed")
}
func (s *Server) instanceAction(w http.ResponseWriter, r *http.Request, id string, action []string) {
	if r.Method != http.MethodPost || len(action) == 0 {
		writeError(w, 405, "MethodNotAllowed")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	x := s.resources["instance"][id]
	if x == nil {
		writeError(w, 404, "NotFound")
		return
	}
	switch action[0] {
	case "start":
		x.LifecycleState = "RUNNING"
		x.ETag = s.etagLocked()
		writeJSON(w, 200, s.resourceMapLocked(x))
	default:
		writeError(w, 404, "NotFound")
	}
}

func (s *Server) rulesRoute(w http.ResponseWriter, r *http.Request, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x := s.resources["networksecuritygroup"][id]
	if x == nil {
		writeError(w, 404, "NotFound")
		return
	}
	rules, _ := x.Values["rules"].([]any)
	if r.Method == http.MethodGet {
		items := make([]any, 0, len(rules))
		for i, v := range rules {
			m, _ := v.(map[string]any)
			if m["id"] == nil {
				m["id"] = s.newIDLocked("securityrule")
			}
			rules[i] = m
			items = append(items, m)
		}
		writeJSON(w, 200, items)
		return
	}
	body, err := readJSON(r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, 400, "InvalidParameter")
		return
	}
	if r.Method == http.MethodPost {
		if len(pathParts(r.URL.Path)) >= 6 && pathParts(r.URL.Path)[4] == "actions" && pathParts(r.URL.Path)[5] == "remove" {
			remove, _ := body["securityRuleIds"].([]any)
			keep := rules[:0]
			for _, item := range rules {
				m, _ := item.(map[string]any)
				idValue := stringValue(m, "id")
				gone := false
				for _, candidate := range remove {
					if candidateID, ok := candidate.(string); ok && idValue == candidateID {
						gone = true
						break
					}
				}
				if !gone {
					keep = append(keep, item)
				}
			}
			x.Values["rules"] = keep
			writeJSON(w, 200, map[string]any{})
			return
		}
		if v, ok := body["securityRules"].([]any); ok {
			rules = append(rules, v...)
		}
		x.Values["rules"] = rules
		writeJSON(w, 200, map[string]any{})
		return
	}
	if r.Method == http.MethodPost && len(id) > 0 {
		writeJSON(w, 200, map[string]any{})
		return
	}
	writeError(w, 405, "MethodNotAllowed")
}

func (s *Server) workRoute(w http.ResponseWriter, r *http.Request, p []string) {
	if r.Method != http.MethodGet || len(p) != 1 {
		writeError(w, 405, "MethodNotAllowed")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	wr := s.work[p[0]]
	if wr == nil {
		writeError(w, 404, "NotFound")
		return
	}
	wr.polls++
	status := "ACCEPTED"
	pct := 0.0
	if wr.polls > 1 {
		status = "IN_PROGRESS"
		pct = 50
	}
	if wr.polls >= wr.maxPolls {
		status = "SUCCEEDED"
		pct = 100
		if x := s.resources[wr.Kind][wr.ResourceID]; x != nil {
			x.LifecycleState = activeState(wr.Kind)
			x.ETag = s.etagLocked()
		}
	}
	if wr.failed {
		status = "FAILED"
	}
	writeJSON(w, 200, map[string]any{"id": wr.ID, "status": status, "percentComplete": pct})
}
func activeState(kind string) string {
	switch kind {
	case "instance":
		return "RUNNING"
	case "vault":
		return "ACTIVE"
	case "key":
		return "ENABLED"
	case "volume":
		return "AVAILABLE"
	case "volumeattachment":
		return "ATTACHED"
	default:
		return "AVAILABLE"
	}
}

func (s *Server) objectRoute(w http.ResponseWriter, r *http.Request, p []string) {
	if len(p) == 1 && p[0] == "n" {
		if r.Method == http.MethodGet {
			writeJSON(w, 200, s.cfg.Namespace)
			return
		}
		writeError(w, 405, "MethodNotAllowed")
		return
	}
	if len(p) < 3 || p[0] != "n" {
		writeError(w, 404, "NotFound")
		return
	}
	namespace := p[1]
	if len(p) == 3 && p[2] == "b" {
		if r.Method == http.MethodGet {
			s.listBuckets(w, r, namespace)
			return
		}
		if r.Method == http.MethodPost {
			s.createBucket(w, r, namespace)
			return
		}
	}
	if len(p) < 4 || p[2] != "b" {
		writeError(w, 404, "NotFound")
		return
	}
	bucket := p[3]
	if len(p) == 4 {
		if r.Method == http.MethodGet {
			s.bucket(w, r, namespace, bucket)
			return
		}
		if r.Method == http.MethodPut {
			s.updateBucket(w, r, namespace, bucket)
			return
		}
	}
	if len(p) == 5 && p[4] == "lifecyclePolicy" {
		s.lifecycle(w, r, namespace, bucket)
		return
	}
	if len(p) == 5 && p[4] == "o" {
		s.listObjects(w, r, namespace, bucket)
		return
	}
	if len(p) >= 6 && p[4] == "o" {
		s.object(w, r, namespace, bucket, strings.Join(p[5:], "/"))
		return
	}
	writeError(w, 404, "NotFound")
}
func objectKey(ns, b, n string) string { return ns + "\x00" + b + "\x00" + n }
func (s *Server) listBuckets(w http.ResponseWriter, r *http.Request, ns string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := []map[string]string{}
	for _, x := range s.resources["bucket"] {
		if x.Values["namespace"] == ns {
			items = append(items, map[string]string{"name": x.Name})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i]["name"] < items[j]["name"] })
	start, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if start < 0 {
		start = 0
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	if start >= len(items) {
		items = []map[string]string{}
	} else {
		end := start + limit
		if end > len(items) {
			end = len(items)
		}
		if end < len(items) {
			w.Header().Set("opc-next-page", strconv.Itoa(end))
		}
		items = items[start:end]
	}
	writeJSON(w, 200, items)
}
func (s *Server) createBucket(w http.ResponseWriter, r *http.Request, ns string) {
	body, err := readJSON(r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, 400, "InvalidParameter")
		return
	}
	body["namespace"] = ns
	if body["name"] == nil {
		writeError(w, 400, "InvalidParameter")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	token := r.Header.Get("opc-retry-token")
	fingerprint := hashJSON(body)
	if token != "" {
		if prior, ok := s.idempotency[token]; ok {
			if prior.fingerprint != fingerprint {
				writeError(w, http.StatusConflict, "IdempotencyConflict")
				return
			}
			if x := s.resources["bucket"][prior.id]; x != nil {
				w.Header().Set("etag", x.ETag)
				writeJSON(w, http.StatusOK, map[string]any{"name": x.Name, "versioning": stringValue(x.Values, "versioning")})
				return
			}
		}
	}
	for _, x := range s.resources["bucket"] {
		if x.Name == stringValue(body, "name") && x.Values["namespace"] == ns {
			s.respondResourceLocked(w, x.ID, "bucket", 409)
			return
		}
	}
	id := s.newIDLocked("bucket")
	x := &resource{ID: id, Kind: "bucket", Name: stringValue(body, "name"), DisplayName: stringValue(body, "name"), LifecycleState: "ACTIVE", ETag: s.etagLocked(), Values: body}
	if s.resources["bucket"] == nil {
		s.resources["bucket"] = map[string]*resource{}
	}
	s.resources["bucket"][id] = x
	if token != "" {
		s.idempotency[token] = idempotentResult{fingerprint: fingerprint, id: id}
	}
	w.Header().Set("etag", x.ETag)
	writeJSON(w, 200, map[string]any{"name": x.Name, "versioning": stringValue(body, "versioning")})
}
func (s *Server) bucket(w http.ResponseWriter, r *http.Request, ns, b string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.resources["bucket"] {
		if x.Name == b && x.Values["namespace"] == ns {
			w.Header().Set("etag", x.ETag)
			writeJSON(w, 200, map[string]any{"name": b, "versioning": stringValue(x.Values, "versioning")})
			return
		}
	}
	writeError(w, 404, "NotFound")
}
func (s *Server) updateBucket(w http.ResponseWriter, r *http.Request, ns, b string) {
	body, err := readJSON(r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, 400, "InvalidParameter")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.resources["bucket"] {
		if x.Name == b && x.Values["namespace"] == ns {
			if got := r.Header.Get("If-Match"); got != "" && !s.etagOK(x, got) {
				writeError(w, http.StatusPreconditionFailed, "EtagMismatch")
				return
			}
			for k, v := range body {
				x.Values[k] = v
			}
			x.ETag = s.etagLocked()
			w.Header().Set("etag", x.ETag)
			writeJSON(w, 200, map[string]any{})
			return
		}
	}
	writeError(w, 404, "NotFound")
}

func (s *Server) listObjects(w http.ResponseWriter, r *http.Request, ns, b string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]map[string]any, 0)
	for _, o := range s.objects {
		if o.Namespace != ns || o.Bucket != b {
			continue
		}
		items = append(items, map[string]any{"name": o.Name, "etag": o.ETag, "size": len(o.Content), "md5": o.SHA256})
	}
	sort.Slice(items, func(i, j int) bool { return items[i]["name"].(string) < items[j]["name"].(string) })
	start, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if start < 0 {
		start = 0
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	if start >= len(items) {
		items = nil
	} else {
		end := start + limit
		if end > len(items) {
			end = len(items)
		}
		if end < len(items) {
			w.Header().Set("opc-next-page", strconv.Itoa(end))
		}
		items = items[start:end]
	}
	writeJSON(w, http.StatusOK, map[string]any{"objects": items})
}
func (s *Server) lifecycle(w http.ResponseWriter, r *http.Request, ns, b string) {
	if r.Method != http.MethodPut && r.Method != http.MethodGet {
		writeError(w, 405, "MethodNotAllowed")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.resources["bucket"] {
		if x.Name == b && x.Values["namespace"] == ns {
			if r.Method == http.MethodPut {
				if got := r.Header.Get("If-Match"); got != "" && !s.etagOK(x, got) {
					writeError(w, http.StatusPreconditionFailed, "EtagMismatch")
					return
				}
				body, err := readJSON(r, s.cfg.MaxBodyBytes)
				if err != nil {
					writeError(w, 400, "InvalidParameter")
					return
				}
				x.Values["lifecyclePolicy"] = body
				x.ETag = s.etagLocked()
			}
			w.Header().Set("etag", x.ETag)
			if v, ok := x.Values["lifecyclePolicy"]; ok {
				writeJSON(w, 200, v)
				return
			}
			writeError(w, 404, "NotFound")
			return
		}
	}
	writeError(w, 404, "NotFound")
}
func (s *Server) object(w http.ResponseWriter, r *http.Request, ns, b, n string) {
	key := objectKey(ns, b, n)
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.objects[key]
	if r.Method == http.MethodPut {
		if r.Header.Get("If-None-Match") == "*" && o != nil {
			writeError(w, 412, "PreconditionFailed")
			return
		}
		data, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxBodyBytes+1))
		if err != nil || int64(len(data)) > s.cfg.MaxBodyBytes {
			writeError(w, 413, "RequestTooLarge")
			return
		}
		digest := sha256.Sum256(data)
		provided := r.Header.Get("opc-meta-terrascale-sha256")
		if provided != "" && provided != hex.EncodeToString(digest[:]) {
			writeError(w, 400, "InvalidParameter")
			return
		}
		o = &object{Content: append([]byte(nil), data...), SHA256: hex.EncodeToString(digest[:]), ETag: s.etagLocked(), Namespace: ns, Bucket: b, Name: n}
		s.objects[key] = o
		w.Header().Set("etag", o.ETag)
		w.Header().Set("opc-meta-terrascale-sha256", o.SHA256)
		w.WriteHeader(200)
		return
	}
	if o == nil {
		writeError(w, 404, "NotFound")
		return
	}
	if r.Method == http.MethodHead {
		objectHeaders(w, o)
		w.WriteHeader(200)
		return
	}
	if r.Method == http.MethodGet {
		objectHeaders(w, o)
		w.Write(o.Content)
		return
	}
	if r.Method == http.MethodDelete {
		if !s.etagOK(o, r.Header.Get("If-Match")) {
			writeError(w, 412, "EtagMismatch")
			return
		}
		delete(s.objects, key)
		w.WriteHeader(204)
		return
	}
	writeError(w, 405, "MethodNotAllowed")
}
func objectHeaders(w http.ResponseWriter, o *object) {
	w.Header().Set("etag", o.ETag)
	w.Header().Set("opc-meta-terrascale-sha256", o.SHA256)
	w.Header().Set("Content-Length", strconv.Itoa(len(o.Content)))
}

func (s *Server) certificateRoute(w http.ResponseWriter, r *http.Request, p []string) {
	if len(p) == 0 {
		writeError(w, 404, "NotFound")
		return
	}
	if len(p) == 1 && r.Method == http.MethodGet {
		s.listResources(w, r, "certificate")
		return
	}
	if len(p) == 1 && r.Method == http.MethodPost {
		s.createResource(w, r, "certificate", "certificates")
		return
	}
	if len(p) == 2 {
		s.resourceRoute(w, r, "certificate", p[1])
		return
	}
	writeError(w, 404, "NotFound")
}
func (s *Server) allResourcesLocked() []*resource {
	var out []*resource
	for _, m := range s.resources {
		for _, x := range m {
			out = append(out, x)
		}
	}
	return out
}
func (s *Server) newIDLocked(kind string) string {
	s.seq++
	return "ocid1." + kind + ".oc1.local." + strconv.FormatUint(s.seq, 10)
}
func (s *Server) etagLocked() string { s.seq++; return `"v` + strconv.FormatUint(s.seq, 10) + `"` }
func (s *Server) etagOK(x interface{ getETag() string }, got string) bool {
	return got != "" && got == x.getETag()
}

func (x *resource) getETag() string { return x.ETag }
func (x *object) getETag() string   { return x.ETag }
func (s *Server) resourceMapLocked(x *resource) map[string]any {
	m := map[string]any{"id": x.ID, "lifecycleState": x.LifecycleState, "etag": x.ETag}
	if x.CompartmentID != "" {
		m["compartmentId"] = x.CompartmentID
	}
	if x.DisplayName != "" {
		m["displayName"] = x.DisplayName
	}
	if x.Name != "" {
		m["name"] = x.Name
	}
	for k, v := range x.Values {
		if k != "rules" && k != "namespace" && k != "lifecyclePolicy" {
			m[k] = v
		}
	}
	if x.Kind == "instance" {
		m["shape"] = stringValue(x.Values, "shape")
		m["availabilityDomain"] = stringValue(x.Values, "availabilityDomain")
		m["freeformTags"] = x.Values["freeformTags"]
	}
	if x.Kind == "volume" {
		m["sizeInGBs"] = x.Values["sizeInGBs"]
		m["vpusPerGB"] = x.Values["vpusPerGB"]
	}
	if x.Kind == "vault" {
		m["vaultType"] = "DEFAULT"
		ep := s.managementEndpoint
		if ep == "" {
			ep = stringValue(x.Values, "managementEndpoint")
		}
		if ep != "" {
			m["managementEndpoint"] = ep
		}
	}
	return m
}
func (s *Server) respondResourceLocked(w http.ResponseWriter, id, kind string, status int) {
	x := s.resources[kind][id]
	if x == nil {
		writeError(w, 404, "NotFound")
		return
	}
	w.Header().Set("etag", x.ETag)
	if wr := s.workForLocked(kind, id); wr != "" {
		w.Header().Set("opc-work-request-id", wr)
	}
	writeJSON(w, status, s.resourceMapLocked(x))
}
func (s *Server) workForLocked(kind, id string) string {
	for k, w := range s.work {
		if w.Kind == kind && w.ResourceID == id {
			return k
		}
	}
	return ""
}
func (s *Server) readOnlyResource(kind, id string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if x := s.resources[kind][id]; x != nil {
		return s.resourceMapLocked(x)
	}
	return nil
}

func readJSON(r *http.Request, max int64) (map[string]any, error) {
	if r.Body == nil {
		return map[string]any{}, nil
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, errors.New("body")
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err = json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}
func stringValue(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}
func hashJSON(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"code": code, "message": "local OCI endpoint request failed", "status": status})
}
