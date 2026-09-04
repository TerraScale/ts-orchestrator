// Package edge is a bounded, in-process edge endpoint for qualification tests.
//
// It models the part of the sync.api Snippet which is important to the local
// journey: capability verification happens before the cache, the capability
// and user credentials are removed before the canonical origin request, and a
// single deterministic cache location collapses concurrent immutable fills.
// This package is deliberately under sandboxproviders and is not used by an
// orchestrator production binary. It has no Cloudflare or network dependency.
package edge

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// CapabilityHeader is the header accepted by the edge gate.
	CapabilityHeader = "X-TerraScale-Capability"
	// Bucket is the capability expiry bucket width specified by D-14.
	Bucket = 10 * time.Minute
	// Overlap is the accepted mint window. The current and immediately prior
	// bucket are accepted; expiry is the end of the next bucket.
	Overlap = 2 * Bucket
	// DefaultTimeout bounds an origin fill when no timeout is supplied.
	DefaultTimeout = 30 * time.Second

	capabilityTag = "v1"
	maxViewBytes  = 128
	maxScopeBytes = 256
)

// CapabilityRegions is the closed launch-region catalog.
var CapabilityRegions = [...]string{"GRU", "SFO", "FRA"}

// Options configures one local edge endpoint. Origin and Fetch are mutually
// exclusive; Fetch is useful for deterministic tests that need context-aware
// delays and errors, while Origin adapts a normal http.Handler.
type Options struct {
	// Keys is the current key ring. Every key is tried, allowing a rotation
	// overlap. Key is a compatibility shorthand for a one-key ring.
	Keys [][]byte
	Key  []byte
	// Region binds every capability to this origin region. Empty accepts any
	// known region, matching the global sync.api hostname.
	Region string
	// Now supplies the edge clock. It is called for each request.
	Now func() time.Time
	// Origin is a local canonical origin handler. It never receives auth
	// material because the edge strips it before calling the handler.
	Origin http.Handler
	// Fetch is a context-aware local origin adapter. It must return an owned
	// response body; the edge reads and closes it before caching.
	Fetch func(context.Context, *http.Request) (*http.Response, error)
	// Timeout bounds an origin request. A timeout returns a no-store 504.
	Timeout time.Duration
	// CacheEnabled is an optional rule predicate. A nil predicate enables the
	// immutable reactive rule for every recognized log/snapshot path.
	CacheEnabled func(*http.Request) bool
}

// Metrics is a point-in-time copy of endpoint counters. Counters include
// rejected requests and faults so a qualification report can distinguish a
// cache miss from a gate or origin failure.
type Metrics struct {
	OriginFetches      uint64
	CacheHits          uint64
	CacheMisses        uint64
	CollapsedFills     uint64
	CacheableResponses uint64
	NoStoreResponses   uint64
	DeniedRequests     uint64
	TimeoutResponses   uint64
	OriginErrors       uint64
	RuleBypasses       uint64
	Evictions          uint64
	CacheEntries       int
}

type cachedResponse struct {
	status     int
	statusText string
	header     http.Header
	body       []byte
}

type fill struct {
	done chan struct{}
	resp cachedResponse
}

// Handler implements the local edge endpoint. It is safe for concurrent use.
type Handler struct {
	mu sync.Mutex

	keys    [][]byte
	region  string
	now     func() time.Time
	fetch   func(context.Context, *http.Request) (*http.Response, error)
	timeout time.Duration
	rule    func(*http.Request) bool
	ruleOn  bool

	cache map[string]cachedResponse
	fills map[string]*fill
	stats Metrics

	// faults are intentionally mutable: qualification can inject a cache-rule
	// change, origin error, or latency without a second endpoint.
	originErr   error
	originDelay time.Duration
}

// New returns a local edge handler. It does not start a listener.
func New(options Options) *Handler {
	keys := make([][]byte, 0, len(options.Keys)+1)
	for _, key := range options.Keys {
		if len(key) != 0 {
			keys = append(keys, append([]byte(nil), key...))
		}
	}
	if len(options.Key) != 0 {
		keys = append(keys, append([]byte(nil), options.Key...))
	}
	fetch := options.Fetch
	if fetch == nil && options.Origin != nil {
		fetch = handlerFetch(options.Origin)
	}
	if fetch == nil {
		fetch = func(context.Context, *http.Request) (*http.Response, error) {
			return nil, errors.New("edge origin is not configured")
		}
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	rule := options.CacheEnabled
	if rule == nil {
		rule = func(*http.Request) bool { return true }
	}
	return &Handler{
		keys: keys, region: strings.ToUpper(strings.TrimSpace(options.Region)), now: valueOrNow(options.Now),
		fetch: fetch, timeout: timeout, rule: rule, ruleOn: true,
		cache: make(map[string]cachedResponse), fills: make(map[string]*fill),
	}
}

func valueOrNow(now func() time.Time) func() time.Time {
	if now != nil {
		return now
	}
	return time.Now
}

func handlerFetch(origin http.Handler) func(context.Context, *http.Request) (*http.Response, error) {
	return func(ctx context.Context, request *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			origin.ServeHTTP(recorder, request.WithContext(ctx))
			close(done)
		}()
		select {
		case <-done:
			result := recorder.Result()
			return result, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// NewServer starts an httptest listener for one local edge endpoint. Callers
// own the returned server and must close it. It binds only to the test host.
func NewServer(options Options) *httptest.Server { return httptest.NewServer(New(options)) }

// ServeHTTP applies the Snippet gate and routes authorized reads through the
// one local cache. Attach POSTs and every unrecognized route fail closed.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, kind, ok := parseRoute(r.URL)
	if !ok {
		h.deny(w, r.Method, http.StatusNotFound, "not_found", "reactive route not found")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.deny(w, r.Method, http.StatusMethodNotAllowed, "method_not_allowed", "reactive reads are GET or HEAD only")
		return
	}
	if kind == routeSnapshot && r.URL.Query().Get("cut") == "" {
		h.deny(w, r.Method, http.StatusBadRequest, "missing_snapshot_cut", "snapshot reads require the immutable cut")
		return
	}
	capabilities := r.Header.Values(CapabilityHeader)
	if len(capabilities) == 0 || strings.TrimSpace(capabilities[0]) == "" {
		h.deny(w, r.Method, http.StatusUnauthorized, "missing_capability", "this read needs its view capability")
		return
	}
	if len(capabilities) != 1 || strings.Contains(capabilities[0], ",") {
		h.deny(w, r.Method, http.StatusUnauthorized, "invalid_capability", "the view capability is malformed")
		return
	}
	if err := h.verify(capabilities[0], route); err != nil {
		code := "invalid_capability"
		var capabilityErr *CapabilityError
		if errors.As(err, &capabilityErr) {
			code = capabilityErr.Code()
		}
		h.deny(w, r.Method, http.StatusUnauthorized, code, err.Error())
		return
	}

	canonical := canonicalRequest(r)
	key := canonical.URL.String()
	h.serveCached(methodWriter{ResponseWriter: w, method: r.Method}, canonical, key)
}

type routeKind uint8

const (
	routeLog routeKind = iota
	routeSnapshot
)

type route struct {
	view, generation, region string
}

// ParsedCapability is the authenticated, route-bound part of a capability.
// Scope remains encoded as it appeared on the wire; the edge never interprets
// authorization scope.
type ParsedCapability struct {
	View, Generation, Scope, Region string
	Epoch, Expiry                   int64
	Body, Signature                 string
}

// CapabilityError is returned for all gate failures. Code is safe to expose
// in a JSON error while Error intentionally stays generic.
type CapabilityError struct {
	code string
	msg  string
}

func (e *CapabilityError) Error() string { return e.msg }

// Code identifies a gate failure without exposing cryptographic details.
func (e *CapabilityError) Code() string { return e.code }

func capError(code, message string) *CapabilityError {
	return &CapabilityError{code: code, msg: message}
}

// MintCapability emits the D-14 v1 capability consumed by the Cloudflare
// Snippet and this local gate. Expiry is the end of the bucket after the one
// containing now, making capabilities deterministic for equivalent clients.
func MintCapability(key []byte, view string, generation int64, scope string, epoch int64, region string, now time.Time) (string, error) {
	region = strings.ToUpper(strings.TrimSpace(region))
	if len(key) == 0 || !validView(view) || generation < 0 || epoch < 0 || !validRegion(region) || len(scope) > maxScopeBytes {
		return "", errors.New("invalid capability fields")
	}
	field := encodeScope(scope)
	expiry := (now.Unix()/int64(Bucket.Seconds()) + 2) * int64(Bucket.Seconds())
	body := fmt.Sprintf("%s.%s.%d.%s.%d.%s.%d", capabilityTag, view, generation, field, epoch, region, expiry)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(body))
	return body + "." + hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyCapability checks a capability against a route, clock and key ring.
// The previous expiry bucket overlaps the current one, while future-dated
// capabilities fail closed. An empty region leaves the route unpinned.
func VerifyCapability(keys [][]byte, raw string, view, generation, region string, now time.Time) (*ParsedCapability, error) {
	route := route{view: view, generation: generation, region: strings.ToUpper(strings.TrimSpace(region))}
	parsed, err := parseCapability(raw, route)
	if err != nil {
		return nil, err
	}
	seconds := now.Unix()
	if seconds >= parsed.Expiry {
		return nil, capError("expired_capability", "the view capability expired")
	}
	if seconds < parsed.Expiry-int64(Overlap.Seconds()) {
		return nil, capError("invalid_capability", "the view capability is not yet valid")
	}
	for _, key := range keys {
		if len(key) == 0 {
			continue
		}
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(parsed.Body))
		if hmac.Equal(mac.Sum(nil), mustHex(parsed.Signature)) {
			return parsed, nil
		}
	}
	return nil, capError("invalid_capability", "the view capability does not match this view")
}

func mustHex(value string) []byte {
	decoded, _ := hex.DecodeString(value)
	return decoded
}

func parseCapability(raw string, expected route) (*ParsedCapability, error) {
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, ".")
	if raw == "" || strings.Contains(raw, ",") || len(parts) != 8 || parts[0] != capabilityTag {
		return nil, capError("invalid_capability", "the view capability is malformed")
	}
	if parts[1] != expected.view || parts[2] != expected.generation {
		return nil, capError("invalid_capability", "the view capability does not match this view")
	}
	if !validScopeField(parts[3]) || !validInteger(parts[4]) || !validRegion(parts[5]) || !validInteger(parts[6]) || len(parts[7]) != sha256.Size*2 || strings.ToLower(parts[7]) != parts[7] {
		return nil, capError("invalid_capability", "the view capability is malformed")
	}
	if expected.region != "" && parts[5] != expected.region {
		return nil, capError("invalid_capability", "the view capability does not match this region")
	}
	epoch, epochErr := strconv.ParseInt(parts[4], 10, 64)
	expiry, expiryErr := strconv.ParseInt(parts[6], 10, 64)
	if epochErr != nil || expiryErr != nil || epoch < 0 || expiry <= 0 {
		return nil, capError("invalid_capability", "the view capability is malformed")
	}
	if _, err := hex.DecodeString(parts[7]); err != nil {
		return nil, capError("invalid_capability", "the view capability is malformed")
	}
	return &ParsedCapability{View: parts[1], Generation: parts[2], Scope: parts[3], Epoch: epoch, Region: parts[5], Expiry: expiry, Body: strings.Join(parts[:7], "."), Signature: parts[7]}, nil
}

func validRegion(value string) bool {
	for _, region := range CapabilityRegions {
		if value == region {
			return true
		}
	}
	return false
}

func validScopeField(field string) bool {
	if field == "" {
		return false
	}
	plain := true
	for _, c := range field {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == ':') {
			plain = false
			break
		}
	}
	if plain && len(field) <= maxScopeBytes {
		return true
	}
	if !strings.HasPrefix(field, "b64:") {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(field, "b64:"))
	return err == nil && len(decoded) <= maxScopeBytes
}

func encodeScope(scope string) string {
	if validScopeField(scope) {
		return scope
	}
	return "b64:" + base64.RawURLEncoding.EncodeToString([]byte(scope))
}

func (h *Handler) verify(raw string, expected route) error {
	_, err := VerifyCapability(h.keys, raw, expected.view, expected.generation, h.region, h.now())
	return err
}

func parseRoute(u *url.URL) (route, routeKind, bool) {
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 7 && len(parts) != 8 {
		return route{}, 0, false
	}
	if len(parts) < 6 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "reactive" || parts[3] != "views" || !validView(parts[4]) || !validInteger(parts[5]) {
		return route{}, 0, false
	}
	result := route{view: parts[4], generation: parts[5]}
	if len(parts) == 7 {
		if parts[6] != "log" {
			return route{}, 0, false
		}
	} else if parts[6] != "snapshot" || !validInteger(parts[7]) {
		return route{}, 0, false
	}
	if len(parts) == 8 {
		return result, routeSnapshot, true
	}
	return result, routeLog, true
}

func validView(view string) bool {
	if len(view) == 0 || len(view) > maxViewBytes {
		return false
	}
	for _, c := range view {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func validInteger(value string) bool {
	if value == "" || len(value) > 19 {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func canonicalRequest(r *http.Request) *http.Request {
	clone := r.Clone(r.Context())
	clone.URL = CanonicalURL(r.URL)
	clone.RequestURI = clone.URL.RequestURI()
	stripHeader(clone.Header, CapabilityHeader, "Authorization", "Cookie")
	return clone
}

func stripHeader(header http.Header, names ...string) {
	for key := range header {
		for _, name := range names {
			if strings.EqualFold(key, name) {
				delete(header, key)
				break
			}
		}
	}
}

// CanonicalURL retains only the cache-key query field: offset for logs and
// cut for immutable snapshots. Repeated values use the first value, matching
// URLSearchParams.get in the production Snippet.
func CanonicalURL(input *url.URL) *url.URL {
	output := *input
	query := url.Values{}
	if isSnapshotPath(input.Path) {
		if value, present := firstQueryValue(input, "cut"); present {
			query.Set("cut", value)
		}
	} else if value, present := firstQueryValue(input, "offset"); present {
		query.Set("offset", value)
	}
	output.RawQuery = query.Encode()
	output.ForceQuery = false
	output.Fragment = ""
	return &output
}

func isSnapshotPath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) == 8 && parts[6] == "snapshot"
}

func firstQuery(u *url.URL, key string) string {
	value, _ := firstQueryValue(u, key)
	return value
}

func firstQueryValue(u *url.URL, key string) (string, bool) {
	values, ok := u.Query()[key]
	if !ok || len(values) == 0 {
		return "", false
	}
	return values[0], true
}

func (h *Handler) serveCached(w http.ResponseWriter, request *http.Request, key string) {
	h.mu.Lock()
	enabled := h.ruleOn && h.rule(request)
	if !enabled {
		h.stats.RuleBypasses++
		h.mu.Unlock()
		response := h.fill(request)
		h.write(w, response)
		return
	}
	if response, found := h.cache[key]; found {
		h.stats.CacheHits++
		h.mu.Unlock()
		h.write(w, response)
		return
	}
	if pending, found := h.fills[key]; found {
		h.stats.CollapsedFills++
		h.mu.Unlock()
		<-pending.done
		h.write(w, pending.resp)
		return
	}
	pending := &fill{done: make(chan struct{})}
	h.fills[key] = pending
	h.stats.CacheMisses++
	h.mu.Unlock()

	response := h.fill(request)
	h.mu.Lock()
	pending.resp = response
	if cacheable(response) && h.ruleOn && h.rule(request) {
		h.cache[key] = response
	}
	delete(h.fills, key)
	close(pending.done)
	h.mu.Unlock()
	h.write(w, response)
}

func (h *Handler) fill(request *http.Request) cachedResponse {
	h.mu.Lock()
	h.stats.OriginFetches++
	injectedErr := h.originErr
	delay := h.originDelay
	h.mu.Unlock()

	ctx, cancel := context.WithTimeout(request.Context(), h.timeout)
	defer cancel()
	if injectedErr != nil {
		h.mu.Lock()
		h.stats.OriginErrors++
		h.stats.NoStoreResponses++
		h.mu.Unlock()
		return errorResponse(http.StatusBadGateway, "origin_error", injectedErr.Error())
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			h.mu.Lock()
			h.stats.TimeoutResponses++
			h.stats.NoStoreResponses++
			h.mu.Unlock()
			return errorResponse(http.StatusGatewayTimeout, "origin_timeout", "origin request timed out")
		}
	}
	response, err := h.fetch(ctx, request)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			h.mu.Lock()
			h.stats.TimeoutResponses++
			h.stats.NoStoreResponses++
			h.mu.Unlock()
			return errorResponse(http.StatusGatewayTimeout, "origin_timeout", "origin request timed out")
		}
		h.mu.Lock()
		h.stats.OriginErrors++
		h.stats.NoStoreResponses++
		h.mu.Unlock()
		return errorResponse(http.StatusBadGateway, "origin_error", err.Error())
	}
	if response == nil {
		h.mu.Lock()
		h.stats.OriginErrors++
		h.stats.NoStoreResponses++
		h.mu.Unlock()
		return errorResponse(http.StatusBadGateway, "origin_error", "origin returned no response")
	}
	if response.Body == nil {
		h.mu.Lock()
		h.stats.OriginErrors++
		h.stats.NoStoreResponses++
		h.mu.Unlock()
		return errorResponse(http.StatusBadGateway, "origin_error", "origin returned no body")
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	_ = response.Body.Close()
	if readErr != nil {
		h.mu.Lock()
		h.stats.OriginErrors++
		h.stats.NoStoreResponses++
		h.mu.Unlock()
		return errorResponse(http.StatusBadGateway, "origin_error", "origin response could not be read")
	}
	if int64(len(body)) > maxResponseBytes {
		h.mu.Lock()
		h.stats.OriginErrors++
		h.stats.NoStoreResponses++
		h.mu.Unlock()
		return errorResponse(http.StatusBadGateway, "origin_error", "origin response exceeded local edge bound")
	}
	status := response.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	result := cachedResponse{status: status, statusText: response.Status, header: response.Header.Clone(), body: append([]byte(nil), body...)}
	sanitizeHeaders(result.header)
	h.mu.Lock()
	if cacheable(result) {
		h.stats.CacheableResponses++
	} else if hasNoStore(result.header) {
		h.stats.NoStoreResponses++
	}
	h.mu.Unlock()
	return result
}

const maxResponseBytes = 8 << 20

func errorResponse(status int, code, message string) cachedResponse {
	body := []byte(fmt.Sprintf(`{"error":{"code":%q,"message":%q}}`, code, message))
	return cachedResponse{status: status, statusText: http.StatusText(status), header: http.Header{
		"Content-Type":                 []string{"application/json"},
		"Cache-Control":                []string{"no-store"},
		"Cloudflare-Cdn-Cache-Control": []string{"no-store"},
	}, body: body}
}

func sanitizeHeaders(header http.Header) {
	header.Del("Set-Cookie")
	values := header.Values("Vary")
	if len(values) == 0 {
		return
	}
	keep := make([]string, 0, len(values))
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			item = strings.TrimSpace(item)
			lower := strings.ToLower(item)
			if item != "" && lower != "authorization" && lower != "cookie" && lower != strings.ToLower(CapabilityHeader) {
				keep = append(keep, item)
			}
		}
	}
	header.Del("Vary")
	if len(keep) > 0 {
		header.Set("Vary", strings.Join(keep, ", "))
	}
}

func hasNoStore(header http.Header) bool {
	return strings.Contains(strings.ToLower(header.Get("Cache-Control")), "no-store") || strings.Contains(strings.ToLower(header.Get("Cloudflare-Cdn-Cache-Control")), "no-store")
}

func cacheable(response cachedResponse) bool {
	if response.status != http.StatusOK || hasNoStore(response.header) {
		return false
	}
	contentType := strings.ToLower(response.header.Get("Content-Type"))
	edgeControl := strings.ToLower(response.header.Get("Cloudflare-Cdn-Cache-Control"))
	return strings.HasPrefix(contentType, "application/msgpack") && strings.Contains(edgeControl, "public") && strings.Contains(edgeControl, "immutable")
}

func (h *Handler) write(w http.ResponseWriter, response cachedResponse) {
	for key, values := range response.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.status)
	// The net/http server suppresses a body for HEAD, but avoiding the write
	// here also makes httptest.ResponseRecorder behavior match the network.
	if requestMethod(w) != http.MethodHead {
		_, _ = w.Write(response.body)
	}
}

// responseWriter does not expose the request method. ServeHTTP installs this
// tiny wrapper so write can preserve HEAD semantics without changing cache
// entries or exposing request state to the origin.
type methodWriter struct {
	http.ResponseWriter
	method string
}

func (w methodWriter) Method() string { return w.method }

func requestMethod(w http.ResponseWriter) string {
	if typed, ok := w.(interface{ Method() string }); ok {
		return typed.Method()
	}
	return http.MethodGet
}

func (h *Handler) deny(w http.ResponseWriter, method string, status int, code, message string) {
	h.mu.Lock()
	h.stats.DeniedRequests++
	h.mu.Unlock()
	h.write(methodWriter{ResponseWriter: w, method: method}, errorResponse(status, code, message))
}

// Metrics returns a race-free snapshot of endpoint counters.
func (h *Handler) Metrics() Metrics {
	h.mu.Lock()
	defer h.mu.Unlock()
	result := h.stats
	result.CacheEntries = len(h.cache)
	return result
}

// SetRuleEnabled models a Cache Rule enable/disable change. Disabling the
// rule bypasses existing entries but deliberately retains them, as a real
// provider rule change does; callers can call ClearCache or Evict to model an
// eviction/purge explicitly.
func (h *Handler) SetRuleEnabled(enabled bool) {
	h.mu.Lock()
	h.ruleOn = enabled
	h.mu.Unlock()
}

// SetCacheEnabled is an alias named for qualification callers.
func (h *Handler) SetCacheEnabled(enabled bool) { h.SetRuleEnabled(enabled) }

// SetOriginError injects a deterministic origin error into subsequent fills.
// A nil error restores normal origin behavior.
func (h *Handler) SetOriginError(err error) {
	h.mu.Lock()
	h.originErr = err
	h.mu.Unlock()
}

// InjectError is an alias for SetOriginError.
func (h *Handler) InjectError(err error) { h.SetOriginError(err) }

// SetOriginDelay injects deterministic origin latency. A delay beyond Timeout
// produces a no-store timeout response and never occupies the cache.
func (h *Handler) SetOriginDelay(delay time.Duration) {
	if delay < 0 {
		delay = 0
	}
	h.mu.Lock()
	h.originDelay = delay
	h.mu.Unlock()
}

// InjectDelay is an alias for SetOriginDelay.
func (h *Handler) InjectDelay(delay time.Duration) { h.SetOriginDelay(delay) }

// Evict removes one canonical cache entry. It accepts either a full URL or a
// path; malformed values are simply absent. The return value says whether an
// entry was removed.
func (h *Handler) Evict(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	key := CanonicalURL(parsed).String()
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, found := h.cache[key]; !found {
		return false
	}
	delete(h.cache, key)
	h.stats.Evictions++
	return true
}

// EvictURL is the typed form of Evict for callers that already parsed a URL.
func (h *Handler) EvictURL(value *url.URL) bool {
	if value == nil {
		return false
	}
	return h.Evict(value.String())
}

// ClearCache removes all immutable entries and increments eviction count by
// the number removed. In-flight fills are left intact and are not cancelled.
func (h *Handler) ClearCache() {
	h.mu.Lock()
	h.stats.Evictions += uint64(len(h.cache))
	h.cache = make(map[string]cachedResponse)
	h.mu.Unlock()
}

// CacheKey returns the deterministic cache key for an incoming URL.
func CacheKey(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return CanonicalURL(parsed).String(), nil
}
