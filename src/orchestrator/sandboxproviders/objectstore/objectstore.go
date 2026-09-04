// Package objectstore provides a bounded, local object-storage endpoint for
// the Firecracker qualification suite. It deliberately has no dependency on
// production orchestration packages or cloud SDKs.
package objectstore

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultMaxObjectBytes = 16 << 20
	defaultMaxBytes       = 64 << 20
	defaultMaxBuckets     = 128
	defaultMaxObjects     = 4096
	defaultNamespace      = "sandbox"
	maxNameBytes          = 1024
)

// Outcome is a deterministic provider outcome injected into a mutation.
type Outcome string

const (
	OutcomeNormal        Outcome = "normal"
	OutcomeTimeout       Outcome = "timeout"
	OutcomeIndeterminate Outcome = "indeterminate"
)

// FaultPlan controls deterministic faults. Sequence entries are consumed in
// order for mutating requests; the periodic knobs apply after the sequence.
// EventualConsistency makes a successful mutation invisible to reads until
// the delay has elapsed according to Clock.
type FaultPlan struct {
	Sequence            []Outcome
	TimeoutEvery        uint64
	IndeterminateEvery  uint64
	EventualConsistency time.Duration
	// EventualDelay is a readable compatibility alias for
	// EventualConsistency; when both are set the larger delay wins.
	EventualDelay time.Duration
}

// Config bounds the endpoint and chooses its durable local root. A blank Root
// creates a private temporary directory; Close removes that directory. A
// caller-supplied Root is never removed by Close.
type Config struct {
	Root           string
	Namespace      string
	CompartmentID  string
	MaxBytes       int64
	MaxObjectBytes int64
	// MaxBodyBytes is accepted as the conventional provider name and maps to
	// MaxObjectBytes when the latter is unset.
	MaxBodyBytes int64
	MaxBuckets   int
	MaxObjects   int
	Faults       FaultPlan
	Clock        func() time.Time
}

// Options and ObjectStoreConfig are aliases that make httptest fixtures read
// naturally without introducing another configuration shape.
type Options = Config
type ObjectStoreConfig = Config

type bucket struct {
	Name          string          `json:"name"`
	CompartmentID string          `json:"compartmentId,omitempty"`
	Versioning    bool            `json:"versioning"`
	Lifecycle     []lifecycleRule `json:"lifecycle,omitempty"`
	CreatedAt     time.Time       `json:"createdAt"`
	VisibleAt     time.Time       `json:"visibleAt"`
}

type lifecycleRule struct {
	Name      string `json:"name"`
	Prefix    string `json:"prefix,omitempty"`
	Action    string `json:"action"`
	AfterDays uint16 `json:"afterDays"`
}

type objectVersion struct {
	VersionID  string            `json:"versionId"`
	ETag       string            `json:"etag"`
	SHA256     string            `json:"sha256"`
	Size       int64             `json:"size"`
	CreatedAt  time.Time         `json:"createdAt"`
	VisibleAt  time.Time         `json:"visibleAt"`
	Data       string            `json:"data"`
	DeleteMark bool              `json:"deleteMarker,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type multipartUpload struct {
	ID        string
	Namespace string
	Bucket    string
	Object    string
	Parts     map[int]multipartPart
	CreatedAt time.Time
}

type multipartPart struct {
	ETag string
	Data []byte
}

func multipartBytes(upload *multipartUpload) int64 {
	if upload == nil {
		return 0
	}
	var total int64
	for _, part := range upload.Parts {
		total += int64(len(part.Data))
	}
	return total
}

// ObjectMetadata is the metadata returned by object operations.
type ObjectMetadata struct {
	Namespace string
	Bucket    string
	Name      string
	ETag      string
	SHA256    string
	Size      int64
	VersionID string
	CreatedAt time.Time
	Metadata  map[string]string
}

// Server is an http.Handler implementing the bounded local object-storage
// contract. It is safe for concurrent requests.
type Server struct {
	mu          sync.RWMutex
	root        string
	ownedRoot   bool
	config      Config
	buckets     map[string]bucket
	objects     map[string][]objectVersion
	uploads     map[string]*multipartUpload
	bytes       int64
	uploadBytes int64
	versions    int
	sequence    atomic.Uint64
	faultMu     sync.Mutex
	faults      FaultPlan
	closed      bool
}

// New creates a local object store. Existing state under a caller-supplied
// root is loaded, allowing restart/persistence tests.
func New(config Config) (*Server, error) {
	if config.Namespace == "" {
		config.Namespace = defaultNamespace
	}
	if err := validPart(config.Namespace, 128, false); err != nil {
		return nil, fmt.Errorf("objectstore namespace: %w", err)
	}
	if config.MaxObjectBytes <= 0 {
		config.MaxObjectBytes = config.MaxBodyBytes
	}
	if config.MaxObjectBytes <= 0 {
		config.MaxObjectBytes = defaultMaxObjectBytes
	}
	if config.MaxBytes <= 0 {
		config.MaxBytes = defaultMaxBytes
	}
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = config.MaxObjectBytes
	}
	if config.MaxObjectBytes > config.MaxBytes {
		return nil, errors.New("objectstore max object bytes exceeds max bytes")
	}
	if config.MaxBuckets <= 0 {
		config.MaxBuckets = defaultMaxBuckets
	}
	if config.MaxObjects <= 0 {
		config.MaxObjects = defaultMaxObjects
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	root := config.Root
	owned := false
	var err error
	if root == "" {
		root, err = os.MkdirTemp("", "terrascale-objectstore-")
		owned = true
	} else {
		root, err = filepath.Abs(root)
		if err == nil {
			err = os.MkdirAll(root, 0700)
		}
	}
	if err != nil {
		return nil, err
	}
	config.Faults.Sequence = append([]Outcome(nil), config.Faults.Sequence...)
	s := &Server{root: root, ownedRoot: owned, config: config, buckets: map[string]bucket{}, objects: map[string][]objectVersion{}, uploads: map[string]*multipartUpload{}, faults: config.Faults}
	if err := s.load(); err != nil {
		if owned {
			_ = os.RemoveAll(root)
		}
		return nil, err
	}
	return s, nil
}

// NewServer is an explicit alias useful at httptest call sites.
func NewServer(config Config) (*Server, error) { return New(config) }

// NewHandler creates an endpoint and returns it as an http.Handler. The
// concrete server is retained by callers that need lifecycle or fault methods.
func NewHandler(config Config) (*Server, error) { return New(config) }

// Root returns the filesystem root owned by this endpoint.
func (s *Server) Root() string {
	if s == nil {
		return ""
	}
	return s.root
}

// Namespace returns the configured object-storage namespace.
func (s *Server) Namespace() string {
	if s == nil {
		return ""
	}
	return s.config.Namespace
}

// Handler returns the HTTP handler. Server itself also implements Handler.
func (s *Server) Handler() http.Handler { return s }

// Close makes the endpoint unusable and removes only an automatically-created
// temporary root. Caller-owned roots remain intact.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	root, owned := s.root, s.ownedRoot
	s.mu.Unlock()
	if owned {
		return os.RemoveAll(root)
	}
	return nil
}

// SetFaultPlan replaces the deterministic fault plan. It is safe to call
// while requests are in flight; in-flight requests retain their outcome.
func (s *Server) SetFaultPlan(plan FaultPlan) {
	s.faultMu.Lock()
	plan.Sequence = append([]Outcome(nil), plan.Sequence...)
	s.faults = plan
	s.faultMu.Unlock()
}

// SetFaults is a concise alias used by qualification fixtures.
func (s *Server) SetFaults(plan FaultPlan) { s.SetFaultPlan(plan) }

// ClearFaults returns the endpoint to normal, strongly consistent operation.
func (s *Server) ClearFaults() { s.SetFaultPlan(FaultPlan{}) }

// InjectOutcome queues one outcome before periodic faults are considered.
func (s *Server) InjectOutcome(outcome Outcome) {
	s.faultMu.Lock()
	s.faults.Sequence = append(s.faults.Sequence, outcome)
	s.faultMu.Unlock()
}

// Stats reports bounded storage usage.
type Stats struct {
	Bytes   int64
	Objects int
	Buckets int
}

func (s *Server) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Stats{Bytes: s.bytes + s.uploadBytes, Objects: s.versions, Buckets: len(s.buckets)}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r == nil {
		return
	}
	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	if closed {
		http.Error(w, "object store is closed", http.StatusGone)
		return
	}
	path := r.URL.EscapedPath()
	if path == "/n" || path == "/n/" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		s.writeNamespace(w)
		return
	}
	parts, ok := splitEscaped(path)
	if !ok || len(parts) < 3 || parts[0] != "n" || parts[2] != "b" {
		http.NotFound(w, r)
		return
	}
	namespace := parts[1]
	if namespace != s.config.Namespace {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 3 {
		if r.Method != http.MethodGet {
			// OCI creates buckets at /b/ as well as listing them there. The
			// bucket name is carried by the JSON body for a create.
			if r.Method == http.MethodPost {
				s.createBucket(w, r, "")
				return
			}
			methodNotAllowed(w, http.MethodGet, http.MethodPost)
			return
		}
		s.listBuckets(w, r)
		return
	}
	bucketName := parts[3]
	if len(parts) == 4 {
		s.handleBucket(w, r, bucketName)
		return
	}
	if len(parts) == 5 && parts[4] == "lifecyclePolicy" {
		s.handleLifecycle(w, r, bucketName)
		return
	}
	if len(parts) == 5 && parts[4] == "o" {
		s.listObjects(w, r, namespace, bucketName)
		return
	}
	if len(parts) >= 6 && parts[4] == "o" {
		name := strings.Join(parts[5:], "/")
		s.handleObject(w, r, namespace, bucketName, name)
		return
	}
	if len(parts) >= 6 && parts[4] == "u" {
		name := strings.Join(parts[5:], "/")
		s.handleMultipart(w, r, namespace, bucketName, name)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) writeNamespace(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.config.Namespace)
}

func (s *Server) handleBucket(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method == http.MethodGet {
		s.mu.RLock()
		b, ok := s.buckets[name]
		s.mu.RUnlock()
		if !ok || b.VisibleAt.After(s.now()) {
			http.NotFound(w, r)
			return
		}
		s.writeBucket(w, b)
		return
	}
	if r.Method == http.MethodPost {
		s.createBucket(w, r, name)
		return
	}
	if r.Method == http.MethodPut {
		s.setVersioning(w, r, name)
		return
	}
	if r.Method == http.MethodGet && name == "" {
		s.listBuckets(w, r)
		return
	}
	methodNotAllowed(w, http.MethodGet, http.MethodPost, http.MethodPut)
}

func (s *Server) listBuckets(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	names := make([]string, 0, len(s.buckets))
	for n := range s.buckets {
		names = append(names, n)
	}
	s.mu.RUnlock()
	sort.Strings(names)
	limit := s.config.MaxBuckets
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 && n < limit {
			limit = n
		}
	}
	visible := make([]string, 0, len(names))
	compartment := r.URL.Query().Get("compartmentId")
	for _, n := range names {
		s.mu.RLock()
		b := s.buckets[n]
		s.mu.RUnlock()
		if (compartment == "" || b.CompartmentID == compartment) && !b.VisibleAt.After(s.now()) {
			visible = append(visible, n)
		}
	}
	items := make([]map[string]string, 0, min(limit, len(visible)))
	for _, n := range visible[:min(limit, len(visible))] {
		items = append(items, map[string]string{"name": n})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) createBucket(w http.ResponseWriter, r *http.Request, pathName string) {
	var input struct {
		Name          string `json:"name"`
		CompartmentID string `json:"compartmentId"`
		Versioning    string `json:"versioning"`
	}
	if err := decodeSmallJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := input.Name
	if name == "" {
		name = pathName
	}
	if name != pathName && pathName != "" {
		writeError(w, http.StatusBadRequest, "bucket name does not match path")
		return
	}
	if err := validPart(name, 256, false); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.config.CompartmentID != "" && input.CompartmentID != "" && input.CompartmentID != s.config.CompartmentID {
		writeError(w, http.StatusForbidden, "compartment is not served by this endpoint")
		return
	}
	compartmentID := input.CompartmentID
	if compartmentID == "" {
		compartmentID = s.config.CompartmentID
	}
	b := bucket{Name: name, CompartmentID: compartmentID, Versioning: strings.EqualFold(input.Versioning, "enabled"), CreatedAt: s.now()}
	outcome := s.mutationOutcome()
	if outcome == OutcomeTimeout {
		writeFault(w, http.StatusGatewayTimeout, outcome)
		return
	}
	b.VisibleAt = b.CreatedAt.Add(s.faultDelay())
	s.mu.Lock()
	if len(s.buckets) >= s.config.MaxBuckets {
		s.mu.Unlock()
		writeError(w, http.StatusInsufficientStorage, "bucket limit exceeded")
		return
	}
	if _, exists := s.buckets[name]; exists {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "bucket already exists")
		return
	}
	s.buckets[name] = b
	err := s.saveBucket(b)
	s.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if outcome == OutcomeIndeterminate {
		writeFault(w, http.StatusBadGateway, outcome)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) setVersioning(w http.ResponseWriter, r *http.Request, name string) {
	var input struct {
		Versioning string `json:"versioning"`
	}
	if err := decodeSmallJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	outcome := s.mutationOutcome()
	if outcome == OutcomeTimeout {
		writeFault(w, http.StatusGatewayTimeout, outcome)
		return
	}
	s.mu.Lock()
	b, ok := s.buckets[name]
	if !ok {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	b.Versioning = strings.EqualFold(input.Versioning, "enabled")
	s.buckets[name] = b
	err := s.saveBucket(b)
	s.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if outcome == OutcomeIndeterminate {
		writeFault(w, http.StatusBadGateway, outcome)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) writeBucket(w http.ResponseWriter, b bucket) {
	versioning := "Suspended"
	if b.Versioning {
		versioning = "Enabled"
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": b.Name, "compartmentId": b.CompartmentID, "versioning": versioning})
}

func (s *Server) handleLifecycle(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method == http.MethodGet {
		s.mu.RLock()
		b, ok := s.buckets[name]
		s.mu.RUnlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		if b.Lifecycle == nil {
			http.NotFound(w, r)
			return
		}
		items := make([]map[string]any, 0, len(b.Lifecycle))
		for _, rule := range b.Lifecycle {
			action, ok := wireAction(rule.Action)
			if !ok {
				continue
			}
			item := map[string]any{"name": rule.Name, "action": action, "timeAmount": rule.AfterDays, "timeUnit": "DAYS", "isEnabled": true}
			if rule.Prefix != "" {
				item["objectNameFilter"] = map[string]any{"inclusionPrefixes": []string{rule.Prefix}}
			}
			items = append(items, item)
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
		return
	}
	if r.Method != http.MethodPut {
		methodNotAllowed(w, http.MethodGet, http.MethodPut)
		return
	}
	var input struct {
		Items []struct {
			Name, Action     string
			TimeAmount       uint16 `json:"timeAmount"`
			ObjectNameFilter *struct {
				InclusionPrefixes []string `json:"inclusionPrefixes"`
			} `json:"objectNameFilter"`
		} `json:"items"`
	}
	if err := decodeSmallJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rules := make([]lifecycleRule, 0, len(input.Items))
	for _, item := range input.Items {
		action, ok := fromWireAction(item.Action)
		if !ok || item.Name == "" || item.TimeAmount == 0 {
			writeError(w, http.StatusBadRequest, "invalid lifecycle rule")
			return
		}
		prefix := ""
		if item.ObjectNameFilter != nil && len(item.ObjectNameFilter.InclusionPrefixes) > 1 {
			writeError(w, http.StatusBadRequest, "one lifecycle prefix is supported")
			return
		} else if item.ObjectNameFilter != nil && len(item.ObjectNameFilter.InclusionPrefixes) == 1 {
			prefix = item.ObjectNameFilter.InclusionPrefixes[0]
		}
		rules = append(rules, lifecycleRule{Name: item.Name, Prefix: prefix, Action: action, AfterDays: item.TimeAmount})
	}
	outcome := s.mutationOutcome()
	if outcome == OutcomeTimeout {
		writeFault(w, http.StatusGatewayTimeout, outcome)
		return
	}
	s.mu.Lock()
	b, ok := s.buckets[name]
	if !ok {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	b.Lifecycle = rules
	s.buckets[name] = b
	err := s.saveBucket(b)
	s.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if outcome == OutcomeIndeterminate {
		writeFault(w, http.StatusBadGateway, outcome)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleObject(w http.ResponseWriter, r *http.Request, namespace, bucketName, name string) {
	if err := validPart(name, maxNameBytes, true); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if r.Method == http.MethodPut {
		s.putObject(w, r, namespace, bucketName, name)
		return
	}
	if r.Method == http.MethodHead || r.Method == http.MethodGet {
		s.getObject(w, r, namespace, bucketName, name)
		return
	}
	if r.Method == http.MethodDelete {
		s.deleteObject(w, r, namespace, bucketName, name)
		return
	}
	methodNotAllowed(w, http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete)
}

func (s *Server) listObjects(w http.ResponseWriter, r *http.Request, namespace, bucketName string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	prefix := r.URL.Query().Get("prefix")
	s.mu.RLock()
	type listed struct {
		name    string
		version objectVersion
	}
	items := make([]listed, 0)
	nsPrefix := namespace + "\x00" + bucketName + "\x00"
	for key, versions := range s.objects {
		if !strings.HasPrefix(key, nsPrefix) {
			continue
		}
		name := strings.TrimPrefix(key, nsPrefix)
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		v, ok := visibleVersion(versions, s.now())
		if ok && !v.DeleteMark {
			items = append(items, listed{name: name, version: v})
		}
	}
	s.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
	limit := s.config.MaxObjects
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 && n < limit {
			limit = n
		}
	}
	result := make([]map[string]any, 0, min(limit, len(items)))
	for _, item := range items[:min(limit, len(items))] {
		result = append(result, map[string]any{"name": item.name, "size": item.version.Size, "etag": item.version.ETag, "timeCreated": item.version.CreatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"objects": result})
}

func (s *Server) putObject(w http.ResponseWriter, r *http.Request, namespace, bucketName, name string) {
	s.mu.RLock()
	b, bucketOK := s.buckets[bucketName]
	s.mu.RUnlock()
	if !bucketOK {
		http.NotFound(w, r)
		return
	}
	if r.ContentLength > s.config.MaxObjectBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "object exceeds maximum size")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.config.MaxObjectBytes+1))
	if err != nil || int64(len(body)) > s.config.MaxObjectBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "object exceeds maximum size")
		return
	}
	meta, err := digestMetadata(r, body)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	outcome := s.mutationOutcome()
	if outcome == OutcomeTimeout {
		writeFault(w, http.StatusGatewayTimeout, outcome)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	versions := s.objects[objectKey(namespace, bucketName, name)]
	current, hasCurrent := visibleVersion(versions, s.now())
	if hasCurrent && matchesIfNone(r.Header.Get("If-None-Match"), current.ETag) {
		writeError(w, http.StatusPreconditionFailed, "object already exists")
		return
	}
	if value := r.Header.Get("If-Match"); value != "" && (!hasCurrent || !matchesETag(value, current.ETag)) {
		writeError(w, http.StatusPreconditionFailed, "object ETag does not match")
		return
	}
	if s.versions >= s.config.MaxObjects || s.bytes+int64(len(body)) > s.config.MaxBytes {
		writeError(w, http.StatusInsufficientStorage, "object store limit exceeded")
		return
	}
	versionID := "null"
	if b.Versioning {
		versionID = fmt.Sprintf("v%08d", len(versions)+1)
	}
	created := s.now()
	visibleAt := created.Add(s.faultDelay())
	etag := makeETag(body)
	v := objectVersion{VersionID: versionID, ETag: etag, SHA256: meta, Size: int64(len(body)), CreatedAt: created, VisibleAt: visibleAt, Data: s.dataPath(namespace, bucketName, name, versionID), Metadata: userMetadata(r.Header)}
	if err := s.persistVersion(namespace, bucketName, name, v, body); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !b.Versioning {
		for _, old := range versions {
			if old.VersionID != v.VersionID && old.Data != v.Data {
				_ = os.Remove(old.Data)
			}
			if old.VersionID != v.VersionID {
				_ = s.removeObjectMetadata(namespace, bucketName, name, old.VersionID)
			}
		}
		s.bytes -= sumVersions(versions)
		s.versions -= len(versions)
		versions = nil
	}
	versions = append(versions, v)
	s.objects[objectKey(namespace, bucketName, name)] = versions
	s.bytes += v.Size
	s.versions++
	if outcome == OutcomeIndeterminate {
		writeFault(w, http.StatusBadGateway, outcome)
		return
	}
	writeMetadataHeaders(w, toMetadata(namespace, bucketName, name, v))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) getObject(w http.ResponseWriter, r *http.Request, namespace, bucketName, name string) {
	s.mu.RLock()
	versions, ok := s.objects[objectKey(namespace, bucketName, name)]
	v, found := visibleVersion(versions, s.now())
	if requested := r.URL.Query().Get("versionId"); requested != "" {
		v, found = requestedVersion(versions, requested, s.now())
	}
	s.mu.RUnlock()
	if !ok || !found || v.DeleteMark {
		http.NotFound(w, r)
		return
	}
	if value := r.Header.Get("If-Match"); value != "" && !matchesETag(value, v.ETag) {
		writeError(w, http.StatusPreconditionFailed, "object ETag does not match")
		return
	}
	if value := r.Header.Get("If-Unmodified-Since"); value != "" {
		if since, err := http.ParseTime(value); err == nil && v.CreatedAt.After(since.Add(time.Second)) {
			writeError(w, http.StatusPreconditionFailed, "object was modified after the requested time")
			return
		}
	}
	if value := r.Header.Get("If-None-Match"); value != "" && matchesIfNone(value, v.ETag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if value := r.Header.Get("If-Modified-Since"); value != "" && r.Method == http.MethodGet {
		if since, err := http.ParseTime(value); err == nil && !v.CreatedAt.After(since.Add(time.Second)) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	data, err := os.ReadFile(v.Data)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != v.SHA256 {
		writeError(w, http.StatusBadGateway, "object content digest does not match metadata")
		return
	}
	start, end, partial, rangeErr := objectRange(r.Header.Get("Range"), int64(len(data)))
	if rangeErr {
		w.Header().Set("Content-Range", "bytes */"+strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	writeMetadataHeaders(w, toMetadata(namespace, bucketName, name, v))
	w.Header().Set("Accept-Ranges", "bytes")
	if partial {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
		data = data[start : end+1]
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusPartialContent)
	}
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(data)
}

func (s *Server) deleteObject(w http.ResponseWriter, r *http.Request, namespace, bucketName, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := objectKey(namespace, bucketName, name)
	versions, ok := s.objects[key]
	current, found := visibleVersion(versions, s.now())
	if !ok || !found || current.DeleteMark {
		http.NotFound(w, r)
		return
	}
	if value := r.Header.Get("If-Match"); value == "" || !matchesETag(value, current.ETag) {
		writeError(w, http.StatusPreconditionFailed, "object ETag does not match")
		return
	}
	outcome := s.mutationOutcome()
	if outcome == OutcomeTimeout {
		writeFault(w, http.StatusGatewayTimeout, outcome)
		return
	}
	if current.VersionID == "null" {
		_ = os.Remove(current.Data)
		delete(s.objects, key)
		s.bytes -= current.Size
		s.versions--
		_ = s.removeObjectMetadata(namespace, bucketName, name, current.VersionID)
	} else {
		marker := objectVersion{VersionID: fmt.Sprintf("v%08d", len(versions)+1), DeleteMark: true, CreatedAt: s.now(), VisibleAt: s.now().Add(s.faultDelay())}
		if err := s.persistVersion(namespace, bucketName, name, marker, nil); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.objects[key] = append(versions, marker)
		s.versions++
	}
	if outcome == OutcomeIndeterminate {
		writeFault(w, http.StatusBadGateway, outcome)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMultipart(w http.ResponseWriter, r *http.Request, namespace, bucketName, name string) {
	if err := validPart(name, maxNameBytes, true); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	uploadID := r.URL.Query().Get("uploadId")
	if r.Method == http.MethodPost && uploadID == "" {
		s.mu.Lock()
		if _, ok := s.buckets[bucketName]; !ok {
			s.mu.Unlock()
			http.NotFound(w, r)
			return
		}
		if len(s.uploads) >= s.config.MaxObjects {
			s.mu.Unlock()
			writeError(w, http.StatusInsufficientStorage, "multipart upload limit exceeded")
			return
		}
		id := fmt.Sprintf("upload-%08d", s.sequence.Add(1))
		s.uploads[id] = &multipartUpload{ID: id, Namespace: namespace, Bucket: bucketName, Object: name, Parts: map[int]multipartPart{}, CreatedAt: s.now()}
		s.mu.Unlock()
		w.Header().Set("opc-multipart-upload-id", id)
		writeJSON(w, http.StatusOK, map[string]string{"uploadId": id})
		return
	}
	s.mu.Lock()
	upload, ok := s.uploads[uploadID]
	s.mu.Unlock()
	if !ok || upload.Namespace != namespace || upload.Bucket != bucketName || upload.Object != name {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodPut {
		partNum, _ := strconv.Atoi(firstNonEmpty(r.URL.Query().Get("partNum"), r.URL.Query().Get("partNumber")))
		if partNum < 1 || partNum > 10000 {
			writeError(w, http.StatusBadRequest, "invalid part number")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.config.MaxObjectBytes+1))
		if err != nil || int64(len(body)) > s.config.MaxObjectBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "part exceeds maximum size")
			return
		}
		etag := makeETag(body)
		s.mu.Lock()
		if current, exists := s.uploads[uploadID]; !exists || current != upload {
			s.mu.Unlock()
			http.NotFound(w, r)
			return
		}
		previous := int64(len(upload.Parts[partNum].Data))
		if s.bytes+s.uploadBytes-previous+int64(len(body)) > s.config.MaxBytes {
			s.mu.Unlock()
			writeError(w, http.StatusInsufficientStorage, "object store limit exceeded")
			return
		}
		upload.Parts[partNum] = multipartPart{ETag: etag, Data: append([]byte(nil), body...)}
		s.uploadBytes += int64(len(body)) - previous
		s.mu.Unlock()
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method == http.MethodGet {
		s.mu.RLock()
		nums := make([]int, 0, len(upload.Parts))
		for n := range upload.Parts {
			nums = append(nums, n)
		}
		sort.Ints(nums)
		parts := make([]map[string]any, 0, len(nums))
		for _, n := range nums {
			p := upload.Parts[n]
			parts = append(parts, map[string]any{"partNum": n, "etag": p.ETag, "size": len(p.Data)})
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{"parts": parts})
		return
	}
	if r.Method == http.MethodDelete {
		s.mu.Lock()
		if current, exists := s.uploads[uploadID]; exists && current == upload {
			s.uploadBytes -= multipartBytes(upload)
			delete(s.uploads, uploadID)
		}
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method == http.MethodPost {
		s.mu.RLock()
		overLimit := multipartBytes(upload) > s.config.MaxObjectBytes
		s.mu.RUnlock()
		if overLimit {
			writeError(w, http.StatusRequestEntityTooLarge, "multipart object exceeds maximum size")
			return
		}
		s.commitMultipart(w, r, upload)
		return
	}
	methodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete)
}

func (s *Server) commitMultipart(w http.ResponseWriter, r *http.Request, upload *multipartUpload) {
	var input struct {
		Parts []struct {
			PartNum int    `json:"partNum"`
			ETag    string `json:"etag"`
		} `json:"parts"`
		PartsToCommit []struct {
			PartNum int    `json:"partNum"`
			ETag    string `json:"etag"`
		} `json:"partsToCommit"`
	}
	if err := decodeSmallJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(input.Parts) == 0 {
		input.Parts = input.PartsToCommit
	}
	if len(input.Parts) == 0 {
		writeError(w, http.StatusBadRequest, "multipart manifest is empty")
		return
	}
	var body bytes.Buffer
	expected := 1
	s.mu.RLock()
	for _, part := range input.Parts {
		p, ok := upload.Parts[part.PartNum]
		if !ok || part.PartNum != expected || !matchesETag(part.ETag, p.ETag) {
			s.mu.RUnlock()
			writeError(w, http.StatusConflict, "multipart manifest is invalid")
			return
		}
		_, _ = body.Write(p.Data)
		expected++
	}
	s.mu.RUnlock()
	s.mu.Lock()
	current, exists := s.uploads[upload.ID]
	if !exists || current != upload {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "multipart upload is no longer active")
		return
	}
	s.uploadBytes -= multipartBytes(upload)
	delete(s.uploads, upload.ID)
	s.mu.Unlock()
	fake := *r
	fake.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
	fake.ContentLength = int64(body.Len())
	s.putObject(w, &fake, upload.Namespace, upload.Bucket, upload.Object)
}

func digestMetadata(r *http.Request, body []byte) (string, error) {
	sum := sha256.Sum256(body)
	actual := hex.EncodeToString(sum[:])
	expected := strings.TrimSpace(r.Header.Get("opc-meta-terrascale-sha256"))
	if expected == "" {
		expected = strings.TrimSpace(r.Header.Get("x-content-sha256"))
	}
	if expected != "" && !strings.EqualFold(expected, actual) {
		return "", errors.New("object SHA-256 does not match content")
	}
	return actual, nil
}
func makeETag(data []byte) string {
	sum := md5.Sum(data)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}
func toMetadata(ns, bucket, name string, v objectVersion) ObjectMetadata {
	return ObjectMetadata{Namespace: ns, Bucket: bucket, Name: name, ETag: v.ETag, SHA256: v.SHA256, Size: v.Size, VersionID: v.VersionID, CreatedAt: v.CreatedAt, Metadata: cloneMap(v.Metadata)}
}
func (s *Server) now() time.Time { return s.config.Clock().UTC() }
func (s *Server) faultDelay() time.Duration {
	s.faultMu.Lock()
	defer s.faultMu.Unlock()
	if s.faults.EventualDelay > s.faults.EventualConsistency {
		return s.faults.EventualDelay
	}
	return s.faults.EventualConsistency
}
func (s *Server) mutationOutcome() Outcome {
	s.faultMu.Lock()
	defer s.faultMu.Unlock()
	n := s.sequence.Add(1)
	if len(s.faults.Sequence) > 0 {
		out := s.faults.Sequence[0]
		s.faults.Sequence = append([]Outcome(nil), s.faults.Sequence[1:]...)
		return out
	}
	if s.faults.TimeoutEvery > 0 && n%s.faults.TimeoutEvery == 0 {
		return OutcomeTimeout
	}
	if s.faults.IndeterminateEvery > 0 && n%s.faults.IndeterminateEvery == 0 {
		return OutcomeIndeterminate
	}
	return OutcomeNormal
}
func visibleVersion(versions []objectVersion, now time.Time) (objectVersion, bool) {
	for i := len(versions) - 1; i >= 0; i-- {
		if !versions[i].VisibleAt.After(now) {
			return versions[i], true
		}
	}
	return objectVersion{}, false
}

func requestedVersion(versions []objectVersion, id string, now time.Time) (objectVersion, bool) {
	for i := len(versions) - 1; i >= 0; i-- {
		if versions[i].VersionID == id && !versions[i].VisibleAt.After(now) {
			return versions[i], true
		}
	}
	return objectVersion{}, false
}
func sumVersions(v []objectVersion) int64 {
	var n int64
	for _, x := range v {
		n += x.Size
	}
	return n
}
func objectKey(ns, bucket, name string) string { return ns + "\x00" + bucket + "\x00" + name }
func encoded(value string) string              { return base64.RawURLEncoding.EncodeToString([]byte(value)) }
func (s *Server) bucketDir(ns, bucket string) string {
	return filepath.Join(s.root, "b", encoded(ns), encoded(bucket))
}
func (s *Server) dataPath(ns, bucket, name, version string) string {
	return filepath.Join(s.bucketDir(ns, bucket), "o", encoded(name)+"-"+encoded(version)+".data")
}
func (s *Server) metaPath(ns, bucket, name, version string) string {
	return filepath.Join(s.bucketDir(ns, bucket), "o", encoded(name)+"-"+encoded(version)+".json")
}
func (s *Server) saveBucket(b bucket) error {
	dir := filepath.Join(s.root, "b", encoded(s.config.Namespace))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, encoded(b.Name)+".bucket.json"), b, 0600)
}
func (s *Server) persistVersion(ns, bucket, name string, v objectVersion, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(v.Data), 0700); err != nil {
		return err
	}
	if !v.DeleteMark {
		if err := atomicWriteBytes(v.Data, body, 0600); err != nil {
			return err
		}
	}
	return atomicWrite(s.metaPath(ns, bucket, name, v.VersionID), v, 0600)
}
func (s *Server) removeObjectMetadata(ns, bucket, name, version string) error {
	return os.Remove(s.metaPath(ns, bucket, name, version))
}
func atomicWrite(path string, value any, mode os.FileMode) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return atomicWriteBytes(path, data, mode)
}
func atomicWriteBytes(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.Write(data)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	return err
}

func (s *Server) load() error {
	if err := filepath.WalkDir(filepath.Join(s.root, "b"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.HasSuffix(path, ".bucket.json") {
			var b bucket
			if json.Unmarshal(data, &b) == nil {
				s.buckets[b.Name] = b
			}
			return nil
		}
		if !strings.HasSuffix(path, ".json") {
			return nil
		}
		var v objectVersion
		if json.Unmarshal(data, &v) != nil {
			return nil
		}
		rel, _ := filepath.Rel(s.root, path)
		dirs := strings.Split(filepath.ToSlash(rel), "/")
		if len(dirs) < 5 {
			return nil
		}
		nsBytes, nsErr := base64.RawURLEncoding.DecodeString(dirs[1])
		bucketBytes, bucketErr := base64.RawURLEncoding.DecodeString(dirs[2])
		if nsErr != nil || bucketErr != nil {
			return nil
		}
		filename := strings.TrimSuffix(dirs[len(dirs)-1], ".json")
		hyphen := strings.LastIndexByte(filename, '-')
		if hyphen < 1 {
			return nil
		}
		nameBytes, nameErr := base64.RawURLEncoding.DecodeString(filename[:hyphen])
		if nameErr != nil {
			return nil
		}
		key := objectKey(string(nsBytes), string(bucketBytes), string(nameBytes))
		s.objects[key] = append(s.objects[key], v)
		s.bytes += v.Size
		s.versions++
		return nil
	}); err != nil {
		return err
	}
	for key, values := range s.objects {
		sort.Slice(values, func(i, j int) bool { return values[i].CreatedAt.Before(values[j].CreatedAt) })
		s.objects[key] = values
	}
	if len(s.buckets) > s.config.MaxBuckets || s.versions > s.config.MaxObjects || s.bytes > s.config.MaxBytes {
		return errors.New("object store root exceeds configured bounds")
	}
	return nil
}

func splitEscaped(path string) ([]string, bool) {
	if !strings.HasPrefix(path, "/") {
		return nil, false
	}
	raw := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(raw) > 0 && raw[len(raw)-1] == "" {
		raw = raw[:len(raw)-1]
	}
	out := make([]string, 0, len(raw))
	for _, part := range raw {
		value, err := url.PathUnescape(part)
		if err != nil || value == "" {
			return nil, false
		}
		out = append(out, value)
	}
	return out, true
}
func validPart(value string, max int, allowSlash bool) error {
	if value == "" || len(value) > max || strings.ContainsAny(value, "\r\n\x00") || (!allowSlash && strings.Contains(value, "/")) || (!allowSlash && (value == "." || value == "..")) {
		return errors.New("invalid object-storage name")
	}
	return nil
}
func wireAction(value string) (string, bool) {
	switch value {
	case "infrequent-access":
		return "INFREQUENT_ACCESS", true
	case "archive":
		return "ARCHIVE", true
	case "delete":
		return "DELETE", true
	default:
		return "", false
	}
}
func fromWireAction(value string) (string, bool) {
	switch value {
	case "INFREQUENT_ACCESS":
		return "infrequent-access", true
	case "ARCHIVE":
		return "archive", true
	case "DELETE":
		return "delete", true
	default:
		return "", false
	}
}
func decodeSmallJSON(r *http.Request, value any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil {
		return err
	}
	if len(body) > 1<<20 {
		return errors.New("request body exceeds limit")
	}
	if len(body) == 0 {
		return errors.New("request body is empty")
	}
	return json.Unmarshal(body, value)
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"code": http.StatusText(status), "message": message})
}
func writeFault(w http.ResponseWriter, status int, outcome Outcome) {
	w.Header().Set("X-TerraScale-Fault", string(outcome))
	if outcome == OutcomeIndeterminate {
		// A committed mutation followed by a dropped connection is the useful
		// provider contract: callers must resolve it by a read, not by blindly
		// replaying the write. ResponseRecorder has no socket to close, so it
		// receives a bounded 502 instead.
		if h, ok := w.(http.Hijacker); ok {
			if conn, _, err := h.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
	}
	writeError(w, status, "deterministic provider fault: "+string(outcome))
}
func methodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	w.WriteHeader(http.StatusMethodNotAllowed)
}
func writeMetadataHeaders(w http.ResponseWriter, m ObjectMetadata) {
	w.Header().Set("ETag", m.ETag)
	w.Header().Set("opc-meta-terrascale-sha256", m.SHA256)
	w.Header().Set("Content-Length", strconv.FormatInt(m.Size, 10))
	if !m.CreatedAt.IsZero() {
		w.Header().Set("Last-Modified", m.CreatedAt.UTC().Format(http.TimeFormat))
	}
	if m.VersionID != "" {
		w.Header().Set("opc-version-id", m.VersionID)
	}
	for k, v := range m.Metadata {
		w.Header().Set(k, v)
	}
}
func userMetadata(h http.Header) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		if strings.HasPrefix(strings.ToLower(k), "opc-meta-") && len(v) > 0 && strings.ToLower(k) != "opc-meta-terrascale-sha256" && len(out) < 64 && len(k) <= 128 && len(v[0]) <= 1024 {
			out[k] = v[0]
		}
	}
	return out
}
func matchesETag(value, etag string) bool {
	for _, candidate := range strings.Split(value, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == etag || strings.Trim(candidate, `"`) == strings.Trim(etag, `"`) {
			return true
		}
	}
	return false
}
func matchesIfNone(value, etag string) bool { return matchesETag(value, etag) }
func objectRange(value string, size int64) (int64, int64, bool, bool) {
	if value == "" {
		return 0, size - 1, false, false
	}
	if !strings.HasPrefix(value, "bytes=") || strings.Contains(value[6:], ",") {
		return 0, 0, false, true
	}
	spec := strings.TrimSpace(value[6:])
	dash := strings.IndexByte(spec, '-')
	if dash < 0 {
		return 0, 0, false, true
	}
	left, right := strings.TrimSpace(spec[:dash]), strings.TrimSpace(spec[dash+1:])
	var start, end int64
	var err error
	if left == "" {
		n, e := strconv.ParseInt(right, 10, 64)
		if e != nil || n <= 0 {
			return 0, 0, false, true
		}
		if n > size {
			n = size
		}
		start = size - n
		end = size - 1
	} else {
		start, err = strconv.ParseInt(left, 10, 64)
		if err != nil || start < 0 || start >= size {
			return 0, 0, false, true
		}
		if right == "" {
			end = size - 1
		} else {
			end, err = strconv.ParseInt(right, 10, 64)
			if err != nil || end < start {
				return 0, 0, false, true
			}
			if end >= size {
				end = size - 1
			}
		}
	}
	return start, end, true, false
}
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
func cloneMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	out := make(map[string]string, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
