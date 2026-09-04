// Package estatepublisher composes the production I-11 estate projection.
//
// The publisher deliberately owns no HTTP transport.  A typed public
// document client is supplied by the caller (the estate package's client is
// the production adapter).  This keeps the admin projection on the ordinary
// TerraScale API path and makes its authority and failure boundaries
// testable without a network.
package estatepublisher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

const (
	// DefaultInterval is the required I-11 refresh cadence.
	DefaultInterval = 10 * time.Second
	// DefaultPublisherInterval is retained as a descriptive alias.
	DefaultPublisherInterval = DefaultInterval
	// DefaultMaxDocumentBytes bounds one document before it reaches the API.
	DefaultMaxDocumentBytes = 1 << 20
	// DefaultMaxItems bounds arrays and object members in one projection.
	DefaultMaxItems = 4096
	maxAttempts     = 8
	maxBackoff      = 5 * time.Second
)

var (
	ErrFenced        = errors.New("estate publisher: authority is fenced")
	ErrGeneration    = errors.New("estate publisher: generation is invalid")
	ErrStaleRemoval  = errors.New("estate publisher: stale document removal is unavailable")
	ErrPayloadBounds = errors.New("estate publisher: document exceeds bounds")
)

// DocumentIDs is the complete production family set, in stable order.
var DocumentIDs = []string{
	estate.DocRegions, estate.DocHosts, estate.DocDatabases,
	estate.DocRollouts, estate.DocSLO, estate.DocReconcile,
}

const EstateCollection = estate.EstateCollection

// EstateDocIDs returns a copy of the complete production family set.
func EstateDocIDs() []string { return append([]string(nil), DocumentIDs...) }

func QualifiedName(id string) string { return estate.QualifiedName(id) }

// Document is one raw JSON estate document. ID is always relative to the
// "estate" collection, never a user-controlled collection name.
type Document struct {
	ID   string
	Body json.RawMessage
}

// SnapshotSource supplies one coherent observation of all six families.
// estate.Snapshot is intentionally accepted so existing reconciler and
// observation adapters can be passed without conversion code.
type SnapshotSource func(context.Context) (estate.Snapshot, error)

// Authority is checked before every mutation. Implementations should read a
// durable control epoch and return ErrFenced (or wrap it) when this publisher
// no longer owns publication. Generation is included in every idempotency
// key, so a replay from a prior epoch cannot be mistaken for a new write.
type Authority interface {
	Generation(context.Context) (uint64, error)
	CheckFence(context.Context, uint64) error
}

// AuthorityFunc adapts a check function to Authority. GenerationFunc is
// optional; when nil, the configured generation is used.
type AuthorityFunc struct {
	GenerationFunc func(context.Context) (uint64, error)
	FenceFunc      func(context.Context, uint64) error
}

func (f AuthorityFunc) Generation(ctx context.Context) (uint64, error) {
	if f.GenerationFunc == nil {
		return 0, ErrGeneration
	}
	return f.GenerationFunc(ctx)
}

func (f AuthorityFunc) CheckFence(ctx context.Context, generation uint64) error {
	if f.FenceFunc == nil {
		return nil
	}
	return f.FenceFunc(ctx, generation)
}

// WriteOptions are passed to the typed client. Generation and FenceToken are
// additional server-side fencing context; they are never placed in the
// document body.
type WriteOptions struct {
	IdempotencyKey string
	Generation     uint64
	FenceToken     string
}

// DocumentClient is the typed mutation seam. PutPublicDocument is implemented
// by *estate.ControlPlaneClient through PublicClientAdapter below.
type DocumentClient interface {
	PutDocument(context.Context, string, string, json.RawMessage, WriteOptions) error
}

// PublicDocumentClient is the exact public SDK-compatible method used by the
// production adapter. Keeping this interface small avoids introducing a
// second transport or a private dashboard API.
type PublicDocumentClient interface {
	PutPublicDocument(context.Context, string, string, json.RawMessage, estate.DocumentWriteOptions) (estate.DocumentWriteReceipt, error)
}

// PublicClientAdapter adapts estate.ControlPlaneClient (or any public client)
// to DocumentClient. Generation is represented in the idempotency key; the
// optional fence token is represented by the public If-Match precondition.
type PublicClientAdapter struct{ Client PublicDocumentClient }

func (a PublicClientAdapter) PutDocument(ctx context.Context, collection, id string, raw json.RawMessage, options WriteOptions) error {
	if isNil(a.Client) {
		return errors.New("estate publisher: public document client is unavailable")
	}
	_, err := a.Client.PutPublicDocument(ctx, collection, id, raw, estate.DocumentWriteOptions{
		IdempotencyKey: options.IdempotencyKey,
		IfMatch:        options.FenceToken,
	})
	return err
}

// DocumentLister and DocumentRemover are optional capabilities on the typed
// client. Their presence lets production remove documents left by an older
// family declaration. A client without these capabilities still publishes,
// but no deletion is guessed or performed.
type DocumentLister interface {
	ListDocuments(context.Context, string) ([]DocumentRef, error)
}

type DocumentRemover interface {
	DeleteDocument(context.Context, string, string, WriteOptions) error
}

type DocumentRef struct{ ID string }

// Config fully describes one production publisher. No environment or global
// client is consulted. Client accepts either DocumentClient or
// PublicDocumentClient (the latter is adapted automatically).
type Config struct {
	Client    any
	Snapshot  SnapshotSource
	Authority Authority

	// Generation is used when Authority is nil. Production wiring should
	// provide Authority; a fixed non-zero generation remains useful for a
	// fenced bootstrap run and deterministic tests.
	Generation uint64
	FenceToken string

	Interval          time.Duration
	MaxDocumentBytes  int
	MaxItems          int
	RetryMaxAttempts  int
	RetryInitialDelay time.Duration
	RetryMaxDelay     time.Duration
	Sleep             func(context.Context, time.Duration) error

	OnSuccess func(PublishResult)
	OnFailure func(error)
	Now       func() time.Time
}

// PublishResult describes one completed pass. Failed passes are represented
// by LastError and never advance the publisher's committed hashes.
type PublishResult struct {
	Generation uint64
	Writes     int
	Deletes    int
	Documents  int
}

type Status struct {
	Generation    uint64    `json:"generation"`
	LastSuccessAt time.Time `json:"lastSuccessAt,omitempty"`
	LastError     string    `json:"lastError,omitempty"`
	FailureCount  uint64    `json:"failureCount"`
	Writes        uint64    `json:"writes"`
	Deletes       uint64    `json:"deletes"`
	Fenced        bool      `json:"fenced"`
}

// Publisher is safe for concurrent NotifyChange, Publish, Start, and Close.
type Publisher struct {
	client     DocumentClient
	lister     DocumentLister
	remover    DocumentRemover
	snapshot   SnapshotSource
	authority  Authority
	generation uint64
	fenceToken string
	interval   time.Duration
	maxBytes   int
	maxItems   int
	attempts   int
	initial    time.Duration
	maxDelay   time.Duration
	sleep      func(context.Context, time.Duration) error
	onSuccess  func(PublishResult)
	onFailure  func(error)
	now        func() time.Time

	passMu sync.Mutex
	mu     sync.Mutex
	last   map[string][32]byte
	status Status

	notify     chan struct{}
	startOnce  sync.Once
	closeOnce  sync.Once
	cancel     context.CancelFunc
	completion chan struct{}
	started    bool
	closed     bool
}

// New validates and composes a publisher; it does not start a goroutine.
func New(config Config) (*Publisher, error) {
	if isNil(config.Snapshot) {
		return nil, errors.New("estate publisher: snapshot source is required")
	}
	if config.Authority != nil && isNil(config.Authority) {
		return nil, errors.New("estate publisher: authority is unavailable")
	}
	client, err := adaptClient(config.Client)
	if err != nil {
		return nil, err
	}
	if config.Snapshot == nil {
		return nil, errors.New("estate publisher: snapshot source is required")
	}
	if config.Authority == nil && config.Generation == 0 {
		return nil, ErrGeneration
	}
	interval := config.Interval
	if interval == 0 {
		interval = DefaultInterval
	}
	if interval <= 0 {
		return nil, errors.New("estate publisher: interval must be positive")
	}
	maxBytes := config.MaxDocumentBytes
	if maxBytes == 0 {
		maxBytes = DefaultMaxDocumentBytes
	}
	if maxBytes < 1 || maxBytes > DefaultMaxDocumentBytes {
		return nil, errors.New("estate publisher: document byte bound is invalid")
	}
	maxItems := config.MaxItems
	if maxItems == 0 {
		maxItems = DefaultMaxItems
	}
	if maxItems < 1 || maxItems > DefaultMaxItems {
		return nil, errors.New("estate publisher: item bound is invalid")
	}
	attempts := config.RetryMaxAttempts
	if attempts == 0 {
		attempts = 3
	}
	if attempts < 1 || attempts > maxAttempts {
		return nil, errors.New("estate publisher: retry attempts are invalid")
	}
	initial := config.RetryInitialDelay
	if initial == 0 {
		initial = 100 * time.Millisecond
	}
	maxDelay := config.RetryMaxDelay
	if maxDelay == 0 {
		maxDelay = maxBackoff
	}
	if initial < 0 || maxDelay < initial || maxDelay > maxBackoff {
		return nil, errors.New("estate publisher: retry delay is invalid")
	}
	sleep := config.Sleep
	if isNil(sleep) {
		sleep = sleepContext
	}
	now := config.Now
	if isNil(now) {
		now = time.Now
	}
	onSuccess := config.OnSuccess
	if isNil(onSuccess) {
		onSuccess = nil
	}
	onFailure := config.OnFailure
	if isNil(onFailure) {
		onFailure = nil
	}
	p := &Publisher{
		client: client, snapshot: config.Snapshot, authority: config.Authority,
		generation: config.Generation, fenceToken: config.FenceToken,
		interval: interval, maxBytes: maxBytes, maxItems: maxItems,
		attempts: attempts, initial: initial, maxDelay: maxDelay, sleep: sleep,
		onSuccess: onSuccess, onFailure: onFailure,
		now:  now,
		last: make(map[string][32]byte), notify: make(chan struct{}, 1),
		completion: make(chan struct{}),
	}
	if listed, ok := config.Client.(DocumentLister); ok && !isNil(listed) {
		p.lister = listed
	}
	if removed, ok := config.Client.(DocumentRemover); ok && !isNil(removed) {
		p.remover = removed
	}
	return p, nil
}

// NewPublisher is a descriptive alias for New.
func NewPublisher(config Config) (*Publisher, error) { return New(config) }

// NewProductionPublisher is the explicit production spelling used by command
// composition code.
func NewProductionPublisher(config Config) (*Publisher, error) { return New(config) }

func adaptClient(value any) (DocumentClient, error) {
	if isNil(value) {
		return nil, errors.New("estate publisher: typed document client is required")
	}
	switch adapter := value.(type) {
	case PublicClientAdapter:
		if isNil(adapter.Client) {
			return nil, errors.New("estate publisher: public document client is unavailable")
		}
	case *PublicClientAdapter:
		if adapter == nil || isNil(adapter.Client) {
			return nil, errors.New("estate publisher: public document client is unavailable")
		}
	}
	if typed, ok := value.(DocumentClient); ok {
		return typed, nil
	}
	if public, ok := value.(PublicDocumentClient); ok {
		return PublicClientAdapter{Client: public}, nil
	}
	return nil, errors.New("estate publisher: client does not implement the typed document API")
}

// isNil handles an interface containing a typed nil pointer/function. A
// composition root must reject that before an asynchronous publish can panic.
func isNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (p *Publisher) Interval() time.Duration {
	if p == nil {
		return 0
	}
	return p.interval
}

func (p *Publisher) Status() Status {
	if p == nil {
		return Status{Fenced: true, LastError: "estate publisher: unavailable"}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status
}

func (p *Publisher) LastError() error {
	if p == nil {
		return errors.New("estate publisher: unavailable")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.status.LastError == "" {
		return nil
	}
	return errors.New(p.status.LastError)
}

// WriteCount reports successful document PUTs performed by this process.
func (p *Publisher) WriteCount() uint64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status.Writes
}

func (p *Publisher) Completion() <-chan struct{} {
	if p == nil {
		return nil
	}
	return p.completion
}

// NotifyChange coalesces concurrent changes into one immediate pass.
func (p *Publisher) NotifyChange() {
	if p == nil {
		return
	}
	select {
	case p.notify <- struct{}{}:
	default:
	}
}

// Publish performs one serialized observation and publication pass.
func (p *Publisher) Publish(ctx context.Context) (PublishResult, error) {
	if p == nil {
		return PublishResult{}, errors.New("estate publisher: unavailable")
	}
	if ctx == nil {
		return PublishResult{}, errors.New("estate publisher: context is required")
	}
	if err := ctx.Err(); err != nil {
		return PublishResult{}, err
	}
	p.passMu.Lock()
	defer p.passMu.Unlock()
	generation, err := p.currentGeneration(ctx)
	if err != nil {
		return p.failed(err)
	}
	if err := p.checkFence(ctx, generation); err != nil {
		return p.failed(err)
	}
	snapshot, err := p.snapshot(ctx)
	if err != nil {
		return p.failed(fmt.Errorf("observe: %w", err))
	}
	docs, err := p.documents(snapshot)
	if err != nil {
		return p.failed(err)
	}
	result := PublishResult{Generation: generation, Documents: len(docs)}
	seen := make(map[string]struct{}, len(docs))
	committed := make(map[string][32]byte, len(docs))
	for _, doc := range docs {
		seen[doc.ID] = struct{}{}
		sum := revisionDigest(generation, doc.Body)
		p.mu.Lock()
		prior, exists := p.last[doc.ID]
		p.mu.Unlock()
		if exists && prior == sum {
			committed[doc.ID] = sum
			continue
		}
		if err := p.checkFence(ctx, generation); err != nil {
			return p.failed(err)
		}
		options := WriteOptions{Generation: generation, FenceToken: p.fenceToken, IdempotencyKey: idempotencyKey(generation, doc.ID, sum)}
		if err := p.put(ctx, doc.ID, doc.Body, options); err != nil {
			return p.failed(fmt.Errorf("put %s: %w", estate.QualifiedName(doc.ID), err))
		}
		committed[doc.ID] = sum
		result.Writes++
	}
	deleted, err := p.removeStale(ctx, generation, seen)
	if err != nil {
		return p.failed(err)
	}
	result.Deletes = deleted
	p.mu.Lock()
	p.last = committed
	p.status.Generation = generation
	p.status.LastSuccessAt = p.now().UTC()
	p.status.LastError = ""
	p.status.Fenced = false
	p.status.Writes += uint64(result.Writes)
	p.status.Deletes += uint64(result.Deletes)
	p.mu.Unlock()
	if p.onSuccess != nil {
		p.onSuccess(result)
	}
	return result, nil
}

func (p *Publisher) currentGeneration(ctx context.Context) (uint64, error) {
	if p.authority == nil {
		return p.generation, nil
	}
	generation, err := p.authority.Generation(ctx)
	if err != nil {
		return 0, redact(err)
	}
	if generation == 0 {
		return 0, ErrGeneration
	}
	return generation, nil
}

func (p *Publisher) checkFence(ctx context.Context, generation uint64) error {
	if generation == 0 {
		return ErrGeneration
	}
	if p.authority == nil {
		return nil
	}
	if err := p.authority.CheckFence(ctx, generation); err != nil {
		if errors.Is(err, ErrFenced) {
			return ErrFenced
		}
		return redact(err)
	}
	return nil
}

func (p *Publisher) documents(snapshot estate.Snapshot) ([]Document, error) {
	documents := snapshot.Documents()
	if len(documents) != len(DocumentIDs) {
		return nil, errors.New("estate publisher: snapshot does not contain all estate families")
	}
	result := make([]Document, 0, len(documents))
	seen := make(map[string]struct{}, len(documents))
	for _, item := range documents {
		if !validID(item.ID) {
			return nil, errors.New("estate publisher: snapshot contains an invalid document id")
		}
		if _, exists := seen[item.ID]; exists {
			return nil, errors.New("estate publisher: snapshot contains a duplicate document id")
		}
		seen[item.ID] = struct{}{}
		body, err := boundedJSON(item.Body, p.maxBytes, p.maxItems)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", estate.QualifiedName(item.ID), err)
		}
		result = append(result, Document{ID: item.ID, Body: body})
	}
	return result, nil
}

func (p *Publisher) put(ctx context.Context, id string, body json.RawMessage, options WriteOptions) error {
	var last error
	for attempt := 0; attempt < p.attempts; attempt++ {
		if err := p.checkFence(ctx, options.Generation); err != nil {
			return err
		}
		last = p.client.PutDocument(ctx, estate.EstateCollection, id, body, options)
		if last == nil {
			return nil
		}
		if errors.Is(last, context.Canceled) || errors.Is(last, context.DeadlineExceeded) || errors.Is(last, ErrFenced) {
			return last
		}
		if retryable, ok := last.(interface{ Retryable() bool }); ok && !retryable.Retryable() {
			return last
		}
		if attempt+1 == p.attempts {
			break
		}
		delay := p.initial << attempt
		if delay > p.maxDelay || delay < 0 {
			delay = p.maxDelay
		}
		if err := p.sleep(ctx, delay); err != nil {
			return err
		}
	}
	return last
}

func (p *Publisher) removeStale(ctx context.Context, generation uint64, seen map[string]struct{}) (int, error) {
	if p.lister == nil {
		return 0, nil
	}
	if p.remover == nil {
		return 0, ErrStaleRemoval
	}
	refs, err := p.lister.ListDocuments(ctx, estate.EstateCollection)
	if err != nil {
		return 0, fmt.Errorf("list stale documents: %w", redact(err))
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
	deleted := 0
	for _, ref := range refs {
		if !validID(ref.ID) {
			return deleted, errors.New("estate publisher: listing contained an invalid document id")
		}
		if _, ok := seen[ref.ID]; ok {
			continue
		}
		if err := p.checkFence(ctx, generation); err != nil {
			return deleted, err
		}
		sum := sha256.Sum256([]byte("delete\x00" + ref.ID))
		options := WriteOptions{Generation: generation, FenceToken: p.fenceToken, IdempotencyKey: "estate-delete-" + hex.EncodeToString(sum[:])}
		if err := p.delete(ctx, ref.ID, options); err != nil {
			return deleted, fmt.Errorf("delete stale %s: %w", estate.QualifiedName(ref.ID), redact(err))
		}
		deleted++
	}
	return deleted, nil
}

func (p *Publisher) delete(ctx context.Context, id string, options WriteOptions) error {
	var last error
	for attempt := 0; attempt < p.attempts; attempt++ {
		if err := p.checkFence(ctx, options.Generation); err != nil {
			return err
		}
		last = p.remover.DeleteDocument(ctx, estate.EstateCollection, id, options)
		if last == nil {
			return nil
		}
		if errors.Is(last, context.Canceled) || errors.Is(last, context.DeadlineExceeded) || errors.Is(last, ErrFenced) {
			return last
		}
		if retryable, ok := last.(interface{ Retryable() bool }); ok && !retryable.Retryable() {
			return last
		}
		if attempt+1 == p.attempts {
			break
		}
		delay := p.initial << attempt
		if delay > p.maxDelay || delay < 0 {
			delay = p.maxDelay
		}
		if err := p.sleep(ctx, delay); err != nil {
			return err
		}
	}
	return last
}

func (p *Publisher) failed(err error) (PublishResult, error) {
	err = redact(err)
	p.mu.Lock()
	p.status.LastError = err.Error()
	p.status.FailureCount++
	p.status.Fenced = errors.Is(err, ErrFenced)
	p.mu.Unlock()
	if p.onFailure != nil {
		p.onFailure(err)
	}
	return PublishResult{}, err
}

// Start performs an immediate pass, then refreshes every interval and on
// coalesced change notifications. A failed pass stays visible and retries on
// the next event/tick.
func (p *Publisher) Start(ctx context.Context) error {
	if p == nil {
		return errors.New("estate publisher: unavailable")
	}
	if ctx == nil {
		return errors.New("estate publisher: context is required")
	}
	p.startOnce.Do(func() {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return
		}
		p.started = true
		loopCtx, cancel := context.WithCancel(ctx)
		p.cancel = cancel
		p.mu.Unlock()
		go p.run(loopCtx)
	})
	return nil
}

func (p *Publisher) run(ctx context.Context) {
	defer close(p.completion)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	_, _ = p.Publish(ctx)
	for {
		select {
		case <-ctx.Done():
			p.mu.Lock()
			p.started = false
			p.mu.Unlock()
			return
		case <-p.notify:
			_, _ = p.Publish(ctx)
		case <-ticker.C:
			_, _ = p.Publish(ctx)
		}
	}
}

func (p *Publisher) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		cancel, started := p.cancel, p.started
		p.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if !started {
			select {
			case <-p.completion:
			default:
				close(p.completion)
			}
		}
	})
	select {
	case <-p.completion:
		return nil
	case <-time.After(10 * time.Second):
		return errors.New("estate publisher: shutdown timed out")
	}
}

func idempotencyKey(generation uint64, id string, sum [32]byte) string {
	digest := sha256.New()
	_, _ = fmt.Fprintf(digest, "estate-document-v2\x00%d\x00%s\x00", generation, id)
	_, _ = digest.Write(sum[:])
	return "estate-" + hex.EncodeToString(digest.Sum(nil))
}

func revisionDigest(generation uint64, body []byte) [32]byte {
	digest := sha256.New()
	_, _ = fmt.Fprintf(digest, "estate-revision-v1\x00%d\x00", generation)
	_, _ = digest.Write(body)
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func validID(id string) bool {
	if id == "" || len(id) > 255 || id != strings.TrimSpace(id) {
		return false
	}
	for _, r := range id {
		if r < 0x20 || r == 0x7f || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// boundedJSON first converts through JSON to normalize structs and then
// recursively redacts secret-bearing fields. It rejects unsupported values,
// excessive nesting, and oversized arrays/maps before any client call.
func boundedJSON(value any, maxBytes, maxItems int) (json.RawMessage, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, errors.New("encoded value is invalid JSON")
	}
	clean, count, err := redactValue(decoded, "", 0, maxItems)
	if err != nil {
		return nil, err
	}
	if count > maxItems {
		return nil, ErrPayloadBounds
	}
	raw, err = json.Marshal(clean)
	if err != nil {
		return nil, fmt.Errorf("encode redacted value: %w", err)
	}
	if len(raw) > maxBytes {
		return nil, ErrPayloadBounds
	}
	return json.RawMessage(raw), nil
}

func redactValue(value any, key string, depth, maxItems int) (any, int, error) {
	if depth > 32 {
		return nil, 0, ErrPayloadBounds
	}
	if sensitiveKey(key) {
		return "<redacted>", 1, nil
	}
	switch typed := value.(type) {
	case map[string]any:
		if len(typed) > maxItems {
			return nil, 0, ErrPayloadBounds
		}
		result := make(map[string]any, len(typed))
		// Bound members per container, not the total number of scalar leaves.
		// Estate summaries commonly contain many primitive fields and remain
		// valid as long as each object/array is individually bounded.
		count := 1
		for name, child := range typed {
			clean, _, err := redactValue(child, name, depth+1, maxItems)
			if err != nil {
				return nil, 0, err
			}
			result[name] = clean
		}
		return result, count, nil
	case []any:
		if len(typed) > maxItems {
			return nil, 0, ErrPayloadBounds
		}
		result := make([]any, len(typed))
		count := 1
		for i, child := range typed {
			clean, _, err := redactValue(child, "", depth+1, maxItems)
			if err != nil {
				return nil, 0, err
			}
			result[i] = clean
		}
		return result, count, nil
	default:
		return value, 1, nil
	}
}

func sensitiveKey(key string) bool {
	key = strings.ToLower(key)
	for _, marker := range []string{"secret", "token", "password", "credential", "privatekey", "private_key", "api-key", "apikey", "authorization"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func redact(err error) error {
	if err == nil || err == context.Canceled || err == context.DeadlineExceeded {
		return err
	}
	message := err.Error()
	for _, marker := range []string{"authorization", "access_token", "token", "api-key", "apikey", "secret", "password", "credential"} {
		lower := strings.ToLower(message)
		for from := 0; ; {
			offset := strings.Index(lower[from:], marker)
			if offset < 0 {
				break
			}
			offset += from
			end := offset + len(marker)
			for end < len(message) && strings.ContainsRune(" \t:=", rune(message[end])) {
				end++
			}
			valueEnd := end
			for valueEnd < len(message) && !strings.ContainsRune(" ,;)}]\\\"'\n\r", rune(message[valueEnd])) {
				valueEnd++
			}
			message = message[:end] + "<redacted>" + message[valueEnd:]
			lower = strings.ToLower(message)
			from = end + len("<redacted>")
		}
	}
	return fmt.Errorf("%s: %w", message, err)
}
