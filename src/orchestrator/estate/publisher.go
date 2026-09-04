// Estate publisher (I-11, D-79): the orchestrator writes estate state as
// documents into the control-plane database so the admin console reads
// everything through the public API like any customer app.
//
// Mapping: one ordinary TerraScale database (the control-plane database,
// configured on the client) holds collection "estate" with six documents:
// regions, hosts, databases, rollouts, slo, reconcile. The qualified admin
// names are estate.regions, estate.hosts, estate.databases,
// estate.rollouts, estate.slo, estate.reconcile. The publisher PUTs each
// document (create-or-replace) with the document value as the raw JSON
// body, authenticated as Bearer <api key>.
//
// Cadence: tick every Interval (default 10s) and publish on change.
// Publish is also the on-change entry point: callers invoke Publish (or
// NotifyChange when the loop runs via Start) immediately after a mutation
// instead of waiting for the next tick. Change detection hashes the
// canonical JSON of each document and PUTs only the documents whose hash
// moved, so unchanged ticks cost no writes. Snapshots must be
// deterministic: no clocks or random values inside the payload, or every
// tick looks changed.
package estate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
)

// EstateCollection is the control-plane database collection holding the six
// estate documents.
const EstateCollection = "estate"

// Estate document IDs within EstateCollection. QualifiedName renders the
// admin-visible estate.* name.
const (
	DocRegions   = "regions"
	DocHosts     = "hosts"
	DocDatabases = "databases"
	DocRollouts  = "rollouts"
	DocSLO       = "slo"
	DocReconcile = "reconcile"
)

// DefaultPublisherInterval is the I-11/D-79 tick: estate state is
// re-observed and changed documents rewritten every 10 seconds.
const DefaultPublisherInterval = 10 * time.Second

// EstateDocIDs lists the six estate documents in stable publish order.
func EstateDocIDs() []string {
	return []string{DocRegions, DocHosts, DocDatabases, DocRollouts, DocSLO, DocReconcile}
}

// QualifiedName renders the admin-visible estate.* name of one document ID.
func QualifiedName(docID string) string {
	return EstateCollection + "." + docID
}

// Snapshot is one observation of the six estate documents. Each field is
// marshaled as the document value; nil marshals to null. Keep payloads
// deterministic (no timestamps) so change detection works.
type Snapshot struct {
	Regions   any
	Hosts     any
	Databases any
	Rollouts  any
	SLO       any
	Reconcile any
}

// EstateDocument is one document of a Snapshot in publish order.
type EstateDocument struct {
	ID   string
	Body any
}

// Documents returns the six snapshot documents in stable publish order.
func (s Snapshot) Documents() []EstateDocument {
	return []EstateDocument{
		{ID: DocRegions, Body: s.Regions},
		{ID: DocHosts, Body: s.Hosts},
		{ID: DocDatabases, Body: s.Databases},
		{ID: DocRollouts, Body: s.Rollouts},
		{ID: DocSLO, Body: s.SLO},
		{ID: DocReconcile, Body: s.Reconcile},
	}
}

// RegionPayload is the deterministic per-region summary published in the
// regions document.
type RegionPayload struct {
	Code            string `json:"code"`
	OCIName         string `json:"ociName"`
	MemberCount     uint16 `json:"memberCount"`
	PrimaryShape    string `json:"primaryShape"`
	FallbackShape   string `json:"fallbackShape"`
	NetworkCIDR     string `json:"networkCidr"`
	ControlReplicas uint16 `json:"controlReplicas"`
}

// RegionsDoc is the deterministic regions document value built from the
// declared estate. It carries declaration only, never observation.
type RegionsDoc struct {
	EstateVersion uint32          `json:"estateVersion"`
	HomeRegion    string          `json:"homeRegion"`
	Regions       []RegionPayload `json:"regions"`
}

// RegionsPayload renders the deterministic regions document for one declared
// spec. It validates the spec first and fails closed on an invalid estate.
func RegionsPayload(spec Spec) (RegionsDoc, error) {
	if err := spec.Validate(); err != nil {
		return RegionsDoc{}, err
	}
	doc := RegionsDoc{
		EstateVersion: spec.Version,
		HomeRegion:    spec.HomeRegion,
		Regions:       make([]RegionPayload, 0, len(spec.Regions)),
	}
	for _, region := range spec.Regions {
		doc.Regions = append(doc.Regions, RegionPayload{
			Code:            region.Code,
			OCIName:         region.OCIName,
			MemberCount:     region.Members.Count,
			PrimaryShape:    region.Members.PrimaryShape,
			FallbackShape:   region.Members.FallbackShape,
			NetworkCIDR:     region.Network.CIDR,
			ControlReplicas: region.Members.ControlReplicas,
		})
	}
	return doc, nil
}

// DocumentWriter is the write seam the publisher drives. *ControlPlaneClient
// satisfies it; tests substitute a fake. Collection is the control-plane
// collection (normally EstateCollection), docID one of EstateDocIDs.
type DocumentWriter interface {
	PutDocument(ctx context.Context, collection, docID string, body any) error
}

// DocumentWriteOptions carries the controls used by the public SDK mutation
// contract. IdempotencyKey is derived from the document revision and is safe
// to reuse after a process restart. IfMatch is reserved for callers that have
// an explicit optimistic-concurrency revision.
type DocumentWriteOptions struct {
	IdempotencyKey string
	IfMatch        string
}

// DocumentWriteReceipt is the typed receipt returned by a public document
// write. Revisions are opaque server values and must never be manufactured by
// the publisher.
type DocumentWriteReceipt struct {
	Revision string
	ETag     string
}

// PublicDocumentWriter is the typed public HTTP writer seam. Its raw JSON
// value and options match the public SDK's document PUT operation. The
// legacy DocumentWriter interface remains accepted for local providers.
// @public
type PublicDocumentWriter interface {
	PutPublicDocument(ctx context.Context, collection, docID string, value json.RawMessage, options DocumentWriteOptions) (DocumentWriteReceipt, error)
}

// PublisherConfig is the fully explicit configuration of one estate
// publisher. No ambient environment is read; a zero Interval selects the
// 10s default.
type PublisherConfig struct {
	Writer DocumentWriter
	// Snapshot observes the six estate documents. Required; must be
	// deterministic for change detection to converge.
	Snapshot func(ctx context.Context) (Snapshot, error)
	// Collection overrides the control-plane collection. Empty selects
	// EstateCollection.
	Collection string
	// Interval between ticks. Zero selects DefaultPublisherInterval.
	Interval time.Duration
	Now      func() time.Time
	// RetryMaxAttempts includes the first attempt. Zero selects three bounded
	// attempts. Retry delays are capped so a failed control plane cannot create
	// an unbounded backlog or block shutdown indefinitely.
	RetryMaxAttempts  int
	RetryInitialDelay time.Duration
	RetryMaxDelay     time.Duration
	Sleep             func(context.Context, time.Duration) error
	// OnPublish observes every successful tick's write count. Writes are
	// billed, so operators wire this to a budget alert. Never skips writes.
	OnPublish func(writes int)
}

// Publisher is the I-11 loop: Publish performs one tick (observe, PUT
// changed documents), Start ticks Publish until ctx is cancelled, and
// NotifyChange triggers one immediate tick for on-change publishes.
type Publisher struct {
	writer            DocumentWriter
	snapshot          func(ctx context.Context) (Snapshot, error)
	collection        string
	interval          time.Duration
	now               func() time.Time
	onPublish         func(int)
	retryMaxAttempts  int
	retryInitialDelay time.Duration
	retryMaxDelay     time.Duration
	sleep             func(context.Context, time.Duration) error

	mutex      sync.Mutex
	publishMu  sync.Mutex
	last       map[string][32]byte
	writeCount int
	lastErr    error

	notify     chan struct{}
	cancel     context.CancelFunc
	completion chan struct{}
	closeOnce  sync.Once
	started    bool
	closed     bool
}

const (
	defaultPublisherAttempts = 3
	defaultPublisherDelay    = 100 * time.Millisecond
	maxPublisherAttempts     = 8
	maxPublisherDelay        = 5 * time.Second
)

// NewPublisher validates the configuration and composes the loop. Nothing is
// started here; Start does that.
func NewPublisher(config PublisherConfig) (*Publisher, error) {
	if config.Writer == nil {
		return nil, errors.New("estate: publisher writer is required")
	}
	if config.Snapshot == nil {
		return nil, errors.New("estate: publisher snapshot source is required")
	}
	collection := config.Collection
	if collection == "" {
		collection = EstateCollection
	}
	if err := validateDocName(collection); err != nil {
		return nil, fmt.Errorf("estate: publisher collection is invalid: %w", err)
	}
	for _, id := range EstateDocIDs() {
		if err := validateDocName(id); err != nil {
			return nil, fmt.Errorf("estate: publisher document %q is invalid: %w", id, err)
		}
	}
	interval := config.Interval
	if interval == 0 {
		interval = DefaultPublisherInterval
	}
	if interval <= 0 {
		return nil, errors.New("estate: publisher interval must be positive")
	}
	attempts := config.RetryMaxAttempts
	if attempts == 0 {
		attempts = defaultPublisherAttempts
	}
	if attempts < 1 || attempts > maxPublisherAttempts {
		return nil, fmt.Errorf("estate: publisher retry attempts must be between 1 and %d", maxPublisherAttempts)
	}
	initialDelay := config.RetryInitialDelay
	if initialDelay == 0 {
		initialDelay = defaultPublisherDelay
	}
	maxDelay := config.RetryMaxDelay
	if maxDelay == 0 {
		maxDelay = maxPublisherDelay
	}
	if initialDelay < 0 || maxDelay < initialDelay || maxDelay > maxPublisherDelay {
		return nil, errors.New("estate: publisher retry delays are invalid")
	}
	sleep := config.Sleep
	if sleep == nil {
		sleep = sleepPublisher
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Publisher{
		writer:            config.Writer,
		snapshot:          config.Snapshot,
		collection:        collection,
		interval:          interval,
		now:               now,
		onPublish:         config.OnPublish,
		retryMaxAttempts:  attempts,
		retryInitialDelay: initialDelay,
		retryMaxDelay:     maxDelay,
		sleep:             sleep,
		last:              make(map[string][32]byte),
		notify:            make(chan struct{}, 1),
		completion:        make(chan struct{}),
	}, nil
}

// Interval reports the tick cadence the loop runs with.
func (p *Publisher) Interval() time.Duration {
	if p == nil {
		return 0
	}
	return p.interval
}

// WriteCount reports the cumulative document PUTs performed by Publish calls.
func (p *Publisher) WriteCount() int {
	if p == nil {
		return 0
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.writeCount
}

// LastError reports the most recent Publish failure, or nil when the last
// tick succeeded.
func (p *Publisher) LastError() error {
	if p == nil {
		return errors.New("estate: publisher is unavailable")
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.lastErr
}

// Completion closes when the Start context is cancelled and the loop exits.
func (p *Publisher) Completion() <-chan struct{} {
	if p == nil {
		return nil
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.completion
}

// NotifyChange triggers one immediate tick for an on-change publish. It never
// blocks; a pending tick already covers a burst of changes.
func (p *Publisher) NotifyChange() {
	if p == nil {
		return
	}
	select {
	case p.notify <- struct{}{}:
	default:
	}
}

// Publish performs one tick: observe the snapshot, marshal each document
// canonically, and PUT only the documents whose hash moved since the last
// successful write of that document.
func (p *Publisher) Publish(ctx context.Context) (int, error) {
	if p == nil {
		return 0, errors.New("estate: publisher is unavailable")
	}
	if ctx == nil {
		return 0, errors.New("estate: publisher context is required")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	// A single in-flight observation gives each document one ordered revision
	// and prevents concurrent callers from issuing duplicate PUTs.
	p.publishMu.Lock()
	defer p.publishMu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	snapshot, err := p.snapshot(ctx)
	if err != nil {
		err = redactFailure(err)
		p.recordErr(err)
		return 0, err
	}
	writes := 0
	for _, doc := range snapshot.Documents() {
		if err := validateDocName(doc.ID); err != nil {
			p.recordErr(err)
			return writes, err
		}
		raw, err := marshalCanonical(doc.Body)
		if err != nil {
			err = redactFailure(err)
			p.recordErr(err)
			return writes, err
		}
		sum := sha256.Sum256(raw)
		if p.unchanged(doc.ID, sum) {
			continue
		}
		options := DocumentWriteOptions{IdempotencyKey: documentIdempotencyKey(p.collection, doc.ID, sum)}
		if err := p.putWithRetry(ctx, doc.ID, doc.Body, raw, options); err != nil {
			err = redactFailure(err)
			p.recordErr(err)
			return writes, err
		}
		p.recordChanged(doc.ID, sum)
		writes++
	}
	p.mutex.Lock()
	p.writeCount += writes
	hook := p.onPublish
	p.mutex.Unlock()
	if hook != nil {
		// Hooks are observers only. A slow hook must not hold publisher state
		// locks, but it is still part of the bounded publish backpressure.
		hook(writes)
	}
	p.recordErr(nil)
	return writes, nil
}

func (p *Publisher) putWithRetry(ctx context.Context, docID string, body any, raw []byte, options DocumentWriteOptions) error {
	var lastErr error
	for attempt := 0; attempt < p.retryMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if typed, ok := p.writer.(PublicDocumentWriter); ok {
			_, lastErr = typed.PutPublicDocument(ctx, p.collection, docID, json.RawMessage(append([]byte(nil), raw...)), options)
		} else {
			lastErr = p.writer.PutDocument(ctx, p.collection, docID, body)
		}
		if lastErr == nil {
			return nil
		}
		if errors.Is(lastErr, context.Canceled) || errors.Is(lastErr, context.DeadlineExceeded) {
			return lastErr
		}
		if classified, ok := lastErr.(retryableWriteError); ok && !classified.Retryable() {
			return lastErr
		}
		if attempt+1 == p.retryMaxAttempts {
			break
		}
		delay := p.retryInitialDelay << attempt
		if delay < 0 || delay > p.retryMaxDelay {
			delay = p.retryMaxDelay
		}
		if err := p.sleep(ctx, delay); err != nil {
			return err
		}
	}
	return lastErr
}

func sleepPublisher(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func documentIdempotencyKey(collection, docID string, sum [32]byte) string {
	// Keep the key deterministic across retries and process restarts while
	// avoiding collection/document identifiers in a header's observable value.
	digest := sha256.New()
	_, _ = digest.Write([]byte("estate-document-v1\x00" + collection + "\x00" + docID + "\x00"))
	_, _ = digest.Write(sum[:])
	return "estate-" + hex.EncodeToString(digest.Sum(nil))
}

type redactedFailure struct {
	cause error
	text  string
}

type retryableWriteError interface {
	Retryable() bool
}

func (e *redactedFailure) Error() string { return e.text }
func (e *redactedFailure) Unwrap() error { return e.cause }

func redactFailure(err error) error {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	message := err.Error()
	for _, marker := range []string{"authorization", "access_token", "token", "api-key", "apikey", "secret", "password"} {
		message = redactAfterMarker(message, marker)
	}
	return &redactedFailure{cause: err, text: message}
}

func redactAfterMarker(message, marker string) string {
	for offset := 0; offset+len(marker) < len(message); offset++ {
		if !strings.EqualFold(message[offset:offset+len(marker)], marker) {
			continue
		}
		end := offset + len(marker)
		for end < len(message) && (message[end] == ' ' || message[end] == '\t' || message[end] == ':' || message[end] == '=') {
			end++
		}
		valueEnd := end
		for valueEnd < len(message) && !strings.ContainsRune(" ,;)}]\\\"'\n\r", rune(message[valueEnd])) {
			valueEnd++
		}
		message = message[:end] + "<redacted>" + message[valueEnd:]
		offset = end + len("<redacted>")
	}
	return message
}

// Start ticks Publish every Interval until ctx is cancelled: one immediate
// tick, then the ticker, plus NotifyChange-triggered ticks. Only the first
// call starts the loop; later calls are no-ops. A tick failure is retained
// in LastError and retried on the next tick; the loop never invents facts.
func (p *Publisher) Start(ctx context.Context) error {
	if p == nil {
		return errors.New("estate: publisher is unavailable")
	}
	if ctx == nil {
		return errors.New("estate: publisher context is required")
	}
	p.mutex.Lock()
	if p.closed || p.started {
		p.mutex.Unlock()
		return nil
	}
	p.started = true
	ctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	completion := make(chan struct{})
	p.completion = completion
	p.mutex.Unlock()
	go func() {
		defer func() {
			p.mutex.Lock()
			p.started = false
			p.cancel = nil
			p.mutex.Unlock()
			close(completion)
		}()
		ticker := time.NewTicker(p.interval)
		defer ticker.Stop()
		for {
			_, _ = p.Publish(ctx)
			select {
			case <-ctx.Done():
				return
			case <-p.notify:
			case <-ticker.C:
			}
		}
	}()
	return nil
}

// Close stops the loop started by Start and waits for it to exit. It is
// idempotent and safe to call without Start.
func (p *Publisher) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.mutex.Lock()
		p.closed = true
		cancel := p.cancel
		started := p.started
		if p.completion == nil {
			p.completion = make(chan struct{})
		}
		if !started {
			select {
			case <-p.completion:
			default:
				close(p.completion)
			}
		}
		p.mutex.Unlock()
		if cancel != nil {
			cancel()
		}
	})
	select {
	case <-p.completion:
		return nil
	case <-time.After(10 * time.Second):
		return errors.New("estate: publisher shutdown timed out")
	}
}

func (p *Publisher) unchanged(id string, sum [32]byte) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	previous, ok := p.last[id]
	return ok && previous == sum
}

func (p *Publisher) recordChanged(id string, sum [32]byte) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.last[id] = sum
}

func (p *Publisher) recordErr(err error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.lastErr = err
}

func marshalCanonical(value any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, fmt.Errorf("estate: encode snapshot document: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func validateDocName(value string) error {
	if value == "" || len(value) > 255 || value != strings.TrimSpace(value) {
		return errors.New("name must be a bounded whitespace-free token")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || unicode.IsSpace(r) {
			return errors.New("name must not contain control characters")
		}
	}
	return nil
}

// ControlPlaneClientConfig is the explicit configuration of the direct
// control-plane API client. No ambient environment is read.
type ControlPlaneClientConfig struct {
	// BaseURL is the public API root, e.g. https://gru.api.terrascale.tech.
	// Required. Production uses https; http is accepted only for
	// loopback test servers.
	BaseURL string
	// Database is the control-plane database name. Required.
	Database string
	// Token returns the Bearer API key. Required; a function so rotation
	// is visible without restart.
	Token func() string
	// ProjectID is sent as X-TerraScale-Project-ID when non-empty.
	ProjectID string
	// HTTP overrides the transport. Nil selects a 10s-timeout client.
	HTTP *http.Client
}

// ControlPlaneClient is the direct REST client the publisher writes
// through: PUT /api/v1/databases/{db}/collections/{collection}/documents/{id}
// with the document value as the raw JSON body. It speaks plain net/http,
// no SDK, so every byte on the wire stays auditable. Never logs tokens.
type ControlPlaneClient struct {
	baseURL  string
	database string
	token    func() string
	project  string
	http     *http.Client
}

const (
	controlPlaneTimeout  = 10 * time.Second
	maxControlPlaneBody  = 8 << 20
	maxEstateDocumentLen = 1 << 20
)

// NewControlPlaneClient validates the configuration and composes the client.
func NewControlPlaneClient(config ControlPlaneClientConfig) (*ControlPlaneClient, error) {
	base := strings.TrimSpace(config.BaseURL)
	if base == "" {
		return nil, errors.New("estate: control-plane base URL is required")
	}
	parsed, err := url.ParseRequestURI(base)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("estate: control-plane base URL must be an absolute URL with no credentials, query, or fragment")
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		host := strings.ToLower(parsed.Hostname())
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return nil, errors.New("estate: control-plane http is allowed only for loopback test servers")
		}
	default:
		return nil, errors.New("estate: control-plane base URL must be https")
	}
	database := strings.TrimSpace(config.Database)
	if err := validateDocName(database); err != nil {
		return nil, errors.New("estate: control-plane database name is required")
	}
	if config.Token == nil {
		return nil, errors.New("estate: control-plane token source is required")
	}
	httpClient := config.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: controlPlaneTimeout}
	}
	return &ControlPlaneClient{
		baseURL:  strings.TrimSuffix(base, "/"),
		database: database,
		token:    config.Token,
		project:  config.ProjectID,
		http:     httpClient,
	}, nil
}

// StaticToken returns a token source holding one fixed API key.
func StaticToken(key string) func() string {
	return func() string { return key }
}

// PutDocument creates or replaces one control-plane document with the value
// marshaled as the raw JSON body.
func (c *ControlPlaneClient) PutDocument(ctx context.Context, collection, docID string, body any) error {
	if c == nil {
		return errors.New("estate: control-plane client is unavailable")
	}
	raw, err := marshalCanonical(body)
	if err != nil {
		return err
	}
	_, err = c.PutPublicDocument(ctx, collection, docID, raw, DocumentWriteOptions{})
	return err
}

// PutPublicDocument writes one raw JSON value using the same route and
// headers as the public SDK. The idempotency key is stable for one logical
// document revision, making an uncertain response safe to replay.
func (c *ControlPlaneClient) PutPublicDocument(ctx context.Context, collection, docID string, raw json.RawMessage, options DocumentWriteOptions) (DocumentWriteReceipt, error) {
	if c == nil {
		return DocumentWriteReceipt{}, errors.New("estate: control-plane client is unavailable")
	}
	if ctx == nil {
		return DocumentWriteReceipt{}, errors.New("estate: control-plane context is required")
	}
	if err := ctx.Err(); err != nil {
		return DocumentWriteReceipt{}, err
	}
	if err := validateDocName(collection); err != nil {
		return DocumentWriteReceipt{}, errors.New("estate: control-plane collection name is invalid")
	}
	if err := validateDocName(docID); err != nil {
		return DocumentWriteReceipt{}, errors.New("estate: control-plane document id is invalid")
	}
	token := ""
	if c.token != nil {
		token = strings.TrimSpace(c.token())
	}
	if token == "" {
		return DocumentWriteReceipt{}, errors.New("estate: control-plane token is not configured")
	}
	if !json.Valid(raw) {
		return DocumentWriteReceipt{}, errors.New("estate: control-plane document is not valid JSON")
	}
	if len(raw) > maxEstateDocumentLen {
		return DocumentWriteReceipt{}, errors.New("estate: control-plane document exceeds the 1 MiB limit")
	}
	if options.IdempotencyKey != "" && (len(options.IdempotencyKey) > 128 || strings.ContainsAny(options.IdempotencyKey, "\r\n")) {
		return DocumentWriteReceipt{}, errors.New("estate: control-plane idempotency key is invalid")
	}
	if options.IfMatch != "" && strings.ContainsAny(options.IfMatch, "\r\n") {
		return DocumentWriteReceipt{}, errors.New("estate: control-plane revision precondition is invalid")
	}
	path := "/api/v1/databases/" + url.PathEscape(c.database) +
		"/collections/" + url.PathEscape(collection) +
		"/documents/" + url.PathEscape(docID)
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return DocumentWriteReceipt{}, fmt.Errorf("estate: control-plane request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	if c.project != "" {
		request.Header.Set("X-TerraScale-Project-ID", c.project)
	}
	if options.IdempotencyKey != "" {
		request.Header.Set("Idempotency-Key", options.IdempotencyKey)
	}
	if options.IfMatch != "" {
		request.Header.Set("If-Match", options.IfMatch)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return DocumentWriteReceipt{}, fmt.Errorf("estate: control-plane put %s failed: %w", QualifiedName(docID), err)
	}
	defer response.Body.Close()
	limited, err := io.ReadAll(io.LimitReader(response.Body, maxControlPlaneBody+1))
	if err != nil {
		return DocumentWriteReceipt{}, fmt.Errorf("estate: control-plane put %s failed: read response: %w", QualifiedName(docID), err)
	}
	if len(limited) > maxControlPlaneBody {
		return DocumentWriteReceipt{}, fmt.Errorf("estate: control-plane put %s failed: response too large", QualifiedName(docID))
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return DocumentWriteReceipt{}, controlPlaneError(docID, response.StatusCode, limited)
	}
	receipt := DocumentWriteReceipt{ETag: response.Header.Get("ETag")}
	if len(bytes.TrimSpace(limited)) != 0 {
		var payload struct {
			Revision string `json:"revision"`
		}
		if err := json.Unmarshal(limited, &payload); err != nil {
			return DocumentWriteReceipt{}, fmt.Errorf("estate: control-plane put %s failed: invalid response", QualifiedName(docID))
		}
		receipt.Revision = payload.Revision
	}
	return receipt, nil
}

func controlPlaneError(docID string, status int, body []byte) error {
	// Do not include provider response text: it is untrusted and frequently
	// echoes authorization material or request payloads. Keep body referenced
	// so callers can pass a bounded read without accidentally logging it.
	_ = body
	return controlPlaneWriteError{docID: docID, status: status}
}

type controlPlaneWriteError struct {
	docID  string
	status int
}

func (e controlPlaneWriteError) Error() string {
	return fmt.Sprintf("estate: control-plane put %s failed: status %d", QualifiedName(e.docID), e.status)
}

func (e controlPlaneWriteError) Retryable() bool {
	return e.status == http.StatusRequestTimeout || e.status == http.StatusTooManyRequests || e.status >= 500
}
