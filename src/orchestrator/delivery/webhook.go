package delivery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const MaximumWebhookBody = 1 << 20
const MinimumWebhookSecret = 32

type WebhookKind uint8

const (
	WebhookUnspecified WebhookKind = iota
	WebhookPush
	WebhookPullRequest
)

type WebhookError uint8

const (
	WebhookNoError WebhookError = iota
	WebhookEmptyPayload
	WebhookPayloadTooLarge
	WebhookUnsupportedContentType
	WebhookInvalidSecret
	WebhookInvalidRepository
	WebhookInvalidSignature
	WebhookInvalidDeliveryID
	WebhookUnsupportedEvent
	WebhookMalformedPayload
	WebhookRepositoryMismatch
	WebhookInvalidBaseRevision
	WebhookInvalidRevision
	WebhookInvalidReference
	WebhookUnsupportedAction
)

type WebhookEnvelope struct {
	DeliveryID        string      `json:"deliveryId"`
	Kind              WebhookKind `json:"kind"`
	Action            string      `json:"action"`
	Repository        string      `json:"repository"`
	SourceRepository  string      `json:"sourceRepository"`
	BaseRevision      string      `json:"baseRevision"`
	Revision          string      `json:"revision"`
	SourceRef         string      `json:"sourceRef"`
	TargetRef         string      `json:"targetRef,omitempty"`
	PullRequestNumber int64       `json:"pullRequestNumber,omitempty"`
	IsDeletion        bool        `json:"isDeletion"`
	PayloadSHA256     string      `json:"payloadSha256"`
}

func (e WebhookEnvelope) IsFork() bool { return e.Repository != e.SourceRepository }
func (e WebhookEnvelope) DeliveryKey() string {
	return "forgejo-delivery:" + e.Repository + ":" + e.DeliveryID
}
func (e WebhookEnvelope) DedupeKey() string {
	return "forgejo-payload:" + e.Repository + ":" + e.PayloadSHA256
}

type WebhookVerification struct {
	Envelope *WebhookEnvelope
	Error    WebhookError
}

func (v WebhookVerification) Accepted() bool { return v.Envelope != nil && v.Error == WebhookNoError }

func VerifyWebhook(payload, secret []byte, expectedRepository, contentType, signature, deliveryID, event string) WebhookVerification {
	if len(payload) == 0 {
		return reject(WebhookEmptyPayload)
	}
	if len(payload) > MaximumWebhookBody {
		return reject(WebhookPayloadTooLarge)
	}
	if !isJSONContentType(contentType) {
		return reject(WebhookUnsupportedContentType)
	}
	if len(secret) < MinimumWebhookSecret {
		return reject(WebhookInvalidSecret)
	}
	if !ValidRepository(expectedRepository) {
		return reject(WebhookInvalidRepository)
	}
	if !verifyHMAC(payload, secret, signature) {
		return reject(WebhookInvalidSignature)
	}
	if len(deliveryID) != 36 || deliveryID[8] != '-' || deliveryID[13] != '-' || deliveryID[18] != '-' || deliveryID[23] != '-' {
		return reject(WebhookInvalidDeliveryID)
	}
	for i, c := range deliveryID {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !isHexByte(byte(c)) {
			return reject(WebhookInvalidDeliveryID)
		}
	}
	if deliveryID == "00000000-0000-0000-0000-000000000000" {
		return reject(WebhookInvalidDeliveryID)
	}
	kind := WebhookUnspecified
	switch event {
	case "push":
		kind = WebhookPush
	case "pull_request":
		kind = WebhookPullRequest
	default:
		return reject(WebhookUnsupportedEvent)
	}
	if duplicateJSONProperties(payload) {
		return reject(WebhookMalformedPayload)
	}
	var root map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return reject(WebhookMalformedPayload)
	}
	if dec.More() {
		return reject(WebhookMalformedPayload)
	}
	digest := sha256.Sum256(payload)
	if kind == WebhookPush {
		return parsePush(root, expectedRepository, deliveryID, hex.EncodeToString(digest[:]))
	}
	return parsePullRequest(root, expectedRepository, deliveryID, hex.EncodeToString(digest[:]))
}
func reject(e WebhookError) WebhookVerification { return WebhookVerification{Error: e} }
func verifyHMAC(payload, secret []byte, supplied string) bool {
	if len(supplied) != sha256.Size*2 {
		return false
	}
	b, err := hex.DecodeString(supplied)
	if err != nil {
		return false
	}
	h := hmac.New(sha256.New, secret)
	_, _ = h.Write(payload)
	expected := h.Sum(nil)
	return subtle.ConstantTimeCompare(b, expected) == 1
}
func parsePush(root map[string]json.RawMessage, expected, delivery, digest string) WebhookVerification {
	repo, ok := nestedRepository(root, "repository")
	if !ok {
		return reject(WebhookMalformedPayload)
	}
	if repo != expected {
		return reject(WebhookRepositoryMismatch)
	}
	base, ok := stringField(root, "before")
	if !ok || !objectID(base) {
		return reject(WebhookInvalidBaseRevision)
	}
	revision, ok := stringField(root, "after")
	if !ok || !objectID(revision) {
		return reject(WebhookInvalidRevision)
	}
	ref, ok := stringField(root, "ref")
	if !ok || !validFullRef(ref) {
		return reject(WebhookInvalidReference)
	}
	base, revision = strings.ToLower(base), strings.ToLower(revision)
	if allZero(revision) && allZero(base) {
		return reject(WebhookInvalidBaseRevision)
	}
	return WebhookVerification{Envelope: &WebhookEnvelope{DeliveryID: delivery, Kind: WebhookPush, Action: "push", Repository: repo, SourceRepository: repo, BaseRevision: base, Revision: revision, SourceRef: ref, IsDeletion: allZero(revision), PayloadSHA256: digest}}
}
func parsePullRequest(root map[string]json.RawMessage, expected, delivery, digest string) WebhookVerification {
	repo, ok := nestedRepository(root, "repository")
	if !ok {
		return reject(WebhookMalformedPayload)
	}
	var pr map[string]json.RawMessage
	if !objectField(root, "pull_request", &pr) {
		return reject(WebhookMalformedPayload)
	}
	var head, base map[string]json.RawMessage
	if !objectField(pr, "head", &head) || !objectField(pr, "base", &base) {
		return reject(WebhookMalformedPayload)
	}
	source, ok := nestedRepository(head, "repo")
	if !ok {
		return reject(WebhookMalformedPayload)
	}
	target, ok := nestedRepository(base, "repo")
	if !ok {
		return reject(WebhookMalformedPayload)
	}
	action, aok := stringField(root, "action")
	number, nok := intField(root, "number")
	if !aok || !nok || number <= 0 {
		return reject(WebhookMalformedPayload)
	}
	if repo != expected || target != expected {
		return reject(WebhookRepositoryMismatch)
	}
	if !validAction(action) {
		return reject(WebhookUnsupportedAction)
	}
	baseRev, bok := stringField(base, "sha")
	revision, rok := stringField(head, "sha")
	if !bok || !validRevision(baseRev) || allZero(baseRev) {
		return reject(WebhookInvalidBaseRevision)
	}
	if !rok || !validRevision(revision) || allZero(revision) {
		return reject(WebhookInvalidRevision)
	}
	sourceRef, sok := stringField(head, "ref")
	targetRef, tok := stringField(base, "ref")
	if !sok || !tok || !validBranchRef(sourceRef) || !validBranchRef(targetRef) {
		return reject(WebhookInvalidReference)
	}
	return WebhookVerification{Envelope: &WebhookEnvelope{DeliveryID: delivery, Kind: WebhookPullRequest, Action: action, Repository: repo, SourceRepository: source, BaseRevision: strings.ToLower(baseRev), Revision: strings.ToLower(revision), SourceRef: sourceRef, TargetRef: targetRef, PullRequestNumber: number, PayloadSHA256: digest}}
}
func stringField(m map[string]json.RawMessage, key string) (string, bool) {
	var s string
	b, ok := m[key]
	if !ok || json.Unmarshal(b, &s) != nil {
		return "", false
	}
	return s, true
}
func objectField(m map[string]json.RawMessage, key string, out *map[string]json.RawMessage) bool {
	b, ok := m[key]
	if !ok || json.Unmarshal(b, out) != nil || *out == nil {
		return false
	}
	return true
}
func nestedRepository(m map[string]json.RawMessage, key string) (string, bool) {
	var o map[string]json.RawMessage
	if !objectField(m, key, &o) {
		return "", false
	}
	s, ok := stringField(o, "full_name")
	return s, ok && ValidRepository(s)
}
func intField(m map[string]json.RawMessage, key string) (int64, bool) {
	b, ok := m[key]
	if !ok {
		return 0, false
	}
	var n json.Number
	if json.Unmarshal(b, &n) != nil {
		return 0, false
	}
	v, e := n.Int64()
	return v, e == nil
}
func validRevision(s string) bool { return (len(s) == 40 || len(s) == 64) && !allZero(s) && allHex(s) }
func allZero(s string) bool {
	for _, c := range s {
		if c != '0' {
			return false
		}
	}
	return true
}
func allHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
func isHexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
func ValidRepository(s string) bool {
	if len(s) < 3 || len(s) > 256 || strings.Count(s, "/") != 1 {
		return false
	}
	for _, c := range s {
		if !(c == '/' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return s[0] != '/' && s[len(s)-1] != '/'
}
func validFullRef(s string) bool {
	return (strings.HasPrefix(s, "refs/heads/") || strings.HasPrefix(s, "refs/tags/")) && validRef(s)
}
func validBranchRef(s string) bool { return !strings.HasPrefix(s, "refs/") && validRef(s) }
func validRef(s string) bool {
	if len(s) == 0 || len(s) > 512 || s == "@" || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "/") || strings.HasSuffix(s, ".") || strings.HasSuffix(s, "/") || strings.Contains(s, "..") || strings.Contains(s, "//") || strings.Contains(s, "@{") {
		return false
	}
	for _, c := range s {
		if c <= ' ' || strings.ContainsRune("~^:?*[\\", c) || c == 127 {
			return false
		}
	}
	for _, p := range strings.Split(s, "/") {
		if p == "" || strings.HasPrefix(p, ".") || strings.HasSuffix(strings.ToLower(p), ".lock") {
			return false
		}
	}
	return true
}
func validAction(s string) bool {
	switch s {
	case "opened", "closed", "reopened", "edited", "assigned", "unassigned", "label_updated", "label_cleared", "synchronized", "milestoned", "demilestoned", "reviewed", "review_requested", "review_request_removed":
		return true
	}
	return false
}
func isJSONContentType(s string) bool {
	p := strings.SplitN(s, ";", 2)[0]
	return strings.EqualFold(strings.TrimSpace(p), "application/json")
}
func duplicateJSONProperties(payload []byte) bool { // Decode recursively so every object has its own field set.
	d := json.NewDecoder(bytes.NewReader(payload))
	t, err := d.Token()
	if err != nil {
		return true
	}
	if duplicateValue(d, t) {
		return true
	}
	_, err = d.Token()
	return err == nil // a second top-level token is invalid JSON
}
func duplicateValue(d *json.Decoder, token json.Token) bool {
	delim, ok := token.(json.Delim)
	if !ok {
		return false
	}
	if delim == '[' {
		for {
			t, e := d.Token()
			if e != nil {
				return true
			}
			if t == json.Delim(']') {
				return false
			}
			if duplicateValue(d, t) {
				return true
			}
		}
	}
	if delim != '{' {
		return true
	}
	seen := map[string]struct{}{}
	for {
		key, e := d.Token()
		if e != nil {
			return true
		}
		if key == json.Delim('}') {
			return false
		}
		name, ok := key.(string)
		if !ok {
			return true
		}
		if _, ok := seen[name]; ok {
			return true
		}
		seen[name] = struct{}{}
		value, e := d.Token()
		if e != nil {
			return true
		}
		if duplicateValue(d, value) {
			return true
		}
	}
}

type WebhookConfig struct {
	ListenAddress string
	Path          string
	Repository    string
	SecretFile    string
}

func ResolveWebhookConfig(address, path, repository, secretFile string) (WebhookConfig, error) {
	if strings.TrimSpace(address) == "" || strings.TrimSpace(path) == "" || !ValidRepository(repository) || strings.TrimSpace(secretFile) == "" {
		return WebhookConfig{}, errors.New("webhook configuration requires listen address, path, repository, and secret file")
	}
	u, e := url.Parse(address)
	if e != nil || u.Scheme != "http" && u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Host == "" {
		return WebhookConfig{}, errors.New("webhook listen address is invalid")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return WebhookConfig{}, errors.New("plaintext webhook ingress must be loopback")
	}
	if !strings.HasPrefix(path, "/") || len(path) > 256 || strings.ContainsAny(path, "?\r\n") {
		return WebhookConfig{}, errors.New("webhook path is invalid")
	}
	p, e := privateFile(secretFile, MinimumWebhookSecret, 4096)
	if e != nil {
		return WebhookConfig{}, e
	}
	return WebhookConfig{ListenAddress: u.String(), Path: path, Repository: repository, SecretFile: p}, nil
}
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func privateFile(path string, min, max int) (string, error) {
	p, e := filepath.Abs(path)
	if e != nil {
		return "", e
	}
	st, e := os.Stat(p)
	if e != nil || !st.Mode().IsRegular() || st.Size() < int64(min) || st.Size() > int64(max) {
		return "", fmt.Errorf("secret file must be a bounded regular file")
	}
	if st.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("secret file must be private")
	}
	return p, nil
}
func readSecret(path string, min, max int) ([]byte, error) {
	p, e := privateFile(path, min, max)
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return nil, e
	}
	if len(b) < min || len(b) > max {
		clear(b)
		return nil, errors.New("secret file is out of bounds")
	}
	return b, nil
}

type WebhookAcceptor interface {
	Accept(context.Context, *WebhookEnvelope) (JournalReceipt, error)
}
type WebhookHandler struct {
	Config   WebhookConfig
	Journal  WebhookAcceptor
	secret   []byte
	once     sync.Once
	secretMu sync.RWMutex
}

func NewWebhookHandler(config WebhookConfig, journal WebhookAcceptor) (*WebhookHandler, error) {
	if journal == nil {
		return nil, errors.New("webhook journal is required")
	}
	s, e := readSecret(config.SecretFile, MinimumWebhookSecret, 4096)
	if e != nil {
		return nil, e
	}
	return &WebhookHandler{Config: config, Journal: journal, secret: s}, nil
}
func (h *WebhookHandler) Close() {
	h.once.Do(func() {
		h.secretMu.Lock()
		defer h.secretMu.Unlock()
		clear(h.secret)
	})
}
func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != h.Config.Path {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	body, e := io.ReadAll(io.LimitReader(r.Body, MaximumWebhookBody+1))
	if e != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if len(body) > MaximumWebhookBody {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	h.secretMu.RLock()
	secret := append([]byte(nil), h.secret...)
	h.secretMu.RUnlock()
	v := VerifyWebhook(body, secret, h.Config.Repository, r.Header.Get("Content-Type"), r.Header.Get("X-Forgejo-Signature"), r.Header.Get("X-Forgejo-Delivery"), r.Header.Get("X-Forgejo-Event"))
	clear(secret)
	if !v.Accepted() {
		if v.Error == WebhookUnsupportedContentType {
			w.WriteHeader(http.StatusUnsupportedMediaType)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
		return
	}
	receipt, e := h.Journal.Accept(ctx, v.Envelope)
	if e != nil {
		if errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled) {
			w.WriteHeader(http.StatusRequestTimeout)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		return
	}
	if !receipt.CanAcknowledge() {
		w.WriteHeader(http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
