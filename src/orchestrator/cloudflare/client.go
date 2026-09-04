// Package cloudflare reconciles the terrascale.tech Cloudflare zone to the
// declared state in zone.go (GOAL D-67, items I-2b/X-3). It speaks plain REST
// against api.cloudflare.com/client/v4 — no SDK — so every byte on the wire
// stays auditable. Every reconciler depends on a narrow interface and every
// HTTP call goes through an injectable http.RoundTripper, so tests never
// touch the network.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultBaseURL is the Cloudflare API v4 root.
const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

// EnvAPIToken is the environment variable holding the zone token. Only the
// orchestrator holds Cloudflare tokens with write scope (D-67); a configured
// token is what switches real calls on (owner step O-4).
const EnvAPIToken = "CLOUDFLARE_API_TOKEN"

// Purge limits on the Pro plan (D-20/D-63).
const (
	MaxPurgeTagsPerRequest = 100
	purgeMinInterval       = 200 * time.Millisecond // 5 purge requests/second
)

// TokenFromEnv returns the API token the reconciler authenticates with.
func TokenFromEnv() (string, error) {
	token := strings.TrimSpace(os.Getenv(EnvAPIToken))
	if token == "" {
		return "", fmt.Errorf("cloudflare: %s is not set", EnvAPIToken)
	}
	return token, nil
}

// APIError maps a failed Cloudflare response. Bodies, tokens, and headers are
// never copied into it.
type APIError struct {
	Op      string
	Status  int
	Code    int
	Message string
}

func (e *APIError) Error() string {
	switch {
	case e.Status != 0 && e.Message != "":
		return fmt.Sprintf("cloudflare %s failed: status %d: %s", e.Op, e.Status, e.Message)
	case e.Status != 0:
		return fmt.Sprintf("cloudflare %s failed: status %d", e.Op, e.Status)
	default:
		return "cloudflare " + e.Op + " failed"
	}
}

// ErrNotFound reports a missing KV key.
var ErrNotFound = errors.New("cloudflare: kv key not found")

// Client is bound to one zone (and its account, for KV) and implements every
// per-resource interface declared in this package.
type Client struct {
	Token     string
	ZoneID    string
	AccountID string
	BaseURL   string
	HTTP      http.RoundTripper

	maxAttempts int
	sleep       func(context.Context, time.Duration) error
	now         func() time.Time

	mu        sync.Mutex
	nextPurge time.Time
}

// NewClient returns a client for an already-resolved zone.
func NewClient(token, zoneID, accountID string) *Client {
	return &Client{
		Token:       token,
		ZoneID:      zoneID,
		AccountID:   accountID,
		BaseURL:     DefaultBaseURL,
		HTTP:        http.DefaultTransport,
		maxAttempts: 4,
		sleep:       sleepContext,
		now:         time.Now,
	}
}

// Resolve looks the zone up by name so the returned client is bound to the
// zone and account identifiers every other call needs.
func Resolve(ctx context.Context, token, zoneName string, rt http.RoundTripper) (*Client, error) {
	c := NewClient(token, "", "")
	if rt != nil {
		c.HTTP = rt
	}
	var result []struct {
		ID      string `json:"id"`
		Account struct {
			ID string `json:"id"`
		} `json:"account"`
	}
	path := "/zones?name=" + url.QueryEscape(zoneName)
	if err := c.do(ctx, "resolve zone", http.MethodGet, path, nil, &result); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("cloudflare: zone %s not found", zoneName)
	}
	c.ZoneID, c.AccountID = result[0].ID, result[0].Account.ID
	return c, nil
}

func (c *Client) zonePath(suffix string) string {
	return "/zones/" + url.PathEscape(c.ZoneID) + suffix
}

func (c *Client) accountPath(suffix string) string {
	return "/accounts/" + url.PathEscape(c.AccountID) + suffix
}

const maxBodyBytes = 8 << 20

type envelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func apiErrorFromEnvelope(op string, status int, raw []byte) *APIError {
	err := &APIError{Op: op, Status: status}
	var env envelope
	if json.Unmarshal(raw, &env) == nil && len(env.Errors) > 0 {
		err.Code, err.Message = env.Errors[0].Code, env.Errors[0].Message
	}
	return err
}

// roundtrip performs one logical request, retrying rate limits and transient
// 5xx with backoff (Retry-After honored, capped).
func (c *Client) roundtrip(ctx context.Context, op, method, path string, payload []byte) (int, []byte, error) {
	if !strings.HasPrefix(path, "/") {
		return 0, nil, fmt.Errorf("cloudflare %s: invalid path", op)
	}
	attempts := c.maxAttempts
	if attempts < 1 {
		attempts = 1
	}
	for attempt := 0; ; attempt++ {
		var body io.Reader
		if payload != nil {
			body = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
		if err != nil {
			return 0, nil, fmt.Errorf("cloudflare %s: %w", op, err)
		}
		req.Header.Set("Authorization", "Bearer "+c.Token)
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.HTTP.RoundTrip(req)
		if err != nil {
			return 0, nil, fmt.Errorf("cloudflare %s: transport: %w", op, err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
		resp.Body.Close()
		if readErr != nil {
			return 0, nil, fmt.Errorf("cloudflare %s: read response: %w", op, readErr)
		}
		if len(raw) > maxBodyBytes {
			return 0, nil, &APIError{Op: op, Status: resp.StatusCode, Message: "response too large"}
		}
		if !retryable(resp.StatusCode) || attempt+1 >= attempts {
			return resp.StatusCode, raw, nil
		}
		if err := c.sleep(ctx, backoff(resp.Header.Get("Retry-After"), attempt)); err != nil {
			return 0, nil, fmt.Errorf("cloudflare %s: %w", op, err)
		}
	}
}

func retryable(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusBadGateway ||
		status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

func backoff(retryAfter string, attempt int) time.Duration {
	if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds >= 0 {
		if d := time.Duration(seconds) * time.Second; d <= 30*time.Second {
			return d
		}
		return 30 * time.Second
	}
	d := 500 * time.Millisecond << attempt
	if d > 8*time.Second {
		d = 8 * time.Second
	}
	return d
}

// do sends one enveloped request and decodes result into out when non-nil.
func (c *Client) do(ctx context.Context, op, method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return fmt.Errorf("cloudflare %s: encode request: %w", op, err)
		}
	}
	status, raw, err := c.roundtrip(ctx, op, method, path, payload)
	if err != nil {
		return err
	}
	var env envelope
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &env); err != nil {
			return &APIError{Op: op, Status: status, Message: "malformed response envelope"}
		}
	}
	if status < 200 || status >= 300 || !env.Success {
		return apiErrorFromEnvelope(op, status, raw)
	}
	if out != nil && len(env.Result) > 0 && string(env.Result) != "null" {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("cloudflare %s: decode result: %w", op, err)
		}
	}
	return nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// PurgeTags purges cache tags in batches of at most 100, at most 5 purge
// requests per second (D-20). Immutable reactive responses never go through
// this path (D-55); it serves database deletion, security purge, and
// retired-generation cleanup.
func (c *Client) PurgeTags(ctx context.Context, tags []string) error {
	unique := map[string]struct{}{}
	for _, tag := range tags {
		if tag != "" {
			unique[tag] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(unique))
	for tag := range unique {
		ordered = append(ordered, tag)
	}
	sort.Strings(ordered)
	for start := 0; start < len(ordered); start += MaxPurgeTagsPerRequest {
		end := min(start+MaxPurgeTagsPerRequest, len(ordered))
		if err := c.throttlePurge(ctx); err != nil {
			return err
		}
		batch := ordered[start:end]
		body := map[string][]string{"tags": batch}
		if err := c.do(ctx, "purge cache tags", http.MethodPost, c.zonePath("/purge_cache"), body, nil); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) throttlePurge(ctx context.Context) error {
	c.mu.Lock()
	now := c.now()
	wait := time.Duration(0)
	if c.nextPurge.After(now) {
		wait = c.nextPurge.Sub(now)
		c.nextPurge = c.nextPurge.Add(purgeMinInterval)
	} else {
		c.nextPurge = now.Add(purgeMinInterval)
	}
	c.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	return c.sleep(ctx, wait)
}
