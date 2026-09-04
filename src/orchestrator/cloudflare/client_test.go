package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeTransport is the fake every test in this package drives the client
// through. No test performs a real Cloudflare call.
type fakeCall struct {
	Method string
	Path   string // path (without /client/v4) plus query
	Body   string
	Auth   string
}

func (c fakeCall) String() string { return c.Method + " " + c.Path + " " + c.Body }

type fakeTransport struct {
	mu      sync.Mutex
	calls   []fakeCall
	handler func(fakeCall) (int, string, http.Header)
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	call := fakeCall{
		Method: req.Method,
		Path:   strings.TrimPrefix(req.URL.Path, "/client/v4"),
		Body:   string(body),
		Auth:   req.Header.Get("Authorization"),
	}
	if req.URL.RawQuery != "" {
		call.Path += "?" + req.URL.RawQuery
	}
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()
	status, resp, headers := f.handler(call)
	if headers == nil {
		headers = http.Header{}
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(resp)),
		Header:     headers,
		Request:    req,
	}, nil
}

func (f *fakeTransport) recorded() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeCall(nil), f.calls...)
}

func okEnvelope(result string) (int, string, http.Header) {
	return http.StatusOK, `{"success":true,"result":` + result + `}`, nil
}

func failEnvelope(status, code int, message string) (int, string, http.Header) {
	return status, fmt.Sprintf(`{"success":false,"errors":[{"code":%d,"message":%q}]}`, code, message), nil
}

func testClient(h func(fakeCall) (int, string, http.Header)) (*Client, *fakeTransport) {
	ft := &fakeTransport{handler: h}
	c := NewClient("token-1", "zone-1", "account-1")
	c.HTTP = ft
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c, ft
}

func summarize(p *Plan) []string {
	if len(p.Changes) == 0 {
		return nil
	}
	out := make([]string, 0, len(p.Changes))
	for _, ch := range p.Changes {
		out = append(out, string(ch.Action)+" "+ch.Resource+" "+ch.Detail)
	}
	return out
}

func TestClientMapsAPIErrors(t *testing.T) {
	c, ft := testClient(func(call fakeCall) (int, string, http.Header) {
		return failEnvelope(http.StatusBadRequest, 1001, "dns record already exists")
	})
	err := func() error {
		_, err := c.ListDNSRecords(context.Background())
		return err
	}()
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want APIError, got %v", err)
	}
	if apiErr.Status != 400 || apiErr.Code != 1001 {
		t.Fatalf("want status 400 code 1001, got %+v", apiErr)
	}
	if strings.Contains(apiErr.Error(), "token") {
		t.Fatalf("error leaked sensitive material: %v", apiErr)
	}
	if len(ft.recorded()) != 1 {
		t.Fatalf("no retry expected on 400, got %d calls", len(ft.recorded()))
	}
}

func TestClientRetriesRateLimitWithRetryAfter(t *testing.T) {
	calls := 0
	c, ft := testClient(func(call fakeCall) (int, string, http.Header) {
		calls++
		if calls == 1 {
			return http.StatusTooManyRequests,
				`{"success":false,"errors":[{"code":971,"message":"rate limited"}]}`,
				http.Header{"Retry-After": []string{"0"}}
		}
		return okEnvelope("[]")
	})
	var sleeps []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		return nil
	}
	if _, err := c.ListDNSRecords(context.Background()); err != nil {
		t.Fatalf("expected success after backoff, got %v", err)
	}
	if got := len(ft.recorded()); got != 2 {
		t.Fatalf("want 2 calls (429 then 200), got %d", got)
	}
	if len(sleeps) != 1 {
		t.Fatalf("want one backoff sleep, got %v", sleeps)
	}
}

func TestClientGivesUpAfterMaxAttempts(t *testing.T) {
	c, ft := testClient(func(call fakeCall) (int, string, http.Header) {
		return failEnvelope(http.StatusTooManyRequests, 971, "rate limited")
	})
	if _, err := c.ListDNSRecords(context.Background()); err == nil {
		t.Fatal("expected error when rate limited forever")
	}
	if got := len(ft.recorded()); got != 4 {
		t.Fatalf("want 4 attempts, got %d", got)
	}
}

func TestClientSendsBearerToken(t *testing.T) {
	var auth string
	c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
		auth = call.Auth
		return okEnvelope("[]")
	})
	_, _ = c.ListDNSRecords(context.Background())
	if auth != "Bearer token-1" {
		t.Fatalf("want bearer auth, got %q", auth)
	}
}

func TestPurgeTagsBatchesAndThrottles(t *testing.T) {
	tags := make([]string, 0, 250)
	for i := range 250 {
		tags = append(tags, fmt.Sprintf("db-%03d", i))
	}
	tags = append(tags, "db-000") // duplicate is dropped

	var sleeps []time.Duration
	base := time.Unix(0, 0)
	c, ft := testClient(func(call fakeCall) (int, string, http.Header) {
		if !strings.HasPrefix(call.Path, "/zones/zone-1/purge_cache") || call.Method != http.MethodPost {
			t.Errorf("unexpected call %v", call)
		}
		var body struct {
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal([]byte(call.Body), &body); err != nil {
			t.Fatalf("malformed purge body: %v", err)
		}
		if len(body.Tags) > MaxPurgeTagsPerRequest {
			t.Fatalf("batch of %d exceeds the D-20 limit of 100", len(body.Tags))
		}
		if len(body.Tags) == 0 {
			t.Fatalf("empty batch sent")
		}
		return okEnvelope("null")
	})
	fakeNow := base
	c.sleep = func(_ context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		fakeNow = fakeNow.Add(d) // sleeps advance the fake clock, like real time
		return nil
	}
	c.now = func() time.Time { return fakeNow }

	if err := c.PurgeTags(context.Background(), tags); err != nil {
		t.Fatalf("purge failed: %v", err)
	}
	calls := ft.recorded()
	if len(calls) != 3 {
		t.Fatalf("want 3 batches for 250 tags, got %d", len(calls))
	}
	// 5/s: no wait before the first, 200ms before each later batch.
	if !reflect.DeepEqual(sleeps, []time.Duration{200 * time.Millisecond, 200 * time.Millisecond}) {
		t.Fatalf("want 5 req/s pacing, got %v", sleeps)
	}
}

func TestPurgeTagsEmptyIsNoop(t *testing.T) {
	c, ft := testClient(func(call fakeCall) (int, string, http.Header) {
		t.Errorf("unexpected call %v", call)
		return okEnvelope("null")
	})
	if err := c.PurgeTags(context.Background(), nil); err != nil {
		t.Fatalf("empty purge should be a no-op: %v", err)
	}
	if len(ft.recorded()) != 0 {
		t.Fatal("no requests expected")
	}
}

func TestResolveBindsZoneAndAccount(t *testing.T) {
	_, ft := testClient(func(call fakeCall) (int, string, http.Header) {
		if call.Path != "/zones?name=terrascale.tech" {
			t.Errorf("unexpected path %s", call.Path)
		}
		return okEnvelope(`[{"id":"z9","account":{"id":"a7"}}]`)
	})
	resolved, err := Resolve(context.Background(), "token-1", "terrascale.tech", ft)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if resolved.ZoneID != "z9" || resolved.AccountID != "a7" {
		t.Fatalf("zone not bound: %+v", resolved)
	}
	if len(ft.recorded()) != 1 {
		t.Fatal("one call expected")
	}
}

func TestResolveUnknownZone(t *testing.T) {
	_, ft := testClient(func(call fakeCall) (int, string, http.Header) {
		return okEnvelope("[]")
	})
	if _, err := Resolve(context.Background(), "token-1", "missing.tech", ft); err == nil {
		t.Fatal("expected error for unknown zone")
	}
}
