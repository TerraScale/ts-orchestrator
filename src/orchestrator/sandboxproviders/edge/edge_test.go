package edge

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func testClock() (time.Time, func() time.Time) {
	now := time.Unix(2_931_234*600+1, 0)
	return now, func() time.Time { return now }
}

func capabilityFor(t *testing.T, view string, now time.Time) string {
	t.Helper()
	capability, err := MintCapability(testKey, view, 1, "rule:v1:shared", 1, "GRU", now)
	if err != nil {
		t.Fatal(err)
	}
	return capability
}

func reactiveRequest(capability, view string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://sync.test/api/v1/reactive/views/"+view+"/1/log?offset=4&ignored=reader", nil)
	request.Header.Set(CapabilityHeader, capability)
	request.Header.Set("Authorization", "Bearer different-reader")
	request.Header.Set("Cookie", "session=secret")
	return request
}

func immutableOrigin(body string, calls *atomic.Int32, seen chan *http.Request) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if seen != nil {
			seen <- request
		}
		writer.Header().Set("Content-Type", "application/msgpack")
		writer.Header().Set("Cache-Control", "private, max-age=0")
		writer.Header().Set("Cloudflare-CDN-Cache-Control", "public, max-age=60, immutable")
		writer.Header().Set("ETag", `"frozen-4"`)
		writer.Header().Set("Set-Cookie", "must-not-cross-edge")
		writer.Header().Set("Vary", "Authorization, Cookie, Accept-Encoding")
		_, _ = writer.Write([]byte(body))
	})
}

func TestGateCanonicalizesAndStripsAuthenticationBeforeOrigin(t *testing.T) {
	now, clock := testClock()
	var calls atomic.Int32
	seen := make(chan *http.Request, 1)
	handler := New(Options{Key: testKey, Now: clock, Origin: immutableOrigin("frame", &calls, seen)})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, reactiveRequest(capabilityFor(t, "v-local", now), "v-local"))
	if response.Code != http.StatusOK || response.Body.String() != "frame" {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
	originRequest := <-seen
	if originRequest.URL.String() != "http://sync.test/api/v1/reactive/views/v-local/1/log?offset=4" || originRequest.RequestURI != "/api/v1/reactive/views/v-local/1/log?offset=4" {
		t.Fatalf("non-canonical origin URL = %s request-uri=%s", originRequest.URL, originRequest.RequestURI)
	}
	for _, header := range []string{CapabilityHeader, "Authorization", "Cookie"} {
		if got := originRequest.Header.Get(header); got != "" {
			t.Errorf("origin received %s = %q", header, got)
		}
	}
	if response.Header().Get("Set-Cookie") != "" || response.Header().Get("Vary") != "Accept-Encoding" {
		t.Fatalf("auth-varying response headers leaked: cookie=%q vary=%q", response.Header().Get("Set-Cookie"), response.Header().Get("Vary"))
	}
	if got := handler.Metrics(); got.CacheEntries != 1 || got.CacheableResponses != 1 {
		t.Fatalf("metrics = %+v", got)
	}
}

func TestEquivalentReadersCollapseToOneImmutableFill(t *testing.T) {
	now, clock := testClock()
	var calls atomic.Int32
	handler := New(Options{Key: testKey, Now: clock, Origin: immutableOrigin("same-bytes", &calls, nil)})
	capability := capabilityFor(t, "v-local", now)
	const readers = 48
	responses := make(chan *httptest.ResponseRecorder, readers)
	var group sync.WaitGroup
	for i := 0; i < readers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, reactiveRequest(capability, "v-local"))
			responses <- recorder
		}()
	}
	group.Wait()
	close(responses)
	for response := range responses {
		if response.Code != http.StatusOK || response.Body.String() != "same-bytes" {
			t.Fatalf("reader response = %d %q", response.Code, response.Body.String())
		}
	}
	metrics := handler.Metrics()
	if calls.Load() != 1 || metrics.OriginFetches != 1 || metrics.CacheEntries != 1 || metrics.CollapsedFills+metrics.CacheHits != readers-1 {
		t.Fatalf("collapse metrics = %+v origin calls=%d", metrics, calls.Load())
	}
}

func TestNoStoreTimeoutIsNeverCached(t *testing.T) {
	now, clock := testClock()
	var calls atomic.Int32
	handler := New(Options{Key: testKey, Now: clock, Timeout: 15 * time.Millisecond, Fetch: func(ctx context.Context, request *http.Request) (*http.Response, error) {
		calls.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	capability := capabilityFor(t, "v-local", now)
	for i := 0; i < 2; i++ {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, reactiveRequest(capability, "v-local"))
		if recorder.Code != http.StatusGatewayTimeout || recorder.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("timeout response = %d headers=%v", recorder.Code, recorder.Header())
		}
	}
	metrics := handler.Metrics()
	if calls.Load() != 2 || metrics.CacheEntries != 0 || metrics.NoStoreResponses != 2 || metrics.TimeoutResponses != 2 {
		t.Fatalf("timeout metrics = %+v calls=%d", metrics, calls.Load())
	}
}

func TestCapabilityIsCheckedBeforeCacheAndSupportsRotationOverlap(t *testing.T) {
	now, clock := testClock()
	previous, err := MintCapability(testKey, "v-local", 1, "rule:v1:shared", 1, "GRU", now.Add(-Bucket+time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCapability([][]byte{testKey}, previous, "v-local", "1", "", now); err != nil {
		t.Fatalf("previous bucket capability rejected: %v", err)
	}
	var calls atomic.Int32
	handler := New(Options{Keys: [][]byte{[]byte("old-key"), testKey}, Now: clock, Origin: immutableOrigin("private-frame", &calls, nil)})
	first := reactiveRequest(previous, "v-local")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, first)
	if recorder.Code != http.StatusOK {
		t.Fatalf("rotated capability status = %d", recorder.Code)
	}
	foreign := capabilityFor(t, "v-foreign", now)
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, reactiveRequest(foreign, "v-local"))
	if denied.Code != http.StatusUnauthorized || calls.Load() != 1 || denied.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("foreign capability was not isolated: status=%d calls=%d headers=%v", denied.Code, calls.Load(), denied.Header())
	}
	if _, err := VerifyCapability([][]byte{testKey}, previous, "v-local", "1", "", now.Add(Overlap)); err == nil {
		t.Fatal("expired capability accepted after overlap")
	}
}

func TestInjectedErrorEvictionAndRuleChange(t *testing.T) {
	now, clock := testClock()
	var calls atomic.Int32
	handler := New(Options{Key: testKey, Now: clock, Origin: immutableOrigin("healthy", &calls, nil)})
	capability := capabilityFor(t, "v-local", now)
	request := reactiveRequest(capability, "v-local")
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, request)
	key, err := CacheKey(request.URL.String())
	if err != nil {
		t.Fatal(err)
	}
	if !handler.Evict(key) {
		t.Fatal("expected immutable cache entry to evict")
	}
	handler.SetOriginError(errors.New("injected origin failure"))
	failure := httptest.NewRecorder()
	handler.ServeHTTP(failure, request)
	if failure.Code != http.StatusBadGateway || failure.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("injected error = %d headers=%v", failure.Code, failure.Header())
	}
	handler.SetOriginError(nil)
	handler.SetRuleEnabled(false)
	bypass := httptest.NewRecorder()
	handler.ServeHTTP(bypass, request)
	handler.SetRuleEnabled(true)
	again := httptest.NewRecorder()
	handler.ServeHTTP(again, request)
	metrics := handler.Metrics()
	if first.Code != http.StatusOK || bypass.Code != http.StatusOK || again.Code != http.StatusOK || calls.Load() != 3 || metrics.RuleBypasses != 1 || metrics.CacheEntries != 1 {
		t.Fatalf("fault metrics = %+v calls=%d", metrics, calls.Load())
	}
}

func TestSnapshotCanonicalizationAndHead(t *testing.T) {
	now, clock := testClock()
	var calls atomic.Int32
	handler := New(Options{Key: testKey, Now: clock, Origin: immutableOrigin("snapshot", &calls, nil)})
	capability := capabilityFor(t, "v-local", now)
	request := httptest.NewRequest(http.MethodHead, "http://sync.test/api/v1/reactive/views/v-local/1/snapshot/0?cut=7&offset=99&extra=x", nil)
	request.Header.Set(CapabilityHeader, capability)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.Len() != 0 || calls.Load() != 1 {
		t.Fatalf("HEAD snapshot = %d body=%q calls=%d", recorder.Code, recorder.Body.String(), calls.Load())
	}
	canonical, _ := CacheKey(request.URL.String())
	if !strings.HasSuffix(canonical, "?cut=7") {
		t.Fatalf("snapshot cache key = %s", canonical)
	}
	missing := httptest.NewRecorder()
	request.URL.RawQuery = ""
	handler.ServeHTTP(missing, request)
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("missing cut status = %d", missing.Code)
	}
}

func TestOriginResponseReadFailureIsNoStore(t *testing.T) {
	now, clock := testClock()
	handler := New(Options{Key: testKey, Now: clock, Fetch: func(context.Context, *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	}})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, reactiveRequest(capabilityFor(t, "v-local", now), "v-local"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("empty origin status = %d", recorder.Code)
	}
}
