package ociclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type trackedResponseBody struct {
	io.ReadCloser
	closes atomic.Int32
}

func (b *trackedResponseBody) Close() error {
	b.closes.Add(1)
	return b.ReadCloser.Close()
}

type responseCloseDispatcher struct {
	next           common.HTTPRequestDispatcher
	bodies         []*trackedResponseBody
	openBeforeNext bool
}

func (d *responseCloseDispatcher) Do(request *http.Request) (*http.Response, error) {
	if len(d.bodies) > 0 && d.bodies[len(d.bodies)-1].closes.Load() != 1 {
		d.openBeforeNext = true
	}
	response, err := d.next.Do(request)
	if response != nil && response.Body != nil {
		body := &trackedResponseBody{ReadCloser: response.Body}
		response.Body = body
		d.bodies = append(d.bodies, body)
	}
	return response, err
}

func TestGetObjectClosesErrorBodiesAndLeavesSuccessOpen(t *testing.T) {
	for _, test := range []struct {
		name     string
		status   int
		attempts int
	}{
		{name: "not-found", status: http.StatusNotFound, attempts: 1},
		{name: "retry-exhausted", status: http.StatusServiceUnavailable, attempts: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, signature, present := strings.Cut(r.Header.Get("Authorization"), `signature="`)
				signature, _, closed := strings.Cut(signature, `"`)
				if r.Method != http.MethodGet || !present || !closed || signature == "" {
					t.Error("expected a signed SDK GET")
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.Header().Set("opc-request-id", "fixture-request")
				w.Header().Set("ETag", "fixture-version")
				if strings.HasSuffix(r.URL.Path, "/healthy") {
					_, _ = io.WriteString(w, "healthy")
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, `{"code":"fixture-error","message":"fixture failure"}`)
			}))
			t.Cleanup(server.Close)
			factory, err := New(testProvider(t), Options{Region: "sa-saopaulo-1", Retry: RetryOptions{
				MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond,
			}})
			if err != nil {
				t.Fatal(err)
			}
			client, err := factory.ObjectStorage()
			if err != nil {
				t.Fatal(err)
			}
			PinHost(&client.BaseClient, server.URL)
			dispatcher := &responseCloseDispatcher{next: client.HTTPClient}
			client.HTTPClient = dispatcher
			t.Cleanup(func() {
				for _, body := range dispatcher.bodies {
					if body.closes.Load() == 0 {
						_ = body.Close()
					}
				}
			})
			request := objectstorage.GetObjectRequest{NamespaceName: new("ns"), BucketName: new("bucket"), ObjectName: new("failure")}
			response, err := client.GetObject(RequestContext(t.Context()), request)
			failure, ok := common.IsServiceError(err)
			if !ok {
				t.Fatalf("service error = %v", err)
			}
			if failure.GetHTTPStatusCode() != test.status || failure.GetCode() != "fixture-error" || failure.GetMessage() != "fixture failure" || failure.GetOpcRequestID() != "fixture-request" {
				t.Fatalf("service error fields changed: %v", err)
			}
			if response.RawResponse == nil || response.RawResponse.StatusCode != test.status || response.RawResponse.Header.Get("ETag") != "fixture-version" || response.RawResponse.Header.Get("opc-request-id") != "fixture-request" || response.OpcRequestId == nil || *response.OpcRequestId != "fixture-request" {
				t.Fatalf("error response fields changed: %+v", response)
			}
			if len(dispatcher.bodies) != test.attempts || dispatcher.openBeforeNext {
				t.Fatalf("error attempts = %d, expected %d; prior body left open = %v", len(dispatcher.bodies), test.attempts, dispatcher.openBeforeNext)
			}
			for i, body := range dispatcher.bodies {
				if closes := body.closes.Load(); closes != 1 {
					t.Fatalf("error body %d closed %d times", i, closes)
				}
			}
			request.ObjectName = new("healthy")
			response, err = client.GetObject(RequestContext(t.Context()), request)
			if err != nil {
				t.Fatalf("healthy follow-up: %v", err)
			}
			if len(dispatcher.bodies) != test.attempts+1 || response.Content == nil {
				t.Fatal("healthy response did not return its HTTP stream")
			}
			body := dispatcher.bodies[len(dispatcher.bodies)-1]
			if closes := body.closes.Load(); closes != 0 {
				t.Fatalf("successful stream closed before caller read: %d", closes)
			}
			if content, err := io.ReadAll(response.Content); err != nil || string(content) != "healthy" {
				t.Fatalf("healthy response = %s, %v", content, err)
			}
			if closes := body.closes.Load(); closes != 0 {
				t.Fatalf("successful stream closed before caller Close: %d", closes)
			}
			if err := response.Content.Close(); err != nil {
				t.Fatal(err)
			}
			if closes := body.closes.Load(); closes != 1 {
				t.Fatalf("successful stream caller Close count = %d", closes)
			}
		})
	}
}

func TestReadCancellationJoinsSDKRetryAndPreservesHTTPDeadline(t *testing.T) {
	for _, failure := range []string{"inflight", "backoff", "transport"} {
		t.Run(failure, func(t *testing.T) {
			var failedRequests atomic.Int64
			wireCanceled := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/healthy") {
					w.Header().Set("ETag", "healthy-version")
					_, _ = io.WriteString(w, "healthy")
					return
				}
				failedRequests.Add(1)
				switch failure {
				case "inflight":
					<-r.Context().Done()
					wireCanceled <- struct{}{}
				case "backoff":
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Retry-After", "60")
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = io.WriteString(w, `{"code":"ServiceUnavailable","message":"retry later"}`)
				case "transport":
					connection, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					connection.Close()
				}
			}))
			t.Cleanup(server.Close)
			factory, err := New(testProvider(t), Options{Region: "sa-saopaulo-1", Retry: RetryOptions{BaseDelay: time.Minute, MaxDelay: time.Minute}})
			if err != nil {
				t.Fatal(err)
			}
			client, err := factory.ObjectStorage()
			if err != nil {
				t.Fatal(err)
			}
			client.Host = server.URL
			ConfigureReadCancellation(&client.BaseClient)
			client.HTTPClient = Instrument(client.HTTPClient, string(ServiceObjectStorage))
			ConfigureReadCancellation(&client.BaseClient)
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()
			started := time.Now()
			_, err = client.GetObject(ReadContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new("ns"), BucketName: new("bucket"), ObjectName: new(failure)})
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("read cancellation = %v", err)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("cancellation waited for SDK backoff: %v", elapsed)
			}
			if failure == "inflight" {
				select {
				case <-wireCanceled:
				case <-time.After(time.Second):
					t.Fatal("HTTP request was left running after deadline")
				}
			}
			if failedRequests.Load() != 1 {
				t.Fatalf("canceled operation sent %d HTTP attempts", failedRequests.Load())
			}
			response, err := client.GetObject(ReadContext(t.Context()), objectstorage.GetObjectRequest{NamespaceName: new("ns"), BucketName: new("bucket"), ObjectName: new("healthy")})
			if err != nil {
				t.Fatalf("healthy read after cancellation: %v", err)
			}
			defer response.Content.Close()
			body, err := io.ReadAll(response.Content)
			if err != nil || string(body) != "healthy" {
				t.Fatalf("healthy response = %s, %v", body, err)
			}
		})
	}
}

type cancellationDispatcher struct {
	next          common.HTTPRequestDispatcher
	writeReturned atomic.Bool
}

func (d *cancellationDispatcher) Do(request *http.Request) (*http.Response, error) {
	response, err := d.next.Do(request)
	if request.Method == http.MethodPut {
		d.writeReturned.Store(true)
	}
	return response, err
}

func TestConditionalMutationCancellationJoinsSDKAndRetainsAmbiguousWrite(t *testing.T) {
	var writes atomic.Int64
	accepted := make(chan string, 1)
	wireCanceled := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("ETag", "healthy-version")
			_, _ = io.WriteString(w, "healthy")
			return
		}
		if r.Method != http.MethodPut || r.Header.Get("If-None-Match") != "*" {
			t.Errorf("unconditional mutation: %s %s", r.Method, r.Header)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		writes.Add(1)
		accepted <- string(body)
		<-r.Context().Done()
		wireCanceled <- struct{}{}
	}))
	t.Cleanup(server.Close)
	factory, err := New(testProvider(t), Options{Region: "sa-saopaulo-1"})
	if err != nil {
		t.Fatal(err)
	}
	client, err := factory.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	client.Host = server.URL
	dispatcher := &cancellationDispatcher{next: client.HTTPClient}
	client.HTTPClient = dispatcher
	ConfigureRequestCancellation(&client.BaseClient)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := client.PutObject(RequestContext(ctx), objectstorage.PutObjectRequest{
			NamespaceName: new("ns"), BucketName: new("bucket"), ObjectName: new("conditional"),
			IfNoneMatch: new("*"), ContentLength: new(int64(len("retained bytes"))),
			PutObjectBody: io.NopCloser(strings.NewReader("retained bytes")),
		})
		result <- err
	}()
	select {
	case body := <-accepted:
		if body != "retained bytes" {
			t.Fatalf("accepted mutation bytes = %q", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SDK mutation never reached HTTP server")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("mutation cancellation = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("mutation did not return after cancellation")
	}
	if !dispatcher.writeReturned.Load() {
		t.Fatal("caller returned before the SDK HTTP operation completed")
	}
	select {
	case <-wireCanceled:
	case <-time.After(time.Second):
		t.Fatal("mutation HTTP request outlived cancellation")
	}
	response, err := client.GetObject(RequestContext(t.Context()), objectstorage.GetObjectRequest{NamespaceName: new("ns"), BucketName: new("bucket"), ObjectName: new("healthy")})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Content.Close()
	if body, err := io.ReadAll(response.Content); err != nil || string(body) != "healthy" {
		t.Fatalf("healthy follow-up = %s, %v", body, err)
	}
	if writes.Load() != 1 {
		t.Fatalf("ambiguous mutation sent %d writes; expected its recorded write only", writes.Load())
	}
}
