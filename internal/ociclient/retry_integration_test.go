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
