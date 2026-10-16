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
