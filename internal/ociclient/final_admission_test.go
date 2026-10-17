package ociclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func TestFinalSourceGuardCannotExtendEarlierSDKAdmissionDeadline(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") == "" || r.Method != http.MethodPut {
			t.Error("expected signed SDK PUT")
			w.WriteHeader(401)
			return
		}
		w.Header().Set("ETag", "original")
	}))
	defer server.Close()
	factory, err := New(testProvider(t), Options{Region: "sa-saopaulo-1", Retry: RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := factory.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	client.Host = server.URL
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	ctx = WithAdmission(ctx, func(ctx context.Context) (func(), error) {
		if err := LimitAdmission(ctx, time.Now().Add(time.Minute)); err != nil {
			return nil, err
		}
		return func() {}, nil
	})
	put := func(ctx context.Context) error {
		_, err := client.PutObject(RequestContext(ctx), objectstorage.PutObjectRequest{NamespaceName: new("ns"), BucketName: new("bucket"), ObjectName: new("owned"), PutObjectBody: io.NopCloser(strings.NewReader("original")), ContentLength: new(int64(len("original")))})
		return err
	}
	if err := put(ctx); err != nil || calls.Load() != 1 {
		t.Fatalf("positive SDK request calls=%d err=%v", calls.Load(), err)
	}
	ctx = WithRequestGuard(ctx, func(ctx context.Context) error {
		// Expire the already admitted cap while the final source guard waits.
		state := ctx.Value(admissionDeadlineKey{}).(*admissionDeadline)
		state.until = time.Now().Add(-time.Second)
		return nil
	})
	var denied atomic.Int64
	ctx = WithWireAttempt(ctx, func(*http.Request) (func(*http.Response, error, bool) error, error) {
		return func(_ *http.Response, _ error, sent bool) error {
			if !sent {
				denied.Add(1)
			}
			return nil
		}, nil
	})
	if err := put(ctx); err == nil || calls.Load() != 1 || denied.Load() != 1 {
		t.Fatalf("expired original SDK cap dispatched calls=%d denied=%d err=%v", calls.Load(), denied.Load(), err)
	}
}
