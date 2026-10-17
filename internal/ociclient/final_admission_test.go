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
	for _, requestCanceled := range []bool{true, false} {
		name := "independent-original-canceled"
		if requestCanceled {
			name = "request-original-canceled"
		}
		t.Run(name, func(t *testing.T) {
			operation, cancelOperation := context.WithTimeout(t.Context(), time.Minute)
			defer cancelOperation()
			original, cancelOriginal := context.WithCancel(t.Context())
			defer cancelOriginal()
			entered, resume := make(chan struct{}), make(chan struct{})
			operationDone := operation.Done()
			go func() {
				select {
				case <-entered:
					if requestCanceled {
						cancelOperation()
					} else {
						cancelOriginal()
					}
					close(resume)
				case <-operationDone:
				}
			}()
			var previousChecks, localChecks, unsent atomic.Int64
			operation = WithRequestGuard(operation, func(ctx context.Context) error {
				previousChecks.Add(1)
				close(entered)
				select {
				case <-resume:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			operation = WithRequestGuard(operation, func(ctx context.Context) error {
				localChecks.Add(1)
				if err := ctx.Err(); err != nil {
					return err
				}
				return original.Err()
			})
			operation = WithWireAttempt(operation, func(*http.Request) (func(*http.Response, error, bool) error, error) {
				return func(_ *http.Response, _ error, sent bool) error {
					if !sent {
						unsent.Add(1)
					}
					return nil
				}, nil
			})
			wantLocal := int64(1)
			if requestCanceled {
				wantLocal = 0
			}
			if err := put(operation); err == nil || calls.Load() != 1 || unsent.Load() != 1 || previousChecks.Load() != 1 || localChecks.Load() != wantLocal {
				t.Fatalf("canceled original SDK request dispatched calls=%d unsent=%d previous=%d local=%d err=%v", calls.Load(), unsent.Load(), previousChecks.Load(), localChecks.Load(), err)
			}
		})
	}
}
