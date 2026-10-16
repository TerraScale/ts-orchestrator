package nodescale

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

func TestCapacityAdmissionRechecksEveryHTTPRetry(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		name := "current"
		if revoked {
			name = "revoked"
		}
		t.Run(name, func(t *testing.T) {
			cloud := newCapacityCloud()
			var writes, admissions, guards, checkpoints atomic.Int32
			var originalToken atomic.Value
			var holding, growing, denied atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.Method == http.MethodPut && strings.Contains(request.URL.Path, "/instancePools/") && growing.Load() {
					if token, ok := originalToken.Load().(string); !ok || token == "" || request.Header.Get("opc-retry-token") != token {
						t.Error("wire attempt lost its original checkpointed retry token")
					}
					if !holding.Load() {
						t.Error("wire mutation escaped its authority fence")
					}
					if writes.Add(1) == 1 {
						denied.Store(revoked)
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusTooManyRequests)
						_, _ = w.Write([]byte(`{"code":"TooManyRequests","message":"retry"}`))
						return
					}
				}
				cloud.ServeHTTP(w, request)
			}))
			defer server.Close()
			factory, err := ociclient.New(common.NewRawConfigurationProvider("tenancy", "user", "region", "fingerprint", "", nil),
				ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{
					MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}})
			if err != nil {
				t.Fatal(err)
			}
			base := common.BaseClient{Host: server.URL, BasePath: "20160918", UserAgent: "capacity-retry-integration",
				HTTPClient: server.Client(), Signer: capacitySigner{}}
			factory.Configure(&base, ociclient.ServiceComputeManagement)
			pool, err := newOCIPool(core.ComputeManagementClient{BaseClient: base}, core.ComputeClient{BaseClient: base},
				core.VirtualNetworkClient{BaseClient: base}, "gru", testCompartment, capacityRecipe().Capacity)
			if err != nil {
				t.Fatal(err)
			}
			pool.Admit = func(context.Context, Recipe) (func(), error) {
				admissions.Add(1)
				if denied.Load() {
					return nil, ErrCapacityPending
				}
				if !holding.CompareAndSwap(false, true) {
					t.Error("retry nested the previous admission fence")
					return nil, ErrCapacityPending
				}
				return func() { holding.Store(false) }, nil
			}
			pool.CheckpointGrowth = func(_ context.Context, _ Recipe, request core.UpdateInstancePoolRequest) (core.UpdateInstancePoolRequest, error) {
				checkpoints.Add(1)
				originalToken.Store(deref(request.OpcRetryToken))
				return request, nil
			}
			ctx := ociclient.WithAuthority(t.Context(), func(context.Context) error { guards.Add(1); return nil })
			if _, err := pool.Ensure(ctx, capacityRecipe()); err != nil {
				t.Fatal(err)
			}
			admissions.Store(0)
			guards.Store(0)
			growing.Store(true)
			err = pool.Grow(ctx, 0)
			wantWrites := int32(2)
			if revoked {
				wantWrites = 1
				if !errors.Is(err, ErrCapacityPending) {
					t.Fatalf("revoked retry did not remain pending: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if writes.Load() != wantWrites || admissions.Load() != 2 || guards.Load() != 2 || checkpoints.Load() != 1 || holding.Load() {
				t.Fatalf("per-attempt fences: writes=%d admissions=%d factory guards=%d checkpoints=%d held=%v", writes.Load(), admissions.Load(), guards.Load(), checkpoints.Load(), holding.Load())
			}
			for _, observed := range cloud.pools {
				wantSize := 1
				if revoked {
					wantSize = 0
				}
				if deref(observed.Size) != wantSize {
					t.Fatalf("authority loss changed target size: %d", deref(observed.Size))
				}
			}
		})
	}
}
