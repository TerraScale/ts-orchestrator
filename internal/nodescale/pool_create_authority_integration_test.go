package nodescale

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

func TestPoolOriginalCreateRecoveryCrossesSDKAndJournal(t *testing.T) {
	ctx := t.Context()
	js := capacityJetStream(t)
	journal, err := oci.OpenJournal(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	cloud := newCapacityCloud()
	recipe := capacityRecipe()
	operationID, started := entityid.New(), time.Now().UTC()
	posts := map[string]int{}
	loseConfigurationReply := true
	rejectConfigurationReplay := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, wire *http.Request) {
		path := strings.TrimPrefix(wire.URL.Path, "/20160918")
		kind := oci.PoolCreateConfiguration
		if path == "/instancePools" {
			kind = oci.PoolCreatePool
		}
		if wire.Method == http.MethodPost && (path == "/instanceConfigurations" || path == "/instancePools") {
			posts[kind]++
			stored, found, err := journal.GetPoolCreateRequest(ctx, operationID, kind)
			if err != nil || !found {
				t.Errorf("SDK create preceded its original durable request: found=%v err=%v", found, err)
				w.WriteHeader(http.StatusConflict)
				return
			}
			attempts, err := journal.ListPoolWireAttempts(ctx, operationID, kind)
			if err != nil || len(attempts) != posts[kind] {
				t.Errorf("wire dispatch lacks its distinct durable begin: attempts=%d posts=%d err=%v", len(attempts), posts[kind], err)
			}
			body, err := io.ReadAll(wire.Body)
			if err != nil {
				t.Error(err)
			}
			copy := wire.Clone(ctx)
			copy.URL.Path = path
			copy.Body = io.NopCloser(bytes.NewReader(body))
			digest, err := poolCreateRequestSHA256(copy)
			if err != nil || digest != stored.RequestSHA256 || wire.Header.Get("opc-retry-token") != stored.RetryToken {
				t.Errorf("actual SDK create differs from original checkpoint: digest=%s err=%v", digest, err)
			}
			wire.Body = io.NopCloser(bytes.NewReader(body))
			if kind == oci.PoolCreateConfiguration && rejectConfigurationReplay {
				rejectConfigurationReplay = false
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPreconditionFailed)
				_, _ = w.Write([]byte(`{"code":"NoEtagMatch","message":"replay precondition failed"}`))
				return
			}
			if kind == oci.PoolCreateConfiguration && loseConfigurationReply {
				loseConfigurationReply = false
				cloud.ServeHTTP(httptest.NewRecorder(), wire)
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = connection.Close()
				return
			}
			w.Header().Set("opc-request-id", fmt.Sprintf("%s-response-%d", kind, posts[kind]))
		}
		cloud.ServeHTTP(w, wire)
	}))
	defer server.Close()
	newPool := func(journal *oci.KVJournal) *OCIPool {
		policy := common.NoRetryPolicy()
		base := common.BaseClient{Host: server.URL, BasePath: "20160918", HTTPClient: server.Client(), Signer: capacitySigner{},
			Configuration: common.CustomClientConfiguration{RetryPolicy: &policy}}
		ociclient.ConfigureRequestCancellation(&base)
		pool, err := newOCIPool(core.ComputeManagementClient{BaseClient: base}, core.ComputeClient{BaseClient: base}, core.VirtualNetworkClient{BaseClient: base}, "gru", testCompartment, recipe.Capacity)
		if err != nil {
			t.Fatal(err)
		}
		pool.operationID, pool.Journal = operationID, journal
		pool.Admit = func(context.Context, Recipe) (func(), error) { return func() {}, nil }
		pool.CheckpointCreate = func(ctx context.Context, candidate Recipe, request oci.PoolCreateRequest) (oci.PoolCreateRequest, error) {
			// Receipt provenance is exercised here; signed authority has separate producer scenarios.
			request.OperationID, request.RecipeSHA256 = operationID, candidate.SHA256()
			request.LogicalScopeSHA256, request.ResolvedScopeSHA256 = strings.Repeat("1", 64), strings.Repeat("1", 64)
			request.GrantSHA256, request.GrantGeneration = strings.Repeat("2", 64), 7
			request.TenancyID, request.Region, request.CompartmentID = "ocid1.tenancy.oc1..fixture", oci.RegionGRU, testCompartment
			request.Role, request.Architecture, request.Shape = candidate.Capacity.Role, candidate.Capacity.Architecture, candidate.Capacity.Shape
			request.Currency, request.ReservedMonthlyCents, request.QuoteSHA256 = "USD", 2147, strings.Repeat("3", 64)
			request.StartedAt = started
			return request, journal.RecordPoolCreateRequest(ctx, request)
		}
		return pool
	}
	if _, err := newPool(journal).Ensure(ctx, recipe); err == nil || len(cloud.configs) != 1 || len(cloud.pools) != 0 {
		t.Fatalf("lost reply did not retain exactly one unknown configuration: err=%v configs=%d pools=%d", err, len(cloud.configs), len(cloud.pools))
	}
	rejectConfigurationReplay = true
	if _, err := newPool(journal).Ensure(ctx, recipe); err == nil || len(cloud.configs) != 1 || len(cloud.pools) != 0 {
		t.Fatalf("later rejection cleared the earlier unknown create: err=%v", err)
	}
	attempts, err := journal.ListPoolWireAttempts(ctx, operationID, oci.PoolCreateConfiguration)
	if err != nil || len(attempts) != 2 {
		t.Fatalf("lost per-wire history: attempts=%+v err=%v", attempts, err)
	}
	unknown, rejected := 0, 0
	for _, attempt := range attempts {
		if attempt.Outcome == nil || attempt.Outcome.TransportError && !attempt.Outcome.NotSent {
			unknown++
		}
		if attempt.Outcome != nil && attempt.Outcome.StatusCode == http.StatusPreconditionFailed {
			rejected++
		}
	}
	if unknown != 1 || rejected != 1 {
		t.Fatalf("later 412 replaced earlier unknown: %+v", attempts)
	}
	journal, err = oci.OpenJournal(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	pool := newPool(journal)
	state, err := pool.Ensure(ctx, recipe)
	if err != nil || len(cloud.configs) != 1 || len(cloud.pools) != 1 || posts[oci.PoolCreateConfiguration] != 3 {
		t.Fatalf("unknown create did not replay its exact token: state=%+v err=%v configs=%d pools=%d posts=%v", state, err, len(cloud.configs), len(cloud.pools), posts)
	}
	for _, id := range []string{state.ConfigurationID, state.PoolID} {
		_, result, found, err := journal.GetPoolCreateResource(ctx, id)
		if err != nil || !found || result.ResourceID != id {
			t.Fatalf("positive create lacks exact resource index: %+v found=%v err=%v", result, found, err)
		}
		kv, err := js.KeyValue(ctx, "TS_OCI_OPERATIONS")
		if err != nil {
			t.Fatal(err)
		}
		if err := kv.Delete(ctx, entityid.Derive("oci-pool-resource", id)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := newPool(journal).Ensure(ctx, recipe); err != nil || posts[oci.PoolCreateConfiguration] != 4 || posts[oci.PoolCreatePool] != 2 || len(cloud.configs) != 1 || len(cloud.pools) != 1 {
		t.Fatalf("positive receipt recovery recreated resources: err=%v posts=%v", err, posts)
	}
	attached := cloud.launch("external", state.PoolID, "10.0.0.4", core.InstanceLifecycleStateRunning, launchTags(recipe, roleNode, operationID))
	for _, err := range []error{pool.Name(ctx, attached, "ts-gru-4"), pool.Remove(ctx, attached)} {
		if !errors.Is(err, ErrCapacityPending) {
			t.Fatalf("current membership authorized an instance without original launch lineage: %v", err)
		}
	}
	if len(cloud.detaches) != 0 || deref(cloud.instances[attached].DisplayName) != "external" {
		t.Fatal("unproven external instance was renamed or detached")
	}
}

func TestPoolWireFinalAdmissionRunsAfterDurableBegin(t *testing.T) {
	for _, boundary := range []string{"claim", "admission", "deadline-after-wait"} {
		t.Run(boundary, func(t *testing.T) {
			ctx := t.Context()
			js := capacityJetStream(t)
			kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "WIRE_EXPIRY", Storage: jetstream.FileStorage})
			if err != nil {
				t.Fatal(err)
			}
			var dispatched atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				dispatched.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			policy := common.NoRetryPolicy()
			base := common.BaseClient{Host: server.URL, BasePath: "20160918", HTTPClient: server.Client(), Signer: capacitySigner{},
				Configuration: common.CustomClientConfiguration{RetryPolicy: &policy}}
			ociclient.ConfigureRequestCancellation(&base)
			client := core.ComputeManagementClient{BaseClient: base}
			expires := time.Now().Add(25 * time.Millisecond)
			checkCurrent := func(ctx context.Context) error {
				if _, err := kv.Get(ctx, "begin"); err != nil {
					t.Error("final current-authority check preceded durable begin")
				}
				if !time.Now().Before(expires) {
					return ErrCapacityPending
				}
				return nil
			}
			ctx = ociclient.WithAuthority(ctx, func(ctx context.Context) error {
				if boundary == "claim" {
					return checkCurrent(ctx)
				}
				return nil
			})
			ctx = ociclient.WithAdmission(ctx, func(ctx context.Context) (func(), error) {
				if boundary == "deadline-after-wait" {
					expires = time.Now().Add(25 * time.Millisecond)
					if err := ociclient.LimitAdmission(ctx, expires); err != nil {
						return nil, err
					}
					// A caller can finish a durable state read after its authority was checked.
					timer := time.NewTimer(time.Until(expires))
					defer timer.Stop()
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-timer.C:
					}
					return func() {}, nil
				}
				if err := checkCurrent(ctx); err != nil {
					return nil, err
				}
				return func() {}, nil
			})
			// This tests SDK/JetStream ordering. Signed authority has a separate producer scenario.
			ctx = ociclient.WithWireAttempt(ctx, func(request *http.Request) (func(*http.Response, error, bool) error, error) {
				if _, err := kv.Create(request.Context(), "begin", []byte("original-attempt")); err != nil {
					return nil, err
				}
				if boundary != "deadline-after-wait" {
					timer := time.NewTimer(max(time.Until(expires), time.Nanosecond))
					defer timer.Stop()
					select {
					case <-request.Context().Done():
						return nil, request.Context().Err()
					case <-timer.C:
					}
				}
				return func(response *http.Response, dispatchErr error, sent bool) error {
					if sent || response != nil || dispatchErr == nil || boundary != "deadline-after-wait" && !errors.Is(dispatchErr, ErrCapacityPending) {
						t.Errorf("expired authority was not a definite no-send: sent=%v response=%v err=%v", sent, response, dispatchErr)
					}
					_, err := kv.Create(request.Context(), "outcome", []byte("not-sent"))
					return err
				}, nil
			})
			_, err = client.CreateInstancePool(ociclient.RequestContext(ctx), core.CreateInstancePoolRequest{
				CreateInstancePoolDetails: core.CreateInstancePoolDetails{CompartmentId: new(testCompartment), Size: new(0)}, OpcRetryToken: new("original-token")})
			if err == nil || boundary != "deadline-after-wait" && !errors.Is(err, ErrCapacityPending) || dispatched.Load() != 0 {
				t.Fatalf("expired post-checkpoint authority reached wire: calls=%d err=%v", dispatched.Load(), err)
			}
			outcome, err := kv.Get(ctx, "outcome")
			if err != nil || string(outcome.Value()) != "not-sent" {
				t.Fatalf("definite pre-send denial was not durable: err=%v", err)
			}
		})
	}
}
