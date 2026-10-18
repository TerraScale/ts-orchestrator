package ociclient_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func TestPoolWireFinalAdmissionRunsAfterDurableBegin(t *testing.T) {
	for _, boundary := range []string{"claim", "admission", "deadline-after-wait"} {
		t.Run(boundary, func(t *testing.T) {
			const testCompartment = "ocid1.compartment.oc1..gru"
			ctx := t.Context()
			js := poolFinalAdmissionJetStream(t)
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
			base := common.BaseClient{Host: server.URL, BasePath: "20160918", UserAgent: "pool-wire-integration", HTTPClient: server.Client(), Signer: common.DefaultRequestSigner(factoryBoundaryProvider(t)),
				Configuration: common.CustomClientConfiguration{RetryPolicy: &policy}}
			ociclient.ConfigureRequestCancellation(&base)
			client := core.ComputeManagementClient{BaseClient: base}
			expires := time.Now().Add(25 * time.Millisecond)
			checkCurrent := func(ctx context.Context) error {
				if _, err := kv.Get(ctx, "begin"); err != nil {
					t.Error("final current-authority check preceded durable begin")
				}
				if !time.Now().Before(expires) {
					return nodescale.ErrCapacityPending
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
					if sent || response != nil || dispatchErr == nil || boundary != "deadline-after-wait" && !errors.Is(dispatchErr, nodescale.ErrCapacityPending) {
						t.Errorf("expired authority was not a definite no-send: sent=%v response=%v err=%v", sent, response, dispatchErr)
					}
					_, err := kv.Create(request.Context(), "outcome", []byte("not-sent"))
					return err
				}, nil
			})
			_, err = client.CreateInstancePool(ociclient.RequestContext(ctx), core.CreateInstancePoolRequest{
				CreateInstancePoolDetails: core.CreateInstancePoolDetails{CompartmentId: new(testCompartment),
					InstanceConfigurationId: new("ocid1.instanceconfiguration.oc1.sa-saopaulo-1.fixture"),
					PlacementConfigurations: []core.CreateInstancePoolPlacementConfigurationDetails{{
						AvailabilityDomain: new("fixture:SA-SAOPAULO-1-AD-1"),
						PrimaryVnicSubnets: &core.InstancePoolPlacementPrimarySubnet{SubnetId: new("ocid1.subnet.oc1.sa-saopaulo-1.fixture")},
					}}, Size: new(0)}, OpcRetryToken: new("original-token")})
			if err == nil || boundary != "deadline-after-wait" && !errors.Is(err, nodescale.ErrCapacityPending) || dispatched.Load() != 0 {
				t.Fatalf("expired post-checkpoint authority reached wire: calls=%d err=%v", dispatched.Load(), err)
			}
			outcome, err := kv.Get(ctx, "outcome")
			if err != nil || string(outcome.Value()) != "not-sent" {
				t.Fatalf("definite pre-send denial was not durable: err=%v", err)
			}
		})
	}
}

func poolFinalAdmissionJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(t.TempDir(), "jetstream")})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	return js
}
