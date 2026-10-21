package ociclient_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

func TestFactorySDKRecoveryAndLimiterAdmissionOverVerifiedTLS(t *testing.T) {
	provider, key := sdkLifetimeProvider(t)
	const instanceID = "ocid1.instance.oc1.sa-saopaulo-1.lifetime"
	const objectOperation = "HEAD /n/{id}/b/{id}/o/{id}"
	for _, test := range []struct {
		name      string
		statuses  []int
		errors    uint64
		throttled uint64
	}{
		{name: "object_success", statuses: []int{http.StatusOK}},
		{name: "object_throttled", statuses: []int{http.StatusTooManyRequests, http.StatusOK}, errors: 1, throttled: 1},
		{name: "object_transport", statuses: []int{0, http.StatusOK}, errors: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := sdkLifetimeOperation(string(ociclient.ServiceObjectStorage), objectOperation)
			var calls atomic.Int32
			server := sdkLifetimeServer(t, key, func(w http.ResponseWriter, request *http.Request) {
				index := int(calls.Add(1)) - 1
				if request.Method != http.MethodHead || request.URL.Path != "/n/secretNamespace/b/secretBucket/o/secret/object/name" || index >= len(test.statuses) {
					t.Errorf("unexpected object attempt: %s %s, index=%d", request.Method, request.URL.Path, index)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if test.statuses[index] == 0 {
					sdkLifetimeDrop(t, w)
					return
				}
				w.Header().Set("ETag", "object-etag")
				w.WriteHeader(test.statuses[index])
			})
			factory := sdkLifetimeFactory(t, provider, ociclient.Options{Region: "sa-saopaulo-1",
				Retry: ociclient.RetryOptions{MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}})
			client, err := factory.ObjectStorage()
			if err != nil {
				t.Fatal(err)
			}
			ociclient.PinHost(&client.BaseClient, server.URL)
			response, err := client.HeadObject(ociclient.RequestContext(sdkLifetimeContext(t)), objectstorage.HeadObjectRequest{
				NamespaceName: new("secretNamespace"), BucketName: new("secretBucket"), ObjectName: new("secret/object/name"),
			})
			if err != nil || response.ETag == nil || *response.ETag != "object-etag" || calls.Load() != int32(len(test.statuses)) {
				t.Fatalf("object recovery: response=%+v calls=%d err=%v", response, calls.Load(), err)
			}
			after := sdkLifetimeOperation(string(ociclient.ServiceObjectStorage), objectOperation)
			if after.Calls-before.Calls != uint64(len(test.statuses)) || after.Errors-before.Errors != test.errors ||
				after.Throttled-before.Throttled != test.throttled || after.LastStatus != http.StatusOK ||
				after.TotalSeconds <= before.TotalSeconds || after.MaxSeconds <= 0 {
				t.Fatalf("object attempt measurements: before=%+v after=%+v", before, after)
			}
			var metrics bytes.Buffer
			ociclient.Metrics.WritePrometheus(&metrics)
			for _, secret := range []string{"secretNamespace", "secretBucket", "secret/object/name"} {
				if strings.Contains(metrics.String(), secret) {
					t.Fatalf("object identifier leaked into metrics: %s", secret)
				}
			}
		})
	}

	t.Run("compute_throttle_recovery", func(t *testing.T) {
		var calls atomic.Int32
		server := sdkLifetimeServer(t, key, func(w http.ResponseWriter, request *http.Request) {
			attempt := calls.Add(1)
			if request.Method != http.MethodGet || request.URL.Path != "/20160918/instances/"+instanceID || attempt > 3 {
				t.Errorf("unexpected compute recovery attempt: %s %s, attempt=%d", request.Method, request.URL.Path, attempt)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if attempt < 3 {
				sdkLifetimeJSON(t, w, http.StatusTooManyRequests, map[string]string{"code": "TooManyRequests", "message": "slow down"})
				return
			}
			sdkLifetimeJSON(t, w, http.StatusOK, map[string]string{"id": instanceID, "lifecycleState": "RUNNING"})
		})
		factory := sdkLifetimeFactory(t, provider, ociclient.Options{Region: "sa-saopaulo-1",
			Limits: map[ociclient.Service]ociclient.Limit{ociclient.ServiceCompute: {PerSecond: 1000, Burst: 1}},
			Retry:  ociclient.RetryOptions{BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond}})
		client, err := factory.Compute()
		if err != nil {
			t.Fatal(err)
		}
		ociclient.PinHost(&client.BaseClient, server.URL)
		response, err := client.GetInstance(ociclient.RequestContext(sdkLifetimeContext(t)), core.GetInstanceRequest{InstanceId: new(instanceID)})
		if err != nil || calls.Load() != 3 || response.LifecycleState != core.InstanceLifecycleStateRunning {
			t.Fatalf("compute recovery: calls=%d state=%s err=%v", calls.Load(), response.LifecycleState, err)
		}
		if factory.Limiter(ociclient.ServiceCompute) != factory.Limiter(ociclient.ServiceCompute) {
			t.Fatal("compute clients lost the shared service limiter")
		}
	})

	t.Run("limiter_denies_before_wire", func(t *testing.T) {
		var calls atomic.Int32
		server := sdkLifetimeServer(t, key, func(w http.ResponseWriter, request *http.Request) {
			calls.Add(1)
			t.Errorf("exhausted limiter dispatched %s %s", request.Method, request.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		})
		factory := sdkLifetimeFactory(t, provider, ociclient.Options{Region: "sa-saopaulo-1",
			Limits: map[ociclient.Service]ociclient.Limit{ociclient.ServiceCompute: {PerSecond: 0.001, Burst: 1}}})
		client, err := factory.Compute()
		if err != nil {
			t.Fatal(err)
		}
		ociclient.PinHost(&client.BaseClient, server.URL)
		if !factory.Limiter(ociclient.ServiceCompute).Allow() {
			t.Fatal("initial service limiter token was unavailable")
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		_, err = client.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(instanceID)})
		if err == nil || calls.Load() != 0 || ctx.Err() != nil || !strings.Contains(err.Error(), "rate limiter") {
			t.Fatalf("limiter must refuse before deadline without a request: calls=%d context=%v err=%v", calls.Load(), ctx.Err(), err)
		}
	})

	t.Run("read_transport_recovery", func(t *testing.T) {
		var calls atomic.Int32
		server := sdkLifetimeServer(t, key, func(w http.ResponseWriter, request *http.Request) {
			attempt := calls.Add(1)
			if request.Method != http.MethodGet || request.URL.Path != "/20160918/instances/"+instanceID || attempt > 3 {
				t.Errorf("unexpected read attempt: %s %s, attempt=%d", request.Method, request.URL.Path, attempt)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if attempt < 3 {
				sdkLifetimeDrop(t, w)
				return
			}
			sdkLifetimeJSON(t, w, http.StatusOK, map[string]string{"id": instanceID, "lifecycleState": "RUNNING"})
		})
		factory := sdkLifetimeFactory(t, provider, ociclient.Options{Region: "sa-saopaulo-1",
			Limits: map[ociclient.Service]ociclient.Limit{ociclient.ServiceCompute: {PerSecond: 1000, Burst: 10}},
			Retry:  ociclient.RetryOptions{BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond}})
		client, err := factory.Compute()
		if err != nil {
			t.Fatal(err)
		}
		ociclient.PinHost(&client.BaseClient, server.URL)
		if _, err := client.GetInstance(ociclient.RequestContext(sdkLifetimeContext(t)), core.GetInstanceRequest{InstanceId: new(instanceID)}); err != nil || calls.Load() != 3 {
			t.Fatalf("read did not recover after two dropped responses: calls=%d err=%v", calls.Load(), err)
		}
	})

	t.Run("uncertain_put_retains_effect_once", func(t *testing.T) {
		var calls atomic.Int32
		var applied atomic.Bool
		server := sdkLifetimeServer(t, key, func(w http.ResponseWriter, request *http.Request) {
			calls.Add(1)
			var update core.UpdateInstanceDetails
			if request.Method != http.MethodPut || request.URL.Path != "/20160918/instances/"+instanceID {
				t.Errorf("unexpected mutation: %s %s", request.Method, request.URL.Path)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if err := json.UnmarshalRead(request.Body, &update); err != nil || update.DisplayName == nil || *update.DisplayName != "x" {
				t.Errorf("mutation body=%+v err=%v", update, err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			applied.Store(true)
			sdkLifetimeDrop(t, w)
		})
		factory := sdkLifetimeFactory(t, provider, ociclient.Options{Region: "sa-saopaulo-1",
			Limits: map[ociclient.Service]ociclient.Limit{ociclient.ServiceCompute: {PerSecond: 1000, Burst: 10}},
			Retry:  ociclient.RetryOptions{BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond}})
		client, err := factory.Compute()
		if err != nil {
			t.Fatal(err)
		}
		ociclient.PinHost(&client.BaseClient, server.URL)
		_, err = client.UpdateInstance(ociclient.RequestContext(sdkLifetimeContext(t)), core.UpdateInstanceRequest{
			InstanceId: new(instanceID), UpdateInstanceDetails: core.UpdateInstanceDetails{DisplayName: new("x")},
		})
		if err == nil || calls.Load() != 1 || !applied.Load() {
			t.Fatalf("uncertain PUT must retain its one observed effect: calls=%d applied=%v err=%v", calls.Load(), applied.Load(), err)
		}
	})
}

func TestObjectCancellationRetainsAcceptedEffectsOverVerifiedTLS(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22 (Q-MAIN-GREEN), owner ts-orch consolidation thread: flaky on main and M1 PRs since the 2026-10-21 integration-line merge")
	provider, key := sdkLifetimeProvider(t)
	for _, failure := range []string{"inflight", "backoff", "transport"} {
		t.Run(failure, func(t *testing.T) {
			var failedRequests atomic.Int64
			wireCanceled := make(chan struct{}, 1)
			server := sdkLifetimeServer(t, key, func(w http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodGet || !strings.HasPrefix(request.URL.Path, "/n/ns/b/bucket/o/") {
					t.Errorf("unexpected object read: %s %s", request.Method, request.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if strings.HasSuffix(request.URL.Path, "/healthy") {
					w.Header().Set("ETag", "healthy-version")
					_, err := io.WriteString(w, "healthy")
					if err != nil {
						t.Error(err)
					}
					return
				}
				if !strings.HasSuffix(request.URL.Path, "/"+failure) {
					t.Errorf("unexpected failed object: %s", request.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if failedRequests.Add(1) != 1 {
					t.Error("canceled object read was replayed")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				switch failure {
				case "inflight":
					<-request.Context().Done()
					wireCanceled <- struct{}{}
				case "backoff":
					w.Header().Set("Retry-After", "60")
					sdkLifetimeJSON(t, w, http.StatusServiceUnavailable, map[string]string{"code": "ServiceUnavailable", "message": "retry later"})
				case "transport":
					sdkLifetimeDrop(t, w)
				}
			})
			factory := sdkLifetimeFactory(t, provider, ociclient.Options{Region: "sa-saopaulo-1",
				Retry: ociclient.RetryOptions{BaseDelay: time.Minute, MaxDelay: time.Minute}})
			client, err := factory.ObjectStorage()
			if err != nil {
				t.Fatal(err)
			}
			ociclient.PinHost(&client.BaseClient, server.URL)
			// The factory already instrumented cancellation; repeated installation must stay harmless.
			ociclient.ConfigureReadCancellation(&client.BaseClient)
			ociclient.ConfigureReadCancellation(&client.BaseClient)
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()
			started := time.Now()
			_, err = client.GetObject(ociclient.ReadContext(ctx), objectstorage.GetObjectRequest{
				NamespaceName: new("ns"), BucketName: new("bucket"), ObjectName: new(failure),
			})
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
				t.Fatalf("read cancellation waited for SDK backoff: elapsed=%v err=%v", time.Since(started), err)
			}
			if failure == "inflight" {
				select {
				case <-wireCanceled:
				case <-time.After(time.Second):
					t.Fatal("HTTP request remained running after the read deadline")
				}
			}
			if failedRequests.Load() != 1 {
				t.Fatalf("canceled read sent %d HTTP attempts, want 1", failedRequests.Load())
			}
			sdkLifetimeReadHealthy(t, client)
		})
	}

	t.Run("conditional_write_cancel_retains_bytes", func(t *testing.T) {
		var writes atomic.Int64
		var begins atomic.Int64
		var finishes atomic.Int64
		var wireReturned atomic.Bool
		accepted := make(chan string, 1)
		wireCanceled := make(chan struct{}, 1)
		server := sdkLifetimeServer(t, key, func(w http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodGet && request.URL.Path == "/n/ns/b/bucket/o/healthy" {
				w.Header().Set("ETag", "healthy-version")
				if _, err := io.WriteString(w, "healthy"); err != nil {
					t.Error(err)
				}
				return
			}
			if request.Method != http.MethodPut || request.URL.Path != "/n/ns/b/bucket/o/conditional" || request.Header.Get("If-None-Match") != "*" {
				t.Errorf("unconditional or unexpected mutation: %s %s %s", request.Method, request.URL.Path, request.Header.Get("If-None-Match"))
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
				return
			}
			if writes.Add(1) != 1 {
				t.Error("conditional write was replayed")
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			accepted <- string(body)
			<-request.Context().Done()
			wireCanceled <- struct{}{}
		})
		factory := sdkLifetimeFactory(t, provider, ociclient.Options{Region: "sa-saopaulo-1"})
		client, err := factory.ObjectStorage()
		if err != nil {
			t.Fatal(err)
		}
		ociclient.PinHost(&client.BaseClient, server.URL)
		ctx, cancel := context.WithCancel(sdkLifetimeContext(t))
		defer cancel()
		ctx = ociclient.WithWireAttempt(ctx, func(request *http.Request) (func(*http.Response, error, bool) error, error) {
			begins.Add(1)
			if request.Method != http.MethodPut || request.Header.Get("If-None-Match") != "*" {
				return nil, errors.New("wire journal received an unexpected mutation")
			}
			return func(_ *http.Response, err error, dispatched bool) error {
				finishes.Add(1)
				if !dispatched || !errors.Is(err, context.Canceled) {
					t.Errorf("wire completion: dispatched=%v err=%v", dispatched, err)
				}
				// The production dispatcher invokes finish only after its real HTTP Do returns.
				wireReturned.Store(dispatched)
				return nil
			}, nil
		})
		result := make(chan error, 1)
		done := make(chan struct{})
		t.Cleanup(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("SDK mutation goroutine did not join during cleanup")
			}
		})
		go func() {
			defer close(done)
			_, err := client.PutObject(ociclient.RequestContext(ctx), objectstorage.PutObjectRequest{
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
			t.Fatal("SDK mutation never reached the TLS provider")
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
		if !wireReturned.Load() || begins.Load() != 1 || finishes.Load() != 1 {
			t.Fatalf("caller returned before exactly one HTTP completion: returned=%v begins=%d finishes=%d", wireReturned.Load(), begins.Load(), finishes.Load())
		}
		select {
		case <-wireCanceled:
		case <-time.After(time.Second):
			t.Fatal("mutation HTTP request outlived cancellation")
		}
		sdkLifetimeReadHealthy(t, client)
		if writes.Load() != 1 {
			t.Fatalf("ambiguous mutation sent %d writes, want its one retained effect", writes.Load())
		}
	})
}

func TestRegionalIdentityAndMutationAuthorityFenceOverVerifiedTLS(t *testing.T) {
	provider, key := sdkLifetimeProvider(t)
	t.Run("fenced_mutation_then_read", func(t *testing.T) {
		const vcnID = "ocid1.vcn.oc1.eu-frankfurt-1.lifetime"
		var writes atomic.Int32
		var reads atomic.Int32
		var lost atomic.Bool
		server := sdkLifetimeServer(t, key, func(w http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodGet && request.URL.Path == "/20160918/vcns/"+vcnID {
				reads.Add(1)
				sdkLifetimeJSON(t, w, http.StatusOK, map[string]string{"id": vcnID, "cidrBlock": "10.1.0.0/16"})
				return
			}
			writes.Add(1)
			if request.Method != http.MethodPost || request.URL.Path != "/20160918/vcns" || request.Header.Get("opc-retry-token") != "durable-operation-vcn" {
				t.Errorf("unexpected authenticated mutation: %s %s token=%s", request.Method, request.URL.Path, request.Header.Get("opc-retry-token"))
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var details core.CreateVcnDetails
			if err := json.UnmarshalRead(request.Body, &details); err != nil || details.CompartmentId == nil || *details.CompartmentId != "ocid1.compartment.oc1..owned" || details.CidrBlock == nil || *details.CidrBlock != "10.1.0.0/16" {
				t.Errorf("VCN mutation details=%+v err=%v", details, err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			lost.Store(true)
			sdkLifetimeJSON(t, w, http.StatusServiceUnavailable, map[string]string{"code": "InternalError", "message": "lost response"})
		})
		factory := sdkLifetimeFactory(t, provider, ociclient.Options{Region: "sa-saopaulo-1",
			Retry: ociclient.RetryOptions{BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}})
		home, err := factory.ForRegion("eu-frankfurt-1")
		if err != nil {
			t.Fatal(err)
		}
		if home.Provider() != factory.Provider() {
			t.Fatal("home region changed authenticated identity")
		}
		cached, err := factory.ForRegion("eu-frankfurt-1")
		if err != nil || cached != home || cached.Limiter(ociclient.ServiceNetwork) != home.Limiter(ociclient.ServiceNetwork) {
			t.Fatal("home-region clients do not share their factory and service limiter")
		}
		client, err := home.Network()
		if err != nil {
			t.Fatal(err)
		}
		ociclient.PinHost(&client.BaseClient, server.URL)
		transferred := errors.New("authority transferred")
		ctx := ociclient.WithAuthority(sdkLifetimeContext(t), func(context.Context) error {
			if lost.Load() {
				return transferred
			}
			return nil
		})
		_, err = client.CreateVcn(ociclient.RequestContext(ctx), core.CreateVcnRequest{
			OpcRetryToken:    new("durable-operation-vcn"),
			CreateVcnDetails: core.CreateVcnDetails{CompartmentId: new("ocid1.compartment.oc1..owned"), CidrBlock: new("10.1.0.0/16")},
		})
		if !errors.Is(err, transferred) || !strings.Contains(err.Error(), "authority transferred") || writes.Load() != 1 {
			t.Fatalf("stale SDK retry reached provider: writes=%d err=%v", writes.Load(), err)
		}
		response, err := client.GetVcn(ociclient.RequestContext(ctx), core.GetVcnRequest{VcnId: new(vcnID)})
		if err != nil || response.Id == nil || *response.Id != vcnID || reads.Load() != 1 || writes.Load() != 1 {
			t.Fatalf("read after authority transfer: reads=%d writes=%d response=%+v err=%v", reads.Load(), writes.Load(), response, err)
		}
	})
}

func sdkLifetimeProvider(t *testing.T) (common.ConfigurationProvider, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return common.NewRawConfigurationProvider("ocid1.tenancy.oc1..lifetime", "ocid1.user.oc1..lifetime", "sa-saopaulo-1", "lifetime-fingerprint", string(privateKey), nil), key
}

func sdkLifetimeContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func sdkLifetimeServer(t *testing.T, key *rsa.PrivateKey, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.TLS == nil {
			t.Error("SDK provider request did not cross TLS")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := sdkLifetimeVerify(request, &key.PublicKey); err != nil {
			t.Errorf("SDK request signature: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handler(w, request)
	}))
	server.StartTLS()
	server.Config.SetKeepAlivesEnabled(false)
	t.Cleanup(server.Close)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	bundle := filepath.Join(t.TempDir(), "sdk-fixture-ca.pem")
	if err := os.WriteFile(bundle, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	// The SDK's test-only CA bundle preserves the factory's real dispatcher chain.
	t.Setenv("OCI_DEFAULT_CERTS_PATH", bundle)
	return server
}

func sdkLifetimeVerify(request *http.Request, key *rsa.PublicKey) error {
	authorization, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Signature ")
	if !ok {
		return errors.New("missing OCI Signature authorization")
	}
	fields := make(map[string]string)
	for field := range strings.SplitSeq(authorization, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok || len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
			return errors.New("malformed OCI Signature authorization")
		}
		fields[name] = value[1 : len(value)-1]
	}
	if fields["algorithm"] != "rsa-sha256" || fields["keyId"] != "ocid1.tenancy.oc1..lifetime/ocid1.user.oc1..lifetime/lifetime-fingerprint" {
		return errors.New("unexpected OCI signing identity or algorithm")
	}
	headers := strings.Fields(fields["headers"])
	for _, required := range []string{"(request-target)", "host", "date"} {
		if !slices.Contains(headers, required) {
			return fmt.Errorf("unsigned required header %s", required)
		}
	}
	parts := make([]string, 0, len(headers))
	for _, header := range headers {
		value := request.Header.Get(header)
		switch header {
		case "(request-target)":
			value = strings.ToLower(request.Method) + " " + request.URL.RequestURI()
		case "host":
			value = request.Host
		case "content-length":
			value = fmt.Sprint(request.ContentLength)
		}
		if value == "" {
			return fmt.Errorf("signed header %s is absent", header)
		}
		parts = append(parts, header+": "+value)
	}
	signature, err := base64.StdEncoding.DecodeString(fields["signature"])
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature)
}

func sdkLifetimeFactory(t *testing.T, provider common.ConfigurationProvider, options ociclient.Options) *ociclient.Factory {
	t.Helper()
	factory, err := ociclient.New(provider, options)
	if err != nil {
		t.Fatal(err)
	}
	return factory
}

func sdkLifetimeOperation(service, operation string) observability.OCIOperationView {
	for _, view := range ociclient.APIOperations() {
		if view.Service == service && view.Operation == operation {
			return view
		}
	}
	return observability.OCIOperationView{}
}

func sdkLifetimeJSON(t *testing.T, writer http.ResponseWriter, status int, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if err := json.MarshalWrite(writer, value); err != nil {
		t.Error(err)
	}
}

func sdkLifetimeDrop(t *testing.T, writer http.ResponseWriter) {
	t.Helper()
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		t.Error("TLS fixture must use HTTP/1 for dropped-response scenarios")
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	connection, _, err := hijacker.Hijack()
	if err != nil {
		t.Error(err)
		return
	}
	if err := connection.Close(); err != nil {
		t.Error(err)
	}
}

func sdkLifetimeReadHealthy(t *testing.T, client objectstorage.ObjectStorageClient) {
	t.Helper()
	response, err := client.GetObject(ociclient.ReadContext(sdkLifetimeContext(t)), objectstorage.GetObjectRequest{
		NamespaceName: new("ns"), BucketName: new("bucket"), ObjectName: new("healthy"),
	})
	if err != nil {
		t.Fatalf("healthy read after cancellation: %v", err)
	}
	body, readErr := io.ReadAll(response.Content)
	if err := errors.Join(readErr, response.Content.Close()); err != nil || string(body) != "healthy" {
		t.Fatalf("healthy response = %q, %v", body, err)
	}
}
