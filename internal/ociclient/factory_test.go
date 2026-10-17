package ociclient

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type fakeDispatcher struct {
	status int
	err    error
}

func (dispatcher fakeDispatcher) Do(*http.Request) (*http.Response, error) {
	if dispatcher.err != nil {
		return nil, dispatcher.err
	}
	return &http.Response{StatusCode: dispatcher.status, Body: http.NoBody}, nil
}

func TestOperationCardinalityIsBounded(t *testing.T) {
	service := "bounded-" + strings.ReplaceAll(t.Name(), "/", "-")
	for index := range maxOperationsPerService + 10 {
		apiStats.record(service, "GET /r"+strings.Repeat("x", index%40)+string(rune('a'+index%26))+string(rune('a'+index/26)), 200, false, 0)
	}
	count := 0
	other := false
	for _, operation := range APIOperations() {
		if operation.Service == service {
			count++
			other = other || operation.Operation == "other"
		}
	}
	if count != maxOperationsPerService+1 || !other {
		t.Fatalf("operations for service = %d (other=%v), want bound plus other", count, other)
	}
}

func TestFactoryObjectStorageRecordsHTTPAttempts(t *testing.T) {
	provider := testProvider(t)
	const operation = "HEAD /n/{id}/b/{id}/o/{id}"
	for _, test := range []struct {
		name      string
		statuses  []int
		errors    uint64
		throttled uint64
	}{
		{name: "success", statuses: []int{http.StatusOK}},
		{name: "throttled", statuses: []int{http.StatusTooManyRequests, http.StatusOK}, errors: 1, throttled: 1},
		{name: "transport error", statuses: []int{0, http.StatusOK}, errors: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := recordedOperation(string(ServiceObjectStorage), operation)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				index := int(calls.Add(1)) - 1
				if index >= len(test.statuses) {
					t.Errorf("unexpected HTTP attempt %d", index+1)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				status := test.statuses[index]
				if status == 0 {
					connection, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = connection.Close()
					return
				}
				w.Header().Set("ETag", "object-etag")
				w.WriteHeader(status)
			}))
			defer server.Close()
			factory, err := New(provider, Options{Region: "sa-saopaulo-1",
				Retry: RetryOptions{MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}})
			if err != nil {
				t.Fatal(err)
			}
			client, err := factory.ObjectStorage()
			if err != nil {
				t.Fatal(err)
			}
			PinHost(&client.BaseClient, server.URL)
			response, err := client.HeadObject(t.Context(), objectstorage.HeadObjectRequest{
				NamespaceName: new("secretNamespace"), BucketName: new("secretBucket"), ObjectName: new("secret/object/name"),
			})
			if err != nil {
				t.Fatal(err)
			}
			if response.ETag == nil || *response.ETag != "object-etag" || calls.Load() != int32(len(test.statuses)) {
				t.Fatalf("Object Storage result changed: response=%+v calls=%d", response, calls.Load())
			}
			after := recordedOperation(string(ServiceObjectStorage), operation)
			if after.Calls-before.Calls != uint64(len(test.statuses)) || after.Errors-before.Errors != test.errors ||
				after.Throttled-before.Throttled != test.throttled || after.LastStatus != http.StatusOK ||
				after.TotalSeconds <= before.TotalSeconds || after.MaxSeconds <= 0 {
				t.Fatalf("Object Storage measurements: before=%+v after=%+v", before, after)
			}
			var output bytes.Buffer
			Metrics.WritePrometheus(&output)
			for _, secret := range []string{"secretNamespace", "secretBucket", "secret/object/name"} {
				if strings.Contains(output.String(), secret) {
					t.Fatalf("Object Storage identifier leaked into metrics: %s", secret)
				}
			}
		})
	}
}

func recordedOperation(service, operation string) observability.OCIOperationView {
	operations := APIOperations()
	index := slices.IndexFunc(operations, func(view observability.OCIOperationView) bool {
		return view.Service == service && view.Operation == operation
	})
	if index >= 0 {
		return operations[index]
	}
	return observability.OCIOperationView{}
}

func TestSignedSDKDispatcherRecordsCallsErrorsAndThrottling(t *testing.T) {
	const instanceID = "ocid1.instance.oc1..a"
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		index := calls.Add(1)
		_, signature, present := strings.Cut(request.Header.Get("Authorization"), `signature="`)
		signature, _, closed := strings.Cut(signature, `"`)
		if request.Method != http.MethodGet || request.URL.Path != "/20160918/instances/"+instanceID || !present || !closed || signature == "" {
			t.Error("expected signed SDK GET for the exact instance")
		}
		w.Header().Set("Content-Type", "application/json")
		switch index {
		case 1:
			if err := json.MarshalWrite(w, map[string]string{"id": instanceID, "lifecycleState": "RUNNING"}); err != nil {
				t.Error(err)
			}
		case 2:
			w.WriteHeader(http.StatusTooManyRequests)
			if err := json.MarshalWrite(w, map[string]string{"code": "TooManyRequests", "message": "slow down"}); err != nil {
				t.Error(err)
			}
		case 3:
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
		default:
			t.Errorf("unexpected HTTP attempt %d", index)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	server.Config.SetKeepAlivesEnabled(false)
	factory, err := New(testProvider(t), Options{Region: "sa-saopaulo-1", Retry: RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	compute, err := factory.Compute()
	if err != nil {
		t.Fatal(err)
	}
	PinHost(&compute.BaseClient, server.URL)
	clock := time.Unix(0, 0)
	tick := func() time.Time {
		clock = clock.Add(250 * time.Millisecond)
		return clock
	}
	service := "test-" + strings.ReplaceAll(t.Name(), "/", "-")
	dispatcher := Instrument(compute.HTTPClient, service).(*instrumentedDispatcher)
	// Preserve exact duration assertions around the real SDK HTTP dispatcher.
	dispatcher.now = tick
	compute.HTTPClient = dispatcher
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for index := range 3 {
		response, err := compute.GetInstance(RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(instanceID)})
		switch index {
		case 0:
			if err != nil || response.Id == nil || *response.Id != instanceID || response.LifecycleState != core.InstanceLifecycleStateRunning {
				t.Fatalf("successful SDK response = %+v, %v", response, err)
			}
		case 1:
			failure, ok := common.IsServiceError(err)
			if !ok || failure.GetHTTPStatusCode() != http.StatusTooManyRequests || failure.GetCode() != "TooManyRequests" {
				t.Fatalf("throttled SDK response = %v", err)
			}
		case 2:
			if err == nil {
				t.Fatal("SDK accepted a connection closed before its response")
			}
		}
	}
	if calls.Load() != 3 {
		t.Fatalf("HTTP attempts = %d, want 3", calls.Load())
	}
	var found bool
	for _, operation := range APIOperations() {
		if operation.Service != service {
			continue
		}
		found = true
		if operation.Operation != "GET /instances/{id}" || operation.Calls != 3 || operation.Errors != 2 ||
			operation.Throttled != 1 || operation.MaxSeconds != 0.25 || operation.TotalSeconds != 0.75 {
			t.Fatalf("operation view = %+v", operation)
		}
	}
	if !found {
		t.Fatal("instrumented calls are missing from the API view")
	}
	var output bytes.Buffer
	Metrics.WritePrometheus(&output)
	text := output.String()
	for _, want := range []string{
		`ts_orch_oci_requests_total{service="` + service + `",operation="GET /instances/{id}",code="429"} 1`,
		`ts_orch_oci_requests_total{service="` + service + `",operation="GET /instances/{id}",code="transport_error"} 1`,
		`ts_orch_oci_throttled_total{service="` + service + `",operation="GET /instances/{id}"} 1`,
		`ts_orch_oci_request_duration_seconds_count{service="` + service + `",operation="GET /instances/{id}"} 3`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
	if strings.Contains(text, "ocid1.") {
		t.Fatal("an OCID leaked into a metric label")
	}
}
