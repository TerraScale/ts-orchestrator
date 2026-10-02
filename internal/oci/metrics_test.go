package oci

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func TestOperationTemplateRemovesIdentifiers(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]string{
		"GET https://iaas.sa-saopaulo-1.oraclecloud.com/20160918/instances/ocid1.instance.oc1.sa-saopaulo-1.abc?page=9": "GET /instances/{id}",
		"POST https://iaas.example/20160918/instances/ocid1.instance.oc1..x?action=SOFTSTOP":                            "POST /instances/{id}?action=SOFTSTOP",
		"POST https://iaas.example/20160918/instances/x?action=evil-value":                                              "POST /instances/x?action={action}",
		"GET https://iaas.example/20160918/volumeAttachments?compartmentId=ocid1.compartment.oc1..a":                    "GET /volumeAttachments",
		"GET https://iaas.example/20160918/instances/1234567890/vnics":                                                  "GET /instances/{id}/vnics",
	} {
		method, url, _ := strings.Cut(raw, " ")
		request := httptest.NewRequest(method, url, nil)
		if got := operationTemplate(request); got != want {
			t.Errorf("operationTemplate(%s) = %q, want %q", raw, got, want)
		}
	}
}

func TestInstrumentedDispatcherRecordsCallsErrorsAndThrottling(t *testing.T) {
	clock := time.Unix(0, 0)
	tick := func() time.Time {
		clock = clock.Add(250 * time.Millisecond)
		return clock
	}
	service := "test-" + strings.ReplaceAll(t.Name(), "/", "-")
	for _, next := range []fakeDispatcher{{status: 200}, {status: 429}, {err: errors.New("reset")}} {
		dispatcher := &instrumentedDispatcher{next: next, service: service, now: tick}
		request := httptest.NewRequest(http.MethodGet, "https://iaas.example/20160918/instances/ocid1.instance.oc1..a", nil)
		_, _ = dispatcher.Do(request)
	}
	var found bool
	for _, operation := range APIView().Operations {
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

func TestOperationCardinalityIsBounded(t *testing.T) {
	service := "bounded-" + strings.ReplaceAll(t.Name(), "/", "-")
	for index := range maxOperationsPerService + 10 {
		apiStats.record(service, "GET /r"+strings.Repeat("x", index%40)+string(rune('a'+index%26))+string(rune('a'+index/26)), 200, false, 0)
	}
	count := 0
	other := false
	for _, operation := range APIView().Operations {
		if operation.Service == service {
			count++
			other = other || operation.Operation == "other"
		}
	}
	if count != maxOperationsPerService+1 || !other {
		t.Fatalf("operations for service = %d (other=%v), want bound plus other", count, other)
	}
}
