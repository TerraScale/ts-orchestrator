package oci

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
)

type fakeDispatcher struct{}

func (fakeDispatcher) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

func TestFleetUsesSharedAPIRecorder(t *testing.T) {
	if Metrics != ociclient.Metrics {
		t.Fatal("fleet and Object Storage use different metric sets")
	}
	for _, service := range []string{"compute", "blockstorage", "network"} {
		request := httptest.NewRequest(http.MethodGet, "https://iaas.example/20160918/recorderCompatibility", nil)
		if _, err := ociclient.Instrument(fakeDispatcher{}, service).Do(request); err != nil {
			t.Fatal(err)
		}
		operations := APIView().Operations
		index := slices.IndexFunc(operations, func(operation observability.OCIOperationView) bool {
			return operation.Service == service && operation.Operation == "GET /recorderCompatibility"
		})
		if index < 0 || operations[index].Calls != 1 || operations[index].Errors != 0 {
			t.Fatalf("%s measurements changed: %+v", service, operations)
		}
	}
	if !slices.Equal(APIView().Operations, ociclient.APIOperations()) {
		t.Fatal("fleet view is missing shared OCI operation measurements")
	}
}
