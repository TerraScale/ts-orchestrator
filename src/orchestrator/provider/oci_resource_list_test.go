package provider

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

func TestOCIComputeAdapterListsEveryCanonicalInstancePage(t *testing.T) {
	calls := 0
	core := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != http.MethodGet || request.URL.Query().Get("compartmentId") != "ocid1.compartment.oc1.x" {
			t.Fatal("list lost signed request scope")
		}
		page := request.URL.Query().Get("page")
		if calls == 1 && page != "" || calls == 2 && page != "opaque+next/=" || calls > 2 {
			t.Fatalf("unexpected page request: %s", request.URL)
		}
		headers := http.Header{}
		if calls == 1 {
			headers.Set("opc-next-page", "opaque+next/=")
		}
		return testHTTPResponse(http.StatusOK, fmt.Sprintf(`[{"id":"ocid1.instance.oc1.x.%d"}]`, calls), headers), nil
	})
	values, err := (&OCIComputeNodeClient{OCI: core}).listNodeInstances(context.Background(), "ocid1.compartment.oc1.x")
	if err != nil || len(values) != 2 || calls != 2 {
		t.Fatalf("instance pages=%v calls=%d err=%v", values, calls, err)
	}
}
