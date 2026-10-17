package rootcapacity

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

func TestConstructorRejectsCallerBuiltAuthorityWithoutConnecting(t *testing.T) {
	if _, err := New(context.Background(), nil, region.FoundationResolver{}, nil); err == nil {
		t.Fatal("accepted caller-built capacity authority without signed SDK discovery")
	}
}

func TestWireIdentityPreservesSignedBodyAndRejectsChangedReplay(t *testing.T) {
	body := []byte(`{"instanceId":"ocid1.instance.oc1..original"}`)
	request, err := http.NewRequest(http.MethodPost, "https://iaas.example/instancePools/original/instances", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("opc-retry-token", "original-retry")
	request.Header.Set("if-match", "original-etag")
	before := request.ContentLength
	expected, err := wireSHA256(request)
	if err != nil {
		t.Fatal(err)
	}
	request.URL.Path = "/20160918/instancePools/original/instances"
	actual, err := wireSHA256(request)
	if err != nil || actual != expected || request.ContentLength != before || request.GetBody == nil {
		t.Fatalf("SDK signing path changed original identity or body replay: %v", err)
	}
	for _, read := range []io.Reader{request.Body, func() io.Reader {
		body, err := request.GetBody()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = body.Close() })
		return body
	}()} {
		actual, err := io.ReadAll(read)
		if err != nil || !bytes.Equal(actual, body) {
			t.Fatalf("digest consumed or changed signed request bytes: %v", err)
		}
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.Header.Set("opc-retry-token", "replacement-retry")
	actual, err = wireSHA256(request)
	if err != nil || actual == expected {
		t.Fatalf("replacement token preserved original wire identity: %v", err)
	}
}

func TestObservationCannotWriteProtectedHistory(t *testing.T) {
	observation := rootoci.PoolChildObservation{Cell: "GRU"}
	a := attempt{observation: &observation}
	if err := a.save(context.Background()); err == nil {
		t.Fatal("observation gained protected capacity write admission")
	}
}

func TestProofContextRetainsOriginalCancellation(t *testing.T) {
	original, cancel := context.WithCancel(t.Context())
	a := attempt{}
	proof := a.proofContext(original)
	cancel()
	if proof.Err() != context.Canceled {
		t.Fatal("SDK request wrapper detached opaque authority from original cancellation")
	}
}
