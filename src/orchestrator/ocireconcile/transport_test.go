package ocireconcile

import (
	"io"
	"net/http"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func testOCITransport(t *testing.T, service provider.OCIService, roundTrip roundTripFunc) *provider.OCIHTTPTransport {
	t.Helper()
	host, ok := provider.OCIServiceHost(service, "sa-saopaulo-1")
	if !ok {
		t.Fatal("unknown test service")
	}
	config, err := provider.NewOCIServiceTransportConfig(service, "sa-saopaulo-1", "https://"+host)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := provider.NewOCIHTTPTransport(config, &http.Client{Transport: roundTrip}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return transport
}

func testHTTPResponse(status int, body string, headers http.Header) *http.Response {
	if headers == nil {
		headers = make(http.Header)
	}
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body))}
}
