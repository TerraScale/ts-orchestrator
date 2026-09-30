package bootstrapstart

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type imdsRoundTrip func(*http.Request) (*http.Response, error)

func (fn imdsRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestDescriptorStrictAndFixedIMDS(t *testing.T) {
	for _, body := range []string{
		`{"schemaVersion":1,"slot":"controller-a","bucket":"attacker"}`,
		`{"schemaVersion":1,"slot":"controller-a","slot":"controller-b"}`,
		`{"schemaVersion":1,"slot":"../escape"}`,
		`{"schemaVersion":1,"slot":"a/../escape"}`,
		`{"schemaVersion":2,"slot":"controller-a"}`,
	} {
		if _, err := ParseDescriptor([]byte(body)); !errors.Is(err, ErrInvalidDescriptor) {
			t.Fatalf("accepted invalid descriptor %s: %v", body, err)
		}
	}
	client := IMDSClient{client: &http.Client{Transport: imdsRoundTrip(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != descriptorEndpoint || request.Method != http.MethodGet ||
			request.Header.Get("Authorization") != "Bearer Oracle" ||
			request.Header.Get("Forwarded") != "" || request.Header.Get("X-Forwarded-For") != "" ||
			request.Header.Get("X-Forwarded-Host") != "" {
			t.Fatalf("unexpected fixed IMDS request: %+v", request)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"schemaVersion":1,"slot":"controller-a"}`)), Header: make(http.Header)}, nil
	})}}
	descriptor, err := client.FetchDescriptor(t.Context())
	if err != nil || descriptor.Slot != "controller-a" {
		t.Fatalf("fixed IMDS descriptor = %+v, %v", descriptor, err)
	}
}

func TestIMDSRejectsRedirectOversizeAndForeignDial(t *testing.T) {
	client := NewIMDSClient()
	transport := client.client.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("production IMDS transport inherits a proxy")
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "example.com:80"); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("foreign IMDS dial = %v", err)
	}
	redirect := IMDSClient{client: &http.Client{
		CheckRedirect: client.client.CheckRedirect,
		Transport: imdsRoundTrip(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"http://example.com/"}}, Body: io.NopCloser(strings.NewReader("redirect"))}, nil
		}),
	}}
	if _, err := redirect.FetchDescriptor(t.Context()); err == nil {
		t.Fatal("followed IMDS redirect")
	}
	oversize := IMDSClient{client: &http.Client{Transport: imdsRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxDescriptorBytes+1))), Header: make(http.Header)}, nil
	})}}
	if _, err := oversize.FetchDescriptor(t.Context()); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("oversize IMDS body = %v", err)
	}
}

func TestFetchLaunchMaterialReportsNonControllerInstance(t *testing.T) {
	client := IMDSClient{client: &http.Client{Transport: imdsRoundTrip(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != identityMetadataEndpoint {
			t.Fatalf("launch material read %s before the identity key", request.URL)
		}
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}}
	if _, err := client.FetchLaunchMaterial(t.Context()); !errors.Is(err, ErrNotController) {
		t.Fatalf("instance without controller metadata = %v", err)
	}
	missing := IMDSClient{client: &http.Client{Transport: imdsRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}}
	if _, err := missing.FetchDescriptor(t.Context()); !errors.Is(err, ErrInvalidDescriptor) || errors.Is(err, ErrNotController) {
		t.Fatalf("absent descriptor = %v", err)
	}
}

func TestIMDSInstanceIDIsOnlyALocalLocator(t *testing.T) {
	client := IMDSClient{client: &http.Client{Transport: imdsRoundTrip(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != identityEndpoint || request.Header.Get("Authorization") != "Bearer Oracle" {
			t.Fatalf("unexpected identity endpoint: %s", request.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ocid1.instance.oc1..abc\n")), Header: make(http.Header)}, nil
	})}}
	if id, err := client.FetchInstanceID(t.Context()); err != nil || id != "ocid1.instance.oc1..abc" {
		t.Fatalf("fixed IMDS identity = %q, %v", id, err)
	}
}
