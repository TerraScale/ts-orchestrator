package provider

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

type stageASignerFunc func(*http.Request) error

func (f stageASignerFunc) Sign(request *http.Request) error { return f(request) }

func noStageARetryDelay(context.Context, int) error { return nil }

func TestStageAStrictOCIDRegionalAndGlobalForms(t *testing.T) {
	tests := []struct {
		name  string
		value string
		kind  string
		valid bool
	}{
		{name: "regional", value: "ocid1.instance.oc1.sa-saopaulo-1.testinstance", kind: "instance", valid: true},
		{name: "global", value: "ocid1.compartment.oc1..testcompartment", kind: "compartment", valid: true},
		{name: "global tenancy", value: "ocid1.tenancy.oc1..testtenancy", kind: "tenancy", valid: true},
		{name: "regional missing region", value: "ocid1.instance.oc1..testinstance", kind: "instance"},
		{name: "global carries region", value: "ocid1.compartment.oc1.sa-saopaulo-1.testcompartment", kind: "compartment"},
		{name: "noncanonical region", value: "ocid1.instance.oc1.SA-SAOPAULO-1.testinstance", kind: "instance"},
		{name: "missing unique identifier", value: "ocid1.instance.oc1.sa-saopaulo-1", kind: "instance"},
		{name: "extra empty segment", value: "ocid1.instance.oc1.sa-saopaulo-1..testinstance", kind: "instance"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isOCID(test.value, test.kind); got != test.valid {
				t.Fatalf("isOCID(%q, %q) = %v, want %v", test.value, test.kind, got, test.valid)
			}
		})
	}
}

func TestStageAFencedMutationRetriesPreserveBodyAndHeaders(t *testing.T) {
	body := []byte(`{"displayName":"node-a"}`)
	requests := 0
	delays := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		requests++
		got, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, body) || request.Header.Get("Opc-Retry-Token") != "stable-token" || request.Header.Get("X-Stage-A") != "stable-header" || request.Header.Get("Authorization") != "signed-stable" {
			t.Fatalf("attempt %d body=%q headers=%v", requests, got, request.Header)
		}
		switch requests {
		case 1:
			return testHTTPResponse(http.StatusTooManyRequests, `{"code":"TooManyRequests"}`, nil), nil
		case 2:
			return testHTTPResponse(http.StatusInternalServerError, `{"code":"InternalError"}`, nil), nil
		default:
			return testHTTPResponse(http.StatusOK, `{}`, nil), nil
		}
	})
	transport.Signer = stageASignerFunc(func(request *http.Request) error {
		request.Header.Set("Authorization", "signed-stable")
		return nil
	})
	transport.retryDelay = func(context.Context, int) error {
		delays++
		return nil
	}
	resp, err := transport.DoWithHeaders(context.Background(), http.MethodPost, "/20160918/instances", bytes.NewReader(body), map[string]string{
		"opc-retry-token": "stable-token",
		"x-stage-a":       "stable-header",
	})
	if err != nil {
		t.Fatal(err)
	}
	drainClose(resp.Body)
	if requests != 3 || delays != 2 {
		t.Fatalf("requests=%d delays=%d", requests, delays)
	}
}

func TestStageAFencedMutationRetryExhaustionIsUnknown(t *testing.T) {
	requests := 0
	transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
		requests++
		return testHTTPResponse(http.StatusTooManyRequests, `{"code":"TooManyRequests"}`, nil), nil
	})
	transport.Config.MaxRetries = 1
	transport.retryDelay = noStageARetryDelay
	_, err := transport.DoWithHeaders(context.Background(), http.MethodPut, "/20160918/volumes/test", strings.NewReader("payload"), map[string]string{"If-Match": "etag-a"})
	var unknown *ProviderOutcomeUnknownError
	if !errors.As(err, &unknown) || requests != 2 {
		t.Fatalf("requests=%d err=%v", requests, err)
	}
}

func TestStageAUnfencedAndNotImplementedMutationsAreNotRetried(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		headers map[string]string
	}{
		{name: "unfenced", status: http.StatusTooManyRequests},
		{name: "not implemented", status: http.StatusNotImplemented, headers: map[string]string{"Opc-Retry-Token": "stable-token"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
				requests++
				return testHTTPResponse(test.status, `{"code":"NotImplemented"}`, nil), nil
			})
			transport.retryDelay = noStageARetryDelay
			resp, err := transport.DoWithHeaders(context.Background(), http.MethodPost, "/20160918/instances", strings.NewReader("payload"), test.headers)
			if err != nil {
				t.Fatal(err)
			}
			drainClose(resp.Body)
			if requests != 1 || resp.StatusCode != test.status {
				t.Fatalf("requests=%d status=%d", requests, resp.StatusCode)
			}
		})
	}
}

func TestStageAConflictRetryClassification(t *testing.T) {
	t.Run("retryable", func(t *testing.T) {
		requests := 0
		transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
			requests++
			if requests == 1 {
				return testHTTPResponse(http.StatusConflict, `{"code":"IncorrectState"}`, nil), nil
			}
			return testHTTPResponse(http.StatusOK, `{}`, nil), nil
		})
		transport.retryDelay = noStageARetryDelay
		resp, err := transport.DoWithHeaders(context.Background(), http.MethodDelete, "/20160918/volumes/test", nil, map[string]string{"If-Match": "etag-a"})
		if err != nil {
			t.Fatal(err)
		}
		drainClose(resp.Body)
		if requests != 2 {
			t.Fatalf("requests=%d", requests)
		}
	})

	t.Run("terminal", func(t *testing.T) {
		requests := 0
		transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
			requests++
			return testHTTPResponse(http.StatusConflict, `{"code":"NotAuthorizedOrNotFound"}`, nil), nil
		})
		transport.retryDelay = noStageARetryDelay
		resp, err := transport.DoWithHeaders(context.Background(), http.MethodDelete, "/20160918/volumes/test", nil, map[string]string{"If-Match": "etag-a"})
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := ReadBoundedBody(resp, 1<<10)
		if readErr != nil || string(body) != `{"code":"NotAuthorizedOrNotFound"}` || requests != 1 {
			t.Fatalf("requests=%d body=%q err=%v", requests, body, readErr)
		}
	})

	t.Run("malformed fails closed", func(t *testing.T) {
		requests := 0
		transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
			requests++
			return testHTTPResponse(http.StatusConflict, `not-json`, nil), nil
		})
		transport.retryDelay = noStageARetryDelay
		_, err := transport.DoWithHeaders(context.Background(), http.MethodDelete, "/20160918/volumes/test", nil, map[string]string{"If-Match": "etag-a"})
		var unknown *ProviderOutcomeUnknownError
		if !errors.As(err, &unknown) || requests != 1 {
			t.Fatalf("requests=%d err=%v", requests, err)
		}
	})
}

func TestStageAMutationTransportLossSendsOneRequest(t *testing.T) {
	requests := 0
	transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
		requests++
		return nil, io.ErrUnexpectedEOF
	})
	transport.retryDelay = noStageARetryDelay
	_, err := transport.DoWithHeaders(context.Background(), http.MethodPost, "/20160918/instances", strings.NewReader("payload"), map[string]string{"Opc-Retry-Token": "stable-token"})
	var unknown *ProviderOutcomeUnknownError
	if !errors.As(err, &unknown) || requests != 1 {
		t.Fatalf("requests=%d err=%v", requests, err)
	}
}

func TestStageASignedOCIRedirectIsNotFollowed(t *testing.T) {
	requests := 0
	signatures := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Header.Get("Authorization") != "signed" {
			t.Fatal("request was not signed")
		}
		return testHTTPResponse(http.StatusTemporaryRedirect, "", http.Header{"Location": {"https://attacker.invalid/collect"}}), nil
	})
	transport.Signer = stageASignerFunc(func(request *http.Request) error {
		signatures++
		request.Header.Set("Authorization", "signed")
		return nil
	})
	resp, err := transport.Do(context.Background(), http.MethodGet, "/20160918/instances", nil)
	if err != nil {
		t.Fatal(err)
	}
	drainClose(resp.Body)
	if resp.StatusCode != http.StatusTemporaryRedirect || requests != 1 || signatures != 1 {
		t.Fatalf("status=%d requests=%d signatures=%d", resp.StatusCode, requests, signatures)
	}
}

func TestStageAMutationFailureClassification(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		wantUnknown bool
	}{
		{name: "not implemented terminal", status: http.StatusNotImplemented, body: `{"code":"NotImplemented"}`},
		{name: "terminal conflict", status: http.StatusConflict, body: `{"code":"NotAuthorizedOrNotFound"}`},
		{name: "retryable conflict", status: http.StatusConflict, body: `{"code":"LockConflict"}`, wantUnknown: true},
		{name: "retryable service failure", status: http.StatusServiceUnavailable, body: `{"code":"InternalError"}`, wantUnknown: true},
		{name: "malformed code", status: http.StatusBadRequest, body: `{"code":""}`, wantUnknown: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			journal := testJournal(t)
			intent := testMutation("volume.create", ProviderMutationScope("volume", test.name), ProviderMutationFingerprint(test.name), 1)
			if _, err := journal.Prepare(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			if _, err := journal.MarkSubmitted(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			err := ociMutationFailure(context.Background(), journal, intent, testHTTPResponse(test.status, test.body, nil))
			var unknown *ProviderOutcomeUnknownError
			if errors.As(err, &unknown) != test.wantUnknown {
				t.Fatalf("err=%v wantUnknown=%v", err, test.wantUnknown)
			}
			if !test.wantUnknown {
				var rejected *InvalidOperationError
				if !errors.As(err, &rejected) {
					t.Fatalf("err=%v", err)
				}
			}
		})
	}
}

func TestStageAAttachmentReconciliationRejectsWrongScope(t *testing.T) {
	transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusOK, `[{"id":"ocid1.volumeattachment.oc1.sa-saopaulo-1.testattachment","compartmentId":"ocid1.compartment.oc1..testcompartment","instanceId":"ocid1.instance.oc1.sa-saopaulo-1.testinstance","volumeId":"ocid1.volume.oc1.sa-saopaulo-1.othervolume","lifecycleState":"ATTACHED","etag":"etag-a"}]`, nil), nil
	})
	adapter := &OCIVolumeAttachmentAdapter{Core: transport}
	request := VolumeAttachRequest{
		CompartmentID: "ocid1.compartment.oc1..testcompartment",
		InstanceID:    "ocid1.instance.oc1.sa-saopaulo-1.testinstance",
		VolumeID:      "ocid1.volume.oc1.sa-saopaulo-1.testvolume",
	}
	_, found, err := adapter.findAttachment(context.Background(), request)
	var invalid *InvalidDataError
	if !errors.As(err, &invalid) || found {
		t.Fatalf("found=%v err=%v", found, err)
	}
}

func TestStageARegistryBlobFollowsOneSafeRedirectWithoutCredentials(t *testing.T) {
	blob := "redirected-layer"
	digest := "sha256:" + objectSHA256([]byte(blob))
	const target = "https://namespace.objectstorage.sa-saopaulo-1.oci.customer-oci.com/n/ns/b/bucket/o/layer?token=secret"
	requests := 0
	transport := testOCITransport(t, OCIServiceRegistry, func(request *http.Request) (*http.Response, error) {
		requests++
		switch request.URL.Host {
		case "gru.ocir.io":
			if _, _, ok := request.BasicAuth(); !ok {
				t.Fatal("OCIR request is missing its credential")
			}
			return testHTTPResponse(http.StatusTemporaryRedirect, "", http.Header{"Location": {target}}), nil
		case "namespace.objectstorage.sa-saopaulo-1.oci.customer-oci.com":
			if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
				t.Fatalf("redirect leaked headers %v", request.Header)
			}
			return testHTTPResponse(http.StatusOK, blob, http.Header{"Content-Length": {"16"}}), nil
		default:
			t.Fatalf("unexpected host %q", request.URL.Host)
			return nil, nil
		}
	})
	signer, err := NewOCIRegistryTokenSigner("namespace/runner", "registry-token")
	if err != nil {
		t.Fatal(err)
	}
	transport.Signer = signer
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	targetURL, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(targetURL, []*http.Cookie{{Name: "session", Value: "must-not-leak"}})
	transport.Client.Jar = jar
	adapter, err := NewOCIRegistryAdapter(transport)
	if err != nil {
		t.Fatal(err)
	}
	reader, size, err := adapter.PullBlob(context.Background(), RegistryBlobRequest{Repository: "tenancy/member", Digest: digest})
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil || closeErr != nil || size != int64(len(blob)) || string(got) != blob || requests != 2 {
		t.Fatalf("size=%d body=%q requests=%d readErr=%v closeErr=%v", size, got, requests, err, closeErr)
	}
}

func TestStageARegistryBlobRejectsHostileRedirectsWithoutDisclosure(t *testing.T) {
	tests := []struct {
		name      string
		locations []string
	}{
		{name: "relative", locations: []string{"/object?token=secret"}},
		{name: "plain HTTP", locations: []string{"http://objectstorage.sa-saopaulo-1.oraclecloud.com/object?token=secret"}},
		{name: "wrong region", locations: []string{"https://objectstorage.us-sanjose-1.oraclecloud.com/object?token=secret"}},
		{name: "broad suffix", locations: []string{"https://objectstorage.sa-saopaulo-1.oraclecloud.com.attacker.test/object?token=secret"}},
		{name: "port", locations: []string{"https://objectstorage.sa-saopaulo-1.oraclecloud.com:443/object?token=secret"}},
		{name: "userinfo", locations: []string{"https://user@objectstorage.sa-saopaulo-1.oraclecloud.com/object?token=secret"}},
		{name: "fragment", locations: []string{"https://objectstorage.sa-saopaulo-1.oraclecloud.com/object?token=secret#fragment"}},
		{name: "invalid namespace", locations: []string{"https://bad.name.objectstorage.sa-saopaulo-1.oci.customer-oci.com/object?token=secret"}},
		{name: "duplicate", locations: []string{"https://objectstorage.sa-saopaulo-1.oraclecloud.com/one?token=secret", "https://objectstorage.sa-saopaulo-1.oraclecloud.com/two?token=secret"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			transport := testOCITransport(t, OCIServiceRegistry, func(*http.Request) (*http.Response, error) {
				requests++
				return testHTTPResponse(http.StatusTemporaryRedirect, "", http.Header{"Location": test.locations}), nil
			})
			adapter, err := NewOCIRegistryAdapter(transport)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = adapter.PullBlob(context.Background(), RegistryBlobRequest{Repository: "tenancy/member", Digest: "sha256:" + strings.Repeat("a", 64)})
			if err == nil || requests != 1 || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "token=") {
				t.Fatalf("requests=%d err=%v", requests, err)
			}
		})
	}
}

func TestStageARegistryBlobRejectsASecondRedirect(t *testing.T) {
	requests := 0
	transport := testOCITransport(t, OCIServiceRegistry, func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.Host == "gru.ocir.io" {
			return testHTTPResponse(http.StatusTemporaryRedirect, "", http.Header{"Location": {"https://objectstorage.sa-saopaulo-1.oraclecloud.com/first?token=secret"}}), nil
		}
		return testHTTPResponse(http.StatusTemporaryRedirect, "", http.Header{"Location": {"https://objectstorage.sa-saopaulo-1.oraclecloud.com/second?token=secret"}}), nil
	})
	adapter, err := NewOCIRegistryAdapter(transport)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = adapter.PullBlob(context.Background(), RegistryBlobRequest{Repository: "tenancy/member", Digest: "sha256:" + strings.Repeat("a", 64)})
	if err == nil || requests != 2 || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "token=") {
		t.Fatalf("requests=%d err=%v", requests, err)
	}
}

func TestStageARegistryStreamOverrunNeverReturnsOrHashesProbe(t *testing.T) {
	reader := newLengthDigestVerifyingReadCloser(io.NopCloser(strings.NewReader("abc")), objectSHA256([]byte("ab")), 2)
	defer reader.Close()
	buffer := make([]byte, 3)
	n, err := reader.Read(buffer)
	var invalid *InvalidDataError
	if n != 2 || string(buffer[:n]) != "ab" || !errors.As(err, &invalid) {
		t.Fatalf("n=%d body=%q err=%v", n, buffer[:n], err)
	}
}

func TestStageARegistryContentLengthBoundary(t *testing.T) {
	for _, test := range []struct {
		value string
		valid bool
	}{
		{value: "68719476736", valid: true},
		{value: "68719476737"},
		{value: "+1"},
		{value: " 1"},
		{value: "1, 1"},
	} {
		resp := &http.Response{Header: http.Header{"Content-Length": {test.value}}}
		_, valid := registryBlobContentLength(resp)
		if valid != test.valid {
			t.Fatalf("Content-Length %q valid=%v want=%v", test.value, valid, test.valid)
		}
	}
}

func TestStageARegistryOptionalDigestHeaderIsStrictWhenPresent(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, test := range []struct {
		name    string
		values  []string
		want    string
		present bool
		valid   bool
	}{
		{name: "omitted", valid: true},
		{name: "valid", values: []string{digest}, want: digest, present: true, valid: true},
		{name: "malformed", values: []string{"sha256:not-a-digest"}, present: true},
		{name: "uppercase", values: []string{"sha256:" + strings.Repeat("A", 64)}, present: true},
		{name: "duplicate", values: []string{digest, digest}, present: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{"Docker-Content-Digest": test.values}}
			got, present, valid := registryBlobDigestHeader(resp)
			if got != test.want || present != test.present || valid != test.valid {
				t.Fatalf("digest=%q present=%v valid=%v", got, present, valid)
			}
		})
	}
}
