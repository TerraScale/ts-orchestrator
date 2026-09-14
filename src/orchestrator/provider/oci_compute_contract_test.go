package provider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOCIHTTPTransportRetriesFencedMutationResponsesExactly(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		conflicts  int
		maxRetries int
	}{
		{name: "one incorrect-state conflict", status: http.StatusConflict, body: `{"code":"IncorrectState"}`, conflicts: 1, maxRetries: 2},
		{name: "two lock conflicts", status: http.StatusConflict, body: `{"code":"LockConflict"}`, conflicts: 2, maxRetries: 2},
		{name: "throttled", status: http.StatusTooManyRequests, body: `{"code":"TooManyRequests"}`, conflicts: 1, maxRetries: 2},
		{name: "service unavailable", status: http.StatusServiceUnavailable, body: `{"code":"ServiceUnavailable"}`, conflicts: 1, maxRetries: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var bodies [][]byte
			var requestHeaders []http.Header
			calls := 0
			transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
				calls++
				body, err := io.ReadAll(request.Body)
				if err != nil {
					return nil, err
				}
				bodies = append(bodies, body)
				requestHeaders = append(requestHeaders, request.Header.Clone())
				if calls <= test.conflicts {
					return testHTTPResponse(test.status, test.body, nil), nil
				}
				return testHTTPResponse(http.StatusOK, `{}`, nil), nil
			})
			transport.Config.MaxRetries = test.maxRetries
			transport.retryDelay = func(context.Context, int) error { return nil }
			callerHeaders := map[string]string{"opc-retry-token": "retry-exact", "If-Match": "etag-exact"}
			response, err := transport.DoWithHeaders(context.Background(), http.MethodPost, "/20160918/instances", strings.NewReader(`{"shape":"VM.Standard.A1.Flex"}`), callerHeaders)
			if err != nil || response.StatusCode != http.StatusOK || calls != test.conflicts+1 {
				t.Fatalf("fenced retry response=%v calls=%d err=%v", response, calls, err)
			}
			_, _ = ReadBoundedBody(response, transport.Config.MaxBodyBytes)
			for index := 1; index < len(bodies); index++ {
				if !bytes.Equal(bodies[0], bodies[index]) || !reflect.DeepEqual(requestHeaders[0], requestHeaders[index]) {
					t.Fatalf("retry %d changed body or headers: bodies=%q headers=%v", index, bodies, requestHeaders)
				}
			}
			if requestHeaders[0].Get("opc-retry-token") != "retry-exact" || requestHeaders[0].Get("If-Match") != "etag-exact" {
				t.Fatalf("caller fences were not preserved: %v", requestHeaders[0])
			}
		})
	}
}

func TestOCIHTTPTransportRetryExhaustionIsUnknown(t *testing.T) {
	for _, response := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "conflict", status: http.StatusConflict, body: `{"code":"IncorrectState"}`},
		{name: "throttled", status: http.StatusTooManyRequests, body: `{"code":"TooManyRequests"}`},
		{name: "server error", status: http.StatusBadGateway, body: `{"code":"BadGateway"}`},
	} {
		t.Run(response.name, func(t *testing.T) {
			calls := 0
			transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
				calls++
				return testHTTPResponse(response.status, response.body, nil), nil
			})
			transport.Config.MaxRetries = 2
			transport.retryDelay = func(context.Context, int) error { return nil }
			got, err := transport.DoWithHeaders(context.Background(), http.MethodPost, "/20160918/instances", strings.NewReader(`{"shape":"VM.Standard.A1.Flex"}`), map[string]string{"opc-retry-token": "retry-exhausted"})
			if got != nil || !errors.As(err, new(*ProviderOutcomeUnknownError)) || calls != 3 {
				t.Fatalf("retry exhaustion response=%v calls=%d err=%v", got, calls, err)
			}
		})
	}
}

func TestOCIHTTPTransportDoesNotRetryUnfencedOrNotImplementedMutation(t *testing.T) {
	for _, response := range []struct {
		name    string
		status  int
		body    string
		headers map[string]string
	}{
		{name: "unfenced conflict", status: http.StatusConflict, body: `{"code":"IncorrectState"}`},
		{name: "unfenced throttling", status: http.StatusTooManyRequests, body: `{"code":"TooManyRequests"}`},
		{name: "unfenced server error", status: http.StatusBadGateway, body: `{"code":"BadGateway"}`},
		{name: "fenced not implemented", status: http.StatusNotImplemented, body: `{"code":"NotImplemented"}`, headers: map[string]string{"opc-retry-token": "retry-501"}},
	} {
		t.Run(response.name, func(t *testing.T) {
			calls := 0
			transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
				calls++
				return testHTTPResponse(response.status, response.body, nil), nil
			})
			transport.Config.MaxRetries = 5
			transport.retryDelay = func(context.Context, int) error { return nil }
			got, err := transport.DoWithHeaders(context.Background(), http.MethodPost, "/20160918/instances", strings.NewReader(`{"shape":"VM.Standard.A1.Flex"}`), response.headers)
			if err != nil || got == nil || got.StatusCode != response.status || calls != 1 {
				t.Fatalf("unreplayable response=%v calls=%d err=%v", got, calls, err)
			}
			_, _ = ReadBoundedBody(got, transport.Config.MaxBodyBytes)
		})
	}
}

func TestOCIHTTPTransportReturnsTerminalConflictAfterOneCall(t *testing.T) {
	calls := 0
	transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
		calls++
		return testHTTPResponse(http.StatusConflict, `{"code":"QuotaExceeded"}`, nil), nil
	})
	transport.Config.MaxRetries = 5
	transport.retryDelay = func(context.Context, int) error { return nil }
	response, err := transport.DoWithHeaders(context.Background(), http.MethodPost, "/20160918/volumes", strings.NewReader(`{"sizeInGBs":50}`), map[string]string{"opc-retry-token": "retry-terminal"})
	if err != nil || response == nil || response.StatusCode != http.StatusConflict || calls != 1 {
		t.Fatalf("terminal conflict response=%v calls=%d err=%v", response, calls, err)
	}
	journal := testJournal(t)
	intent := testMutation("volume.create", "volume/terminal-transport", ProviderMutationFingerprint("terminal-transport"), 7)
	if _, err := journal.Prepare(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.MarkSubmitted(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if err := ociMutationFailure(context.Background(), journal, intent, response); err == nil || errors.As(err, new(*ProviderOutcomeUnknownError)) {
		t.Fatalf("terminal conflict classification = %v", err)
	}
	record, err := journal.Prepare(context.Background(), intent)
	if err != nil || record.State != MutationFailed {
		t.Fatalf("terminal conflict journal = %+v, %v", record, err)
	}
}

func TestOCIHTTPTransportMalformedConflictStaysUnknown(t *testing.T) {
	for _, body := range []string{`{`, `{"code":"LockConflict\n"}`} {
		t.Run(body, func(t *testing.T) {
			calls := 0
			transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
				calls++
				return testHTTPResponse(http.StatusConflict, body, nil), nil
			})
			transport.Config.MaxRetries = 2
			transport.retryDelay = func(context.Context, int) error { return nil }
			response, err := transport.DoWithHeaders(context.Background(), http.MethodPost, "/20160918/volumes", strings.NewReader(`{"sizeInGBs":50}`), map[string]string{"opc-retry-token": "retry-malformed"})
			if response != nil || !errors.As(err, new(*ProviderOutcomeUnknownError)) || calls != 1 {
				t.Fatalf("malformed conflict response=%v calls=%d err=%v", response, calls, err)
			}
			journal := testJournal(t)
			intent := testMutation("volume.create", "volume/malformed-conflict", ProviderMutationFingerprint(body), 9)
			if _, err := journal.Prepare(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			if _, err := journal.MarkSubmitted(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			if err := finishUnknown(context.Background(), journal, intent); !errors.As(err, new(*ProviderOutcomeUnknownError)) {
				t.Fatalf("malformed conflict did not stay unknown: %v", err)
			}
			record, err := journal.Prepare(context.Background(), intent)
			if err != nil || record.State != MutationUnknown {
				t.Fatalf("malformed conflict journal = %+v, %v", record, err)
			}
		})
	}
}

func TestOCIHTTPTransportNeverRepostsMutationTransportError(t *testing.T) {
	calls := 0
	transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
		calls++
		return nil, io.ErrUnexpectedEOF
	})
	transport.Config.MaxRetries = 5
	transport.retryDelay = func(context.Context, int) error { return nil }
	response, err := transport.DoWithHeaders(context.Background(), http.MethodPost, "/20160918/instances", strings.NewReader(`{"shape":"VM.Standard.A1.Flex"}`), map[string]string{"opc-retry-token": "retry-transport-loss"})
	if response != nil || !errors.As(err, new(*ProviderOutcomeUnknownError)) || calls != 1 {
		t.Fatalf("transport loss response=%v calls=%d err=%v", response, calls, err)
	}
}

func TestOCIHTTPTransportDoesNotFollowCrossAuthorityRedirect(t *testing.T) {
	targetCalls := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalls++
	}))
	defer target.Close()

	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			targetCalls = 0
			sourceCalls := 0
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Host == "iaas.sa-saopaulo-1.oraclecloud.com" {
					sourceCalls++
					return testHTTPResponse(status, "", http.Header{"Location": {target.URL + "/capture"}}), nil
				}
				return http.DefaultTransport.RoundTrip(request)
			})}
			config, err := NewOCITransportConfig("sa-saopaulo-1", "https://iaas.sa-saopaulo-1.oraclecloud.com")
			if err != nil {
				t.Fatal(err)
			}
			transport, err := NewOCIHTTPTransport(config, client, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := transport.DoWithHeaders(context.Background(), http.MethodPost, "/20160918/instances", strings.NewReader(`{"shape":"VM.Standard.A1.Flex"}`), map[string]string{"opc-retry-token": "retry-redirect"})
			if err != nil || response == nil || response.StatusCode != status || sourceCalls != 1 || targetCalls != 0 {
				t.Fatalf("redirect response=%v sourceCalls=%d targetCalls=%d err=%v", response, sourceCalls, targetCalls, err)
			}
			_, _ = ReadBoundedBody(response, transport.Config.MaxBodyBytes)
		})
	}
}

func TestInstancePrincipalSignerBindsMutationBody(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewInstancePrincipalSigner("instance-principal/key", key)
	if err != nil {
		t.Fatal(err)
	}
	signer.Now = func() time.Time { return time.Unix(1_777_000_000, 0) }
	request, err := http.NewRequest(http.MethodPut, "https://objectstorage.sa-saopaulo-1.oraclecloud.com/n/ns/b/bucket/o/object", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	if err := signer.Sign(request); err != nil {
		t.Fatal(err)
	}
	authorization := request.Header.Get("Authorization")
	for _, required := range []string{"content-length", "content-type", "x-content-sha256"} {
		if !strings.Contains(authorization, required) {
			t.Fatalf("body signature omitted %s: %s", required, authorization)
		}
	}
	if request.Header.Get("Content-Length") != "7" || request.Header.Get("x-content-sha256") == "" {
		t.Fatalf("body signing headers = %v", request.Header)
	}
}

func testOCITransport(t *testing.T, service OCIService, roundTrip roundTripFunc) *OCIHTTPTransport {
	t.Helper()
	host, ok := ociServiceHost(service, "sa-saopaulo-1")
	if !ok {
		t.Fatal("unknown test service")
	}
	config, err := NewOCIServiceTransportConfig(service, "sa-saopaulo-1", "https://"+host)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewOCIHTTPTransport(config, &http.Client{Transport: roundTrip}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return transport
}

func testMutation(action, scope, fingerprint string, epoch uint64) ProviderMutationIntent {
	suffix := ProviderMutationFingerprint(scope)[:16]
	return ProviderMutationIntent{
		OperationID:    ProviderOperationId{Value: "operation-" + suffix},
		Scope:          scope,
		Action:         action,
		Epoch:          ProviderEpoch{Value: epoch},
		IdempotencyKey: ProviderIdempotencyKey{Value: "retry-" + suffix},
		Fingerprint:    fingerprint,
	}
}

func testJournal(t *testing.T) *CASProviderMutationJournal {
	t.Helper()
	journal, err := NewCASProviderMutationJournal(newTestOwnershipCAS())
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func testHTTPResponse(status int, body string, headers http.Header) *http.Response {
	if headers == nil {
		headers = make(http.Header)
	}
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body))}
}

func TestProviderMutationJournalFencesUnknownOutcomes(t *testing.T) {
	journal := testJournal(t)
	first := testMutation("compute.launch", "node-a", ProviderMutationFingerprint("first"), 4)
	if _, err := journal.Prepare(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.MarkSubmitted(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.MarkUnknown(context.Background(), first, ProviderMutationResult{}); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.MarkFailed(context.Background(), first, "timeout"); err == nil {
		t.Fatal("unknown mutation changed to failed")
	}
	if _, err := journal.MarkSubmitted(context.Background(), first); err == nil {
		t.Fatal("unknown mutation changed back to submitted")
	}

	resumed := first
	resumed.Epoch.Value++
	record, err := journal.Prepare(context.Background(), resumed)
	if err != nil || record.State != MutationUnknown || record.Intent.Epoch != resumed.Epoch {
		t.Fatalf("resume = %+v, %v", record, err)
	}
	replacement := testMutation("compute.launch", "node-a", ProviderMutationFingerprint("replacement"), 6)
	if _, err := journal.Prepare(context.Background(), replacement); !errors.As(err, new(*ProviderOutcomeUnknownError)) {
		t.Fatalf("unresolved intent replacement error = %v", err)
	}
	stale := first
	stale.Epoch.Value--
	if _, err := journal.Prepare(context.Background(), stale); err == nil {
		t.Fatal("stale controller epoch crossed the mutation fence")
	}
}

func TestOCIRetryableConflictCodesKeepMutationOutcomeUnknown(t *testing.T) {
	for _, code := range []string{"IncorrectState", "LockConflict"} {
		t.Run(code, func(t *testing.T) {
			journal := testJournal(t)
			intent := testMutation("volume.create", "volume/transient-conflict", ProviderMutationFingerprint(code), 3)
			if _, err := journal.Prepare(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			if _, err := journal.MarkSubmitted(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			err := ociMutationFailure(context.Background(), journal, intent, testHTTPResponse(http.StatusConflict, `{"code":"`+code+`"}`, nil))
			if !errors.As(err, new(*ProviderOutcomeUnknownError)) {
				t.Fatalf("retryable conflict %s became terminal: %v", code, err)
			}
			record, err := journal.Prepare(context.Background(), intent)
			if err != nil || record.State != MutationUnknown {
				t.Fatalf("retryable conflict record = %+v, %v", record, err)
			}
		})
	}

	journal := testJournal(t)
	intent := testMutation("volume.create", "volume/terminal-conflict", ProviderMutationFingerprint("QuotaExceeded"), 4)
	if _, err := journal.Prepare(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.MarkSubmitted(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if err := ociMutationFailure(context.Background(), journal, intent, testHTTPResponse(http.StatusConflict, `{"code":"QuotaExceeded"}`, nil)); err == nil || errors.As(err, new(*ProviderOutcomeUnknownError)) {
		t.Fatalf("terminal conflict was treated as retryable: %v", err)
	}
	record, err := journal.Prepare(context.Background(), intent)
	if err != nil || record.State != MutationFailed {
		t.Fatalf("terminal conflict record = %+v, %v", record, err)
	}
}

func TestOCIAdapterTreatsNotImplementedAsTerminalFailure(t *testing.T) {
	posts := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/20160918/volumes" {
			t.Fatalf("unexpected OCI request %s %s", request.Method, request.URL.String())
		}
		posts++
		return testHTTPResponse(http.StatusNotImplemented, `{"code":"NotImplemented"}`, nil), nil
	})
	journal := testJournal(t)
	adapter, err := NewOCIBlockStorageAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	request := VolumeCreateRequest{
		CompartmentID: "ocid1.compartment.oc1..x", AvailabilityDomain: "AD-1", DisplayName: "not-implemented",
		SizeGiB: 50, VPUsPerGiB: 10,
	}
	request.Mutation = testMutation("volume.create", VolumeCreateMutationScope(request), VolumeCreateMutationFingerprint(request), 5)
	if _, err := adapter.CreateVolume(context.Background(), request); err == nil || errors.As(err, new(*ProviderOutcomeUnknownError)) {
		t.Fatalf("501 adapter classification = %v", err)
	}
	if posts != 1 {
		t.Fatalf("501 adapter made %d requests, want 1", posts)
	}
	record, err := journal.Prepare(context.Background(), request.Mutation)
	if err != nil || record.State != MutationFailed {
		t.Fatalf("501 mutation journal = %+v, %v", record, err)
	}
}

func TestProviderMutationJournalAllowsTerminalReplacementInSameEpoch(t *testing.T) {
	journal := testJournal(t)
	first := testMutation("compute.launch", "node-a", ProviderMutationFingerprint("first"), 9)
	if _, err := journal.Prepare(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.MarkSubmitted(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.MarkFailed(context.Background(), first, "provider-rejected"); err != nil {
		t.Fatal(err)
	}
	replacement := testMutation("compute.terminate", first.Scope, ProviderMutationFingerprint("replacement"), first.Epoch.Value)
	replacement.OperationID.Value = "operation-replacement"
	replacement.IdempotencyKey.Value = "retry-replacement"
	record, err := journal.Prepare(context.Background(), replacement)
	if err != nil || record.State != MutationPrepared || record.Intent.OperationID != replacement.OperationID {
		t.Fatalf("terminal replacement = %+v, %v", record, err)
	}
}

func TestProviderMutationJournalRecordsObservedAbsentDelete(t *testing.T) {
	journal := testJournal(t)
	intent := testMutation("compute.terminate", "instance-a", ProviderMutationFingerprint("terminate"), 3)
	if _, err := journal.Prepare(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	result := ProviderMutationResult{ResourceID: "ocid1.instance.oc1.sa-saopaulo-1.absent", ETag: "instance-etag"}
	record, err := journal.MarkSucceeded(context.Background(), intent, result)
	if err != nil || record.State != MutationSucceeded || record.Result != result {
		t.Fatalf("observed-absent transition = %+v, %v", record, err)
	}
	if _, err := journal.MarkFailed(context.Background(), intent, "provider-rejected"); err == nil {
		t.Fatal("observed-absent success changed terminal outcome")
	}

	create := testMutation("compute.launch", "instance-b", ProviderMutationFingerprint("launch"), 3)
	if _, err := journal.Prepare(context.Background(), create); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.MarkSucceeded(context.Background(), create, result); err == nil {
		t.Fatal("create mutation skipped the required submitted state")
	}
}

func TestOCIComputeTerminateConvergesWhenInstanceIsAlreadyAbsent(t *testing.T) {
	instanceID := "ocid1.instance.oc1.sa-saopaulo-1.absent"
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet {
			t.Fatalf("already-absent termination sent %s", request.Method)
		}
		if request.URL.Path == "/20160918/instances" {
			return testHTTPResponse(http.StatusOK, `[]`, nil), nil
		}
		return testHTTPResponse(http.StatusNotFound, "", nil), nil
	})
	adapter, err := NewOCIComputeAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	adapter.Ownership = testOwnership(t, instanceID)
	request := ComputeTerminateRequest{InstanceID: instanceID, IfMatch: "instance-etag"}
	request.Mutation = testMutation("compute.terminate", ComputeTerminateMutationScope(request), ComputeTerminateMutationFingerprint(request), 4)
	if err := adapter.TerminateInstance(context.Background(), request); err != nil {
		t.Fatalf("already-absent termination failed: %v", err)
	}
	if err := adapter.TerminateInstance(context.Background(), request); err != nil {
		t.Fatalf("terminal termination resume failed: %v", err)
	}
}

type pausingMutationJournal struct {
	ProviderMutationJournal
	pauseAt int
	paused  bool
}

func (j *pausingMutationJournal) MarkSubmitted(ctx context.Context, intent ProviderMutationIntent) (ProviderMutationRecord, error) {
	record, err := j.ProviderMutationJournal.Prepare(ctx, intent)
	if err != nil {
		return ProviderMutationRecord{}, err
	}
	if !j.paused && record.State == MutationPrepared && record.NextAttempt == j.pauseAt {
		j.paused = true
		return record, errors.New("simulated controller restart")
	}
	return j.ProviderMutationJournal.MarkSubmitted(ctx, intent)
}

func TestOCIComputeAdapterPersistsCapacityFallbackCursor(t *testing.T) {
	posts := make([]map[string]any, 0, 2)
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		posts = append(posts, body)
		if len(posts) == 1 {
			return testHTTPResponse(http.StatusInternalServerError, `{"code":"OutOfHostCapacity"}`, nil), nil
		}
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.instance.oc1.saopaulo.resumed","compartmentId":"ocid1.compartment.oc1..x","lifecycleState":"PROVISIONING","availabilityDomain":"AD-2","shape":"VM.Standard.E5.Flex"}`, http.Header{"Etag": {"instance-etag"}}), nil
	})
	journal := &pausingMutationJournal{ProviderMutationJournal: testJournal(t), pauseAt: 1}
	adapter, err := NewOCIComputeAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	request := ComputeLaunchRequest{
		CompartmentID:   "ocid1.compartment.oc1..x",
		DisplayName:     "node-resume",
		ImageID:         "ocid1.image.oc1.sa-saopaulo-1.x",
		BootstrapBase64: base64.StdEncoding.EncodeToString([]byte("#cloud-config\n")),
		Candidates: []ComputeCapacityCandidate{
			{AvailabilityDomain: "AD-1", SubnetID: "ocid1.subnet.oc1.sa-saopaulo-1.ad1", Shape: "VM.Standard.A1.Flex", OCPUs: 1, MemoryGiB: 6},
			{AvailabilityDomain: "AD-2", SubnetID: "ocid1.subnet.oc1.sa-saopaulo-1.ad2", Shape: "VM.Standard.E5.Flex", OCPUs: 1, MemoryGiB: 8},
		},
	}
	request.Mutation = testMutation("compute.launch", ComputeLaunchMutationScope(request), ComputeLaunchMutationFingerprint(request), 1)
	if _, err := adapter.LaunchInstance(context.Background(), request); err == nil || len(posts) != 1 {
		t.Fatalf("interrupted fallback posts=%d err=%v", len(posts), err)
	}
	instance, err := adapter.LaunchInstance(context.Background(), request)
	if err != nil || instance.ID == "" || instance.ETag != "instance-etag" || len(posts) != 2 || posts[1]["availabilityDomain"] != "AD-2" {
		t.Fatalf("resumed fallback instance=%+v posts=%+v err=%v", instance, posts, err)
	}
	firstVNIC := posts[0]["createVnicDetails"].(map[string]any)
	secondVNIC := posts[1]["createVnicDetails"].(map[string]any)
	if firstVNIC["subnetId"] != "ocid1.subnet.oc1.sa-saopaulo-1.ad1" || secondVNIC["subnetId"] != "ocid1.subnet.oc1.sa-saopaulo-1.ad2" {
		t.Fatalf("capacity fallback subnet order = %+v", posts)
	}
}

func TestOCIComputeAdapterNeverRepostsAnUnknownOutcome(t *testing.T) {
	posts, gets := 0, 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		switch request.Method {
		case http.MethodPost:
			posts++
			return nil, io.ErrUnexpectedEOF
		case http.MethodGet:
			gets++
			return testHTTPResponse(http.StatusOK, `[]`, nil), nil
		default:
			return nil, errors.New("unexpected compute method")
		}
	})
	adapter, err := NewOCIComputeAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	request := ComputeLaunchRequest{CompartmentID: "ocid1.compartment.oc1..x", DisplayName: "node-unknown", ImageID: "ocid1.image.oc1.sa-saopaulo-1.x", BootstrapBase64: base64.StdEncoding.EncodeToString([]byte("#cloud-config\n")), Candidates: []ComputeCapacityCandidate{{AvailabilityDomain: "AD-1", SubnetID: "ocid1.subnet.oc1.sa-saopaulo-1.x", Shape: "VM.Standard.A1.Flex", OCPUs: 1, MemoryGiB: 6}}}
	request.Mutation = testMutation("compute.launch", ComputeLaunchMutationScope(request), ComputeLaunchMutationFingerprint(request), 1)
	if _, err := adapter.LaunchInstance(context.Background(), request); !errors.As(err, new(*ProviderOutcomeUnknownError)) {
		t.Fatalf("lost response error = %v", err)
	}
	if _, err := adapter.LaunchInstance(context.Background(), request); !errors.As(err, new(*ProviderOutcomeUnknownError)) {
		t.Fatalf("unknown resume error = %v", err)
	}
	if posts != 1 || gets != 1 {
		t.Fatalf("unknown outcome made posts=%d gets=%d; want one post and observation only", posts, gets)
	}
}

func TestOCIWorkRequestAdapterToleratesEventualVisibility(t *testing.T) {
	reads := 0
	transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
		reads++
		if reads <= 2 {
			return testHTTPResponse(http.StatusNotFound, "", nil), nil
		}
		return testHTTPResponse(http.StatusOK, `{"id":"work-1","status":"SUCCEEDED","percentComplete":100}`, nil), nil
	})
	adapter, err := NewOCIWorkRequestAdapter(transport)
	if err != nil {
		t.Fatal(err)
	}
	adapter.Wait = func(context.Context, time.Duration) error { return nil }
	work, err := adapter.WaitWorkRequest(context.Background(), "work-1", WorkRequestWaitPolicy{MaxPolls: 4, MaxNotFound: 2})
	if err != nil || work.State != WorkRequestSucceeded || reads != 3 {
		t.Fatalf("work request = %+v reads=%d err=%v", work, reads, err)
	}
}

func TestAsyncMutationCompletionPreservesProviderTruth(t *testing.T) {
	oldPolicy := mutationWorkRequestWaitPolicy
	mutationWorkRequestWaitPolicy = WorkRequestWaitPolicy{PollInterval: 0, MaxPolls: 2, MaxNotFound: 1}
	t.Cleanup(func() { mutationWorkRequestWaitPolicy = oldPolicy })

	tests := []struct {
		name          string
		workID        string
		status        int
		providerState string
		unknownFirst  bool
		wantState     ProviderMutationState
		wantError     bool
	}{
		{name: "success", workID: "work-success", status: http.StatusOK, providerState: "SUCCEEDED", wantState: MutationSucceeded},
		{name: "failure after unknown", workID: "work-failed", status: http.StatusOK, providerState: "FAILED", unknownFirst: true, wantState: MutationFailed, wantError: true},
		{name: "cancellation", workID: "work-canceled", status: http.StatusOK, providerState: "CANCELED", wantState: MutationFailed, wantError: true},
		{name: "invisible", workID: "work-invisible", status: http.StatusNotFound, wantState: MutationUnknown, wantError: true},
		{name: "missing work request ID", wantState: MutationUnknown, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			intent := testMutation("compute.terminate", ProviderMutationScope("compute", test.name), ProviderMutationFingerprint(test.name), 1)
			journal := testJournal(t)
			if _, err := journal.Prepare(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			if _, err := journal.MarkSubmitted(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			result := ProviderMutationResult{ResourceID: "ocid1.instance.oc1.sa-saopaulo-1.x", ETag: "instance-etag", WorkRequestID: test.workID}
			if test.unknownFirst {
				if _, err := journal.MarkUnknown(context.Background(), intent, result); err != nil {
					t.Fatal(err)
				}
			}
			transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
				if request.URL.Path != "/20160918/workRequests/"+test.workID {
					t.Fatalf("unexpected work request path %s", request.URL.Path)
				}
				body := `{"id":"` + test.workID + `","status":"` + test.providerState + `","percentComplete":100}`
				return testHTTPResponse(test.status, body, nil), nil
			})
			work, err := NewOCIWorkRequestAdapter(transport)
			if err != nil {
				t.Fatal(err)
			}
			work.Wait = func(context.Context, time.Duration) error { return nil }
			err = finishAsyncMutation(context.Background(), journal, intent, result, work)
			if (err != nil) != test.wantError {
				t.Fatalf("completion error = %v, wantError=%v", err, test.wantError)
			}
			record, err := journal.Prepare(context.Background(), intent)
			if err != nil || record.State != test.wantState || record.Result != result {
				t.Fatalf("completion record = %+v, err=%v", record, err)
			}
		})
	}
}

func TestOCIServiceTransportRejectsCrossServiceAuthority(t *testing.T) {
	if _, err := NewOCIServiceTransportConfig(OCIServiceIdentity, "sa-saopaulo-1", "https://identity.sa-saopaulo-1.oci.oraclecloud.com"); err != nil {
		t.Fatalf("Identity authority rejected: %v", err)
	}
	if _, err := NewOCIServiceTransportConfig(OCIServiceVault, "sa-saopaulo-1", "https://vaults.sa-saopaulo-1.oci.oraclecloud.com"); err != nil {
		t.Fatalf("Vault authority rejected: %v", err)
	}
	if _, err := NewOCIServiceTransportConfig(OCIServiceIdentity, "sa-saopaulo-1", "https://identity.sa-saopaulo-1.oraclecloud.com"); err == nil {
		t.Fatal("Identity signer accepted an authority without the OCI service label")
	}
	if _, err := NewOCIServiceTransportConfig(OCIServiceRegistry, "us-sanjose-1", "https://sjc.ocir.io"); err != nil {
		t.Fatalf("SJC OCIR authority rejected: %v", err)
	}
	if _, err := NewOCIServiceTransportConfig(OCIServiceRegistry, "us-sanjose-1", "https://sfo.ocir.io"); err == nil {
		t.Fatal("SFO alias accepted the wrong OCIR region key")
	}
}

func TestOCIDValidationAcceptsOracleRegionlessResources(t *testing.T) {
	for _, test := range []struct {
		value string
		kind  string
	}{
		{"ocid1.tenancy.oc1..aaaaaaaaxf3fuazos", "tenancy"},
		{"ocid1.compartment.oc1..aaaaaaaam3we6vgnherjq5q2", "compartment"},
		{"ocid1.policy.oc1..aaaaaaaapolicy", "policy"},
		{"ocid1.dynamicgroup.oc1..aaaaaaaadynamicgroup", "dynamicgroup"},
	} {
		if !isOCID(test.value, test.kind) {
			t.Fatalf("real regionless %s OCID was rejected: %s", test.kind, test.value)
		}
	}
	for _, invalid := range []string{
		"ocid1.compartment.oc1.",
		"ocid1.compartment.oc1...aaaa",
		"ocid1.compartment.oc1..aaaa/escape",
		"ocid1.compartment.oc1.sa-saopaulo-1.aaaa",
	} {
		if isOCID(invalid, "compartment") {
			t.Fatalf("invalid OCID was accepted: %s", invalid)
		}
	}
	for _, test := range []struct {
		value string
		kind  string
	}{
		{"ocid1.instance.oc1..aaaa", "instance"},
		{"ocid1.volume.oc1..aaaa", "volume"},
		{"ocid1.volumeattachment.oc1..aaaa", "volumeattachment"},
		{"ocid1.image.oc1..aaaa", "image"},
		{"ocid1.vcn.oc1..aaaa", "vcn"},
		{"ocid1.subnet.oc1..aaaa", "subnet"},
		{"ocid1.networksecuritygroup.oc1..aaaa", "networksecuritygroup"},
		{"ocid1.vault.oc1..aaaa", "vault"},
		{"ocid1.key.oc1..aaaa", "key"},
		{"ocid1.instance.oc1.sa-saopaulo-1", "instance"},
	} {
		if isOCID(test.value, test.kind) {
			t.Fatalf("regionless %s OCID was accepted: %s", test.kind, test.value)
		}
	}
}

func TestOCIComputeTerminateAbsentIsDurablyIdempotent(t *testing.T) {
	deletes := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodDelete {
			deletes++
		}
		if request.Method == http.MethodGet && request.URL.Path == "/20160918/instances" {
			return testHTTPResponse(http.StatusOK, `[]`, nil), nil
		}
		return testHTTPResponse(http.StatusNotFound, "", nil), nil
	})
	journal := testJournal(t)
	adapter, err := NewOCIComputeAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	instanceID := "ocid1.instance.oc1.sa-saopaulo-1.x"
	adapter.Ownership = testOwnership(t, instanceID)
	request := ComputeTerminateRequest{InstanceID: instanceID, IfMatch: "instance-etag"}
	request.Mutation = testMutation("compute.terminate", ComputeTerminateMutationScope(request), ComputeTerminateMutationFingerprint(request), 1)
	if err := adapter.TerminateInstance(context.Background(), request); err != nil {
		t.Fatalf("first absent terminate = %v", err)
	}
	if err := adapter.TerminateInstance(context.Background(), request); err != nil {
		t.Fatalf("retry absent terminate = %v", err)
	}
	if deletes != 0 {
		t.Fatalf("absent terminate issued %d delete requests", deletes)
	}
}

func TestOCIComputeLaunchRejectsOutOfScopeMutationResponse(t *testing.T) {
	request := ComputeLaunchRequest{
		CompartmentID:   "ocid1.compartment.oc1..x",
		DisplayName:     "scope-check",
		ImageID:         "ocid1.image.oc1.sa-saopaulo-1.x",
		BootstrapBase64: base64.StdEncoding.EncodeToString([]byte("#cloud-config\n")),
		Candidates:      []ComputeCapacityCandidate{{AvailabilityDomain: "AD-1", SubnetID: "ocid1.subnet.oc1.sa-saopaulo-1.x", Shape: "VM.Standard.E5.Flex", OCPUs: 1, MemoryGiB: 4}},
	}
	request.Mutation = testMutation("compute.launch", ComputeLaunchMutationScope(request), ComputeLaunchMutationFingerprint(request), 1)
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.instance.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..other","lifecycleState":"PROVISIONING"}`, nil), nil
	})
	adapter, err := NewOCIComputeAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.LaunchInstance(context.Background(), request); err == nil {
		t.Fatal("out-of-scope compute response was accepted")
	}
}

func TestOCIComputeTerminateRejectsOutOfScopeObservation(t *testing.T) {
	deletes := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodDelete {
			deletes++
		}
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.instance.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..other","lifecycleState":"RUNNING"}`, nil), nil
	})
	adapter, err := NewOCIComputeAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	instanceID := "ocid1.instance.oc1.sa-saopaulo-1.x"
	adapter.Ownership = testOwnership(t, instanceID)
	request := ComputeTerminateRequest{InstanceID: instanceID, IfMatch: "instance-etag"}
	request.Mutation = testMutation("compute.terminate", ComputeTerminateMutationScope(request), ComputeTerminateMutationFingerprint(request), 1)
	if err := adapter.TerminateInstance(context.Background(), request); err == nil || deletes != 0 {
		t.Fatalf("out-of-scope compute termination err=%v deletes=%d", err, deletes)
	}
}

func TestOCIComputeLaunchReconciliationFollowsNextPage(t *testing.T) {
	request := ComputeLaunchRequest{
		CompartmentID:   "ocid1.compartment.oc1..x",
		DisplayName:     "paged-reconcile",
		ImageID:         "ocid1.image.oc1.sa-saopaulo-1.x",
		BootstrapBase64: base64.StdEncoding.EncodeToString([]byte("#cloud-config\n")),
		Candidates:      []ComputeCapacityCandidate{{AvailabilityDomain: "AD-1", SubnetID: "ocid1.subnet.oc1.sa-saopaulo-1.x", Shape: "VM.Standard.E5.Flex", OCPUs: 1, MemoryGiB: 4}},
	}
	request.Mutation = testMutation("compute.launch", ComputeLaunchMutationScope(request), ComputeLaunchMutationFingerprint(request), 1)
	journal := testJournal(t)
	if _, err := journal.Prepare(context.Background(), request.Mutation); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.MarkSubmitted(context.Background(), request.Mutation); err != nil {
		t.Fatal(err)
	}
	pageCalls := 0
	transport := testOCITransport(t, OCIServiceCore, func(httpRequest *http.Request) (*http.Response, error) {
		pageCalls++
		if httpRequest.URL.Path == "/20160918/instances/ocid1.instance.oc1.sa-saopaulo-1.x" {
			return testHTTPResponse(http.StatusOK, `{"id":"ocid1.instance.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..x","lifecycleState":"PROVISIONING"}`, http.Header{"Etag": {"instance-etag"}}), nil
		}
		if httpRequest.URL.Query().Get("page") == "" {
			return testHTTPResponse(http.StatusOK, `{"items":[]}`, http.Header{"Opc-Next-Page": {"page-2"}}), nil
		}
		body := `{"items":[{"id":"ocid1.instance.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..x","lifecycleState":"PROVISIONING","freeformTags":{"terrascale-operation":"` + request.Mutation.OperationID.Value + `","terrascale-intent":"` + request.Mutation.Fingerprint + `"}}]}`
		return testHTTPResponse(http.StatusOK, body, nil), nil
	})
	adapter, err := NewOCIComputeAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := adapter.LaunchInstance(context.Background(), request)
	if err != nil || instance.ID != "ocid1.instance.oc1.sa-saopaulo-1.x" || instance.ETag != "instance-etag" || pageCalls != 3 {
		t.Fatalf("paged reconciliation instance=%+v calls=%d err=%v", instance, pageCalls, err)
	}
}

func TestOCIListPaginationRejectsMalformedOrUnboundedContinuation(t *testing.T) {
	valid := testHTTPResponse(http.StatusOK, `{"items":[]}`, http.Header{"Opc-Next-Page": {"page-2"}})
	next, err := nextOCIPage(valid, "", 1)
	if err != nil || next != "page-2" {
		t.Fatalf("valid continuation = %q, %v", next, err)
	}

	cases := []struct {
		name      string
		header    http.Header
		page      string
		pagesRead int
	}{
		{"repeated token", http.Header{"Opc-Next-Page": {"page-2"}}, "page-2", 2},
		{"page bound", http.Header{"Opc-Next-Page": {"page-17"}}, "page-16", maximumOCIPages},
		{"multiple tokens", http.Header{"Opc-Next-Page": {"page-2", "page-3"}}, "", 1},
		{"whitespace token", http.Header{"Opc-Next-Page": {" page-2"}}, "", 1},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			resp := testHTTPResponse(http.StatusOK, `{"items":[]}`, test.header)
			if _, err := nextOCIPage(resp, test.page, test.pagesRead); err == nil {
				t.Fatal("invalid continuation was accepted")
			}
		})
	}
}
