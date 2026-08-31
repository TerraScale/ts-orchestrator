package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

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

func TestProviderMutationJournalPreservesUnknownProviderResult(t *testing.T) {
	journal := testJournal(t)
	intent := testMutation("attachment.delete", ProviderMutationScope("attachment", "restart"), ProviderMutationFingerprint("restart"), 3)
	result := ProviderMutationResult{
		ResourceID:    "ocid1.volumeattachment.oc1.sa-saopaulo-1.restart",
		WorkRequestID: "work-restart",
		ETag:          "etag-restart",
	}
	if _, err := journal.Prepare(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.MarkSubmitted(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.MarkUnknown(context.Background(), intent, result); err != nil {
		t.Fatal(err)
	}

	resumed := intent
	resumed.Epoch.Value++
	record, err := journal.Prepare(context.Background(), resumed)
	if err != nil || record.State != MutationUnknown || record.Result != result {
		t.Fatalf("restart record = %+v, err=%v", record, err)
	}
	if record, err = journal.MarkUnknown(context.Background(), resumed, ProviderMutationResult{}); err != nil || record.Result != result {
		t.Fatalf("empty unknown update lost result: %+v, err=%v", record, err)
	}

	conflict := result
	conflict.WorkRequestID = "work-conflict"
	if _, err := journal.MarkUnknown(context.Background(), resumed, conflict); err == nil {
		t.Fatal("conflicting unknown result replaced provider identity")
	}
	if _, err := journal.MarkProviderFailed(context.Background(), resumed, conflict, "provider-work-request-failed"); err == nil {
		t.Fatal("provider failure used a conflicting work-request identity")
	}
	record, err = journal.Prepare(context.Background(), resumed)
	if err != nil || record.State != MutationUnknown || record.Result != result {
		t.Fatalf("conflict changed durable record = %+v, err=%v", record, err)
	}
	if _, err := journal.MarkFailed(context.Background(), resumed, "timeout"); err == nil {
		t.Fatal("synchronous failure overwrote an unknown provider result")
	}
	if record, err = journal.MarkProviderFailed(context.Background(), resumed, result, "provider-work-request-failed"); err != nil || record.State != MutationFailed || record.Result != result {
		t.Fatalf("provider-proven failure = %+v, err=%v", record, err)
	}
}

func TestProviderMutationJournalRejectsUnprovedProviderFailure(t *testing.T) {
	for _, workID := range []string{"", "work/invalid"} {
		t.Run(workID, func(t *testing.T) {
			journal := testJournal(t)
			intent := testMutation("attachment.delete", ProviderMutationScope("attachment", "unproved", workID), ProviderMutationFingerprint("unproved", workID), 2)
			if _, err := journal.Prepare(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			if _, err := journal.MarkSubmitted(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			result := ProviderMutationResult{ResourceID: "ocid1.volumeattachment.oc1.sa-saopaulo-1.unproved", ETag: "attachment-etag", WorkRequestID: workID}
			if _, err := journal.MarkProviderFailed(context.Background(), intent, result, "provider-work-request-failed"); err == nil {
				t.Fatal("provider failure without a valid work-request identity was accepted")
			}
			record, err := journal.Prepare(context.Background(), intent)
			if err != nil || record.State != MutationSubmitted || record.Result != (ProviderMutationResult{}) {
				t.Fatalf("unproved failure changed record = %+v, err=%v", record, err)
			}
		})
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
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.instance.oc1.saopaulo.resumed","lifecycleState":"PROVISIONING","availabilityDomain":"AD-2","shape":"VM.Standard.E5.Flex"}`, http.Header{"Etag": {"resumed-etag"}}), nil
	})
	journal := &pausingMutationJournal{ProviderMutationJournal: testJournal(t), pauseAt: 1}
	adapter, err := NewOCIComputeAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	request := ComputeLaunchRequest{
		CompartmentID:   "ocid1.compartment.oc1..testcompartment",
		DisplayName:     "node-resume",
		ImageID:         "ocid1.image.oc1.sa-saopaulo-1.testimage",
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
	if err != nil || instance.ID == "" || len(posts) != 2 || posts[1]["availabilityDomain"] != "AD-2" {
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
	request := ComputeLaunchRequest{CompartmentID: "ocid1.compartment.oc1..testcompartment", DisplayName: "node-unknown", ImageID: "ocid1.image.oc1.sa-saopaulo-1.testimage", BootstrapBase64: base64.StdEncoding.EncodeToString([]byte("#cloud-config\n")), Candidates: []ComputeCapacityCandidate{{AvailabilityDomain: "AD-1", SubnetID: "ocid1.subnet.oc1.sa-saopaulo-1.testsubnet", Shape: "VM.Standard.A1.Flex", OCPUs: 1, MemoryGiB: 6}}}
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

func TestOCIWorkRequestAdapterRejectsMalformedProgressAndReturnsLastObservation(t *testing.T) {
	t.Run("non-finite progress", func(t *testing.T) {
		for _, progress := range []string{"NaN", "1e1000"} {
			transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
				return testHTTPResponse(http.StatusOK, `{"id":"work-finite","status":"IN_PROGRESS","percentComplete":`+progress+`}`, nil), nil
			})
			adapter, err := NewOCIWorkRequestAdapter(transport)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := adapter.GetWorkRequest(context.Background(), "work-finite"); err == nil {
				t.Fatalf("non-finite progress %q was accepted", progress)
			}
		}
	})

	t.Run("poll exhaustion", func(t *testing.T) {
		reads := 0
		transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
			reads++
			return testHTTPResponse(http.StatusOK, `{"id":"work-last","status":"ACCEPTED","percentComplete":37}`, nil), nil
		})
		adapter, err := NewOCIWorkRequestAdapter(transport)
		if err != nil {
			t.Fatal(err)
		}
		adapter.Wait = func(context.Context, time.Duration) error { return nil }
		work, err := adapter.WaitWorkRequest(context.Background(), "work-last", WorkRequestWaitPolicy{MaxPolls: 2, MaxNotFound: 1})
		if !errors.As(err, new(*ProviderOutcomeUnknownError)) || work.State != WorkRequestAccepted || work.PercentComplete != 37 || reads != 2 {
			t.Fatalf("exhausted work request = %+v reads=%d err=%v", work, reads, err)
		}
	})

	for _, id := range []string{" work", "work/path", "work\nheader", "work☃"} {
		if validWorkRequestID(id) {
			t.Fatalf("invalid work-request ID was accepted: %q", id)
		}
	}
}

func TestAsyncMutationCompletionPreservesProviderTruth(t *testing.T) {
	policy := WorkRequestWaitPolicy{PollInterval: 0, MaxPolls: 2, MaxNotFound: 1}

	tests := []struct {
		name          string
		workID        string
		status        int
		providerState string
		unknownFirst  bool
		wantState     ProviderMutationState
		wantFailure   string
		wantError     bool
	}{
		{name: "success", workID: "work-success", status: http.StatusOK, providerState: "SUCCEEDED", wantState: MutationSucceeded},
		{name: "failure after restart", workID: "work-failed", status: http.StatusOK, providerState: "FAILED", unknownFirst: true, wantState: MutationFailed, wantFailure: "provider-work-request-failed", wantError: true},
		{name: "cancellation", workID: "work-canceled", status: http.StatusOK, providerState: "CANCELED", wantState: MutationFailed, wantFailure: "provider-work-request-canceled", wantError: true},
		{name: "invisible", workID: "work-invisible", status: http.StatusNotFound, wantState: MutationUnknown, wantError: true},
		{name: "missing work request ID", wantState: MutationUnknown, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			intent := testMutation("attachment.delete", ProviderMutationScope("attachment", test.name), ProviderMutationFingerprint(test.name), 1)
			journal := testJournal(t)
			if _, err := journal.Prepare(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			if _, err := journal.MarkSubmitted(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			result := ProviderMutationResult{ResourceID: "ocid1.volumeattachment.oc1.sa-saopaulo-1.async", ETag: "attachment-etag", WorkRequestID: test.workID}
			if test.unknownFirst {
				if _, err := journal.MarkUnknown(context.Background(), intent, result); err != nil {
					t.Fatal(err)
				}
				intent.Epoch.Value++
				if _, err := journal.Prepare(context.Background(), intent); err != nil {
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
			err = finishAsyncMutation(context.Background(), journal, intent, result, work, policy)
			if (err != nil) != test.wantError {
				t.Fatalf("completion error = %v, wantError=%v", err, test.wantError)
			}
			record, err := journal.Prepare(context.Background(), intent)
			if err != nil || record.State != test.wantState || record.Result != result || record.FailureCode != test.wantFailure {
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
