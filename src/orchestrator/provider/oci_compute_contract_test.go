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
	if _, err := journal.MarkUnknown(context.Background(), first); err != nil {
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
	result := ProviderMutationResult{ResourceID: "ocid1.instance.oc1.absent", ETag: "instance-etag"}
	record, err := journal.MarkSucceeded(context.Background(), intent, result)
	if err != nil || record.State != MutationSucceeded || record.Result != result {
		t.Fatalf("observed-absent transition = %+v, %v", record, err)
	}
	if _, err := journal.MarkFailed(context.Background(), intent, "provider-rejected"); err == nil {
		t.Fatal("observed-absent success changed terminal outcome")
	}
}

func TestOCIComputeTerminateConvergesWhenInstanceIsAlreadyAbsent(t *testing.T) {
	instanceID := "ocid1.instance.oc1.absent"
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet {
			t.Fatalf("already-absent termination sent %s", request.Method)
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
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.instance.oc1.saopaulo.resumed","lifecycleState":"PROVISIONING","availabilityDomain":"AD-2","shape":"VM.Standard.E5.Flex"}`, nil), nil
	})
	journal := &pausingMutationJournal{ProviderMutationJournal: testJournal(t), pauseAt: 1}
	adapter, err := NewOCIComputeAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	request := ComputeLaunchRequest{
		CompartmentID:   "ocid1.compartment.oc1.x",
		DisplayName:     "node-resume",
		ImageID:         "ocid1.image.oc1.x",
		BootstrapBase64: base64.StdEncoding.EncodeToString([]byte("#cloud-config\n")),
		Candidates: []ComputeCapacityCandidate{
			{AvailabilityDomain: "AD-1", SubnetID: "ocid1.subnet.oc1.ad1", Shape: "VM.Standard.A1.Flex", OCPUs: 1, MemoryGiB: 6},
			{AvailabilityDomain: "AD-2", SubnetID: "ocid1.subnet.oc1.ad2", Shape: "VM.Standard.E5.Flex", OCPUs: 1, MemoryGiB: 8},
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
	if firstVNIC["subnetId"] != "ocid1.subnet.oc1.ad1" || secondVNIC["subnetId"] != "ocid1.subnet.oc1.ad2" {
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
	request := ComputeLaunchRequest{CompartmentID: "ocid1.compartment.oc1.x", DisplayName: "node-unknown", ImageID: "ocid1.image.oc1.x", BootstrapBase64: base64.StdEncoding.EncodeToString([]byte("#cloud-config\n")), Candidates: []ComputeCapacityCandidate{{AvailabilityDomain: "AD-1", SubnetID: "ocid1.subnet.oc1.x", Shape: "VM.Standard.A1.Flex", OCPUs: 1, MemoryGiB: 6}}}
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

func TestOCIVaultManagementEndpointRequiresVaultOCIDAndRegion(t *testing.T) {
	valid := "https://ocid1.vault.oc1.sa-saopaulo-1.x.management.kms.sa-saopaulo-1.oci.oraclecloud.com"
	if _, err := NewOCIServiceTransportConfig(OCIServiceVaultManagement, "sa-saopaulo-1", valid); err != nil {
		t.Fatalf("valid Vault management endpoint rejected: %v", err)
	}
	for _, endpoint := range []string{
		"https://ocid1.vault.oc1.sa-saopaulo-1.x.management.kms.us-phoenix-1.oci.oraclecloud.com",
		"https://ocid1.vault.oc1.sa-saopaulo-1.x-management.kms.sa-saopaulo-1.oraclecloud.com",
		"https://vault-management.kms.sa-saopaulo-1.oci.oraclecloud.com",
		"https://ocid1.vault.oc1.sa-saopaulo-1.x.management.kms.sa-saopaulo-1.oci.oraclecloud.com:443",
	} {
		if _, err := NewOCIServiceTransportConfig(OCIServiceVaultManagement, "sa-saopaulo-1", endpoint); err == nil {
			t.Fatalf("malformed or cross-region Vault management endpoint accepted: %s", endpoint)
		}
	}
}

func TestOCIComputeTerminateAbsentIsDurablyIdempotent(t *testing.T) {
	deletes := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodDelete {
			deletes++
		}
		return testHTTPResponse(http.StatusNotFound, "", nil), nil
	})
	journal := testJournal(t)
	adapter, err := NewOCIComputeAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	instanceID := "ocid1.instance.oc1.x"
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
