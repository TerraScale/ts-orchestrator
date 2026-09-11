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
	host, ok := OCIServiceHost(service, "sa-saopaulo-1")
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
		BootstrapBase64: base64.StdEncoding.EncodeToString([]byte("#cloud-config\n")),
		Candidates: []ComputeCapacityCandidate{
			{AvailabilityDomain: "AD-1", SubnetID: "ocid1.subnet.oc1.ad1", Shape: "VM.Standard.A1.Flex", Architecture: "arm64", ImageID: "ocid1.image.oc1.arm64", OCPUs: 1, MemoryGiB: 6},
			{AvailabilityDomain: "AD-2", SubnetID: "ocid1.subnet.oc1.ad2", Shape: "VM.Standard.E5.Flex", Architecture: "amd64", ImageID: "ocid1.image.oc1.amd64", OCPUs: 1, MemoryGiB: 8},
		},
	}
	request.Mutation = testMutation("compute.launch", ComputeLaunchMutationScope(request), ComputeLaunchMutationFingerprint(request), 1)
	changed := request
	changed.Candidates = append([]ComputeCapacityCandidate(nil), request.Candidates...)
	changed.Candidates[1].ImageID = "ocid1.image.oc1.amd64.changed"
	if ComputeLaunchMutationFingerprint(changed) == ComputeLaunchMutationFingerprint(request) {
		t.Fatal("candidate image must be part of the durable launch fingerprint")
	}
	changed.Mutation = request.Mutation
	if _, err := adapter.LaunchInstance(context.Background(), changed); err == nil {
		t.Fatal("a changed candidate image must not cross the original mutation fence")
	}
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

func TestOCIComputeAdapterStartIsJournaledAndReplayed(t *testing.T) {
	const instanceID = "ocid1.instance.oc1.start"
	ownership := testOwnership(t, instanceID)
	starts, reads := 0, 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			reads++
			state := "STOPPED"
			if reads > 1 {
				state = "RUNNING"
			}
			headers := make(http.Header)
			headers.Set("ETag", "etag-1")
			return testHTTPResponse(http.StatusOK, `{"id":"`+instanceID+`","compartmentId":"ocid1.compartment.oc1.x","lifecycleState":"`+state+`","shape":"VM.Standard.A1.Flex"}`, headers), nil
		}
		if request.Method == http.MethodPost {
			starts++
			if request.Header.Get("If-Match") != "etag-1" || request.Header.Get("Opc-Retry-Token") == "" {
				t.Fatalf("start fence headers = %v", request.Header)
			}
			return testHTTPResponse(http.StatusAccepted, "", nil), nil
		}
		t.Fatalf("unexpected request %s %s", request.Method, request.URL)
		return nil, nil
	})
	journal := testJournal(t)
	adapter, err := NewOCIComputeAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	adapter.Ownership = ownership
	request := ComputeStartRequest{InstanceID: instanceID, IfMatch: "etag-1", Generation: 1}
	request.Mutation = ProviderMutationIntent{OperationID: ProviderOperationId{Value: "start-op"}, Scope: ComputeStartMutationScope(request), Action: "compute.start", Epoch: ProviderEpoch{Value: 1}, IdempotencyKey: ProviderIdempotencyKey{Value: "start-key"}}
	request.Mutation.Fingerprint = ComputeStartMutationFingerprint(request)
	if err := adapter.StartInstance(context.Background(), request); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	if err := adapter.StartInstance(context.Background(), request); err != nil {
		t.Fatalf("replayed start: %v", err)
	}
	if starts != 1 {
		t.Fatalf("start requests = %d, want one durable submission", starts)
	}
}

func TestOCIComputeAdapterStartRejectsStaleGeneration(t *testing.T) {
	const instanceID = "ocid1.instance.oc1.stale"
	ownership := testOwnership(t, instanceID)
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		t.Fatalf("stale generation reached OCI: %s %s", request.Method, request.URL)
		return nil, nil
	})
	journal := testJournal(t)
	adapter, err := NewOCIComputeAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	adapter.Ownership = ownership
	request := ComputeStartRequest{InstanceID: instanceID, IfMatch: "etag-1", Generation: 2}
	request.Mutation = ProviderMutationIntent{OperationID: ProviderOperationId{Value: "stale-start"}, Scope: ComputeStartMutationScope(request), Action: "compute.start", Epoch: ProviderEpoch{Value: 1}, IdempotencyKey: ProviderIdempotencyKey{Value: "stale-key"}}
	request.Mutation.Fingerprint = ComputeStartMutationFingerprint(request)
	if err := adapter.StartInstance(context.Background(), request); err == nil {
		t.Fatal("stale generation was accepted")
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
	request := ComputeLaunchRequest{CompartmentID: "ocid1.compartment.oc1.x", DisplayName: "node-unknown", BootstrapBase64: base64.StdEncoding.EncodeToString([]byte("#cloud-config\n")), Candidates: []ComputeCapacityCandidate{{AvailabilityDomain: "AD-1", SubnetID: "ocid1.subnet.oc1.x", Shape: "VM.Standard.A1.Flex", Architecture: "arm64", ImageID: "ocid1.image.oc1.x", OCPUs: 1, MemoryGiB: 6}}}
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

func TestOCIComputeAdapterRecoveryRecordsOwnershipBeforeCompleting(t *testing.T) {
	posts, reads := 0, 0
	operation := ""
	intent := ""
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		switch request.Method {
		case http.MethodPost:
			posts++
			return nil, io.ErrUnexpectedEOF
		case http.MethodGet:
			reads++
			body := `[{"id":"ocid1.instance.oc1.recovered","compartmentId":"ocid1.compartment.oc1.x","lifecycleState":"PROVISIONING","shape":"VM.Standard.A1.Flex","freeformTags":{"terrascale-operation":"` + operation + `","terrascale-intent":"` + intent + `"}}]`
			return testHTTPResponse(http.StatusOK, body, nil), nil
		default:
			return nil, errors.New("unexpected compute method")
		}
	})
	ownership, err := NewDurableOwnershipJournal(newTestOwnershipCAS(), 4)
	if err != nil {
		t.Fatal(err)
	}
	journal := testJournal(t)
	adapter, err := NewOCIComputeAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	adapter.Ownership = ownership
	request := ComputeLaunchRequest{
		CompartmentID: "ocid1.compartment.oc1.x", DisplayName: "node-recovery", CellID: "gru", Generation: 1,
		ServerIdentity: "spiffe://terrascale/member/gru-1", Environment: "production", Cluster: "cluster", MemberID: "member-1",
		BootstrapBase64: base64.StdEncoding.EncodeToString([]byte("#cloud-config\n")),
		Candidates:      []ComputeCapacityCandidate{{AvailabilityDomain: "AD-1", SubnetID: "ocid1.subnet.oc1.x", Shape: "VM.Standard.A1.Flex", Architecture: "arm64", ImageID: "ocid1.image.oc1.x", OCPUs: 1, MemoryGiB: 6}},
	}
	request.Mutation = testMutation("compute.launch", ComputeLaunchMutationScope(request), ComputeLaunchMutationFingerprint(request), 1)
	operation = request.Mutation.OperationID.Value
	intent = request.Mutation.Fingerprint
	if _, err := adapter.LaunchInstance(t.Context(), request); !errors.As(err, new(*ProviderOutcomeUnknownError)) {
		t.Fatalf("lost response error = %v", err)
	}
	instance, err := adapter.LaunchInstance(t.Context(), request)
	if err != nil || instance.ID != "ocid1.instance.oc1.recovered" {
		t.Fatalf("recovered instance = %+v, %v", instance, err)
	}
	if posts != 1 || reads != 1 {
		t.Fatalf("recovery calls = posts %d reads %d; want one post and one observation", posts, reads)
	}
	record, found, err := ownership.Lookup(t.Context(), ProviderResourceId{Value: instance.ID})
	if err != nil || !found || record.CompartmentId.Value != request.CompartmentID || record.Generation.Value != request.Generation {
		t.Fatalf("recovered ownership = %+v found=%v err=%v", record, found, err)
	}
}

func TestOCIComputeAdapterReconcileLaunchRejectsDuplicateIntent(t *testing.T) {
	posts, reads := 0, 0
	intent := ""
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		switch request.Method {
		case http.MethodPost:
			posts++
			return nil, errors.New("replacement POST is forbidden")
		case http.MethodGet:
			reads++
			body := `[{"id":"ocid1.instance.oc1.one","freeformTags":{"terrascale-operation":"op","terrascale-intent":"` + intent + `"}},{"id":"ocid1.instance.oc1.two","freeformTags":{"terrascale-operation":"op","terrascale-intent":"` + intent + `"}}]`
			return testHTTPResponse(http.StatusOK, body, nil), nil
		default:
			return nil, errors.New("unexpected compute method")
		}
	})
	journal := testJournal(t)
	adapter, err := NewOCIComputeAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	request := ComputeLaunchRequest{CompartmentID: "ocid1.compartment.oc1.x", DisplayName: "node-duplicate", BootstrapBase64: base64.StdEncoding.EncodeToString([]byte("#cloud-config\n")), Candidates: []ComputeCapacityCandidate{{AvailabilityDomain: "AD-1", SubnetID: "ocid1.subnet.oc1.x", Shape: "VM.Standard.A1.Flex", Architecture: "arm64", ImageID: "ocid1.image.oc1.x", OCPUs: 1, MemoryGiB: 6}}}
	request.Mutation = testMutation("compute.launch", ComputeLaunchMutationScope(request), ComputeLaunchMutationFingerprint(request), 1)
	request.Mutation.OperationID.Value = "op"
	intent = request.Mutation.Fingerprint
	if _, err := journal.Prepare(t.Context(), request.Mutation); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.MarkSubmitted(t.Context(), request.Mutation); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.ReconcileInstanceLaunch(t.Context(), request); err == nil || !strings.Contains(err.Error(), "duplicate intent") {
		t.Fatalf("duplicate recovery error = %v", err)
	}
	if posts != 0 || reads != 1 {
		t.Fatalf("duplicate recovery calls = posts %d reads %d", posts, reads)
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
}

func TestOCIComputeTerminationWaitsForTerminalAndNeverRepeatsSubmission(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted asynchronously", true: "response lost"}[lost], func(t *testing.T) {
			state := "RUNNING"
			reads404 := false
			deletes := 0
			transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
				if request.URL.Path != "/20160918/instances/ocid1.instance.oc1.x" {
					t.Fatalf("resource %s", request.URL.Path)
				}
				if request.Method == http.MethodGet {
					if reads404 {
						return testHTTPResponse(404, `{}`, nil), nil
					}
					etag := "etag-before"
					if state != "RUNNING" {
						etag = "etag-after"
					}
					body := `{"id":"ocid1.instance.oc1.x","compartmentId":"ocid1.compartment.oc1.x","lifecycleState":"` + state + `"}`
					return testHTTPResponse(200, body, http.Header{"Etag": []string{etag}}), nil
				}
				if request.Method != http.MethodDelete || request.Header.Get("If-Match") != "etag-before" {
					t.Fatalf("unconditional mutation %s %+v", request.Method, request.Header)
				}
				deletes++
				state = "TERMINATING"
				if lost {
					return nil, io.ErrUnexpectedEOF
				}
				return testHTTPResponse(202, ``, nil), nil
			})
			ownership, err := NewDurableOwnershipJournal(newTestOwnershipCAS(), 2)
			if err != nil {
				t.Fatal(err)
			}
			if err := ownership.Record(t.Context(), ProviderOwnershipRecord{ResourceId: ProviderResourceId{Value: "ocid1.instance.oc1.x"}, CompartmentId: ProviderCompartmentId{Value: "ocid1.compartment.oc1.x"}, CellId: ProviderCellId{Value: "gru"}, Generation: ProviderGeneration{Value: 1}}); err != nil {
				t.Fatal(err)
			}
			journal := testJournal(t)
			construct := func() *OCIComputeAdapter {
				return &OCIComputeAdapter{Core: transport, Journal: journal, Ownership: ownership}
			}
			request := ComputeTerminateRequest{InstanceID: "ocid1.instance.oc1.x", IfMatch: "etag-before"}
			request.Mutation = testMutation("compute.terminate", ComputeTerminateMutationScope(request), ComputeTerminateMutationFingerprint(request), 1)
			if err := construct().ReconcileInstanceTermination(t.Context(), request); !errors.Is(err, ErrComputeTerminationPending) || deletes != 0 {
				t.Fatalf("reconciliation submitted a live instance: deletes=%d error=%v", deletes, err)
			}
			if err := construct().TerminateInstance(t.Context(), request); err == nil {
				t.Fatal("accepted or unknown result completed before terminal")
			}
			reads404 = true
			if err := construct().ReconcileInstanceTermination(t.Context(), request); !errors.Is(err, ErrComputeTerminationPending) {
				t.Fatalf("reconciliation interpreted 404 as terminal: %v", err)
			}
			if err := construct().TerminateInstance(t.Context(), request); !errors.Is(err, ErrComputeTerminationPending) {
				t.Fatalf("404 interpreted as terminal: %v", err)
			}
			reads404 = false
			if err := construct().ReconcileInstanceTermination(t.Context(), request); !errors.Is(err, ErrComputeTerminationPending) {
				t.Fatalf("reconciliation completed terminating instance: %v", err)
			}
			if err := construct().TerminateInstance(t.Context(), request); !errors.Is(err, ErrComputeTerminationPending) {
				t.Fatalf("terminating restart: %v", err)
			}
			if deletes != 1 {
				t.Fatalf("duplicate destructive request: %d", deletes)
			}
			state = "TERMINATED"
			if err := construct().ReconcileInstanceTermination(t.Context(), request); err != nil {
				t.Fatal(err)
			}
			record, err := journal.Prepare(t.Context(), request.Mutation)
			if err != nil || record.State != MutationSucceeded || deletes != 1 {
				t.Fatalf("terminal record=%+v calls=%d err=%v", record, deletes, err)
			}
			reads404 = true
			if err := construct().ReconcileInstanceTermination(t.Context(), request); !errors.Is(err, ErrComputeTerminationPending) {
				t.Fatalf("completed reconciliation skipped authoritative terminal read: %v", err)
			}
		})
	}
}
