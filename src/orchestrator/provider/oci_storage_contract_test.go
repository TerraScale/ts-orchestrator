package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type testObjectAuthority struct {
	durable bool
	objects map[ObjectRef]ObjectStorageReservation
}

func (a *testObjectAuthority) AuthoritativeDurable() bool { return a != nil && a.durable }
func (a *testObjectAuthority) LookupObject(_ context.Context, object ObjectRef) (ObjectStorageReservation, bool, error) {
	reservation, found := a.objects[object]
	return reservation, found, nil
}

var (
	testObjectSignerOnce sync.Once
	testObjectSignerKey  *rsa.PrivateKey
	testObjectSignerErr  error
)

func testObjectAdapter(t *testing.T, transport *OCIHTTPTransport, journal ProviderMutationJournal, objects ...ObjectRef) *OCIObjectStorageAdapter {
	t.Helper()
	testObjectSignerOnce.Do(func() { testObjectSignerKey, testObjectSignerErr = rsa.GenerateKey(rand.Reader, 2048) })
	if testObjectSignerErr != nil {
		t.Fatal(testObjectSignerErr)
	}
	signer, err := NewInstancePrincipalSigner("ocid1.instance.oc1.sa-saopaulo-1.testsigner", testObjectSignerKey)
	if err != nil {
		t.Fatal(err)
	}
	signer.Now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	transport.Signer = signer
	reservations := make(map[ObjectRef]ObjectStorageReservation, len(objects))
	for _, object := range objects {
		reservations[object] = ObjectStorageReservation{Object: object}
	}
	adapter, err := NewOCIObjectStorageAdapter(transport, journal, OCIObjectStorageScope{
		Namespace: "namespace", LedgerBucket: "ledger", BackupBucket: "backups",
	}, &testObjectAuthority{durable: true, objects: reservations})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func testOwnership(t *testing.T, ids ...string) *DurableOwnershipJournal {
	t.Helper()
	journal, err := NewDurableOwnershipJournal(newTestOwnershipCAS(), 32)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		record := ProviderOwnershipRecord{ResourceId: ProviderResourceId{Value: id}, CellId: ProviderCellId{Value: "gru"}, CompartmentId: ProviderCompartmentId{Value: "ocid1.compartment.oc1..testcompartment"}, Generation: ProviderGeneration{Value: 1}}
		if err := journal.Record(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	}
	return journal
}

type nonDurableTestOwnership struct{}

func (*nonDurableTestOwnership) AuthoritativeDurable() bool { return false }
func (*nonDurableTestOwnership) Record(context.Context, ProviderOwnershipRecord) error {
	return nil
}
func (*nonDurableTestOwnership) Lookup(context.Context, ProviderResourceId) (ProviderOwnershipRecord, bool, error) {
	return ProviderOwnershipRecord{}, false, nil
}

func testRegistryAdapter(t *testing.T, transport *OCIHTTPTransport) *OCIRegistryAdapter {
	t.Helper()
	if transport.Signer == nil {
		signer, err := NewOCIRegistryTokenSigner("tenancy/runner", "registry-token")
		if err != nil {
			t.Fatal(err)
		}
		transport.Signer = signer
	}
	adapter, err := NewOCIRegistryAdapter(transport, OCIRegistryScope{
		Namespace:    "tenancy",
		Repositories: []string{"member", "terrascale/member"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func testVolumeIntentTags(request VolumeCreateRequest) string {
	tags, _ := safeFreeformTags(request.Tags)
	raw, _ := json.Marshal(bindMutationTags(tags, request.Mutation))
	return string(raw)
}

func TestOCIBlockVolumeAdapterContract(t *testing.T) {
	var requestBody map[string]any
	request := VolumeCreateRequest{CompartmentID: "ocid1.compartment.oc1..testcompartment", AvailabilityDomain: "AD-1", DisplayName: "data-node-a", SizeGiB: 100, VPUsPerGiB: 20, Tags: map[string]string{"role": "data"}}
	request.Mutation = testMutation("volume.create", VolumeCreateMutationScope(request), VolumeCreateMutationFingerprint(request), 2)
	transport := testOCITransport(t, OCIServiceCore, func(httpRequest *http.Request) (*http.Response, error) {
		if httpRequest.Method != http.MethodPost || httpRequest.URL.Path != "/20160918/volumes" {
			t.Fatalf("unexpected volume request %s %s", httpRequest.Method, httpRequest.URL.String())
		}
		if err := json.NewDecoder(httpRequest.Body).Decode(&requestBody); err != nil {
			t.Fatal(err)
		}
		body := `{"id":"ocid1.volume.oc1.sa-saopaulo-1.testvolume","compartmentId":"ocid1.compartment.oc1..testcompartment","availabilityDomain":"AD-1","displayName":"data-node-a","lifecycleState":"PROVISIONING","sizeInGBs":100,"vpusPerGB":20,"freeformTags":` + testVolumeIntentTags(request) + `}`
		return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"volume-etag"}}), nil
	})
	adapter, err := NewOCIBlockStorageAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	volume, err := adapter.CreateVolume(context.Background(), request)
	if err != nil || volume.ID != "ocid1.volume.oc1.sa-saopaulo-1.testvolume" || volume.ETag != "volume-etag" {
		t.Fatalf("create volume = %+v, %v", volume, err)
	}
	if requestBody["sizeInGBs"] != float64(100) || requestBody["vpusPerGB"] != float64(20) || requestBody["freeformTags"].(map[string]any)["terrascale-intent"] != request.Mutation.Fingerprint {
		t.Fatalf("volume create payload = %+v", requestBody)
	}
}

func TestOCIVolumeAttachmentAdapterContract(t *testing.T) {
	var requestBody map[string]any
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/20160918/volumeAttachments" {
			t.Fatalf("unexpected attachment request %s %s", request.Method, request.URL.String())
		}
		if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
			t.Fatal(err)
		}
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.volumeattachment.oc1.sa-saopaulo-1.testattachment","compartmentId":"ocid1.compartment.oc1..testcompartment","instanceId":"ocid1.instance.oc1.sa-saopaulo-1.testinstance","volumeId":"ocid1.volume.oc1.sa-saopaulo-1.testvolume","displayName":"data-node-a","isReadOnly":false,"lifecycleState":"ATTACHING"}`, http.Header{"Etag": {"attachment-etag"}}), nil
	})
	adapter, err := NewOCIVolumeAttachmentAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	adapter.Ownership = testOwnership(t, "ocid1.instance.oc1.sa-saopaulo-1.testinstance", "ocid1.volume.oc1.sa-saopaulo-1.testvolume")
	request := VolumeAttachRequest{CompartmentID: "ocid1.compartment.oc1..testcompartment", InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.testinstance", VolumeID: "ocid1.volume.oc1.sa-saopaulo-1.testvolume", DisplayName: "data-node-a"}
	request.Mutation = testMutation("attachment.create", VolumeAttachMutationScope(request), VolumeAttachMutationFingerprint(request), 3)
	attachment, err := adapter.AttachVolume(context.Background(), request)
	if err != nil || attachment.ID != "ocid1.volumeattachment.oc1.sa-saopaulo-1.testattachment" || attachment.ETag != "attachment-etag" {
		t.Fatalf("attach volume = %+v, %v", attachment, err)
	}
	if requestBody["type"] != "iscsi" || requestBody["compartmentId"] != request.CompartmentID || requestBody["instanceId"] != request.InstanceID || requestBody["volumeId"] != request.VolumeID {
		t.Fatalf("attachment payload = %+v", requestBody)
	}
}

func TestOCIStorageProductionAsyncPathsPreserveProviderTruth(t *testing.T) {
	const (
		compartment  = "ocid1.compartment.oc1..testcompartment"
		volumeID     = "ocid1.volume.oc1.sa-saopaulo-1.asyncvolume"
		instanceID   = "ocid1.instance.oc1.sa-saopaulo-1.asyncinstance"
		attachmentID = "ocid1.volumeattachment.oc1.sa-saopaulo-1.asyncattachment"
	)
	policy := WorkRequestWaitPolicy{PollInterval: 0, MaxPolls: 1, MaxNotFound: 0}

	t.Run("volume create success", func(t *testing.T) {
		posts := 0
		request := VolumeCreateRequest{CompartmentID: compartment, AvailabilityDomain: "AD-1", DisplayName: "async-volume", SizeGiB: 100, VPUsPerGiB: 20}
		request.Mutation = testMutation("volume.create", VolumeCreateMutationScope(request), VolumeCreateMutationFingerprint(request), 1)
		transport := testOCITransport(t, OCIServiceCore, func(httpRequest *http.Request) (*http.Response, error) {
			switch {
			case httpRequest.Method == http.MethodPost && httpRequest.URL.Path == "/20160918/volumes":
				posts++
				body := `{"id":"` + volumeID + `","compartmentId":"` + compartment + `","availabilityDomain":"AD-1","displayName":"async-volume","lifecycleState":"PROVISIONING","sizeInGBs":100,"vpusPerGB":20,"freeformTags":` + testVolumeIntentTags(request) + `}`
				return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"volume-etag"}, "Opc-Work-Request-Id": {"volume-work"}}), nil
			case httpRequest.Method == http.MethodGet && httpRequest.URL.Path == "/20160918/workRequests/volume-work":
				return testHTTPResponse(http.StatusOK, `{"id":"volume-work","status":"SUCCEEDED","percentComplete":100}`, nil), nil
			default:
				t.Fatalf("unexpected volume create request %s %s", httpRequest.Method, httpRequest.URL.String())
				return nil, io.ErrUnexpectedEOF
			}
		})
		journal := testJournal(t)
		adapter, err := NewOCIBlockStorageAdapter(transport, journal)
		if err != nil {
			t.Fatal(err)
		}
		adapter.waitPolicy = policy
		volume, err := adapter.CreateVolume(context.Background(), request)
		if err != nil || volume.ID != volumeID || posts != 1 {
			t.Fatalf("async volume create = %+v posts=%d err=%v", volume, posts, err)
		}
		record, err := journal.Prepare(context.Background(), request.Mutation)
		want := ProviderMutationResult{ResourceID: volumeID, ETag: "volume-etag", WorkRequestID: "volume-work"}
		if err != nil || record.State != MutationSucceeded || record.Result != want {
			t.Fatalf("async volume create record = %+v err=%v", record, err)
		}
	})

	t.Run("volume create work success without resource proof stays unknown", func(t *testing.T) {
		posts := 0
		transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
			switch {
			case request.Method == http.MethodPost && request.URL.Path == "/20160918/volumes":
				posts++
				return testHTTPResponse(http.StatusOK, `not-json`, http.Header{"Etag": {"unbound-etag"}, "Opc-Work-Request-Id": {"unbound-work"}}), nil
			case request.Method == http.MethodGet && request.URL.Path == "/20160918/workRequests/unbound-work":
				return testHTTPResponse(http.StatusOK, `{"id":"unbound-work","status":"SUCCEEDED","percentComplete":100}`, nil), nil
			default:
				t.Fatalf("unexpected unbound volume request %s %s", request.Method, request.URL.String())
				return nil, io.ErrUnexpectedEOF
			}
		})
		journal := testJournal(t)
		adapter, err := NewOCIBlockStorageAdapter(transport, journal)
		if err != nil {
			t.Fatal(err)
		}
		adapter.waitPolicy = policy
		request := VolumeCreateRequest{CompartmentID: compartment, AvailabilityDomain: "AD-1", DisplayName: "unbound-volume", SizeGiB: 100, VPUsPerGiB: 20}
		request.Mutation = testMutation("volume.create", VolumeCreateMutationScope(request), VolumeCreateMutationFingerprint(request), 1)
		if _, err := adapter.CreateVolume(context.Background(), request); err == nil {
			t.Fatal("work success without a scope-bound resource result was accepted")
		}
		record, err := journal.Prepare(context.Background(), request.Mutation)
		want := ProviderMutationResult{ETag: "unbound-etag", WorkRequestID: "unbound-work"}
		if err != nil || record.State != MutationUnknown || record.Result != want || posts != 1 {
			t.Fatalf("unbound volume create record = %+v posts=%d err=%v", record, posts, err)
		}
	})

	t.Run("attachment create failure", func(t *testing.T) {
		posts := 0
		transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
			switch {
			case request.Method == http.MethodPost && request.URL.Path == "/20160918/volumeAttachments":
				posts++
				body := `{"id":"` + attachmentID + `","compartmentId":"` + compartment + `","instanceId":"` + instanceID + `","volumeId":"` + volumeID + `","displayName":"async-attachment","isReadOnly":true,"lifecycleState":"ATTACHING"}`
				return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"attachment-etag"}, "Opc-Work-Request-Id": {"attachment-work"}}), nil
			case request.Method == http.MethodGet && request.URL.Path == "/20160918/workRequests/attachment-work":
				return testHTTPResponse(http.StatusOK, `{"id":"attachment-work","status":"FAILED","percentComplete":100}`, nil), nil
			default:
				t.Fatalf("unexpected attachment create request %s %s", request.Method, request.URL.String())
				return nil, io.ErrUnexpectedEOF
			}
		})
		journal := testJournal(t)
		adapter, err := NewOCIVolumeAttachmentAdapter(transport, journal)
		if err != nil {
			t.Fatal(err)
		}
		adapter.waitPolicy = policy
		adapter.Ownership = testOwnership(t, instanceID, volumeID)
		request := VolumeAttachRequest{CompartmentID: compartment, InstanceID: instanceID, VolumeID: volumeID, DisplayName: "async-attachment", ReadOnly: true}
		request.Mutation = testMutation("attachment.create", VolumeAttachMutationScope(request), VolumeAttachMutationFingerprint(request), 2)
		if _, err := adapter.AttachVolume(context.Background(), request); err == nil {
			t.Fatal("failed attachment work request was accepted")
		}
		record, err := journal.Prepare(context.Background(), request.Mutation)
		want := ProviderMutationResult{ResourceID: attachmentID, ETag: "attachment-etag", WorkRequestID: "attachment-work"}
		if err != nil || record.State != MutationFailed || record.Result != want || record.FailureCode != "provider-work-request-failed" || posts != 1 {
			t.Fatalf("failed attachment record = %+v posts=%d err=%v", record, posts, err)
		}
	})

	t.Run("volume delete invisibility then restart success", func(t *testing.T) {
		deletes := 0
		workVisible := false
		transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
			switch {
			case request.Method == http.MethodGet && request.URL.Path == "/20160918/volumes/"+volumeID:
				body := `{"id":"` + volumeID + `","compartmentId":"` + compartment + `","lifecycleState":"AVAILABLE","sizeInGBs":100,"vpusPerGB":20}`
				return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"volume-etag"}}), nil
			case request.Method == http.MethodDelete && request.URL.Path == "/20160918/volumes/"+volumeID:
				deletes++
				return testHTTPResponse(http.StatusAccepted, "", http.Header{"Opc-Work-Request-Id": {"delete-volume-work"}}), nil
			case request.Method == http.MethodGet && request.URL.Path == "/20160918/workRequests/delete-volume-work":
				if !workVisible {
					return testHTTPResponse(http.StatusNotFound, "", nil), nil
				}
				return testHTTPResponse(http.StatusOK, `{"id":"delete-volume-work","status":"SUCCEEDED","percentComplete":100}`, nil), nil
			default:
				t.Fatalf("unexpected volume delete request %s %s", request.Method, request.URL.String())
				return nil, io.ErrUnexpectedEOF
			}
		})
		journal := testJournal(t)
		adapter, err := NewOCIBlockStorageAdapter(transport, journal)
		if err != nil {
			t.Fatal(err)
		}
		adapter.waitPolicy = policy
		adapter.Ownership = testOwnership(t, volumeID)
		request := VolumeDeleteRequest{VolumeID: volumeID, IfMatch: "volume-etag"}
		request.Mutation = testMutation("volume.delete", VolumeDeleteMutationScope(request), VolumeDeleteMutationFingerprint(request), 3)
		if err := adapter.DeleteVolume(context.Background(), request); err == nil {
			t.Fatal("invisible volume work request was accepted")
		}
		want := ProviderMutationResult{ResourceID: volumeID, ETag: "volume-etag", WorkRequestID: "delete-volume-work"}
		record, err := journal.Prepare(context.Background(), request.Mutation)
		if err != nil || record.State != MutationUnknown || record.Result != want || deletes != 1 {
			t.Fatalf("invisible volume delete record = %+v deletes=%d err=%v", record, deletes, err)
		}
		workVisible = true
		request.Mutation.Epoch.Value++
		if err := adapter.DeleteVolume(context.Background(), request); err != nil {
			t.Fatalf("restarted volume delete = %v", err)
		}
		record, err = journal.Prepare(context.Background(), request.Mutation)
		if err != nil || record.State != MutationSucceeded || record.Result != want || deletes != 1 {
			t.Fatalf("restarted volume delete record = %+v deletes=%d err=%v", record, deletes, err)
		}
	})

	t.Run("attachment delete cancellation", func(t *testing.T) {
		deletes := 0
		transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
			switch {
			case request.Method == http.MethodGet && request.URL.Path == "/20160918/volumeAttachments/"+attachmentID:
				body := `{"id":"` + attachmentID + `","compartmentId":"` + compartment + `","instanceId":"` + instanceID + `","volumeId":"` + volumeID + `","isReadOnly":false,"lifecycleState":"ATTACHED"}`
				return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"attachment-etag"}}), nil
			case request.Method == http.MethodDelete && request.URL.Path == "/20160918/volumeAttachments/"+attachmentID:
				deletes++
				return testHTTPResponse(http.StatusAccepted, "", http.Header{"Opc-Work-Request-Id": {"detach-work"}}), nil
			case request.Method == http.MethodGet && request.URL.Path == "/20160918/workRequests/detach-work":
				return testHTTPResponse(http.StatusOK, `{"id":"detach-work","status":"CANCELED","percentComplete":50}`, nil), nil
			default:
				t.Fatalf("unexpected attachment delete request %s %s", request.Method, request.URL.String())
				return nil, io.ErrUnexpectedEOF
			}
		})
		journal := testJournal(t)
		adapter, err := NewOCIVolumeAttachmentAdapter(transport, journal)
		if err != nil {
			t.Fatal(err)
		}
		adapter.waitPolicy = policy
		adapter.Ownership = testOwnership(t, attachmentID)
		request := VolumeDetachRequest{AttachmentID: attachmentID, IfMatch: "attachment-etag"}
		request.Mutation = testMutation("attachment.delete", VolumeDetachMutationScope(request), VolumeDetachMutationFingerprint(request), 4)
		if err := adapter.DetachVolume(context.Background(), request); err == nil {
			t.Fatal("canceled detach work request was accepted")
		}
		want := ProviderMutationResult{ResourceID: attachmentID, ETag: "attachment-etag", WorkRequestID: "detach-work"}
		record, err := journal.Prepare(context.Background(), request.Mutation)
		if err != nil || record.State != MutationFailed || record.Result != want || record.FailureCode != "provider-work-request-canceled" || deletes != 1 {
			t.Fatalf("canceled detach record = %+v deletes=%d err=%v", record, deletes, err)
		}
	})
}

func TestOCIStorageCreateRestartRevalidatesRecordedResource(t *testing.T) {
	const (
		compartment = "ocid1.compartment.oc1..testcompartment"
		volumeID    = "ocid1.volume.oc1.sa-saopaulo-1.mismatchedrestart"
	)
	posts := 0
	request := VolumeCreateRequest{CompartmentID: compartment, AvailabilityDomain: "AD-1", DisplayName: "restart-volume", SizeGiB: 100, VPUsPerGiB: 20, Tags: map[string]string{"role": "data"}}
	request.Mutation = testMutation("volume.create", VolumeCreateMutationScope(request), VolumeCreateMutationFingerprint(request), 1)
	transport := testOCITransport(t, OCIServiceCore, func(httpRequest *http.Request) (*http.Response, error) {
		switch {
		case httpRequest.Method == http.MethodPost && httpRequest.URL.Path == "/20160918/volumes":
			posts++
			body := `{"id":"` + volumeID + `","compartmentId":"` + compartment + `","availabilityDomain":"AD-2","displayName":"other-volume","lifecycleState":"PROVISIONING","sizeInGBs":101,"vpusPerGB":20,"freeformTags":` + testVolumeIntentTags(request) + `}`
			return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"mismatched-etag"}, "Opc-Work-Request-Id": {"mismatched-work"}}), nil
		case httpRequest.Method == http.MethodGet && httpRequest.URL.Path == "/20160918/workRequests/mismatched-work":
			return testHTTPResponse(http.StatusOK, `{"id":"mismatched-work","status":"SUCCEEDED","percentComplete":100}`, nil), nil
		case httpRequest.Method == http.MethodGet && httpRequest.URL.Path == "/20160918/volumes/"+volumeID:
			body := `{"id":"` + volumeID + `","compartmentId":"` + compartment + `","availabilityDomain":"AD-2","displayName":"other-volume","lifecycleState":"AVAILABLE","sizeInGBs":101,"vpusPerGB":20,"freeformTags":` + testVolumeIntentTags(request) + `}`
			return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"current-etag"}}), nil
		default:
			t.Fatalf("unexpected mismatched restart request %s %s", httpRequest.Method, httpRequest.URL.String())
			return nil, io.ErrUnexpectedEOF
		}
	})
	journal := testJournal(t)
	adapter, err := NewOCIBlockStorageAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	adapter.waitPolicy = WorkRequestWaitPolicy{PollInterval: 0, MaxPolls: 1, MaxNotFound: 0}
	if _, err := adapter.CreateVolume(context.Background(), request); err == nil {
		t.Fatal("mismatched initial volume response was accepted")
	}
	want := ProviderMutationResult{ResourceID: volumeID, ETag: "mismatched-etag", WorkRequestID: "mismatched-work"}
	record, err := journal.Prepare(context.Background(), request.Mutation)
	if err != nil || record.State != MutationUnknown || record.Result != want || posts != 1 {
		t.Fatalf("mismatched initial record = %+v posts=%d err=%v", record, posts, err)
	}
	request.Mutation.Epoch.Value++
	if _, err := adapter.CreateVolume(context.Background(), request); err == nil {
		t.Fatal("mismatched recorded resource became trusted after restart")
	}
	record, err = journal.Prepare(context.Background(), request.Mutation)
	if err != nil || record.State != MutationUnknown || record.Result != want || posts != 1 {
		t.Fatalf("mismatched restart record = %+v posts=%d err=%v", record, posts, err)
	}
}

func TestOCIAttachmentCreateRestartPollsPartialWorkBeforeReconciliation(t *testing.T) {
	const (
		compartment  = "ocid1.compartment.oc1..testcompartment"
		volumeID     = "ocid1.volume.oc1.sa-saopaulo-1.partialwork"
		instanceID   = "ocid1.instance.oc1.sa-saopaulo-1.partialwork"
		attachmentID = "ocid1.volumeattachment.oc1.sa-saopaulo-1.partialwork"
	)
	tests := []struct {
		name        string
		status      string
		wantState   ProviderMutationState
		wantFailure string
		wantError   bool
	}{
		{name: "succeeded", status: "SUCCEEDED", wantState: MutationSucceeded},
		{name: "failed", status: "FAILED", wantState: MutationFailed, wantFailure: "provider-work-request-failed", wantError: true},
		{name: "canceled", status: "CANCELED", wantState: MutationFailed, wantFailure: "provider-work-request-canceled", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			posts := 0
			terminal := false
			request := VolumeAttachRequest{CompartmentID: compartment, InstanceID: instanceID, VolumeID: volumeID, DisplayName: "partial-attachment", ReadOnly: true}
			request.Mutation = testMutation("attachment.create", VolumeAttachMutationScope(request), VolumeAttachMutationFingerprint(request), 1)
			transport := testOCITransport(t, OCIServiceCore, func(httpRequest *http.Request) (*http.Response, error) {
				switch {
				case httpRequest.Method == http.MethodPost && httpRequest.URL.Path == "/20160918/volumeAttachments":
					posts++
					return testHTTPResponse(http.StatusOK, `not-json`, http.Header{"Opc-Work-Request-Id": {"partial-work"}}), nil
				case httpRequest.Method == http.MethodGet && httpRequest.URL.Path == "/20160918/workRequests/partial-work":
					if !terminal {
						return testHTTPResponse(http.StatusNotFound, "", nil), nil
					}
					body := `{"id":"partial-work","status":"` + test.status + `","percentComplete":100}`
					return testHTTPResponse(http.StatusOK, body, nil), nil
				case httpRequest.Method == http.MethodGet && httpRequest.URL.Path == "/20160918/volumeAttachments":
					body := `{"items":[{"id":"` + attachmentID + `","compartmentId":"` + compartment + `","instanceId":"` + instanceID + `","volumeId":"` + volumeID + `","displayName":"partial-attachment","isReadOnly":true,"lifecycleState":"ATTACHED"}]}`
					return testHTTPResponse(http.StatusOK, body, nil), nil
				case httpRequest.Method == http.MethodGet && httpRequest.URL.Path == "/20160918/volumeAttachments/"+attachmentID:
					body := `{"id":"` + attachmentID + `","compartmentId":"` + compartment + `","instanceId":"` + instanceID + `","volumeId":"` + volumeID + `","displayName":"partial-attachment","isReadOnly":true,"lifecycleState":"ATTACHED"}`
					return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"attachment-etag"}}), nil
				default:
					t.Fatalf("unexpected partial work request %s %s", httpRequest.Method, httpRequest.URL.String())
					return nil, io.ErrUnexpectedEOF
				}
			})
			journal := testJournal(t)
			adapter, err := NewOCIVolumeAttachmentAdapter(transport, journal)
			if err != nil {
				t.Fatal(err)
			}
			adapter.waitPolicy = WorkRequestWaitPolicy{PollInterval: 0, MaxPolls: 1, MaxNotFound: 0}
			adapter.Ownership = testOwnership(t, instanceID, volumeID)
			if _, err := adapter.AttachVolume(context.Background(), request); err == nil {
				t.Fatal("invisible partial work request was accepted")
			}
			partial := ProviderMutationResult{WorkRequestID: "partial-work"}
			record, err := journal.Prepare(context.Background(), request.Mutation)
			if err != nil || record.State != MutationUnknown || record.Result != partial || posts != 1 {
				t.Fatalf("partial initial record = %+v posts=%d err=%v", record, posts, err)
			}
			terminal = true
			request.Mutation.Epoch.Value++
			attachment, resumeErr := adapter.AttachVolume(context.Background(), request)
			if (resumeErr != nil) != test.wantError {
				t.Fatalf("partial resume error = %v wantError=%v", resumeErr, test.wantError)
			}
			record, err = journal.Prepare(context.Background(), request.Mutation)
			if err != nil || record.State != test.wantState || record.FailureCode != test.wantFailure || posts != 1 {
				t.Fatalf("partial terminal record = %+v posts=%d err=%v", record, posts, err)
			}
			if test.wantState == MutationSucceeded {
				want := ProviderMutationResult{ResourceID: attachmentID, ETag: "attachment-etag", WorkRequestID: "partial-work"}
				if record.Result != want || attachment.ID != attachmentID || attachment.WorkRequestID != "partial-work" {
					t.Fatalf("partial success result = %+v attachment=%+v", record.Result, attachment)
				}
			} else if record.Result != partial {
				t.Fatalf("partial failure result changed: %+v", record.Result)
			}
		})
	}
}

func TestOCIStorageCreateRestartPreservesSubmittedProviderResult(t *testing.T) {
	const (
		compartment  = "ocid1.compartment.oc1..testcompartment"
		volumeID     = "ocid1.volume.oc1.sa-saopaulo-1.submittedresult"
		instanceID   = "ocid1.instance.oc1.sa-saopaulo-1.submittedresult"
		attachmentID = "ocid1.volumeattachment.oc1.sa-saopaulo-1.submittedresult"
	)
	policy := WorkRequestWaitPolicy{PollInterval: 0, MaxPolls: 1, MaxNotFound: 0}

	t.Run("volume", func(t *testing.T) {
		posts := 0
		terminal := false
		request := VolumeCreateRequest{CompartmentID: compartment, AvailabilityDomain: "AD-1", DisplayName: "submitted-volume", SizeGiB: 100, VPUsPerGiB: 20, Tags: map[string]string{"role": "data"}}
		request.Mutation = testMutation("volume.create", VolumeCreateMutationScope(request), VolumeCreateMutationFingerprint(request), 1)
		transport := testOCITransport(t, OCIServiceCore, func(httpRequest *http.Request) (*http.Response, error) {
			switch {
			case httpRequest.Method == http.MethodPost && httpRequest.URL.Path == "/20160918/volumes":
				posts++
				body := `{"id":"` + volumeID + `","compartmentId":"` + compartment + `","availabilityDomain":"AD-1","displayName":"submitted-volume","lifecycleState":"PROVISIONING","sizeInGBs":100,"vpusPerGB":20,"freeformTags":` + testVolumeIntentTags(request) + `}`
				return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"submitted-volume-etag"}, "Opc-Work-Request-Id": {"submitted-volume-work"}}), nil
			case httpRequest.Method == http.MethodGet && httpRequest.URL.Path == "/20160918/workRequests/submitted-volume-work":
				if !terminal {
					return testHTTPResponse(http.StatusNotFound, "", nil), nil
				}
				return testHTTPResponse(http.StatusOK, `{"id":"submitted-volume-work","status":"SUCCEEDED","percentComplete":100}`, nil), nil
			case httpRequest.Method == http.MethodGet && httpRequest.URL.Path == "/20160918/volumes/"+volumeID:
				body := `{"id":"` + volumeID + `","compartmentId":"` + compartment + `","availabilityDomain":"AD-1","displayName":"submitted-volume","lifecycleState":"AVAILABLE","sizeInGBs":100,"vpusPerGB":20,"freeformTags":` + testVolumeIntentTags(request) + `}`
				return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"current-volume-etag"}}), nil
			default:
				t.Fatalf("unexpected submitted volume request %s %s", httpRequest.Method, httpRequest.URL.String())
				return nil, io.ErrUnexpectedEOF
			}
		})
		journal := testJournal(t)
		adapter, err := NewOCIBlockStorageAdapter(transport, journal)
		if err != nil {
			t.Fatal(err)
		}
		adapter.waitPolicy = policy
		if _, err := adapter.CreateVolume(context.Background(), request); err == nil {
			t.Fatal("invisible submitted volume work request was accepted")
		}
		want := ProviderMutationResult{ResourceID: volumeID, ETag: "submitted-volume-etag", WorkRequestID: "submitted-volume-work"}
		record, err := journal.Prepare(context.Background(), request.Mutation)
		if err != nil || record.State != MutationUnknown || record.Result != want || posts != 1 {
			t.Fatalf("submitted volume record = %+v posts=%d err=%v", record, posts, err)
		}
		terminal = true
		request.Mutation.Epoch.Value++
		volume, err := adapter.CreateVolume(context.Background(), request)
		if err != nil || volume.ID != volumeID || volume.ETag != want.ETag || volume.WorkRequestID != want.WorkRequestID || posts != 1 {
			t.Fatalf("resumed volume = %+v posts=%d err=%v", volume, posts, err)
		}
		record, err = journal.Prepare(context.Background(), request.Mutation)
		if err != nil || record.State != MutationSucceeded || record.Result != want {
			t.Fatalf("resumed volume record = %+v err=%v", record, err)
		}
	})

	t.Run("attachment", func(t *testing.T) {
		posts := 0
		terminal := false
		request := VolumeAttachRequest{CompartmentID: compartment, InstanceID: instanceID, VolumeID: volumeID, DisplayName: "submitted-attachment", ReadOnly: true}
		request.Mutation = testMutation("attachment.create", VolumeAttachMutationScope(request), VolumeAttachMutationFingerprint(request), 1)
		transport := testOCITransport(t, OCIServiceCore, func(httpRequest *http.Request) (*http.Response, error) {
			switch {
			case httpRequest.Method == http.MethodPost && httpRequest.URL.Path == "/20160918/volumeAttachments":
				posts++
				body := `{"id":"` + attachmentID + `","compartmentId":"` + compartment + `","instanceId":"` + instanceID + `","volumeId":"` + volumeID + `","displayName":"submitted-attachment","isReadOnly":true,"lifecycleState":"ATTACHING"}`
				return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"submitted-attachment-etag"}, "Opc-Work-Request-Id": {"submitted-attachment-work"}}), nil
			case httpRequest.Method == http.MethodGet && httpRequest.URL.Path == "/20160918/workRequests/submitted-attachment-work":
				if !terminal {
					return testHTTPResponse(http.StatusNotFound, "", nil), nil
				}
				return testHTTPResponse(http.StatusOK, `{"id":"submitted-attachment-work","status":"SUCCEEDED","percentComplete":100}`, nil), nil
			case httpRequest.Method == http.MethodGet && httpRequest.URL.Path == "/20160918/volumeAttachments/"+attachmentID:
				body := `{"id":"` + attachmentID + `","compartmentId":"` + compartment + `","instanceId":"` + instanceID + `","volumeId":"` + volumeID + `","displayName":"submitted-attachment","isReadOnly":true,"lifecycleState":"ATTACHED"}`
				return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"current-attachment-etag"}}), nil
			default:
				t.Fatalf("unexpected submitted attachment request %s %s", httpRequest.Method, httpRequest.URL.String())
				return nil, io.ErrUnexpectedEOF
			}
		})
		journal := testJournal(t)
		adapter, err := NewOCIVolumeAttachmentAdapter(transport, journal)
		if err != nil {
			t.Fatal(err)
		}
		adapter.waitPolicy = policy
		adapter.Ownership = testOwnership(t, instanceID, volumeID)
		if _, err := adapter.AttachVolume(context.Background(), request); err == nil {
			t.Fatal("invisible submitted attachment work request was accepted")
		}
		want := ProviderMutationResult{ResourceID: attachmentID, ETag: "submitted-attachment-etag", WorkRequestID: "submitted-attachment-work"}
		record, err := journal.Prepare(context.Background(), request.Mutation)
		if err != nil || record.State != MutationUnknown || record.Result != want || posts != 1 {
			t.Fatalf("submitted attachment record = %+v posts=%d err=%v", record, posts, err)
		}
		terminal = true
		request.Mutation.Epoch.Value++
		attachment, err := adapter.AttachVolume(context.Background(), request)
		if err != nil || attachment.ID != attachmentID || attachment.ETag != want.ETag || attachment.WorkRequestID != want.WorkRequestID || posts != 1 {
			t.Fatalf("resumed attachment = %+v posts=%d err=%v", attachment, posts, err)
		}
		record, err = journal.Prepare(context.Background(), request.Mutation)
		if err != nil || record.State != MutationSucceeded || record.Result != want {
			t.Fatalf("resumed attachment record = %+v err=%v", record, err)
		}
	})
}

func TestOCIStorageReconciliationIsPagedScopedAndIntentBound(t *testing.T) {
	const (
		compartment  = "ocid1.compartment.oc1..testcompartment"
		volumeID     = "ocid1.volume.oc1.sa-saopaulo-1.reconciled"
		instanceID   = "ocid1.instance.oc1.sa-saopaulo-1.reconciled"
		attachmentID = "ocid1.volumeattachment.oc1.sa-saopaulo-1.reconciled"
	)

	volumeRequest := VolumeCreateRequest{CompartmentID: compartment, AvailabilityDomain: "AD-1", DisplayName: "reconciled-volume", SizeGiB: 100, VPUsPerGiB: 20}
	volumeRequest.Mutation = testMutation("volume.create", VolumeCreateMutationScope(volumeRequest), VolumeCreateMutationFingerprint(volumeRequest), 1)
	volumeJournal := testJournal(t)
	if _, err := volumeJournal.Prepare(context.Background(), volumeRequest.Mutation); err != nil {
		t.Fatal(err)
	}
	if _, err := volumeJournal.MarkSubmitted(context.Background(), volumeRequest.Mutation); err != nil {
		t.Fatal(err)
	}
	volumeCalls := 0
	volumeTransport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		volumeCalls++
		if request.Method != http.MethodGet || request.URL.Query().Get("compartmentId") != compartment && request.URL.Path == "/20160918/volumes" {
			t.Fatalf("unscoped volume reconciliation request %s %s", request.Method, request.URL.String())
		}
		if request.URL.Path == "/20160918/volumes/"+volumeID {
			body := `{"id":"` + volumeID + `","compartmentId":"` + compartment + `","availabilityDomain":"AD-1","displayName":"reconciled-volume","lifecycleState":"AVAILABLE","sizeInGBs":100,"vpusPerGB":20,"freeformTags":` + testVolumeIntentTags(volumeRequest) + `}`
			return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"reconciled-volume-etag"}}), nil
		}
		if request.URL.Query().Get("page") == "" {
			return testHTTPResponse(http.StatusOK, `{"items":[]}`, http.Header{"Opc-Next-Page": {"page-2"}}), nil
		}
		body := `{"items":[{"id":"` + volumeID + `","compartmentId":"` + compartment + `","availabilityDomain":"AD-1","displayName":"reconciled-volume","lifecycleState":"AVAILABLE","sizeInGBs":100,"vpusPerGB":20,"freeformTags":{"terrascale-operation":"` + volumeRequest.Mutation.OperationID.Value + `","terrascale-intent":"` + volumeRequest.Mutation.Fingerprint + `"}}]}`
		return testHTTPResponse(http.StatusOK, body, nil), nil
	})
	volumeAdapter, err := NewOCIBlockStorageAdapter(volumeTransport, volumeJournal)
	if err != nil {
		t.Fatal(err)
	}
	volume, err := volumeAdapter.CreateVolume(context.Background(), volumeRequest)
	if err != nil || volume.ID != volumeID || volume.ETag != "reconciled-volume-etag" || volumeCalls != 3 {
		t.Fatalf("paged volume reconciliation = %+v calls=%d err=%v", volume, volumeCalls, err)
	}

	attachmentRequest := VolumeAttachRequest{CompartmentID: compartment, InstanceID: instanceID, VolumeID: volumeID, DisplayName: "reconciled-attachment", ReadOnly: true}
	attachmentRequest.Mutation = testMutation("attachment.create", VolumeAttachMutationScope(attachmentRequest), VolumeAttachMutationFingerprint(attachmentRequest), 2)
	attachmentJournal := testJournal(t)
	if _, err := attachmentJournal.Prepare(context.Background(), attachmentRequest.Mutation); err != nil {
		t.Fatal(err)
	}
	if _, err := attachmentJournal.MarkSubmitted(context.Background(), attachmentRequest.Mutation); err != nil {
		t.Fatal(err)
	}
	attachmentCalls := 0
	attachmentTransport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		attachmentCalls++
		if request.URL.Path == "/20160918/volumeAttachments/"+attachmentID {
			body := `{"id":"` + attachmentID + `","compartmentId":"` + compartment + `","instanceId":"` + instanceID + `","volumeId":"` + volumeID + `","displayName":"reconciled-attachment","isReadOnly":true,"lifecycleState":"ATTACHED"}`
			return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"reconciled-attachment-etag"}}), nil
		}
		if request.Method != http.MethodGet || request.URL.Path != "/20160918/volumeAttachments" || request.URL.Query().Get("compartmentId") != compartment || request.URL.Query().Get("instanceId") != instanceID || request.URL.Query().Get("volumeId") != volumeID {
			t.Fatalf("unscoped attachment reconciliation request %s %s", request.Method, request.URL.String())
		}
		if request.URL.Query().Get("page") == "" {
			return testHTTPResponse(http.StatusOK, `{"items":[]}`, http.Header{"Opc-Next-Page": {"page-2"}}), nil
		}
		body := `{"items":[{"id":"` + attachmentID + `","compartmentId":"` + compartment + `","instanceId":"` + instanceID + `","volumeId":"` + volumeID + `","displayName":"reconciled-attachment","isReadOnly":true,"lifecycleState":"ATTACHED"}]}`
		return testHTTPResponse(http.StatusOK, body, nil), nil
	})
	attachmentAdapter, err := NewOCIVolumeAttachmentAdapter(attachmentTransport, attachmentJournal)
	if err != nil {
		t.Fatal(err)
	}
	attachmentAdapter.Ownership = testOwnership(t, instanceID, volumeID)
	attachment, err := attachmentAdapter.AttachVolume(context.Background(), attachmentRequest)
	if err != nil || attachment.ID != attachmentID || attachment.ETag != "reconciled-attachment-etag" || attachmentCalls != 3 {
		t.Fatalf("paged attachment reconciliation = %+v calls=%d err=%v", attachment, attachmentCalls, err)
	}
}

func TestOCIStorageCreateResponsesMustMatchDurableIntent(t *testing.T) {
	const (
		compartment = "ocid1.compartment.oc1..testcompartment"
		volumeID    = "ocid1.volume.oc1.sa-saopaulo-1.binding"
		instanceID  = "ocid1.instance.oc1.sa-saopaulo-1.binding"
	)

	t.Run("volume immutable attributes", func(t *testing.T) {
		transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
			body := `{"id":"` + volumeID + `","compartmentId":"` + compartment + `","availabilityDomain":"AD-2","displayName":"bound-volume","lifecycleState":"PROVISIONING","sizeInGBs":101,"vpusPerGB":20}`
			return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"volume-etag"}}), nil
		})
		journal := testJournal(t)
		adapter, err := NewOCIBlockStorageAdapter(transport, journal)
		if err != nil {
			t.Fatal(err)
		}
		request := VolumeCreateRequest{CompartmentID: compartment, AvailabilityDomain: "AD-1", DisplayName: "bound-volume", SizeGiB: 100, VPUsPerGiB: 20}
		request.Mutation = testMutation("volume.create", VolumeCreateMutationScope(request), VolumeCreateMutationFingerprint(request), 1)
		if _, err := adapter.CreateVolume(context.Background(), request); err == nil {
			t.Fatal("volume response with mismatched placement and size was accepted")
		}
		record, err := journal.Prepare(context.Background(), request.Mutation)
		if err != nil || record.State != MutationUnknown || record.Result.ResourceID != volumeID || record.Result.ETag != "volume-etag" {
			t.Fatalf("mismatched volume record = %+v err=%v", record, err)
		}
	})

	t.Run("volume exact bound tags", func(t *testing.T) {
		tests := []struct {
			name   string
			mutate func(map[string]string)
		}{
			{name: "user tag", mutate: func(tags map[string]string) { tags["role"] = "other" }},
			{name: "reserved tag", mutate: func(tags map[string]string) { tags["terrascale-operation"] = "other-operation" }},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				journal := testJournal(t)
				request := VolumeCreateRequest{CompartmentID: compartment, AvailabilityDomain: "AD-1", DisplayName: "bound-volume", SizeGiB: 100, VPUsPerGiB: 20, Tags: map[string]string{"role": "data"}}
				request.Mutation = testMutation("volume.create", VolumeCreateMutationScope(request), VolumeCreateMutationFingerprint(request), 1)
				tags := bindMutationTags(map[string]string{"role": "data"}, request.Mutation)
				test.mutate(tags)
				rawTags, err := json.Marshal(tags)
				if err != nil {
					t.Fatal(err)
				}
				transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
					body := `{"id":"` + volumeID + `","compartmentId":"` + compartment + `","availabilityDomain":"AD-1","displayName":"bound-volume","lifecycleState":"PROVISIONING","sizeInGBs":100,"vpusPerGB":20,"freeformTags":` + string(rawTags) + `}`
					return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"volume-etag"}}), nil
				})
				adapter, err := NewOCIBlockStorageAdapter(transport, journal)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := adapter.CreateVolume(context.Background(), request); err == nil {
					t.Fatal("volume response with mismatched bound tags was accepted")
				}
				record, err := journal.Prepare(context.Background(), request.Mutation)
				if err != nil || record.State != MutationUnknown || record.Result.ResourceID != volumeID || record.Result.ETag != "volume-etag" {
					t.Fatalf("mismatched volume tag record = %+v err=%v", record, err)
				}
			})
		}
	})

	t.Run("attachment display name and read-only mode", func(t *testing.T) {
		transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
			body := `{"id":"ocid1.volumeattachment.oc1.sa-saopaulo-1.binding","compartmentId":"` + compartment + `","instanceId":"` + instanceID + `","volumeId":"` + volumeID + `","displayName":"other-name","isReadOnly":false,"lifecycleState":"ATTACHING"}`
			return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"attachment-etag"}}), nil
		})
		journal := testJournal(t)
		adapter, err := NewOCIVolumeAttachmentAdapter(transport, journal)
		if err != nil {
			t.Fatal(err)
		}
		adapter.Ownership = testOwnership(t, instanceID, volumeID)
		request := VolumeAttachRequest{CompartmentID: compartment, InstanceID: instanceID, VolumeID: volumeID, DisplayName: "bound-attachment", ReadOnly: true}
		request.Mutation = testMutation("attachment.create", VolumeAttachMutationScope(request), VolumeAttachMutationFingerprint(request), 2)
		if _, err := adapter.AttachVolume(context.Background(), request); err == nil {
			t.Fatal("attachment response with mismatched display name and mode was accepted")
		}
		record, err := journal.Prepare(context.Background(), request.Mutation)
		if err != nil || record.State != MutationUnknown || record.Result.ResourceID == "" || record.Result.ETag != "attachment-etag" {
			t.Fatalf("mismatched attachment record = %+v err=%v", record, err)
		}
	})
}

func TestOCIAttachmentReadOnlyRequiresExplicitBoolean(t *testing.T) {
	const (
		compartment  = "ocid1.compartment.oc1..testcompartment"
		volumeID     = "ocid1.volume.oc1.sa-saopaulo-1.readonlypresence"
		instanceID   = "ocid1.instance.oc1.sa-saopaulo-1.readonlypresence"
		attachmentID = "ocid1.volumeattachment.oc1.sa-saopaulo-1.readonlypresence"
	)
	tests := []struct {
		name        string
		field       string
		readOnly    bool
		wantSuccess bool
	}{
		{name: "missing"},
		{name: "null", field: `,"isReadOnly":null`},
		{name: "string", field: `,"isReadOnly":"false"`},
		{name: "number", field: `,"isReadOnly":0`},
		{name: "duplicate same value", field: `,"isReadOnly":false,"isReadOnly":false`},
		{name: "duplicate contradictory value", field: `,"isReadOnly":false,"isReadOnly":true`},
		{name: "wrong explicit value", field: `,"isReadOnly":true`},
		{name: "explicit false", field: `,"isReadOnly":false`, wantSuccess: true},
		{name: "explicit true", field: `,"isReadOnly":true`, readOnly: true, wantSuccess: true},
	}

	t.Run("create response", func(t *testing.T) {
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				posts := 0
				transport := testOCITransport(t, OCIServiceCore, func(httpRequest *http.Request) (*http.Response, error) {
					if httpRequest.Method != http.MethodPost || httpRequest.URL.Path != "/20160918/volumeAttachments" {
						t.Fatalf("unexpected attachment create request %s %s", httpRequest.Method, httpRequest.URL.String())
					}
					posts++
					body := `{"id":"` + attachmentID + `","compartmentId":"` + compartment + `","instanceId":"` + instanceID + `","volumeId":"` + volumeID + `","displayName":"presence-attachment"` + test.field + `,"lifecycleState":"ATTACHING"}`
					return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"attachment-etag"}}), nil
				})
				journal := testJournal(t)
				adapter, err := NewOCIVolumeAttachmentAdapter(transport, journal)
				if err != nil {
					t.Fatal(err)
				}
				adapter.Ownership = testOwnership(t, instanceID, volumeID)
				request := VolumeAttachRequest{CompartmentID: compartment, InstanceID: instanceID, VolumeID: volumeID, DisplayName: "presence-attachment", ReadOnly: test.readOnly}
				request.Mutation = testMutation("attachment.create", VolumeAttachMutationScope(request), VolumeAttachMutationFingerprint(request), 1)
				attachment, createErr := adapter.AttachVolume(context.Background(), request)
				if (createErr == nil) != test.wantSuccess || posts != 1 {
					t.Fatalf("attachment create = %+v posts=%d err=%v wantSuccess=%v", attachment, posts, createErr, test.wantSuccess)
				}
				record, err := journal.Prepare(context.Background(), request.Mutation)
				if err != nil {
					t.Fatal(err)
				}
				if test.wantSuccess {
					if record.State != MutationSucceeded || attachment.ID != attachmentID {
						t.Fatalf("explicit attachment result = %+v record=%+v", attachment, record)
					}
				} else if record.State != MutationUnknown {
					t.Fatalf("malformed attachment response state = %s", record.State)
				}
			})
		}
	})

	t.Run("reconciliation response", func(t *testing.T) {
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				request := VolumeAttachRequest{CompartmentID: compartment, InstanceID: instanceID, VolumeID: volumeID, DisplayName: "presence-attachment", ReadOnly: test.readOnly}
				request.Mutation = testMutation("attachment.create", VolumeAttachMutationScope(request), VolumeAttachMutationFingerprint(request), 1)
				journal := testJournal(t)
				if _, err := journal.Prepare(context.Background(), request.Mutation); err != nil {
					t.Fatal(err)
				}
				if _, err := journal.MarkSubmitted(context.Background(), request.Mutation); err != nil {
					t.Fatal(err)
				}
				calls := 0
				listValue := "false"
				if request.ReadOnly {
					listValue = "true"
				}
				transport := testOCITransport(t, OCIServiceCore, func(httpRequest *http.Request) (*http.Response, error) {
					calls++
					switch httpRequest.URL.Path {
					case "/20160918/volumeAttachments":
						body := `{"items":[{"id":"` + attachmentID + `","compartmentId":"` + compartment + `","instanceId":"` + instanceID + `","volumeId":"` + volumeID + `","displayName":"presence-attachment","isReadOnly":` + listValue + `,"lifecycleState":"ATTACHED"}]}`
						return testHTTPResponse(http.StatusOK, body, nil), nil
					case "/20160918/volumeAttachments/" + attachmentID:
						body := `{"id":"` + attachmentID + `","compartmentId":"` + compartment + `","instanceId":"` + instanceID + `","volumeId":"` + volumeID + `","displayName":"presence-attachment"` + test.field + `,"lifecycleState":"ATTACHED"}`
						return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"attachment-etag"}}), nil
					default:
						t.Fatalf("unexpected attachment reconciliation request %s %s", httpRequest.Method, httpRequest.URL.String())
						return nil, io.ErrUnexpectedEOF
					}
				})
				adapter, err := NewOCIVolumeAttachmentAdapter(transport, journal)
				if err != nil {
					t.Fatal(err)
				}
				adapter.Ownership = testOwnership(t, instanceID, volumeID)
				attachment, reconcileErr := adapter.AttachVolume(context.Background(), request)
				if (reconcileErr == nil) != test.wantSuccess || calls != 2 {
					t.Fatalf("attachment reconciliation = %+v calls=%d err=%v wantSuccess=%v", attachment, calls, reconcileErr, test.wantSuccess)
				}
				record, err := journal.Prepare(context.Background(), request.Mutation)
				if err != nil {
					t.Fatal(err)
				}
				if test.wantSuccess {
					if record.State != MutationSucceeded || attachment.ID != attachmentID {
						t.Fatalf("explicit reconciled attachment = %+v record=%+v", attachment, record)
					}
				} else if record.State == MutationSucceeded {
					t.Fatalf("malformed reconciliation became terminal: %+v", record)
				}
			})
		}
	})

	t.Run("reconciliation list response", func(t *testing.T) {
		for _, test := range tests {
			if test.wantSuccess {
				continue
			}
			t.Run(test.name, func(t *testing.T) {
				request := VolumeAttachRequest{CompartmentID: compartment, InstanceID: instanceID, VolumeID: volumeID, DisplayName: "presence-attachment", ReadOnly: false}
				request.Mutation = testMutation("attachment.create", VolumeAttachMutationScope(request), VolumeAttachMutationFingerprint(request), 1)
				journal := testJournal(t)
				if _, err := journal.Prepare(context.Background(), request.Mutation); err != nil {
					t.Fatal(err)
				}
				if _, err := journal.MarkSubmitted(context.Background(), request.Mutation); err != nil {
					t.Fatal(err)
				}
				calls := 0
				transport := testOCITransport(t, OCIServiceCore, func(httpRequest *http.Request) (*http.Response, error) {
					calls++
					if httpRequest.Method != http.MethodGet || httpRequest.URL.Path != "/20160918/volumeAttachments" {
						t.Fatalf("malformed list item triggered another request: %s %s", httpRequest.Method, httpRequest.URL.String())
					}
					body := `{"items":[{"id":"` + attachmentID + `","compartmentId":"` + compartment + `","instanceId":"` + instanceID + `","volumeId":"` + volumeID + `","displayName":"presence-attachment"` + test.field + `,"lifecycleState":"ATTACHED"}]}`
					return testHTTPResponse(http.StatusOK, body, nil), nil
				})
				adapter, err := NewOCIVolumeAttachmentAdapter(transport, journal)
				if err != nil {
					t.Fatal(err)
				}
				adapter.Ownership = testOwnership(t, instanceID, volumeID)
				if _, err := adapter.AttachVolume(context.Background(), request); err == nil {
					t.Fatal("malformed attachment list response was accepted")
				}
				record, err := journal.Prepare(context.Background(), request.Mutation)
				if err != nil || record.State == MutationSucceeded || calls != 1 {
					t.Fatalf("malformed list record = %+v calls=%d err=%v", record, calls, err)
				}
			})
		}
	})

	t.Run("direct get response", func(t *testing.T) {
		tests := []struct {
			name        string
			field       string
			wantSuccess bool
		}{
			{name: "missing"},
			{name: "null", field: `,"isReadOnly":null`},
			{name: "string", field: `,"isReadOnly":"false"`},
			{name: "number", field: `,"isReadOnly":0`},
			{name: "duplicate same value", field: `,"isReadOnly":false,"isReadOnly":false`},
			{name: "duplicate contradictory value", field: `,"isReadOnly":false,"isReadOnly":true`},
			{name: "explicit false", field: `,"isReadOnly":false`, wantSuccess: true},
			{name: "explicit true", field: `,"isReadOnly":true`, wantSuccess: true},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				calls := 0
				transport := testOCITransport(t, OCIServiceCore, func(httpRequest *http.Request) (*http.Response, error) {
					calls++
					if httpRequest.Method != http.MethodGet || httpRequest.URL.Path != "/20160918/volumeAttachments/"+attachmentID {
						t.Fatalf("unexpected attachment read request %s %s", httpRequest.Method, httpRequest.URL.String())
					}
					body := `{"id":"` + attachmentID + `","compartmentId":"` + compartment + `","instanceId":"` + instanceID + `","volumeId":"` + volumeID + `","displayName":"presence-attachment"` + test.field + `,"lifecycleState":"ATTACHED"}`
					return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"attachment-etag"}}), nil
				})
				adapter, err := NewOCIVolumeAttachmentAdapter(transport, testJournal(t))
				if err != nil {
					t.Fatal(err)
				}
				adapter.Ownership = testOwnership(t, attachmentID)
				attachment, found, readErr := adapter.GetVolumeAttachment(context.Background(), attachmentID)
				if (readErr == nil) != test.wantSuccess || found != test.wantSuccess || calls != 1 {
					t.Fatalf("attachment read = %+v found=%v calls=%d err=%v wantSuccess=%v", attachment, found, calls, readErr, test.wantSuccess)
				}
			})
		}
	})
}

func TestOCIStoragePublicReadsRequireDurableScopedProof(t *testing.T) {
	const (
		compartment      = "ocid1.compartment.oc1..testcompartment"
		wrongCompartment = "ocid1.compartment.oc1..wrongcompartment"
		volumeID         = "ocid1.volume.oc1.sa-saopaulo-1.publicread"
		attachmentID     = "ocid1.volumeattachment.oc1.sa-saopaulo-1.publicread"
		instanceID       = "ocid1.instance.oc1.sa-saopaulo-1.publicread"
	)
	type resourceCase struct {
		name       string
		id         string
		directPath string
		listPath   string
		listedBody string
		wrongBody  string
		read       func(*testing.T, *OCIHTTPTransport, DurableOwnershipEvidence) (bool, error)
	}
	resources := []resourceCase{
		{
			name:       "volume",
			id:         volumeID,
			directPath: "/20160918/volumes/" + volumeID,
			listPath:   "/20160918/volumes",
			listedBody: `{"items":[{"id":"` + volumeID + `","compartmentId":"` + compartment + `"}]}`,
			wrongBody:  `{"id":"` + volumeID + `","compartmentId":"` + wrongCompartment + `","lifecycleState":"AVAILABLE","sizeInGBs":100,"vpusPerGB":20}`,
			read: func(t *testing.T, transport *OCIHTTPTransport, ownership DurableOwnershipEvidence) (bool, error) {
				t.Helper()
				adapter, err := NewOCIBlockStorageAdapter(transport, testJournal(t))
				if err != nil {
					t.Fatal(err)
				}
				adapter.Ownership = ownership
				_, found, err := adapter.GetBlockVolume(context.Background(), volumeID)
				return found, err
			},
		},
		{
			name:       "attachment",
			id:         attachmentID,
			directPath: "/20160918/volumeAttachments/" + attachmentID,
			listPath:   "/20160918/volumeAttachments",
			listedBody: `{"items":[{"id":"` + attachmentID + `","compartmentId":"` + compartment + `","instanceId":"` + instanceID + `","volumeId":"` + volumeID + `","isReadOnly":false}]}`,
			wrongBody:  `{"id":"` + attachmentID + `","compartmentId":"` + wrongCompartment + `","instanceId":"` + instanceID + `","volumeId":"` + volumeID + `","isReadOnly":false,"lifecycleState":"ATTACHED"}`,
			read: func(t *testing.T, transport *OCIHTTPTransport, ownership DurableOwnershipEvidence) (bool, error) {
				t.Helper()
				adapter, err := NewOCIVolumeAttachmentAdapter(transport, testJournal(t))
				if err != nil {
					t.Fatal(err)
				}
				adapter.Ownership = ownership
				_, found, err := adapter.GetVolumeAttachment(context.Background(), attachmentID)
				return found, err
			},
		},
	}

	for _, resource := range resources {
		t.Run(resource.name+" ownership", func(t *testing.T) {
			tests := []struct {
				name      string
				ownership func(*testing.T) DurableOwnershipEvidence
			}{
				{name: "missing", ownership: func(*testing.T) DurableOwnershipEvidence { return nil }},
				{name: "non-durable", ownership: func(*testing.T) DurableOwnershipEvidence { return &nonDurableTestOwnership{} }},
				{name: "unrecorded", ownership: func(t *testing.T) DurableOwnershipEvidence { return testOwnership(t) }},
			}
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					calls := 0
					transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
						calls++
						t.Fatalf("ownership failure sent a provider request: %s %s", request.Method, request.URL.String())
						return nil, io.ErrUnexpectedEOF
					})
					found, err := resource.read(t, transport, test.ownership(t))
					if err == nil || found || calls != 0 {
						t.Fatalf("found=%v calls=%d err=%v", found, calls, err)
					}
				})
			}
		})

		t.Run(resource.name+" wrong compartment", func(t *testing.T) {
			calls := 0
			transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Method != http.MethodGet || request.URL.Path != resource.directPath {
					t.Fatalf("unexpected wrong-compartment request %s %s", request.Method, request.URL.String())
				}
				return testHTTPResponse(http.StatusOK, resource.wrongBody, http.Header{"Etag": {"resource-etag"}}), nil
			})
			found, err := resource.read(t, transport, testOwnership(t, resource.id))
			if err == nil || found || calls != 1 {
				t.Fatalf("found=%v calls=%d err=%v", found, calls, err)
			}
		})

		t.Run(resource.name+" 404 proof", func(t *testing.T) {
			type listPage struct {
				status int
				body   string
				next   string
			}
			empty := `{"items":[]}`
			tests := []struct {
				name    string
				pages   []listPage
				wantErr bool
			}{
				{name: "authorized absence", pages: []listPage{{body: empty}}},
				{name: "listed denial", pages: []listPage{{body: resource.listedBody}}, wantErr: true},
				{name: "unauthorized list", pages: []listPage{{status: http.StatusForbidden, body: `{"code":"NotAuthorized"}`}}, wantErr: true},
				{name: "malformed list", pages: []listPage{{body: `not-json`}}, wantErr: true},
				{name: "null list", pages: []listPage{{body: `null`}}, wantErr: true},
				{name: "partial pagination", pages: []listPage{{body: empty, next: "page-2"}, {status: http.StatusForbidden, body: `{"code":"NotAuthorized"}`}}, wantErr: true},
				{name: "paginated absence", pages: []listPage{{body: empty, next: "page-2"}, {body: empty}}},
				{name: "paginated listed denial", pages: []listPage{{body: empty, next: "page-2"}, {body: resource.listedBody}}, wantErr: true},
			}
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					listCalls := 0
					requests := 0
					transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
						requests++
						if request.Method != http.MethodGet {
							t.Fatalf("public read sent a mutation: %s %s", request.Method, request.URL.String())
						}
						if request.URL.Path == resource.directPath {
							return testHTTPResponse(http.StatusNotFound, `{"code":"NotAuthorizedOrNotFound"}`, nil), nil
						}
						if request.URL.Path != resource.listPath || request.URL.Query().Get("compartmentId") != compartment || request.URL.Query().Get("limit") != "1000" {
							t.Fatalf("unscoped absence request %s", request.URL.String())
						}
						if listCalls >= len(test.pages) {
							t.Fatalf("unexpected extra list page %s", request.URL.String())
						}
						page := test.pages[listCalls]
						expectedToken := ""
						if listCalls > 0 {
							expectedToken = test.pages[listCalls-1].next
						}
						if request.URL.Query().Get("page") != expectedToken {
							t.Fatalf("page token = %q want %q", request.URL.Query().Get("page"), expectedToken)
						}
						listCalls++
						status := page.status
						if status == 0 {
							status = http.StatusOK
						}
						headers := http.Header{}
						if page.next != "" {
							headers.Set("Opc-Next-Page", page.next)
						}
						return testHTTPResponse(status, page.body, headers), nil
					})
					found, err := resource.read(t, transport, testOwnership(t, resource.id))
					if (err != nil) != test.wantErr || found || listCalls != len(test.pages) || requests != 1+len(test.pages) {
						t.Fatalf("found=%v requests=%d listCalls=%d err=%v wantErr=%v", found, requests, listCalls, err, test.wantErr)
					}
				})
			}
		})
	}
}

func TestOCIStorageRejectsNoncanonicalHeadersAndUnboundedPagination(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		seen      map[string]struct{}
		pagesRead int
	}{
		{name: "duplicate", headers: http.Header{"Opc-Next-Page": {"page-2", "page-3"}}, seen: map[string]struct{}{}, pagesRead: 1},
		{name: "whitespace", headers: http.Header{"Opc-Next-Page": {" page-2"}}, seen: map[string]struct{}{}, pagesRead: 1},
		{name: "control", headers: http.Header{"Opc-Next-Page": {"page\t2"}}, seen: map[string]struct{}{}, pagesRead: 1},
		{name: "repeated", headers: http.Header{"Opc-Next-Page": {"page-2"}}, seen: map[string]struct{}{"page-2": {}}, pagesRead: 2},
		{name: "page bound", headers: http.Header{"Opc-Next-Page": {"page-17"}}, seen: map[string]struct{}{}, pagesRead: maximumOCIPages},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp := testHTTPResponse(http.StatusOK, "", test.headers)
			if _, err := nextOCIPage(resp, test.seen, test.pagesRead); err == nil {
				t.Fatal("invalid OCI continuation was accepted")
			}
		})
	}

	const volumeID = "ocid1.volume.oc1.sa-saopaulo-1.headercheck"
	transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
		body := `{"id":"` + volumeID + `","compartmentId":"ocid1.compartment.oc1..testcompartment","lifecycleState":"AVAILABLE","sizeInGBs":100,"vpusPerGB":20,"etag":"body-etag"}`
		return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"first-etag", "second-etag"}}), nil
	})
	adapter, err := NewOCIBlockStorageAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	adapter.Ownership = testOwnership(t, volumeID)
	if _, _, err := adapter.GetBlockVolume(context.Background(), volumeID); err == nil {
		t.Fatal("duplicate ETag headers were accepted or replaced by the body ETag")
	}
}

func TestOCIStorageDeletesNeedAuthorizedAbsenceProofAndNeverResubmit(t *testing.T) {
	const (
		compartment = "ocid1.compartment.oc1..testcompartment"
		volumeID    = "ocid1.volume.oc1.sa-saopaulo-1.absence"
	)
	deletes := 0
	deleteSubmitted := false
	absenceAuthorized := false
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodDelete:
			deletes++
			deleteSubmitted = true
			return testHTTPResponse(http.StatusAccepted, "", nil), nil
		case request.URL.Path == "/20160918/volumes":
			if !absenceAuthorized {
				return testHTTPResponse(http.StatusForbidden, `{"code":"NotAuthorized"}`, nil), nil
			}
			return testHTTPResponse(http.StatusOK, `{"items":[]}`, nil), nil
		case !deleteSubmitted:
			body := `{"id":"` + volumeID + `","compartmentId":"` + compartment + `","lifecycleState":"AVAILABLE","sizeInGBs":100,"vpusPerGB":20}`
			return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"volume-etag"}}), nil
		default:
			return testHTTPResponse(http.StatusNotFound, `{"code":"NotAuthorizedOrNotFound"}`, nil), nil
		}
	})
	journal := testJournal(t)
	adapter, err := NewOCIBlockStorageAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	adapter.Ownership = testOwnership(t, volumeID)
	request := VolumeDeleteRequest{VolumeID: volumeID, IfMatch: "volume-etag"}
	request.Mutation = testMutation("volume.delete", VolumeDeleteMutationScope(request), VolumeDeleteMutationFingerprint(request), 1)
	if err := adapter.DeleteVolume(context.Background(), request); err == nil {
		t.Fatal("202 without a work request or authorized absence proof was accepted")
	}
	want := ProviderMutationResult{ResourceID: volumeID, ETag: "volume-etag"}
	record, err := journal.Prepare(context.Background(), request.Mutation)
	if err != nil || record.State != MutationUnknown || record.Result != want || deletes != 1 {
		t.Fatalf("ambiguous delete record = %+v deletes=%d err=%v", record, deletes, err)
	}
	absenceAuthorized = true
	request.Mutation.Epoch.Value++
	if err := adapter.DeleteVolume(context.Background(), request); err != nil {
		t.Fatalf("authorized absence did not finish delete: %v", err)
	}
	record, err = journal.Prepare(context.Background(), request.Mutation)
	if err != nil || record.State != MutationSucceeded || record.Result != want || deletes != 1 {
		t.Fatalf("proved delete record = %+v deletes=%d err=%v", record, deletes, err)
	}
}

func TestOCIStorageNullListCannotAuthorizeAbsence(t *testing.T) {
	const (
		compartment  = "ocid1.compartment.oc1..testcompartment"
		volumeID     = "ocid1.volume.oc1.sa-saopaulo-1.nullabsence"
		attachmentID = "ocid1.volumeattachment.oc1.sa-saopaulo-1.nullabsence"
	)

	t.Run("volume delete", func(t *testing.T) {
		deletes := 0
		transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
			switch {
			case request.Method == http.MethodDelete:
				deletes++
				return testHTTPResponse(http.StatusNoContent, "", nil), nil
			case request.URL.Path == "/20160918/volumes/"+volumeID:
				return testHTTPResponse(http.StatusNotFound, `{"code":"NotAuthorizedOrNotFound"}`, nil), nil
			case request.URL.Path == "/20160918/volumes":
				return testHTTPResponse(http.StatusOK, `null`, nil), nil
			default:
				t.Fatalf("unexpected null volume absence request %s %s", request.Method, request.URL.String())
				return nil, io.ErrUnexpectedEOF
			}
		})
		journal := testJournal(t)
		adapter, err := NewOCIBlockStorageAdapter(transport, journal)
		if err != nil {
			t.Fatal(err)
		}
		adapter.Ownership = testOwnership(t, volumeID)
		request := VolumeDeleteRequest{VolumeID: volumeID, IfMatch: "volume-etag"}
		request.Mutation = testMutation("volume.delete", VolumeDeleteMutationScope(request), VolumeDeleteMutationFingerprint(request), 1)
		if err := adapter.DeleteVolume(context.Background(), request); err == nil {
			t.Fatal("null volume list authorized absence")
		}
		if deletes != 0 {
			t.Fatalf("null volume list sent %d deletes", deletes)
		}
	})

	t.Run("attachment detach", func(t *testing.T) {
		deletes := 0
		transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
			switch {
			case request.Method == http.MethodDelete:
				deletes++
				return testHTTPResponse(http.StatusNoContent, "", nil), nil
			case request.URL.Path == "/20160918/volumeAttachments/"+attachmentID:
				return testHTTPResponse(http.StatusNotFound, `{"code":"NotAuthorizedOrNotFound"}`, nil), nil
			case request.URL.Path == "/20160918/volumeAttachments":
				return testHTTPResponse(http.StatusOK, `null`, nil), nil
			default:
				t.Fatalf("unexpected null attachment absence request %s %s", request.Method, request.URL.String())
				return nil, io.ErrUnexpectedEOF
			}
		})
		journal := testJournal(t)
		adapter, err := NewOCIVolumeAttachmentAdapter(transport, journal)
		if err != nil {
			t.Fatal(err)
		}
		adapter.Ownership = testOwnership(t, attachmentID)
		request := VolumeDetachRequest{AttachmentID: attachmentID, IfMatch: "attachment-etag"}
		request.Mutation = testMutation("attachment.delete", VolumeDetachMutationScope(request), VolumeDetachMutationFingerprint(request), 1)
		if err := adapter.DetachVolume(context.Background(), request); err == nil {
			t.Fatal("null attachment list authorized absence")
		}
		if deletes != 0 {
			t.Fatalf("null attachment list sent %d deletes", deletes)
		}
	})
}

func TestOCIObjectStorageAdapterContract(t *testing.T) {
	content := []byte("durable ledger segment")
	digest := objectSHA256(content)
	object := ObjectRef{Namespace: "namespace", Bucket: "ledger", Name: "region/segment-1"}
	putCalls := 0
	transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
		if request.URL.EscapedPath() != "/n/namespace/b/ledger/o/region%2Fsegment-1" {
			t.Fatalf("unexpected object path %s", request.URL.String())
		}
		switch request.Method {
		case http.MethodPut:
			putCalls++
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != string(content) || request.Header.Get("If-None-Match") != "*" || request.Header.Get("opc-meta-terrascale-sha256") != digest {
				t.Fatalf("object put body=%q headers=%v", body, request.Header)
			}
			return testHTTPResponse(http.StatusOK, "", http.Header{"Etag": {"object-etag"}}), nil
		case http.MethodHead:
			return testHTTPResponse(http.StatusOK, "", http.Header{
				"Content-Length": {stringInt(len(content))}, "Content-Type": {"application/octet-stream"},
				"Etag": {"object-etag"}, "Opc-Meta-Terrascale-Sha256": {digest},
			}), nil
		default:
			t.Fatalf("unexpected object request %s %s", request.Method, request.URL.String())
			return nil, io.ErrUnexpectedEOF
		}
	})
	adapter := testObjectAdapter(t, transport, testJournal(t), object)
	request := ObjectPutRequest{Object: object, Content: content, SHA256: digest}
	request.Mutation = testMutation("object.put", ObjectPutMutationScope(request), ObjectPutMutationFingerprint(request), 5)
	metadata, err := adapter.PutObject(context.Background(), request)
	if err != nil || metadata.ETag != "object-etag" || metadata.SHA256 != digest || putCalls != 1 {
		t.Fatalf("put object = %+v, calls=%d, err=%v", metadata, putCalls, err)
	}
}

func TestOCIRegistryAdapterVerifiesManifestAndBlobDigests(t *testing.T) {
	manifest := []byte(validRegistryManifestBody(ociImageManifestMediaType))
	manifestDigest := "sha256:" + objectSHA256(manifest)
	blob := "layer-bytes"
	blobDigest := "sha256:" + objectSHA256([]byte(blob))
	transport := testOCITransport(t, OCIServiceRegistry, func(request *http.Request) (*http.Response, error) {
		username, token, ok := request.BasicAuth()
		if !ok || username != "tenancy/runner" || token != "registry-token" {
			t.Fatal("registry request did not carry the injected OCIR credential")
		}
		switch {
		case strings.Contains(request.URL.Path, "/manifests/"):
			return testHTTPResponse(http.StatusOK, string(manifest), http.Header{"Content-Length": {stringInt(len(manifest))}, "Docker-Content-Digest": {manifestDigest}, "Content-Type": {"application/vnd.oci.image.manifest.v1+json"}}), nil
		case strings.Contains(request.URL.Path, "/blobs/"):
			return testHTTPResponse(http.StatusOK, blob, http.Header{"Docker-Content-Digest": {blobDigest}, "Content-Length": {"11"}, "Content-Type": {"application/octet-stream"}}), nil
		default:
			return nil, io.ErrUnexpectedEOF
		}
	})
	signer, err := NewOCIRegistryTokenSigner("tenancy/runner", "registry-token")
	if err != nil {
		t.Fatal(err)
	}
	transport.Signer = signer
	adapter := testRegistryAdapter(t, transport)
	gotManifest, err := adapter.PullManifest(context.Background(), RegistryManifestRequest{Repository: "tenancy/terrascale/member", Reference: manifestDigest})
	if err != nil || gotManifest.Digest != manifestDigest || string(gotManifest.Content) != string(manifest) {
		t.Fatalf("manifest = %+v, %v", gotManifest, err)
	}
	reader, size, err := adapter.PullBlob(context.Background(), RegistryBlobRequest{Repository: "tenancy/terrascale/member", Digest: blobDigest})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	gotBlob, err := io.ReadAll(reader)
	if err != nil || size != int64(len(blob)) || string(gotBlob) != blob {
		t.Fatalf("blob size=%d body=%q err=%v", size, gotBlob, err)
	}
}

func TestOCIRegistryAdapterFollowsOneValidatedBlobRedirect(t *testing.T) {
	blob := "redirected-layer"
	digest := "sha256:" + objectSHA256([]byte(blob))
	for _, host := range []string{
		"objectstorage.sa-saopaulo-1.oraclecloud.com",
		"objectstorage.sa-saopaulo-1.oci.customer-oci.com",
		"namespace-1.objectstorage.sa-saopaulo-1.oci.customer-oci.com",
	} {
		t.Run(host, func(t *testing.T) {
			calls := 0
			transport := testOCITransport(t, OCIServiceRegistry, func(request *http.Request) (*http.Response, error) {
				calls++
				switch calls {
				case 1:
					username, token, ok := request.BasicAuth()
					if !ok || username != "namespace/runner" || token != "registry-token" {
						t.Fatal("initial registry request did not carry its OCIR credential")
					}
					location := "https://" + host + "/p/presigned/n/namespace/b/layers/o/blob?token=presigned-secret"
					return testHTTPResponse(http.StatusTemporaryRedirect, "", http.Header{"Location": {location}}), nil
				case 2:
					if request.URL.Host != host || request.URL.Path != "/p/presigned/n/namespace/b/layers/o/blob" || request.URL.RawQuery != "token=presigned-secret" {
						t.Fatalf("redirect request authority or target changed: host=%q path=%q", request.URL.Host, request.URL.Path)
					}
					if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || request.Header.Get("Accept") != "application/octet-stream" {
						t.Fatalf("redirect request carried registry credentials or wrong media type: %v", request.Header)
					}
					return testHTTPResponse(http.StatusOK, blob, http.Header{"Content-Length": {"16"}}), nil
				default:
					t.Fatal("registry blob pull followed more than one redirect hop")
					return nil, io.ErrUnexpectedEOF
				}
			})
			signer, err := NewOCIRegistryTokenSigner("namespace/runner", "registry-token")
			if err != nil {
				t.Fatal(err)
			}
			transport.Signer = signer
			adapter, err := NewOCIRegistryAdapter(transport)
			if err != nil {
				t.Fatal(err)
			}
			reader, size, err := adapter.PullBlob(context.Background(), RegistryBlobRequest{Repository: "tenancy/terrascale/member", Digest: digest})
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			content, err := io.ReadAll(reader)
			if err != nil || string(content) != blob || size != int64(len(blob)) || calls != 2 {
				t.Fatalf("redirected blob size=%d body=%q calls=%d err=%v", size, content, calls, err)
			}
		})
	}
}

func TestOCIRegistryAdapterRejectsHostileBlobRedirectsWithoutLeakingTargets(t *testing.T) {
	tests := map[string]string{
		"relative":          "/p/blob?token=presigned-secret",
		"plaintext":         "http://objectstorage.sa-saopaulo-1.oraclecloud.com/p/blob?token=presigned-secret",
		"userinfo":          "https://user@objectstorage.sa-saopaulo-1.oraclecloud.com/p/blob?token=presigned-secret",
		"fragment":          "https://objectstorage.sa-saopaulo-1.oraclecloud.com/p/blob?token=presigned-secret#fragment",
		"port":              "https://objectstorage.sa-saopaulo-1.oraclecloud.com:443/p/blob?token=presigned-secret",
		"wrong-region":      "https://objectstorage.us-sanjose-1.oraclecloud.com/p/blob?token=presigned-secret",
		"oracle-suffix":     "https://objectstorage.sa-saopaulo-1.oraclecloud.com.evil.test/p/blob?token=presigned-secret",
		"nested-namespace":  "https://a.b.objectstorage.sa-saopaulo-1.oci.customer-oci.com/p/blob?token=presigned-secret",
		"invalid-namespace": "https://-namespace.objectstorage.sa-saopaulo-1.oci.customer-oci.com/p/blob?token=presigned-secret",
		"registry-host":     "https://gru.ocir.io/p/blob?token=presigned-secret",
	}
	for name, location := range tests {
		t.Run(name, func(t *testing.T) {
			calls := 0
			transport := testOCITransport(t, OCIServiceRegistry, func(*http.Request) (*http.Response, error) {
				calls++
				if calls != 1 {
					t.Fatal("invalid registry redirect reached its target")
				}
				return testHTTPResponse(http.StatusTemporaryRedirect, "", http.Header{"Location": {location}}), nil
			})
			adapter, err := NewOCIRegistryAdapter(transport)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = adapter.PullBlob(context.Background(), RegistryBlobRequest{Repository: "tenancy/member", Digest: "sha256:" + strings.Repeat("a", 64)})
			if err == nil || calls != 1 || strings.Contains(err.Error(), location) || strings.Contains(err.Error(), "presigned-secret") {
				t.Fatalf("hostile redirect calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestOCIRegistryAdapterBoundsRedirectsAndRedactsFailures(t *testing.T) {
	digest := "sha256:" + objectSHA256([]byte("expected"))
	t.Run("second redirect", func(t *testing.T) {
		calls := 0
		transport := testOCITransport(t, OCIServiceRegistry, func(*http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return testHTTPResponse(http.StatusTemporaryRedirect, "", http.Header{"Location": {"https://objectstorage.sa-saopaulo-1.oraclecloud.com/p/blob?token=first-secret"}}), nil
			}
			return testHTTPResponse(http.StatusTemporaryRedirect, "", http.Header{"Location": {"https://evil.test/blob?token=second-secret"}}), nil
		})
		adapter, err := NewOCIRegistryAdapter(transport)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = adapter.PullBlob(context.Background(), RegistryBlobRequest{Repository: "tenancy/member", Digest: digest})
		if err == nil || calls != 2 || strings.Contains(err.Error(), "first-secret") || strings.Contains(err.Error(), "second-secret") {
			t.Fatalf("second redirect calls=%d err=%v", calls, err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		calls := 0
		transport := testOCITransport(t, OCIServiceRegistry, func(request *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return testHTTPResponse(http.StatusTemporaryRedirect, "", http.Header{"Location": {"https://objectstorage.sa-saopaulo-1.oraclecloud.com/p/blob?token=presigned-secret"}}), nil
			}
			return nil, errors.New(request.URL.String())
		})
		adapter, err := NewOCIRegistryAdapter(transport)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = adapter.PullBlob(context.Background(), RegistryBlobRequest{Repository: "tenancy/member", Digest: digest})
		if err == nil || calls != 2 || strings.Contains(err.Error(), "presigned-secret") || strings.Contains(err.Error(), "objectstorage") {
			t.Fatalf("redirect transport error calls=%d err=%v", calls, err)
		}
	})

	for name, response := range map[string]*http.Response{
		"over 64 GiB":          testHTTPResponse(http.StatusOK, "", http.Header{"Content-Length": {"68719476737"}}),
		"duplicate length":     testHTTPResponse(http.StatusOK, "", http.Header{"Content-Length": {"8", "9"}}),
		"wrong digest header":  testHTTPResponse(http.StatusOK, "expected", http.Header{"Content-Length": {"8"}, "Docker-Content-Digest": {"sha256:" + strings.Repeat("b", 64)}}),
		"duplicate digest":     testHTTPResponse(http.StatusOK, "expected", http.Header{"Content-Length": {"8"}, "Docker-Content-Digest": {digest, digest}}),
		"malformed digest":     testHTTPResponse(http.StatusOK, "expected", http.Header{"Content-Length": {"8"}, "Docker-Content-Digest": {"sha256:not-a-digest"}}),
		"uppercase digest hex": testHTTPResponse(http.StatusOK, "expected", http.Header{"Content-Length": {"8"}, "Docker-Content-Digest": {"sha256:" + strings.Repeat("A", 64)}}),
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			transport := testOCITransport(t, OCIServiceRegistry, func(*http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return testHTTPResponse(http.StatusTemporaryRedirect, "", http.Header{"Location": {"https://objectstorage.sa-saopaulo-1.oraclecloud.com/p/blob?token=presigned-secret"}}), nil
				}
				return response, nil
			})
			adapter, err := NewOCIRegistryAdapter(transport)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = adapter.PullBlob(context.Background(), RegistryBlobRequest{Repository: "tenancy/member", Digest: digest})
			if err == nil || calls != 2 || strings.Contains(err.Error(), "presigned-secret") {
				t.Fatalf("redirect metadata calls=%d err=%v", calls, err)
			}
		})
	}

	t.Run("stream length and digest", func(t *testing.T) {
		for name, body := range map[string]string{"length": "expected-extra", "digest": "mismatch"} {
			t.Run(name, func(t *testing.T) {
				calls := 0
				transport := testOCITransport(t, OCIServiceRegistry, func(*http.Request) (*http.Response, error) {
					calls++
					if calls == 1 {
						return testHTTPResponse(http.StatusTemporaryRedirect, "", http.Header{"Location": {"https://objectstorage.sa-saopaulo-1.oraclecloud.com/p/blob?token=presigned-secret"}}), nil
					}
					return testHTTPResponse(http.StatusOK, body, http.Header{"Content-Length": {"8"}}), nil
				})
				adapter, err := NewOCIRegistryAdapter(transport)
				if err != nil {
					t.Fatal(err)
				}
				reader, _, err := adapter.PullBlob(context.Background(), RegistryBlobRequest{Repository: "tenancy/member", Digest: digest})
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				if name == "length" {
					buffer := make([]byte, 3)
					content := make([]byte, 0, len("expected"))
					var readErr error
					for readErr == nil {
						n, err := reader.Read(buffer)
						content = append(content, buffer[:n]...)
						readErr = err
					}
					if string(content) != "expected" || len(content) != 8 {
						t.Fatalf("length probe returned bytes outside declared content: %q", content)
					}
					var invalidData *InvalidDataError
					if !errors.As(readErr, &invalidData) {
						t.Fatalf("length probe error=%v", readErr)
					}
					n, err := reader.Read(buffer)
					if n != 0 || !errors.Is(err, io.EOF) {
						t.Fatalf("bounded reader after overrun returned n=%d err=%v", n, err)
					}
					return
				}
				if _, err := io.ReadAll(reader); err == nil {
					t.Fatal("redirected blob stream accepted invalid digest")
				}
			})
		}
	})

	t.Run("exact 64 GiB bound", func(t *testing.T) {
		size, err := registryBlobContentLength(testHTTPResponse(http.StatusOK, "", http.Header{"Content-Length": {"68719476736"}}))
		if err != nil || size != 64<<30 {
			t.Fatalf("exact registry blob size bound=%d err=%v", size, err)
		}
	})
}

func TestOCIResourceReadsUseHeaderETags(t *testing.T) {
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/20160918/instances/ocid1.instance.oc1.sa-saopaulo-1.x":
			return testHTTPResponse(http.StatusOK, `{"id":"ocid1.instance.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..x","lifecycleState":"RUNNING","etag":"body-etag"}`, http.Header{"Etag": {"instance-header-etag"}}), nil
		case "/20160918/volumes/ocid1.volume.oc1.sa-saopaulo-1.x":
			return testHTTPResponse(http.StatusOK, `{"id":"ocid1.volume.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..x","lifecycleState":"AVAILABLE","sizeInGBs":100,"vpusPerGB":20,"etag":"body-etag"}`, http.Header{"Etag": {"volume-header-etag"}}), nil
		case "/20160918/volumeAttachments/ocid1.volumeattachment.oc1.sa-saopaulo-1.x":
			return testHTTPResponse(http.StatusOK, `{"id":"ocid1.volumeattachment.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..x","instanceId":"ocid1.instance.oc1.sa-saopaulo-1.x","volumeId":"ocid1.volume.oc1.sa-saopaulo-1.x","lifecycleState":"ATTACHED","etag":"body-etag"}`, http.Header{"Etag": {"attachment-header-etag"}}), nil
		default:
			t.Fatalf("unexpected OCI resource read %s", request.URL.Path)
			return nil, io.ErrUnexpectedEOF
		}
	})

	compute, err := NewOCIComputeAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	instance, found, err := compute.GetInstance(context.Background(), "ocid1.instance.oc1.sa-saopaulo-1.x")
	if err != nil || !found || instance.ETag != "instance-header-etag" {
		t.Fatalf("instance read = %+v, found=%v, err=%v", instance, found, err)
	}

	volumes, err := NewOCIBlockStorageAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	volume, found, err := volumes.GetBlockVolume(context.Background(), "ocid1.volume.oc1.sa-saopaulo-1.x")
	if err != nil || !found || volume.ETag != "volume-header-etag" {
		t.Fatalf("volume read = %+v, found=%v, err=%v", volume, found, err)
	}

	attachments, err := NewOCIVolumeAttachmentAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	attachment, found, err := attachments.GetVolumeAttachment(context.Background(), "ocid1.volumeattachment.oc1.sa-saopaulo-1.x")
	if err != nil || !found || attachment.ETag != "attachment-header-etag" {
		t.Fatalf("attachment read = %+v, found=%v, err=%v", attachment, found, err)
	}
}

func TestOCIStorageDeletesConvergeWhenResourcesAreAlreadyAbsent(t *testing.T) {
	volumeID := "ocid1.volume.oc1.sa-saopaulo-1.absent"
	attachmentID := "ocid1.volumeattachment.oc1.sa-saopaulo-1.absent"

	volumeTransport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet {
			t.Fatalf("already-absent volume deletion sent %s", request.Method)
		}
		if request.URL.Path == "/20160918/volumes" {
			return testHTTPResponse(http.StatusOK, `[]`, nil), nil
		}
		return testHTTPResponse(http.StatusNotFound, "", nil), nil
	})
	volumeAdapter, err := NewOCIBlockStorageAdapter(volumeTransport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	volumeAdapter.Ownership = testOwnership(t, volumeID)
	volumeRequest := VolumeDeleteRequest{VolumeID: volumeID, IfMatch: "volume-etag"}
	volumeRequest.Mutation = testMutation("volume.delete", VolumeDeleteMutationScope(volumeRequest), VolumeDeleteMutationFingerprint(volumeRequest), 5)
	if err := volumeAdapter.DeleteVolume(context.Background(), volumeRequest); err != nil {
		t.Fatalf("already-absent volume deletion failed: %v", err)
	}

	attachmentTransport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet {
			t.Fatalf("already-absent attachment deletion sent %s", request.Method)
		}
		if request.URL.Path == "/20160918/volumeAttachments" {
			return testHTTPResponse(http.StatusOK, `[]`, nil), nil
		}
		return testHTTPResponse(http.StatusNotFound, "", nil), nil
	})
	attachmentAdapter, err := NewOCIVolumeAttachmentAdapter(attachmentTransport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	attachmentAdapter.Ownership = testOwnership(t, attachmentID)
	attachmentRequest := VolumeDetachRequest{AttachmentID: attachmentID, IfMatch: "attachment-etag"}
	attachmentRequest.Mutation = testMutation("attachment.delete", VolumeDetachMutationScope(attachmentRequest), VolumeDetachMutationFingerprint(attachmentRequest), 6)
	if err := attachmentAdapter.DetachVolume(context.Background(), attachmentRequest); err != nil {
		t.Fatalf("already-absent attachment deletion failed: %v", err)
	}

	objectTransport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && request.URL.Path == "/n/namespace/b/ledger/o" {
			return testHTTPResponse(http.StatusOK, `{"objects":[]}`, nil), nil
		}
		if request.Method != http.MethodHead {
			t.Fatalf("already-absent object deletion sent %s %s", request.Method, request.URL.String())
		}
		return testHTTPResponse(http.StatusNotFound, "", nil), nil
	})
	objectAdapter, err := NewOCIObjectStorageAdapter(objectTransport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	objectRequest := ObjectDeleteRequest{Object: ObjectRef{Namespace: "namespace", Bucket: "ledger", Name: "absent"}, IfMatch: "object-etag"}
	objectRequest.Mutation = testMutation("object.delete", ObjectDeleteMutationScope(objectRequest), ObjectDeleteMutationFingerprint(objectRequest), 7)
	if err := objectAdapter.DeleteObject(context.Background(), objectRequest); err != nil {
		t.Fatalf("already-absent object deletion failed: %v", err)
	}
}

func TestOCIBlockVolumeDeleteAbsentIsDurablyIdempotent(t *testing.T) {
	deletes := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodDelete {
			deletes++
		}
		if request.Method == http.MethodGet && request.URL.Path == "/20160918/volumes" {
			return testHTTPResponse(http.StatusOK, `[]`, nil), nil
		}
		return testHTTPResponse(http.StatusNotFound, "", nil), nil
	})
	journal := testJournal(t)
	adapter, err := NewOCIBlockStorageAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	volumeID := "ocid1.volume.oc1.sa-saopaulo-1.x"
	adapter.Ownership = testOwnership(t, volumeID)
	request := VolumeDeleteRequest{VolumeID: volumeID, IfMatch: "volume-etag"}
	request.Mutation = testMutation("volume.delete", VolumeDeleteMutationScope(request), VolumeDeleteMutationFingerprint(request), 1)
	if err := adapter.DeleteVolume(context.Background(), request); err != nil {
		t.Fatalf("first absent volume delete = %v", err)
	}
	if err := adapter.DeleteVolume(context.Background(), request); err != nil {
		t.Fatalf("retry absent volume delete = %v", err)
	}
	if deletes != 0 {
		t.Fatalf("absent volume delete issued %d delete requests", deletes)
	}
}

func TestOCIBlockVolumeDeleteStaysUnknownUntilAuthorizedListProvesAbsence(t *testing.T) {
	volumeID := "ocid1.volume.oc1.sa-saopaulo-1.x"
	deleteSubmitted := false
	listAuthorized := false
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodDelete:
			deleteSubmitted = true
			return testHTTPResponse(http.StatusAccepted, "", nil), nil
		case request.URL.Path == "/20160918/volumes":
			if listAuthorized {
				return testHTTPResponse(http.StatusOK, `[]`, nil), nil
			}
			return testHTTPResponse(http.StatusForbidden, `{"code":"NotAuthorized"}`, nil), nil
		case !deleteSubmitted:
			return testHTTPResponse(http.StatusOK, `{"id":"ocid1.volume.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..x","lifecycleState":"AVAILABLE","sizeInGBs":100,"vpusPerGB":20}`, http.Header{"Etag": {"volume-etag"}}), nil
		default:
			return testHTTPResponse(http.StatusNotFound, `{"code":"NotAuthorizedOrNotFound"}`, nil), nil
		}
	})
	journal := testJournal(t)
	adapter, err := NewOCIBlockStorageAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	adapter.Ownership = testOwnership(t, volumeID)
	request := VolumeDeleteRequest{VolumeID: volumeID, IfMatch: "volume-etag"}
	request.Mutation = testMutation("volume.delete", VolumeDeleteMutationScope(request), VolumeDeleteMutationFingerprint(request), 1)
	if err := adapter.DeleteVolume(context.Background(), request); err == nil {
		t.Fatal("accepted asynchronous delete without a work-request ID was treated as complete")
	}
	if err := adapter.DeleteVolume(context.Background(), request); err == nil {
		t.Fatal("unauthorized list proved volume absence")
	}
	record, err := journal.Prepare(context.Background(), request.Mutation)
	if err != nil || record.State != MutationUnknown {
		t.Fatalf("ambiguous delete record = %+v, %v", record, err)
	}
	listAuthorized = true
	if err := adapter.DeleteVolume(context.Background(), request); err != nil {
		t.Fatalf("authorized empty list did not complete deletion: %v", err)
	}
	record, err = journal.Prepare(context.Background(), request.Mutation)
	if err != nil || record.State != MutationSucceeded {
		t.Fatalf("list-proven delete record = %+v, %v", record, err)
	}
}

func TestOCIStorageMutationResponsesStayInRequestedCompartment(t *testing.T) {
	volumeRequest := VolumeCreateRequest{CompartmentID: "ocid1.compartment.oc1..x", AvailabilityDomain: "AD-1", DisplayName: "scope-check", SizeGiB: 100, VPUsPerGiB: 20}
	volumeRequest.Mutation = testMutation("volume.create", VolumeCreateMutationScope(volumeRequest), VolumeCreateMutationFingerprint(volumeRequest), 1)
	volumeTransport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.volume.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..other","lifecycleState":"PROVISIONING","sizeInGBs":100,"vpusPerGB":20}`, http.Header{"Etag": {"volume-etag"}}), nil
	})
	volumeAdapter, err := NewOCIBlockStorageAdapter(volumeTransport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := volumeAdapter.CreateVolume(context.Background(), volumeRequest); err == nil {
		t.Fatal("out-of-scope volume response was accepted")
	}

	attachmentRequest := VolumeAttachRequest{CompartmentID: "ocid1.compartment.oc1..x", InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.x", VolumeID: "ocid1.volume.oc1.sa-saopaulo-1.x", DisplayName: "scope-check"}
	attachmentRequest.Mutation = testMutation("attachment.create", VolumeAttachMutationScope(attachmentRequest), VolumeAttachMutationFingerprint(attachmentRequest), 2)
	attachmentTransport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.volumeattachment.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..other","instanceId":"ocid1.instance.oc1.sa-saopaulo-1.x","volumeId":"ocid1.volume.oc1.sa-saopaulo-1.x","lifecycleState":"ATTACHING"}`, http.Header{"Etag": {"attachment-etag"}}), nil
	})
	attachmentAdapter, err := NewOCIVolumeAttachmentAdapter(attachmentTransport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	attachmentAdapter.Ownership = testOwnership(t, attachmentRequest.InstanceID, attachmentRequest.VolumeID)
	if _, err := attachmentAdapter.AttachVolume(context.Background(), attachmentRequest); err == nil {
		t.Fatal("out-of-scope attachment response was accepted")
	}
}

func TestOCIStorageReconciliationFollowsNextPage(t *testing.T) {
	volumeRequest := VolumeCreateRequest{CompartmentID: "ocid1.compartment.oc1..x", AvailabilityDomain: "AD-1", DisplayName: "paged-volume", SizeGiB: 100, VPUsPerGiB: 20}
	volumeRequest.Mutation = testMutation("volume.create", VolumeCreateMutationScope(volumeRequest), VolumeCreateMutationFingerprint(volumeRequest), 1)
	volumeJournal := testJournal(t)
	if _, err := volumeJournal.Prepare(context.Background(), volumeRequest.Mutation); err != nil {
		t.Fatal(err)
	}
	if _, err := volumeJournal.MarkSubmitted(context.Background(), volumeRequest.Mutation); err != nil {
		t.Fatal(err)
	}
	volumeCalls := 0
	volumeTransport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		volumeCalls++
		if request.URL.Path == "/20160918/volumes/ocid1.volume.oc1.sa-saopaulo-1.x" {
			return testHTTPResponse(http.StatusOK, `{"id":"ocid1.volume.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..x","lifecycleState":"AVAILABLE","sizeInGBs":100,"vpusPerGB":20}`, http.Header{"Etag": {"volume-etag"}}), nil
		}
		if request.URL.Query().Get("page") == "" {
			return testHTTPResponse(http.StatusOK, `{"items":[]}`, http.Header{"Opc-Next-Page": {"page-2"}}), nil
		}
		body := `{"items":[{"id":"ocid1.volume.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..x","lifecycleState":"AVAILABLE","sizeInGBs":100,"vpusPerGB":20,"freeformTags":{"terrascale-operation":"` + volumeRequest.Mutation.OperationID.Value + `","terrascale-intent":"` + volumeRequest.Mutation.Fingerprint + `"}}]}`
		return testHTTPResponse(http.StatusOK, body, nil), nil
	})
	volumeAdapter, err := NewOCIBlockStorageAdapter(volumeTransport, volumeJournal)
	if err != nil {
		t.Fatal(err)
	}
	volume, err := volumeAdapter.CreateVolume(context.Background(), volumeRequest)
	if err != nil || volume.ID != "ocid1.volume.oc1.sa-saopaulo-1.x" || volume.ETag != "volume-etag" || volumeCalls != 3 {
		t.Fatalf("paged volume reconciliation volume=%+v calls=%d err=%v", volume, volumeCalls, err)
	}

	attachmentRequest := VolumeAttachRequest{CompartmentID: "ocid1.compartment.oc1..x", InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.x", VolumeID: "ocid1.volume.oc1.sa-saopaulo-1.x", DisplayName: "paged-attachment"}
	attachmentRequest.Mutation = testMutation("attachment.create", VolumeAttachMutationScope(attachmentRequest), VolumeAttachMutationFingerprint(attachmentRequest), 2)
	attachmentJournal := testJournal(t)
	if _, err := attachmentJournal.Prepare(context.Background(), attachmentRequest.Mutation); err != nil {
		t.Fatal(err)
	}
	if _, err := attachmentJournal.MarkSubmitted(context.Background(), attachmentRequest.Mutation); err != nil {
		t.Fatal(err)
	}
	attachmentCalls := 0
	attachmentTransport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		attachmentCalls++
		if request.URL.Path == "/20160918/volumeAttachments/ocid1.volumeattachment.oc1.sa-saopaulo-1.x" {
			return testHTTPResponse(http.StatusOK, `{"id":"ocid1.volumeattachment.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..x","instanceId":"ocid1.instance.oc1.sa-saopaulo-1.x","volumeId":"ocid1.volume.oc1.sa-saopaulo-1.x","lifecycleState":"ATTACHED"}`, http.Header{"Etag": {"attachment-etag"}}), nil
		}
		if request.URL.Query().Get("page") == "" {
			return testHTTPResponse(http.StatusOK, `{"items":[]}`, http.Header{"Opc-Next-Page": {"page-2"}}), nil
		}
		return testHTTPResponse(http.StatusOK, `{"items":[{"id":"ocid1.volumeattachment.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..x","instanceId":"ocid1.instance.oc1.sa-saopaulo-1.x","volumeId":"ocid1.volume.oc1.sa-saopaulo-1.x","lifecycleState":"ATTACHED"}]}`, nil), nil
	})
	attachmentAdapter, err := NewOCIVolumeAttachmentAdapter(attachmentTransport, attachmentJournal)
	if err != nil {
		t.Fatal(err)
	}
	attachmentAdapter.Ownership = testOwnership(t, attachmentRequest.InstanceID, attachmentRequest.VolumeID)
	attachment, err := attachmentAdapter.AttachVolume(context.Background(), attachmentRequest)
	if err != nil || attachment.ID != "ocid1.volumeattachment.oc1.sa-saopaulo-1.x" || attachment.ETag != "attachment-etag" || attachmentCalls != 3 {
		t.Fatalf("paged attachment reconciliation attachment=%+v calls=%d err=%v", attachment, attachmentCalls, err)
	}
}

func TestOCIStorageDeletesRejectOutOfScopeObservations(t *testing.T) {
	volumeID := "ocid1.volume.oc1.sa-saopaulo-1.x"
	volumeDeletes := 0
	volumeTransport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodDelete {
			volumeDeletes++
		}
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.volume.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..other","lifecycleState":"AVAILABLE","sizeInGBs":100}`, nil), nil
	})
	volumeAdapter, err := NewOCIBlockStorageAdapter(volumeTransport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	volumeAdapter.Ownership = testOwnership(t, volumeID)
	volumeRequest := VolumeDeleteRequest{VolumeID: volumeID, IfMatch: "volume-etag"}
	volumeRequest.Mutation = testMutation("volume.delete", VolumeDeleteMutationScope(volumeRequest), VolumeDeleteMutationFingerprint(volumeRequest), 1)
	if err := volumeAdapter.DeleteVolume(context.Background(), volumeRequest); err == nil || volumeDeletes != 0 {
		t.Fatalf("out-of-scope volume delete err=%v deletes=%d", err, volumeDeletes)
	}

	attachmentID := "ocid1.volumeattachment.oc1.sa-saopaulo-1.x"
	attachmentDeletes := 0
	attachmentTransport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodDelete {
			attachmentDeletes++
		}
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.volumeattachment.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..other","instanceId":"ocid1.instance.oc1.sa-saopaulo-1.x","volumeId":"ocid1.volume.oc1.sa-saopaulo-1.x","lifecycleState":"ATTACHED"}`, nil), nil
	})
	attachmentAdapter, err := NewOCIVolumeAttachmentAdapter(attachmentTransport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	attachmentAdapter.Ownership = testOwnership(t, attachmentID)
	attachmentRequest := VolumeDetachRequest{AttachmentID: attachmentID, IfMatch: "attachment-etag"}
	attachmentRequest.Mutation = testMutation("attachment.delete", VolumeDetachMutationScope(attachmentRequest), VolumeDetachMutationFingerprint(attachmentRequest), 2)
	if err := attachmentAdapter.DetachVolume(context.Background(), attachmentRequest); err == nil || attachmentDeletes != 0 {
		t.Fatalf("out-of-scope attachment delete err=%v deletes=%d", err, attachmentDeletes)
	}
}

func TestOCIVolumeDetachAbsentIsDurablyIdempotent(t *testing.T) {
	deletes := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodDelete {
			deletes++
		}
		if request.Method == http.MethodGet && request.URL.Path == "/20160918/volumeAttachments" {
			return testHTTPResponse(http.StatusOK, `[]`, nil), nil
		}
		return testHTTPResponse(http.StatusNotFound, "", nil), nil
	})
	journal := testJournal(t)
	adapter, err := NewOCIVolumeAttachmentAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	attachmentID := "ocid1.volumeattachment.oc1.sa-saopaulo-1.x"
	adapter.Ownership = testOwnership(t, attachmentID)
	request := VolumeDetachRequest{AttachmentID: attachmentID, IfMatch: "attachment-etag"}
	request.Mutation = testMutation("attachment.delete", VolumeDetachMutationScope(request), VolumeDetachMutationFingerprint(request), 1)
	if err := adapter.DetachVolume(context.Background(), request); err != nil {
		t.Fatalf("first absent detach = %v", err)
	}
	if err := adapter.DetachVolume(context.Background(), request); err != nil {
		t.Fatalf("retry absent detach = %v", err)
	}
	if deletes != 0 {
		t.Fatalf("absent detach issued %d delete requests", deletes)
	}
}

func TestOCIObjectDeleteAbsentIsDurablyIdempotent(t *testing.T) {
	deletes := 0
	transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodDelete {
			deletes++
		}
		if request.Method == http.MethodGet && request.URL.Path == "/n/namespace/b/ledger/o" {
			return testHTTPResponse(http.StatusOK, `{"objects":[]}`, nil), nil
		}
		return testHTTPResponse(http.StatusNotFound, "", nil), nil
	})
	journal := testJournal(t)
	adapter, err := NewOCIObjectStorageAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	request := ObjectDeleteRequest{Object: ObjectRef{Namespace: "namespace", Bucket: "ledger", Name: "region/segment-absent"}, IfMatch: "object-etag"}
	request.Mutation = testMutation("object.delete", ObjectDeleteMutationScope(request), ObjectDeleteMutationFingerprint(request), 1)
	if err := adapter.DeleteObject(context.Background(), request); err != nil {
		t.Fatalf("first absent object delete = %v", err)
	}
	if err := adapter.DeleteObject(context.Background(), request); err != nil {
		t.Fatalf("retry absent object delete = %v", err)
	}
	if deletes != 0 {
		t.Fatalf("absent object delete issued %d delete requests", deletes)
	}
}

func TestOCIObjectNotAuthorizedOrNotFoundNeedsExactListProof(t *testing.T) {
	object := ObjectRef{Namespace: "namespace", Bucket: "ledger", Name: "region/segment"}
	newRequest := func() ObjectDeleteRequest {
		request := ObjectDeleteRequest{Object: object, IfMatch: "object-etag"}
		request.Mutation = testMutation("object.delete", ObjectDeleteMutationScope(request), ObjectDeleteMutationFingerprint(request), 1)
		return request
	}

	t.Run("unauthorized list cannot prove absence", func(t *testing.T) {
		deletes := 0
		transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodDelete {
				deletes++
			}
			if request.Method == http.MethodGet && request.URL.Path == "/n/namespace/b/ledger/o" {
				return testHTTPResponse(http.StatusForbidden, `{"code":"NotAuthorized"}`, nil), nil
			}
			return testHTTPResponse(http.StatusNotFound, `{"code":"NotAuthorizedOrNotFound"}`, nil), nil
		})
		adapter, err := NewOCIObjectStorageAdapter(transport, testJournal(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := adapter.DeleteObject(context.Background(), newRequest()); err == nil || deletes != 0 {
			t.Fatalf("ambiguous 404 became terminal absence: err=%v deletes=%d", err, deletes)
		}
	})

	t.Run("prefix collision is not the object", func(t *testing.T) {
		deletes := 0
		transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodDelete {
				deletes++
			}
			if request.Method == http.MethodGet && request.URL.Path == "/n/namespace/b/ledger/o" {
				if request.URL.Query().Get("prefix") != object.Name || request.URL.Query().Get("fields") != "name" {
					t.Fatalf("absence list was not exact-prefix scoped: %s", request.URL.String())
				}
				return testHTTPResponse(http.StatusOK, `{"objects":[{"name":"region/segment-later"}]}`, nil), nil
			}
			return testHTTPResponse(http.StatusNotFound, `{"code":"NotAuthorizedOrNotFound"}`, nil), nil
		})
		adapter, err := NewOCIObjectStorageAdapter(transport, testJournal(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := adapter.DeleteObject(context.Background(), newRequest()); err != nil || deletes != 0 {
			t.Fatalf("prefix collision absence err=%v deletes=%d", err, deletes)
		}
	})

	t.Run("exact listed object disproves absence", func(t *testing.T) {
		transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodGet && request.URL.Path == "/n/namespace/b/ledger/o" {
				return testHTTPResponse(http.StatusOK, `{"objects":[{"name":"region/segment"}]}`, nil), nil
			}
			return testHTTPResponse(http.StatusNotFound, `{"code":"NotAuthorizedOrNotFound"}`, nil), nil
		})
		adapter, err := NewOCIObjectStorageAdapter(transport, testJournal(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := adapter.DeleteObject(context.Background(), newRequest()); err == nil {
			t.Fatal("exact listed object was treated as absent")
		}
	})
}
