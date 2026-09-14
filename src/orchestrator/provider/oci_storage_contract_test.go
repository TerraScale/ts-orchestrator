package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
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

func TestOCIBlockVolumeAdapterContract(t *testing.T) {
	var requestBody map[string]any
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/workRequests/") {
			return testHTTPResponse(http.StatusOK, `{"id":"volume-work","status":"SUCCEEDED","percentComplete":100}`, nil), nil
		}
		if request.Method != http.MethodPost || request.URL.Path != "/20160918/volumes" {
			t.Fatalf("unexpected volume request %s %s", request.Method, request.URL.String())
		}
		if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
			t.Fatal(err)
		}
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.volume.oc1.sa-saopaulo-1.testvolume","compartmentId":"ocid1.compartment.oc1..testcompartment","availabilityDomain":"AD-1","displayName":"data-node-a","lifecycleState":"PROVISIONING","sizeInGBs":100,"vpusPerGB":20}`, http.Header{"Etag": {"volume-etag"}, "Opc-Work-Request-Id": {"volume-work"}}), nil
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
	binding, err := NewOCIObjectStorageBinding("namespace", "ledger", "backups")
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewOCIObjectStorageAdapterWithBinding(transport, testJournal(t), binding)
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
	transport.Signer = stageASignerFunc(func(*http.Request) error { return nil })
	adapter, err := NewOCIObjectStorageAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	request := ObjectPutRequest{Object: ObjectRef{Namespace: "namespace", Bucket: "ledger", Name: "region/segment-1"}, Content: content, SHA256: digest}
	request.Mutation = testMutation("object.put", ObjectPutMutationScope(request), ObjectPutMutationFingerprint(request), 5)
	metadata, err := adapter.PutObject(context.Background(), request)
	if err != nil || metadata.ETag != "object-etag" || metadata.SHA256 != digest || putCalls != 1 {
		t.Fatalf("put object = %+v, calls=%d, err=%v", metadata, putCalls, err)
	}
}

func TestOCIObjectStorageHead404UsesAuthorizedListProof(t *testing.T) {
	object := ObjectRef{Namespace: "namespace", Bucket: "ledger", Name: "region/segment-1"}
	transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
		switch request.Method {
		case http.MethodHead:
			return testHTTPResponse(http.StatusNotFound, "", nil), nil
		case http.MethodGet:
			return testHTTPResponse(http.StatusOK, `{"objects":[{"name":"region/segment-1"}]}`, nil), nil
		default:
			t.Fatalf("unexpected Object Storage request %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	})
	adapter, err := NewOCIObjectStorageAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	_, found, err := adapter.HeadObject(context.Background(), object)
	if err == nil || found || !strings.Contains(err.Error(), "listed object") {
		t.Fatalf("listed 404 proof = found=%v err=%v", found, err)
	}
}

func TestOCIObjectStorageHead404AcceptsAuthorizedAbsence(t *testing.T) {
	object := ObjectRef{Namespace: "namespace", Bucket: "ledger", Name: "region/segment-1"}
	transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
		switch request.Method {
		case http.MethodHead:
			return testHTTPResponse(http.StatusNotFound, "", nil), nil
		case http.MethodGet:
			return testHTTPResponse(http.StatusOK, `{"objects":[]}`, nil), nil
		default:
			t.Fatalf("unexpected Object Storage request %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	})
	adapter, err := NewOCIObjectStorageAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	_, found, err := adapter.HeadObject(context.Background(), object)
	if err != nil || found {
		t.Fatalf("absent 404 proof = found=%v err=%v", found, err)
	}
}

func TestOCIObjectStorageGetVerifiesDeclaredLength(t *testing.T) {
	content := []byte("payload")
	digest := objectSHA256(content)
	transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusOK, string(content), http.Header{
			"Content-Length":             {"4"},
			"Etag":                       {"object-etag"},
			"Opc-Meta-Terrascale-Sha256": {digest},
		}), nil
	})
	adapter, err := NewOCIObjectStorageAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	reader, _, err := adapter.GetObject(context.Background(), ObjectRef{Namespace: "namespace", Bucket: "ledger", Name: "region/segment-1"})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := io.ReadAll(reader); err == nil || !strings.Contains(err.Error(), "content length") {
		t.Fatalf("length mismatch read error = %v", err)
	}
}

func TestOCIObjectStorageDelete404DoesNotAssumeAbsence(t *testing.T) {
	object := ObjectRef{Namespace: "namespace", Bucket: "ledger", Name: "region/segment-1"}
	content := []byte("payload")
	digest := objectSHA256(content)
	transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
		switch request.Method {
		case http.MethodHead:
			return testHTTPResponse(http.StatusOK, "", http.Header{
				"Content-Length":             {"7"},
				"Etag":                       {"object-etag"},
				"Opc-Meta-Terrascale-Sha256": {digest},
			}), nil
		case http.MethodDelete:
			return testHTTPResponse(http.StatusNotFound, "", nil), nil
		case http.MethodGet:
			return testHTTPResponse(http.StatusOK, `{"objects":[{"name":"region/segment-1"}]}`, nil), nil
		default:
			t.Fatalf("unexpected Object Storage request %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	})
	adapter, err := NewOCIObjectStorageAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	request := ObjectDeleteRequest{Object: object, IfMatch: "object-etag"}
	request.Mutation = testMutation("object.delete", ObjectDeleteMutationScope(request), ObjectDeleteMutationFingerprint(request), 1)
	if err := adapter.DeleteObject(context.Background(), request); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("listed delete 404 = %v", err)
	}
	record, err := adapter.Journal.Prepare(context.Background(), request.Mutation)
	if err != nil || record.State != MutationFailed || record.FailureCode != "provider-not-authorized" {
		t.Fatalf("listed delete 404 journal = %+v err=%v", record, err)
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

func TestOCIBlockVolumeDeleteResumesDurableWorkRequest(t *testing.T) {
	const volumeID = "ocid1.volume.oc1.sa-saopaulo-1.resume-delete"
	const compartment = "ocid1.compartment.oc1..testcompartment"
	visible := false
	deletes := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/20160918/volumes/"+volumeID:
			body := `{"id":"` + volumeID + `","compartmentId":"` + compartment + `","lifecycleState":"AVAILABLE","sizeInGBs":100,"vpusPerGB":20}`
			return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"volume-etag"}}), nil
		case request.Method == http.MethodDelete:
			deletes++
			return testHTTPResponse(http.StatusAccepted, "", http.Header{"Opc-Work-Request-Id": {"delete-work"}}), nil
		case request.Method == http.MethodGet && request.URL.Path == "/20160918/workRequests/delete-work":
			if !visible {
				return testHTTPResponse(http.StatusNotFound, "", nil), nil
			}
			return testHTTPResponse(http.StatusOK, `{"id":"delete-work","status":"SUCCEEDED","percentComplete":100}`, nil), nil
		default:
			t.Fatalf("unexpected volume delete request %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	})
	journal := testJournal(t)
	adapter, err := NewOCIBlockStorageAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	adapter.WaitPolicy = WorkRequestWaitPolicy{MaxPolls: 1, MaxNotFound: 0}
	adapter.Ownership = testOwnership(t, volumeID)
	request := VolumeDeleteRequest{VolumeID: volumeID, IfMatch: "volume-etag"}
	request.Mutation = testMutation("volume.delete", VolumeDeleteMutationScope(request), VolumeDeleteMutationFingerprint(request), 1)
	if err := adapter.DeleteVolume(context.Background(), request); err == nil || !errors.As(err, new(*ProviderOutcomeUnknownError)) {
		t.Fatalf("invisible delete = %v", err)
	}
	visible = true
	request.Mutation.Epoch.Value++
	if err := adapter.DeleteVolume(context.Background(), request); err != nil {
		t.Fatalf("resumed delete = %v", err)
	}
	if deletes != 1 {
		t.Fatalf("delete submissions = %d, want 1", deletes)
	}
	record, err := journal.Prepare(context.Background(), request.Mutation)
	if err != nil || record.State != MutationSucceeded || record.Result.WorkRequestID != "delete-work" {
		t.Fatalf("resumed delete journal = %+v err=%v", record, err)
	}
}

func TestOCIVolumeAttachmentDetachResumesDurableWorkRequest(t *testing.T) {
	const attachmentID = "ocid1.volumeattachment.oc1.sa-saopaulo-1.resume-detach"
	const compartment = "ocid1.compartment.oc1..testcompartment"
	visible := false
	deletes := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/20160918/volumeAttachments/"+attachmentID:
			body := `{"id":"` + attachmentID + `","compartmentId":"` + compartment + `","instanceId":"ocid1.instance.oc1.sa-saopaulo-1.instance","volumeId":"ocid1.volume.oc1.sa-saopaulo-1.volume","lifecycleState":"ATTACHED"}`
			return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"attachment-etag"}}), nil
		case request.Method == http.MethodDelete:
			deletes++
			return testHTTPResponse(http.StatusAccepted, "", http.Header{"Opc-Work-Request-Id": {"detach-work"}}), nil
		case request.Method == http.MethodGet && request.URL.Path == "/20160918/workRequests/detach-work":
			if !visible {
				return testHTTPResponse(http.StatusNotFound, "", nil), nil
			}
			return testHTTPResponse(http.StatusOK, `{"id":"detach-work","status":"SUCCEEDED","percentComplete":100}`, nil), nil
		default:
			t.Fatalf("unexpected attachment detach request %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	})
	journal := testJournal(t)
	adapter, err := NewOCIVolumeAttachmentAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	adapter.WaitPolicy = WorkRequestWaitPolicy{MaxPolls: 1, MaxNotFound: 0}
	adapter.Ownership = testOwnership(t, attachmentID)
	request := VolumeDetachRequest{AttachmentID: attachmentID, IfMatch: "attachment-etag"}
	request.Mutation = testMutation("attachment.delete", VolumeDetachMutationScope(request), VolumeDetachMutationFingerprint(request), 1)
	if err := adapter.DetachVolume(context.Background(), request); err == nil || !errors.As(err, new(*ProviderOutcomeUnknownError)) {
		t.Fatalf("invisible detach = %v", err)
	}
	visible = true
	request.Mutation.Epoch.Value++
	if err := adapter.DetachVolume(context.Background(), request); err != nil {
		t.Fatalf("resumed detach = %v", err)
	}
	if deletes != 1 {
		t.Fatalf("detach submissions = %d, want 1", deletes)
	}
}

func TestOCIStorageAsyncFailurePersistsProviderTruth(t *testing.T) {
	const compartment = "ocid1.compartment.oc1..testcompartment"
	const instanceID = "ocid1.instance.oc1.sa-saopaulo-1.failed-instance"
	const volumeID = "ocid1.volume.oc1.sa-saopaulo-1.failed-volume"
	const attachmentID = "ocid1.volumeattachment.oc1.sa-saopaulo-1.failed-attachment"

	t.Run("attachment failed", func(t *testing.T) {
		transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
			switch {
			case request.Method == http.MethodPost:
				body := `{"id":"` + attachmentID + `","compartmentId":"` + compartment + `","instanceId":"` + instanceID + `","volumeId":"` + volumeID + `","displayName":"failed-attachment","isReadOnly":true,"lifecycleState":"ATTACHING"}`
				return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"attachment-etag"}, "Opc-Work-Request-Id": {"attachment-work"}}), nil
			case request.Method == http.MethodGet && request.URL.Path == "/20160918/workRequests/attachment-work":
				return testHTTPResponse(http.StatusOK, `{"id":"attachment-work","status":"FAILED","percentComplete":100}`, nil), nil
			default:
				t.Fatalf("unexpected failed attachment request %s %s", request.Method, request.URL.String())
				return nil, nil
			}
		})
		journal := testJournal(t)
		adapter, err := NewOCIVolumeAttachmentAdapter(transport, journal)
		if err != nil {
			t.Fatal(err)
		}
		adapter.WaitPolicy = WorkRequestWaitPolicy{MaxPolls: 1, MaxNotFound: 0}
		adapter.Ownership = testOwnership(t, instanceID, volumeID)
		request := VolumeAttachRequest{CompartmentID: compartment, InstanceID: instanceID, VolumeID: volumeID, DisplayName: "failed-attachment", ReadOnly: true}
		request.Mutation = testMutation("attachment.create", VolumeAttachMutationScope(request), VolumeAttachMutationFingerprint(request), 1)
		if _, err := adapter.AttachVolume(context.Background(), request); err == nil {
			t.Fatal("failed attachment work request was accepted")
		}
		record, err := journal.Prepare(context.Background(), request.Mutation)
		want := ProviderMutationResult{ResourceID: attachmentID, ETag: "attachment-etag", WorkRequestID: "attachment-work"}
		if err != nil || record.State != MutationFailed || record.Result != want || record.FailureCode != "provider-work-request-failed" {
			t.Fatalf("failed attachment journal = %+v err=%v", record, err)
		}
	})

	t.Run("volume delete canceled", func(t *testing.T) {
		transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
			switch {
			case request.Method == http.MethodGet && request.URL.Path == "/20160918/volumes/"+volumeID:
				body := `{"id":"` + volumeID + `","compartmentId":"` + compartment + `","lifecycleState":"AVAILABLE","sizeInGBs":100,"vpusPerGB":20}`
				return testHTTPResponse(http.StatusOK, body, http.Header{"Etag": {"volume-etag"}}), nil
			case request.Method == http.MethodDelete:
				return testHTTPResponse(http.StatusAccepted, "", http.Header{"Opc-Work-Request-Id": {"delete-work"}}), nil
			case request.Method == http.MethodGet && request.URL.Path == "/20160918/workRequests/delete-work":
				return testHTTPResponse(http.StatusOK, `{"id":"delete-work","status":"CANCELED","percentComplete":100}`, nil), nil
			default:
				t.Fatalf("unexpected canceled volume request %s %s", request.Method, request.URL.String())
				return nil, nil
			}
		})
		journal := testJournal(t)
		adapter, err := NewOCIBlockStorageAdapter(transport, journal)
		if err != nil {
			t.Fatal(err)
		}
		adapter.WaitPolicy = WorkRequestWaitPolicy{MaxPolls: 1, MaxNotFound: 0}
		adapter.Ownership = testOwnership(t, volumeID)
		request := VolumeDeleteRequest{VolumeID: volumeID, IfMatch: "volume-etag"}
		request.Mutation = testMutation("volume.delete", VolumeDeleteMutationScope(request), VolumeDeleteMutationFingerprint(request), 1)
		if err := adapter.DeleteVolume(context.Background(), request); err == nil {
			t.Fatal("canceled volume work request was accepted")
		}
		record, err := journal.Prepare(context.Background(), request.Mutation)
		want := ProviderMutationResult{ResourceID: volumeID, ETag: "volume-etag", WorkRequestID: "delete-work"}
		if err != nil || record.State != MutationFailed || record.Result != want || record.FailureCode != "provider-work-request-canceled" {
			t.Fatalf("canceled volume journal = %+v err=%v", record, err)
		}
	})
}

func TestOCIStorageCreateTransportLossDoesNotResubmit(t *testing.T) {
	const compartment = "ocid1.compartment.oc1..testcompartment"
	volumePosts, attachmentPosts := 0, 0
	volumeTransport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPost {
			volumePosts++
			return nil, io.ErrUnexpectedEOF
		}
		return testHTTPResponse(http.StatusOK, `[]`, nil), nil
	})
	volumeJournal := testJournal(t)
	volumeAdapter, err := NewOCIBlockStorageAdapter(volumeTransport, volumeJournal)
	if err != nil {
		t.Fatal(err)
	}
	volumeRequest := VolumeCreateRequest{CompartmentID: compartment, AvailabilityDomain: "AD-1", DisplayName: "loss-volume", SizeGiB: 100, VPUsPerGiB: 20}
	volumeRequest.Mutation = testMutation("volume.create", VolumeCreateMutationScope(volumeRequest), VolumeCreateMutationFingerprint(volumeRequest), 1)
	if _, err := volumeAdapter.CreateVolume(context.Background(), volumeRequest); err == nil {
		t.Fatal("transport-loss volume create was accepted")
	}
	volumeRequest.Mutation.Epoch.Value++
	if _, err := volumeAdapter.CreateVolume(context.Background(), volumeRequest); err == nil {
		t.Fatal("unproved volume create resume was accepted")
	}
	if volumePosts != 1 {
		t.Fatalf("volume posts = %d, want 1", volumePosts)
	}

	attachmentTransport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPost {
			attachmentPosts++
			return nil, io.ErrUnexpectedEOF
		}
		return testHTTPResponse(http.StatusOK, `[]`, nil), nil
	})
	attachmentJournal := testJournal(t)
	attachmentAdapter, err := NewOCIVolumeAttachmentAdapter(attachmentTransport, attachmentJournal)
	if err != nil {
		t.Fatal(err)
	}
	instanceID := "ocid1.instance.oc1.sa-saopaulo-1.loss-instance"
	volumeID := "ocid1.volume.oc1.sa-saopaulo-1.loss-volume"
	attachmentAdapter.Ownership = testOwnership(t, instanceID, volumeID)
	attachmentRequest := VolumeAttachRequest{CompartmentID: compartment, InstanceID: instanceID, VolumeID: volumeID, DisplayName: "loss-attachment"}
	attachmentRequest.Mutation = testMutation("attachment.create", VolumeAttachMutationScope(attachmentRequest), VolumeAttachMutationFingerprint(attachmentRequest), 1)
	if _, err := attachmentAdapter.AttachVolume(context.Background(), attachmentRequest); err == nil {
		t.Fatal("transport-loss attachment create was accepted")
	}
	attachmentRequest.Mutation.Epoch.Value++
	if _, err := attachmentAdapter.AttachVolume(context.Background(), attachmentRequest); err == nil {
		t.Fatal("unproved attachment create resume was accepted")
	}
	if attachmentPosts != 1 {
		t.Fatalf("attachment posts = %d, want 1", attachmentPosts)
	}
}

func TestOCIStoragePaginationRejectsMalformedSequences(t *testing.T) {
	for _, test := range []struct {
		name   string
		header http.Header
		seen   map[string]struct{}
		read   int
	}{
		{name: "duplicate header", header: http.Header{"Opc-Next-Page": {"p1", "p2"}}, seen: map[string]struct{}{}, read: 1},
		{name: "loop", header: http.Header{"Opc-Next-Page": {"p1"}}, seen: map[string]struct{}{"p1": {}}, read: 2},
		{name: "whitespace", header: http.Header{"Opc-Next-Page": {" p1"}}, seen: map[string]struct{}{}, read: 1},
		{name: "control", header: http.Header{"Opc-Next-Page": {"p\t1"}}, seen: map[string]struct{}{}, read: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := nextOCIPage(testHTTPResponse(http.StatusOK, "", test.header), test.seen, test.read); err == nil {
				t.Fatal("malformed pagination was accepted")
			}
		})
	}

	const compartment = "ocid1.compartment.oc1..testcompartment"
	for _, test := range []struct {
		name string
		path string
		body string
	}{
		{name: "volume", path: "/20160918/volumes", body: `{"items":[]}`},
		{name: "attachment", path: "/20160918/volumeAttachments", body: `{"items":[]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
				return testHTTPResponse(http.StatusOK, test.body, http.Header{"Opc-Next-Page": {"p1", "p1"}}), nil
			})
			if test.name == "volume" {
				adapter := &OCIBlockStorageAdapter{Core: transport}
				if _, err := adapter.listVolumes(context.Background(), url.Values{"compartmentId": {compartment}}); err == nil {
					t.Fatal("volume pagination was accepted")
				}
			} else {
				adapter := &OCIVolumeAttachmentAdapter{Core: transport}
				if _, err := adapter.listAttachments(context.Background(), url.Values{"compartmentId": {compartment}}); err == nil {
					t.Fatal("attachment pagination was accepted")
				}
			}
		})
	}
}

func TestOCIObjectStoragePaginationRejectsMalformedAbsenceProof(t *testing.T) {
	object := ObjectRef{Namespace: "namespace", Bucket: "ledger", Name: "region/segment-1"}
	for _, test := range []struct {
		name string
		next string
	}{
		{name: "loop", next: "cursor-1"},
		{name: "whitespace", next: " cursor-1"},
		{name: "control", next: "cursor\t1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodHead {
					return testHTTPResponse(http.StatusNotFound, "", nil), nil
				}
				return testHTTPResponse(http.StatusOK, `{"objects":[],"nextStartWith":"`+test.next+`"}`, nil), nil
			})
			adapter, err := NewOCIObjectStorageAdapter(transport, testJournal(t))
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = adapter.HeadObject(context.Background(), object)
			if err == nil {
				t.Fatal("Object Storage pagination was accepted")
			}
		})
	}
}

func TestOCIObjectStoragePutConflictAndIndeterminateOutcome(t *testing.T) {
	object := ObjectRef{Namespace: "namespace", Bucket: "ledger", Name: "region/segment-1"}
	content := []byte("payload")
	digest := objectSHA256(content)
	t.Run("conflict", func(t *testing.T) {
		transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodPut {
				return testHTTPResponse(http.StatusPreconditionFailed, "", nil), nil
			}
			return testHTTPResponse(http.StatusOK, "", http.Header{"Content-Length": {"7"}, "Etag": {"other-etag"}, "Opc-Meta-Terrascale-Sha256": {objectSHA256([]byte("other"))}}), nil
		})
		adapter, err := NewOCIObjectStorageAdapter(transport, testJournal(t))
		if err != nil {
			t.Fatal(err)
		}
		request := ObjectPutRequest{Object: object, Content: content, SHA256: digest}
		request.Mutation = testMutation("object.put", ObjectPutMutationScope(request), ObjectPutMutationFingerprint(request), 1)
		if _, err := adapter.PutObject(context.Background(), request); err == nil {
			t.Fatal("object conflict was accepted")
		}
	})
	t.Run("indeterminate", func(t *testing.T) {
		puts := 0
		transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
			switch request.Method {
			case http.MethodPut:
				puts++
				return nil, io.ErrUnexpectedEOF
			case http.MethodHead:
				return testHTTPResponse(http.StatusNotFound, "", nil), nil
			default:
				return testHTTPResponse(http.StatusOK, `{"objects":[]}`, nil), nil
			}
		})
		journal := testJournal(t)
		adapter, err := NewOCIObjectStorageAdapter(transport, journal)
		if err != nil {
			t.Fatal(err)
		}
		request := ObjectPutRequest{Object: object, Content: content, SHA256: digest}
		request.Mutation = testMutation("object.put", ObjectPutMutationScope(request), ObjectPutMutationFingerprint(request), 1)
		if _, err := adapter.PutObject(context.Background(), request); err == nil || !errors.As(err, new(*ProviderOutcomeUnknownError)) {
			t.Fatalf("indeterminate put = %v", err)
		}
		if puts != 1 {
			t.Fatalf("put submissions = %d, want 1", puts)
		}
	})
}

func TestOCIStorageStreamingRejectsShortOverlongAndWrongDigest(t *testing.T) {
	for _, test := range []struct {
		name    string
		content string
		expect  string
		size    int64
		want    string
	}{
		{name: "short", content: "abc", expect: objectSHA256([]byte("abc")), size: 4, want: "length"},
		{name: "overlong", content: "abc", expect: objectSHA256([]byte("ab")), size: 2, want: "length"},
		{name: "digest", content: "abc", expect: objectSHA256([]byte("xyz")), size: 3, want: "digest"},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := newLengthDigestVerifyingReadCloser(io.NopCloser(strings.NewReader(test.content)), test.expect, test.size)
			defer reader.Close()
			if _, err := io.ReadAll(reader); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("streaming %s error = %v", test.name, err)
			}
		})
	}
}

func TestProviderMutationJournalRecordsProviderFailureAndObservedAbsence(t *testing.T) {
	journal := testJournal(t)
	absent := testMutation("volume.delete", ProviderMutationScope("volume", "absent"), ProviderMutationFingerprint("absent"), 1)
	if _, err := journal.Prepare(context.Background(), absent); err != nil {
		t.Fatal(err)
	}
	if record, err := journal.MarkSucceeded(context.Background(), absent, ProviderMutationResult{ResourceID: "ocid1.volume.oc1.sa-saopaulo-1.absent", ETag: "etag"}); err != nil || record.State != MutationSucceeded {
		t.Fatalf("observed absence transition = %+v err=%v", record, err)
	}

	intent := testMutation("attachment.delete", ProviderMutationScope("attachment", "failed"), ProviderMutationFingerprint("failed"), 1)
	result := ProviderMutationResult{ResourceID: "ocid1.volumeattachment.oc1.sa-saopaulo-1.failed", WorkRequestID: "work-failed", ETag: "etag"}
	if _, err := journal.Prepare(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.MarkSubmitted(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.MarkUnknown(context.Background(), intent, result); err != nil {
		t.Fatal(err)
	}
	record, err := journal.MarkProviderFailed(context.Background(), intent, result, "provider-work-request-failed")
	if err != nil || record.State != MutationFailed || record.Result != result || record.FailureCode != "provider-work-request-failed" {
		t.Fatalf("provider failure = %+v err=%v", record, err)
	}
}

func TestOCIWorkRequestAdapterTerminalAndBoundedFailures(t *testing.T) {
	for _, test := range []struct {
		name   string
		status string
		state  WorkRequestState
	}{
		{name: "failed", status: "FAILED", state: WorkRequestFailed},
		{name: "canceled", status: "CANCELED", state: WorkRequestCanceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
				return testHTTPResponse(http.StatusOK, `{"id":"work-terminal","status":"`+test.status+`","percentComplete":100}`, nil), nil
			})
			adapter, err := NewOCIWorkRequestAdapter(transport)
			if err != nil {
				t.Fatal(err)
			}
			adapter.Wait = func(context.Context, time.Duration) error { return nil }
			work, err := adapter.WaitWorkRequest(context.Background(), "work-terminal", WorkRequestWaitPolicy{MaxPolls: 2, MaxNotFound: 0})
			if err == nil || work.State != test.state {
				t.Fatalf("terminal work = %+v err=%v", work, err)
			}
		})
	}
	t.Run("invisible bound", func(t *testing.T) {
		transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
			return testHTTPResponse(http.StatusNotFound, "", nil), nil
		})
		adapter, err := NewOCIWorkRequestAdapter(transport)
		if err != nil {
			t.Fatal(err)
		}
		adapter.Wait = func(context.Context, time.Duration) error { return nil }
		work, err := adapter.WaitWorkRequest(context.Background(), "work-invisible", WorkRequestWaitPolicy{MaxPolls: 4, MaxNotFound: 1})
		if err == nil || work.State != WorkRequestNotVisible || !errors.As(err, new(*ProviderOutcomeUnknownError)) {
			t.Fatalf("invisible work = %+v err=%v", work, err)
		}
	})
	t.Run("poll bound", func(t *testing.T) {
		transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
			return testHTTPResponse(http.StatusOK, `{"id":"work-poll","status":"IN_PROGRESS","percentComplete":25}`, nil), nil
		})
		adapter, err := NewOCIWorkRequestAdapter(transport)
		if err != nil {
			t.Fatal(err)
		}
		adapter.Wait = func(context.Context, time.Duration) error { return nil }
		work, err := adapter.WaitWorkRequest(context.Background(), "work-poll", WorkRequestWaitPolicy{MaxPolls: 2, MaxNotFound: 0})
		if err == nil || work.State != WorkRequestInProgress || !errors.As(err, new(*ProviderOutcomeUnknownError)) {
			t.Fatalf("poll-bound work = %+v err=%v", work, err)
		}
	})
}

func TestOCIWorkRequestAndMutationHeadersAreCanonical(t *testing.T) {
	for _, id := range []string{" work", "work/part", "work?part", "work\tpart"} {
		if validWorkRequestID(id) {
			t.Fatalf("malformed work request ID accepted: %q", id)
		}
	}
	for _, values := range [][]string{{"etag", "duplicate"}, {" etag"}, {"etag\nvalue"}} {
		if _, err := canonicalOCIETag(testHTTPResponse(http.StatusOK, "", http.Header{"Etag": values})); err == nil {
			t.Fatalf("malformed ETag accepted: %v", values)
		}
	}
	for _, values := range [][]string{{"work", "duplicate"}, {" work"}, {"work/part"}} {
		if _, err := optionalOCIWorkRequestID(testHTTPResponse(http.StatusOK, "", http.Header{"Opc-Work-Request-Id": values})); err == nil {
			t.Fatalf("malformed work-request header accepted: %v", values)
		}
	}
}

func TestProviderMutationJournalRejectsPreparedSuccessExceptObservedAbsence(t *testing.T) {
	for _, action := range []string{"volume.create", "attachment.create", "object.put", "compute.launch"} {
		t.Run(action, func(t *testing.T) {
			journal := testJournal(t)
			intent := testMutation(action, ProviderMutationScope("test", action), ProviderMutationFingerprint(action), 1)
			if _, err := journal.Prepare(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			if _, err := journal.MarkSucceeded(context.Background(), intent, ProviderMutationResult{ResourceID: "resource", ETag: "etag"}); err == nil {
				t.Fatal("prepared create mutation transitioned directly to success")
			}
		})
	}

	journal := testJournal(t)
	intent := testMutation("object.delete", ProviderMutationScope("object", "absent-transition"), ProviderMutationFingerprint("absent-transition"), 1)
	if _, err := journal.Prepare(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.MarkSucceeded(context.Background(), intent, ProviderMutationResult{ResourceID: "object", ETag: "etag"}); err != nil {
		t.Fatalf("observed-absence delete transition failed: %v", err)
	}
}

func TestOCIStoragePaginationEnforcesMaximumPageBound(t *testing.T) {
	const compartment = "ocid1.compartment.oc1..testcompartment"
	for _, test := range []struct {
		name string
		list func(*testing.T, *OCIHTTPTransport) error
	}{
		{name: "volume", list: func(t *testing.T, transport *OCIHTTPTransport) error {
			return func() error {
				adapter := &OCIBlockStorageAdapter{Core: transport}
				_, err := adapter.listVolumes(context.Background(), url.Values{"compartmentId": {compartment}})
				return err
			}()
		}},
		{name: "attachment", list: func(t *testing.T, transport *OCIHTTPTransport) error {
			return func() error {
				adapter := &OCIVolumeAttachmentAdapter{Core: transport}
				_, err := adapter.listAttachments(context.Background(), url.Values{"compartmentId": {compartment}})
				return err
			}()
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
				calls++
				next := "page-" + strconv.Itoa(calls)
				return testHTTPResponse(http.StatusOK, `{"items":[]}`, http.Header{"Opc-Next-Page": {next}}), nil
			})
			if err := test.list(t, transport); err == nil || calls != maximumOCIPages {
				t.Fatalf("%s page bound err=%v calls=%d", test.name, err, calls)
			}
		})
	}

	t.Run("object storage absence", func(t *testing.T) {
		calls := 0
		transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodHead {
				return testHTTPResponse(http.StatusNotFound, "", nil), nil
			}
			calls++
			return testHTTPResponse(http.StatusOK, `{"objects":[],"nextStartWith":"`+"cursor-"+strconv.Itoa(calls)+`"}`, nil), nil
		})
		adapter, err := NewOCIObjectStorageAdapter(transport, testJournal(t))
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = adapter.HeadObject(context.Background(), ObjectRef{Namespace: "namespace", Bucket: "ledger", Name: "region/segment-1"})
		if err == nil || calls != maximumOCIPages {
			t.Fatalf("object page bound err=%v calls=%d", err, calls)
		}
	})
}

func TestOCIObjectStorageRejectsDuplicateMetadataHeadersThroughHeadAndGet(t *testing.T) {
	content := []byte("payload")
	digest := objectSHA256(content)
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		for _, name := range []string{"Etag", "Opc-Meta-Terrascale-Sha256"} {
			t.Run(method+"/"+name, func(t *testing.T) {
				headers := http.Header{
					"Content-Length":             {"7"},
					"Etag":                       {"object-etag"},
					"Opc-Meta-Terrascale-Sha256": {digest},
				}
				headers[name] = []string{headers[name][0], headers[name][0]}
				transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
					return testHTTPResponse(http.StatusOK, string(content), headers), nil
				})
				adapter, err := NewOCIObjectStorageAdapter(transport, testJournal(t))
				if err != nil {
					t.Fatal(err)
				}
				if method == http.MethodHead {
					_, _, err = adapter.HeadObject(context.Background(), ObjectRef{Namespace: "namespace", Bucket: "ledger", Name: "region/segment-1"})
				} else {
					var reader io.ReadCloser
					reader, _, err = adapter.GetObject(context.Background(), ObjectRef{Namespace: "namespace", Bucket: "ledger", Name: "region/segment-1"})
					if reader != nil {
						_ = reader.Close()
					}
				}
				if err == nil {
					t.Fatalf("duplicate %s header accepted through %s", name, method)
				}
			})
		}
	}
}
