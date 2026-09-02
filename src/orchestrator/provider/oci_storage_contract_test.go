package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

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
	request := VolumeCreateRequest{CompartmentID: "ocid1.compartment.oc1..testcompartment", AvailabilityDomain: "AD-1", DisplayName: "data-node-a", SizeGiB: 100, VPUsPerGiB: 20, Tags: map[string]string{"role": "data"}}
	request.Mutation = testMutation("volume.create", VolumeCreateMutationScope(request), VolumeCreateMutationFingerprint(request), 2)
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

func TestOCIObjectStorageAdapterContract(t *testing.T) {
	content := []byte("durable ledger segment")
	digest := objectSHA256(content)
	putCalls := 0
	transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPut || request.URL.EscapedPath() != "/n/namespace/b/ledger/o/region%2Fsegment-1" {
			t.Fatalf("unexpected object request %s %s", request.Method, request.URL.String())
		}
		putCalls++
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != string(content) || request.Header.Get("If-None-Match") != "*" || request.Header.Get("opc-meta-terrascale-sha256") != digest {
			t.Fatalf("object put body=%q headers=%v", body, request.Header)
		}
		return testHTTPResponse(http.StatusOK, "", http.Header{"Etag": {"object-etag"}}), nil
	})
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
	manifest := []byte(`{"schemaVersion":2}`)
	manifestDigest := "sha256:" + objectSHA256(manifest)
	blob := "layer-bytes"
	blobDigest := "sha256:" + objectSHA256([]byte(blob))
	transport := testOCITransport(t, OCIServiceRegistry, func(request *http.Request) (*http.Response, error) {
		username, token, ok := request.BasicAuth()
		if !ok || username != "namespace/runner" || token != "registry-token" {
			t.Fatal("registry request did not carry the injected OCIR credential")
		}
		switch {
		case strings.Contains(request.URL.Path, "/manifests/"):
			return testHTTPResponse(http.StatusOK, string(manifest), http.Header{"Docker-Content-Digest": {manifestDigest}, "Content-Type": {"application/vnd.oci.image.manifest.v1+json"}}), nil
		case strings.Contains(request.URL.Path, "/blobs/"):
			return testHTTPResponse(http.StatusOK, blob, http.Header{"Docker-Content-Digest": {blobDigest}, "Content-Length": {"11"}}), nil
		default:
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
