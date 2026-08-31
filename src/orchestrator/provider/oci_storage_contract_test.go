package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func testOwnership(t *testing.T, ids ...string) *DurableOwnershipJournal {
	t.Helper()
	journal, err := NewDurableOwnershipJournal(newTestOwnershipCAS(), 32)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		record := ProviderOwnershipRecord{ResourceId: ProviderResourceId{Value: id}, CellId: ProviderCellId{Value: "gru"}, CompartmentId: ProviderCompartmentId{Value: "ocid1.compartment.oc1.x"}, Generation: ProviderGeneration{Value: 1}}
		if err := journal.Record(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	}
	return journal
}

func TestOCIBlockVolumeAdapterContract(t *testing.T) {
	var requestBody map[string]any
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/20160918/volumes" {
			t.Fatalf("unexpected volume request %s %s", request.Method, request.URL.String())
		}
		if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
			t.Fatal(err)
		}
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.volume.oc1.x","compartmentId":"ocid1.compartment.oc1.x","lifecycleState":"PROVISIONING","sizeInGBs":100,"vpusPerGB":20}`, http.Header{"Etag": {"volume-etag"}, "Opc-Work-Request-Id": {"volume-work"}}), nil
	})
	adapter, err := NewOCIBlockStorageAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	request := VolumeCreateRequest{CompartmentID: "ocid1.compartment.oc1.x", AvailabilityDomain: "AD-1", DisplayName: "data-node-a", SizeGiB: 100, VPUsPerGiB: 20, Tags: map[string]string{"role": "data"}}
	request.Mutation = testMutation("volume.create", VolumeCreateMutationScope(request), VolumeCreateMutationFingerprint(request), 2)
	volume, err := adapter.CreateVolume(context.Background(), request)
	if err != nil || volume.ID != "ocid1.volume.oc1.x" || volume.ETag != "volume-etag" {
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
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.volumeattachment.oc1.x","compartmentId":"ocid1.compartment.oc1.x","instanceId":"ocid1.instance.oc1.x","volumeId":"ocid1.volume.oc1.x","lifecycleState":"ATTACHING"}`, http.Header{"Etag": {"attachment-etag"}}), nil
	})
	adapter, err := NewOCIVolumeAttachmentAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	adapter.Ownership = testOwnership(t, "ocid1.instance.oc1.x", "ocid1.volume.oc1.x")
	request := VolumeAttachRequest{CompartmentID: "ocid1.compartment.oc1.x", InstanceID: "ocid1.instance.oc1.x", VolumeID: "ocid1.volume.oc1.x", DisplayName: "data-node-a"}
	request.Mutation = testMutation("attachment.create", VolumeAttachMutationScope(request), VolumeAttachMutationFingerprint(request), 3)
	attachment, err := adapter.AttachVolume(context.Background(), request)
	if err != nil || attachment.ID != "ocid1.volumeattachment.oc1.x" || attachment.ETag != "attachment-etag" {
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

func TestOCIStorageDeletesConvergeWhenResourcesAreAlreadyAbsent(t *testing.T) {
	volumeID := "ocid1.volume.oc1.absent"
	attachmentID := "ocid1.volumeattachment.oc1.absent"

	volumeTransport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet {
			t.Fatalf("already-absent volume deletion sent %s", request.Method)
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
		if request.Method != http.MethodHead {
			t.Fatalf("already-absent object deletion sent %s", request.Method)
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
		return testHTTPResponse(http.StatusNotFound, "", nil), nil
	})
	journal := testJournal(t)
	adapter, err := NewOCIBlockStorageAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	volumeID := "ocid1.volume.oc1.x"
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

func TestOCIVolumeDetachAbsentIsDurablyIdempotent(t *testing.T) {
	deletes := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodDelete {
			deletes++
		}
		return testHTTPResponse(http.StatusNotFound, "", nil), nil
	})
	journal := testJournal(t)
	adapter, err := NewOCIVolumeAttachmentAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	attachmentID := "ocid1.volumeattachment.oc1.x"
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
