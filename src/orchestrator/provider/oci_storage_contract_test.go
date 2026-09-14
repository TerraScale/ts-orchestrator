package provider

import (
	"context"
	"encoding/json"
	"errors"
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
		record := ProviderOwnershipRecord{ResourceId: ProviderResourceId{Value: id}, CellId: ProviderCellId{Value: "gru"}, CompartmentId: ProviderCompartmentId{Value: "ocid1.compartment.oc1..x"}, Generation: ProviderGeneration{Value: 1}}
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
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.volume.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..x","lifecycleState":"PROVISIONING","sizeInGBs":100,"vpusPerGB":20}`, http.Header{"Etag": {"volume-etag"}, "Opc-Work-Request-Id": {"volume-work"}}), nil
	})
	adapter, err := NewOCIBlockStorageAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	request := VolumeCreateRequest{CompartmentID: "ocid1.compartment.oc1..x", AvailabilityDomain: "AD-1", DisplayName: "data-node-a", SizeGiB: 100, VPUsPerGiB: 20, Tags: map[string]string{"role": "data"}}
	request.Mutation = testMutation("volume.create", VolumeCreateMutationScope(request), VolumeCreateMutationFingerprint(request), 2)
	volume, err := adapter.CreateVolume(context.Background(), request)
	if err != nil || volume.ID != "ocid1.volume.oc1.sa-saopaulo-1.x" || volume.ETag != "volume-etag" {
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
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.volumeattachment.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..x","instanceId":"ocid1.instance.oc1.sa-saopaulo-1.x","volumeId":"ocid1.volume.oc1.sa-saopaulo-1.x","lifecycleState":"ATTACHING"}`, http.Header{"Etag": {"attachment-etag"}}), nil
	})
	adapter, err := NewOCIVolumeAttachmentAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	adapter.Ownership = testOwnership(t, "ocid1.instance.oc1.sa-saopaulo-1.x", "ocid1.volume.oc1.sa-saopaulo-1.x")
	request := VolumeAttachRequest{CompartmentID: "ocid1.compartment.oc1..x", InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.x", VolumeID: "ocid1.volume.oc1.sa-saopaulo-1.x", DisplayName: "data-node-a"}
	request.Mutation = testMutation("attachment.create", VolumeAttachMutationScope(request), VolumeAttachMutationFingerprint(request), 3)
	attachment, err := adapter.AttachVolume(context.Background(), request)
	if err != nil || attachment.ID != "ocid1.volumeattachment.oc1.sa-saopaulo-1.x" || attachment.ETag != "attachment-etag" {
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
