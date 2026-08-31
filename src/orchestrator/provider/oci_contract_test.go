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
	"sync"
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

func TestOCIComputeAdapterFallsBackAcrossCapacityCandidatesAndResumes(t *testing.T) {
	var mu sync.Mutex
	var posts []map[string]any
	var tokens []string
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/20160918/instances" {
			t.Fatalf("unexpected compute request %s %s", request.Method, request.URL.String())
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		posts = append(posts, body)
		tokens = append(tokens, request.Header.Get("opc-retry-token"))
		attempt := len(posts)
		mu.Unlock()
		if attempt == 1 {
			return testHTTPResponse(http.StatusInternalServerError, `{"code":"OutOfHostCapacity","message":"no A1 hosts"}`, nil), nil
		}
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.instance.oc1.saopaulo.x","compartmentId":"ocid1.compartment.oc1.x","lifecycleState":"PROVISIONING","availabilityDomain":"AD-2","shape":"VM.Standard.E5.Flex","etag":"instance-etag"}`, http.Header{"Opc-Work-Request-Id": {"work-1"}}), nil
	})
	adapter, err := NewOCIComputeAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	request := ComputeLaunchRequest{
		CompartmentID:   "ocid1.compartment.oc1.x",
		DisplayName:     "terrascale-node-a",
		ImageID:         "ocid1.image.oc1.x",
		SubnetID:        "ocid1.subnet.oc1.x",
		NSGIDs:          []string{"ocid1.networksecuritygroup.oc1.x"},
		BootstrapBase64: base64.StdEncoding.EncodeToString([]byte("#cloud-config\n")),
		Candidates: []ComputeCapacityCandidate{
			{AvailabilityDomain: "AD-1", Shape: "VM.Standard.A1.Flex", OCPUs: 4, MemoryGiB: 24},
			{AvailabilityDomain: "AD-2", Shape: "VM.Standard.E5.Flex", OCPUs: 4, MemoryGiB: 24},
		},
		Tags: map[string]string{"role": "member"},
	}
	request.Mutation = testMutation("compute.launch", ComputeLaunchMutationScope(request), ComputeLaunchMutationFingerprint(request), 7)
	instance, err := adapter.LaunchInstance(context.Background(), request)
	if err != nil || instance.ID != "ocid1.instance.oc1.saopaulo.x" || len(posts) != 2 {
		t.Fatalf("launch = %+v, posts = %d, err = %v", instance, len(posts), err)
	}
	if posts[0]["availabilityDomain"] != "AD-1" || posts[1]["availabilityDomain"] != "AD-2" || posts[1]["shape"] != "VM.Standard.E5.Flex" {
		t.Fatalf("capacity fallback order = %+v", posts)
	}
	shape := posts[1]["shapeConfig"].(map[string]any)
	if shape["ocpus"] != float64(4) || shape["memoryInGBs"] != float64(24) || tokens[0] == tokens[1] || len(tokens[0]) != 64 {
		t.Fatalf("capacity request was not fully or independently bound: shape=%v tokens=%v", shape, tokens)
	}
	if _, err := adapter.LaunchInstance(context.Background(), request); err != nil || len(posts) != 2 {
		t.Fatalf("durable resume posted again: posts=%d err=%v", len(posts), err)
	}
	forged := request
	forged.Mutation = testMutation("compute.launch", "forged-scope", ComputeLaunchMutationFingerprint(forged), 8)
	if _, err := adapter.LaunchInstance(context.Background(), forged); err == nil || len(posts) != 2 {
		t.Fatalf("caller-chosen scope bypassed the compute fence: posts=%d err=%v", len(posts), err)
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
			t.Fatalf("unexpected method %s", request.Method)
			return nil, nil
		}
	})
	adapter, err := NewOCIComputeAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	request := ComputeLaunchRequest{CompartmentID: "ocid1.compartment.oc1.x", DisplayName: "node-unknown", ImageID: "ocid1.image.oc1.x", SubnetID: "ocid1.subnet.oc1.x", BootstrapBase64: base64.StdEncoding.EncodeToString([]byte("#cloud-config\n")), Candidates: []ComputeCapacityCandidate{{AvailabilityDomain: "AD-1", Shape: "VM.Standard.A1.Flex", OCPUs: 1, MemoryGiB: 6}}}
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
	request := VolumeAttachRequest{CompartmentID: "ocid1.compartment.oc1.x", InstanceID: "ocid1.instance.oc1.x", VolumeID: "ocid1.volume.oc1.x", DisplayName: "data-node-a", ReadOnly: false}
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
			t.Fatalf("unexpected registry path %s", request.URL.Path)
			return nil, nil
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
	gotBlob, _ := io.ReadAll(reader)
	if size != int64(len(blob)) || string(gotBlob) != blob {
		t.Fatalf("blob size=%d body=%q", size, gotBlob)
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

type fakeEstateReader map[string]string

func (f fakeEstateReader) Read(_ context.Context, service OCIService, path string) ([]byte, int, error) {
	body, ok := f[string(service)+"|"+path]
	if !ok {
		return nil, http.StatusNotFound, nil
	}
	return []byte(body), http.StatusOK, nil
}

func TestEstateVerifierRejectsMalformedManualEstate(t *testing.T) {
	control := "ocid1.compartment.oc1.control"
	network := "ocid1.compartment.oc1.network"
	workload := "ocid1.compartment.oc1.workload"
	vcn := "ocid1.vcn.oc1.x"
	subnets := []string{"ocid1.subnet.oc1.a", "ocid1.subnet.oc1.b", "ocid1.subnet.oc1.c"}
	nsgs := []string{"ocid1.networksecuritygroup.oc1.a", "ocid1.networksecuritygroup.oc1.b", "ocid1.networksecuritygroup.oc1.c"}
	vault := "ocid1.vault.oc1.x"
	key := "ocid1.key.oc1.x"
	policy := "ocid1.policy.oc1.x"
	statement := "Allow dynamic-group terrascale-orchestrator to manage instances in compartment terrascale-workload"
	spec := OCIEstateSpec{Region: "sa-saopaulo-1", TenancyID: "ocid1.tenancy.oc1.x", ControlCompartmentID: control, NetworkCompartmentID: network, WorkloadCompartmentID: workload, VCNID: vcn, SubnetIDs: subnets, NetworkSecurityGroupIDs: nsgs, IAMPolicyCompartmentID: control, IAMPolicies: []OCIEstatePolicy{{ID: policy, Statements: []string{statement}}}, VaultID: vault, KeyID: key, KeyManagementEndpoint: "https://vault-management.kms.sa-saopaulo-1.oraclecloud.com", ObjectNamespace: "namespace", LedgerBucket: "terrascale-ledger", BackupBucket: "terrascale-backups"}
	reader := fakeEstateReader{}
	for _, compartment := range []string{control, network, workload} {
		reader[string(OCIServiceIdentity)+"|/20160918/compartments/"+compartment] = `{"id":"` + compartment + `","lifecycleState":"ACTIVE"}`
	}
	reader[string(OCIServiceCore)+"|/20160918/vcns/"+vcn] = `{"id":"` + vcn + `","compartmentId":"` + network + `","lifecycleState":"AVAILABLE"}`
	for _, subnet := range subnets {
		reader[string(OCIServiceCore)+"|/20160918/subnets/"+subnet] = `{"id":"` + subnet + `","compartmentId":"` + network + `","vcnId":"` + vcn + `","lifecycleState":"AVAILABLE","prohibitPublicIpOnVnic":true}`
	}
	for _, nsg := range nsgs {
		reader[string(OCIServiceCore)+"|/20160918/networkSecurityGroups/"+nsg] = `{"id":"` + nsg + `","compartmentId":"` + network + `","vcnId":"` + vcn + `","lifecycleState":"AVAILABLE"}`
	}
	reader[string(OCIServiceIdentity)+"|/20160918/policies/"+policy] = `{"id":"` + policy + `","compartmentId":"` + control + `","lifecycleState":"ACTIVE","statements":["` + statement + `"]}`
	reader[string(OCIServiceVault)+"|/20180608/vaults/"+vault] = `{"id":"` + vault + `","compartmentId":"` + control + `","lifecycleState":"ACTIVE"}`
	reader[string(OCIServiceVaultManagement)+"|/20180608/keys/"+key] = `{"id":"` + key + `","compartmentId":"` + control + `","lifecycleState":"ENABLED"}`
	reader[string(OCIServiceObjectStorage)+"|/n/namespace/b/terrascale-ledger"] = `{"name":"terrascale-ledger","compartmentId":"` + control + `"}`
	reader[string(OCIServiceObjectStorage)+"|/n/namespace/b/terrascale-backups"] = `{"name":"terrascale-backups","compartmentId":"` + control + `"}`
	if err := VerifyOCIEstate(context.Background(), spec, reader); err != nil {
		t.Fatalf("valid estate rejected: %v", err)
	}
	broken := fakeEstateReader{}
	for path, body := range reader {
		broken[path] = body
	}
	broken[string(OCIServiceCore)+"|/20160918/subnets/"+subnets[0]] = `{"id":"` + subnets[0] + `","compartmentId":"` + network + `","vcnId":"ocid1.vcn.oc1.wrong","lifecycleState":"AVAILABLE","prohibitPublicIpOnVnic":true}`
	if err := VerifyOCIEstate(context.Background(), spec, broken); err == nil {
		t.Fatal("malformed subnet-to-VCN binding passed startup estate verification")
	}
}

func TestOCIServiceTransportRejectsCrossServiceAuthority(t *testing.T) {
	if _, err := NewOCIServiceTransportConfig(OCIServiceObjectStorage, "sa-saopaulo-1", "https://iaas.sa-saopaulo-1.oraclecloud.com"); err == nil {
		t.Fatal("Object Storage signer accepted the core service authority")
	}
	if _, err := NewOCIServiceTransportConfig(OCIServiceRegistry, "sa-saopaulo-1", "https://attacker.example"); err == nil {
		t.Fatal("registry signer accepted an arbitrary authority")
	}
	if _, err := NewOCIServiceTransportConfig(OCIServiceRegistry, "sa-saopaulo-1", "https://gru.ocir.io"); err != nil {
		t.Fatalf("GRU OCIR authority rejected: %v", err)
	}
	if _, err := NewOCIServiceTransportConfig(OCIServiceRegistry, "sa-saopaulo-1", "https://sa-saopaulo-1.ocir.io"); err == nil {
		t.Fatal("registry accepted the OCI region name instead of the OCIR region key")
	}
}
