package provider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOCIInstancePrincipalMetadataSourceRetrievesCredentialWithBoundedAccess(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyBody := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certBody := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host != "169.254.169.254" || request.Header.Get("Authorization") != "Bearer Oracle" {
			t.Fatalf("metadata request escaped its bounded authority: %s headers=%v", request.URL, request.Header)
		}
		body := certBody
		if strings.HasSuffix(request.URL.Path, "/key.pem") {
			body = keyBody
		}
		return testHTTPResponse(http.StatusOK, string(body), nil), nil
	})}
	source, err := NewOCIInstancePrincipalMetadataSource(client)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := source.Retrieve(context.Background())
	if err != nil || credentials.Key == nil || credentials.KeyID == "" {
		t.Fatalf("metadata credentials = %+v, %v", credentials, err)
	}
}

func TestOCIInstancePrincipalMetadataSourceRejectsMalformedCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyBody := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if strings.HasSuffix(request.URL.Path, "/key.pem") {
			return testHTTPResponse(http.StatusOK, string(keyBody), nil), nil
		}
		return testHTTPResponse(http.StatusOK, "not-a-certificate", nil), nil
	})}
	source, err := NewOCIInstancePrincipalMetadataSource(client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Retrieve(context.Background()); err == nil {
		t.Fatal("malformed metadata certificate was accepted")
	}
}

func TestNextOCIPageRejectsSeventeenthPage(t *testing.T) {
	response := testHTTPResponse(http.StatusOK, `{"items":[]}`, http.Header{"Opc-Next-Page": {"page-17"}})
	if _, err := nextOCIPage(response, "page-16", maximumOCIPages-1); err == nil {
		t.Fatal("pagination fetched beyond the 16-page bound")
	}
}

func TestNextOCIPageRejectsMalformedContinuationHeaders(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "oversized", value: strings.Repeat("x", 257)},
		{name: "control", value: "page-1\r\nforged: value"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headers := make(http.Header)
			headers.Set("Opc-Next-Page", test.value)
			if _, err := nextOCIPage(testHTTPResponse(http.StatusOK, `{"items":[]}`, headers), "", 0); err == nil {
				t.Fatal("malformed continuation header was treated as end-of-list")
			}
		})
	}
	if _, err := nextOCIPage(testHTTPResponse(http.StatusOK, `{"items":[]}`, http.Header{"Opc-Next-Page": {"page-1", "page-2"}}), "", 0); err == nil {
		t.Fatal("duplicate continuation headers were accepted")
	}
}

func TestOCIListDecodersRejectMalformedDocuments(t *testing.T) {
	for _, raw := range []string{"{}", "null", `{"items":null}`, `{"items":{}}`} {
		if _, err := decodeOCIList[string]([]byte(raw)); err == nil {
			t.Fatalf("decodeOCIList accepted %s", raw)
		}
		if _, err := decodeOCIInstanceList([]byte(raw)); err == nil {
			t.Fatalf("decodeOCIInstanceList accepted %s", raw)
		}
	}
	if items, err := decodeOCIList[string]([]byte(`[]`)); err != nil || items == nil {
		t.Fatalf("decodeOCIList rejected an explicit empty list: items=%v err=%v", items, err)
	}
	if items, err := decodeOCIInstanceList([]byte(`{"items":[]}`)); err != nil || items == nil {
		t.Fatalf("decodeOCIInstanceList rejected an explicit empty list: items=%v err=%v", items, err)
	}
	if items, err := decodeOCIInstanceList([]byte(`[{"id":"ocid1.instance.oc1.x","compartmentId":"ocid1.compartment.oc1.x"}]`)); err != nil || len(items) != 1 {
		t.Fatalf("decodeOCIInstanceList rejected a direct array: items=%v err=%v", items, err)
	}
}

func TestOCITransportRejectsInjectedRedirectPolicy(t *testing.T) {
	redirects := 0
	requests := 0
	injected := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			redirects++
			return nil
		},
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests++
			if request.URL.Host != "iaas.gru.oraclecloud.com" {
				t.Fatalf("redirected OCI request reached the injected transport: %s", request.URL)
			}
			return &http.Response{
				StatusCode: http.StatusTemporaryRedirect,
				Header:     http.Header{"Location": []string{"https://evil.example/redirect"}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    request,
			}, nil
		}),
	}
	cfg, err := NewOCITransportConfig("gru", "https://iaas.gru.oraclecloud.com")
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewOCIHTTPTransport(cfg, injected, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.Do(context.Background(), http.MethodGet, "/20160918/instances", nil); err == nil {
		t.Fatal("signed OCI transport followed a redirect")
	}
	if requests == 0 || redirects != 0 {
		t.Fatalf("redirect handling requests=%d injected redirect calls=%d", requests, redirects)
	}
	if injected.CheckRedirect == nil {
		t.Fatal("transport construction mutated the injected client")
	}
}

func TestOCINodeLaunchResolutionBindsNetworkToEstate(t *testing.T) {
	bootstrap := []byte("#cloud-config\n")
	digest := sha256.Sum256(bootstrap)
	request := CreateNodeProviderRequest{
		Context:    ProviderOperationContext{CompartmentId: ProviderCompartmentId{Value: "ocid1.compartment.oc1.x"}},
		Parameters: CreateNodeProviderParameters{BootstrapEnvelopeDigest: ProviderBootstrapEnvelopeDigest{Sha256: hex.EncodeToString(digest[:])}},
	}
	binding, err := NewOCINodeEstateBinding("ocid1.vcn.oc1.x", []string{"ocid1.subnet.oc1.x"}, []string{"ocid1.networksecuritygroup.oc1.x"})
	if err != nil {
		t.Fatal(err)
	}
	base := OciNodeLaunchSpec{CompartmentId: "ocid1.compartment.oc1.x", VcnId: "ocid1.vcn.oc1.x", SubnetId: "ocid1.subnet.oc1.x", ImageId: "ocid1.image.oc1.x", AvailabilityDomain: "AD-1", Shape: "VM.Standard.A1.Flex", NetworkSecurityGroupIds: []string{"ocid1.networksecuritygroup.oc1.x"}, Ocpus: 1, MemoryGB: 1, BootstrapBase64: base64.StdEncoding.EncodeToString(bootstrap)}
	if err := validateOciNodeLaunchSpecWithEstate(base, request, binding); err != nil {
		t.Fatalf("valid estate-bound launch rejected: %v", err)
	}
	for name, mutate := range map[string]func(*OciNodeLaunchSpec){
		"wrong vcn":      func(spec *OciNodeLaunchSpec) { spec.VcnId = "ocid1.vcn.oc1.other" },
		"outside subnet": func(spec *OciNodeLaunchSpec) { spec.SubnetId = "ocid1.subnet.oc1.other" },
		"outside nsg": func(spec *OciNodeLaunchSpec) {
			spec.NetworkSecurityGroupIds = []string{"ocid1.networksecuritygroup.oc1.other"}
		},
		"empty nsg": func(spec *OciNodeLaunchSpec) { spec.NetworkSecurityGroupIds = nil },
	} {
		t.Run(name, func(t *testing.T) {
			spec := base
			mutate(&spec)
			if err := validateOciNodeLaunchSpecWithEstate(spec, request, binding); err == nil {
				t.Fatal("out-of-scope launch resolution was accepted")
			}
		})
	}
}

func TestOCIInstancePrincipalMetadataSourceBypassesConfiguredProxy(t *testing.T) {
	key, cert := metadataCredentialFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Host != "169.254.169.254" || request.Header.Get("Authorization") != "Bearer Oracle" {
			t.Fatalf("metadata request escaped its fixed authority: host=%q headers=%v", request.Host, request.Header)
		}
		body := cert
		if strings.HasSuffix(request.URL.Path, "/key.pem") {
			body = key
		}
		_, _ = response.Write(body)
	}))
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			t.Fatal("metadata request used the configured proxy")
			return nil, nil
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, serverURL.Host)
		},
	}
	source, err := NewOCIInstancePrincipalMetadataSource(&http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Retrieve(context.Background()); err != nil {
		t.Fatalf("metadata retrieval through direct transport failed: %v", err)
	}
}

func metadataCredentialFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
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

func TestProviderMutationJournalRecordsObservedAbsentDelete(t *testing.T) {
	journal := testJournal(t)
	intent := testMutation("compute.terminate", "instance-a", ProviderMutationFingerprint("terminate"), 3)
	if _, err := journal.Prepare(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	result := ProviderMutationResult{ResourceID: "ocid1.instance.oc1.absent", ETag: "instance-etag"}
	if _, err := journal.MarkSucceeded(context.Background(), intent, result); err == nil {
		t.Fatal("generic success bypassed the prepared mutation submission")
	}
	record, err := journal.MarkAbsentDeleteSucceeded(context.Background(), intent, result)
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
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.instance.oc1.saopaulo.resumed","compartmentId":"ocid1.compartment.oc1.x","lifecycleState":"PROVISIONING","availabilityDomain":"AD-2","shape":"VM.Standard.E5.Flex"}`, nil), nil
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

func TestOCIComputeLaunchRejectsOutOfScopeMutationResponse(t *testing.T) {
	request := ComputeLaunchRequest{
		CompartmentID:   "ocid1.compartment.oc1.x",
		DisplayName:     "scope-check",
		ImageID:         "ocid1.image.oc1.x",
		BootstrapBase64: base64.StdEncoding.EncodeToString([]byte("#cloud-config\n")),
		Candidates:      []ComputeCapacityCandidate{{AvailabilityDomain: "AD-1", SubnetID: "ocid1.subnet.oc1.x", Shape: "VM.Standard.E5.Flex", OCPUs: 1, MemoryGiB: 4}},
	}
	request.Mutation = testMutation("compute.launch", ComputeLaunchMutationScope(request), ComputeLaunchMutationFingerprint(request), 1)
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.instance.oc1.x","compartmentId":"ocid1.compartment.oc1.other","lifecycleState":"PROVISIONING"}`, nil), nil
	})
	adapter, err := NewOCIComputeAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.LaunchInstance(context.Background(), request); err == nil {
		t.Fatal("out-of-scope compute response was accepted")
	}
}

func TestOCIComputeLaunchReconciliationFollowsNextPage(t *testing.T) {
	request := ComputeLaunchRequest{
		CompartmentID:   "ocid1.compartment.oc1.x",
		DisplayName:     "paged-reconcile",
		ImageID:         "ocid1.image.oc1.x",
		BootstrapBase64: base64.StdEncoding.EncodeToString([]byte("#cloud-config\n")),
		Candidates:      []ComputeCapacityCandidate{{AvailabilityDomain: "AD-1", SubnetID: "ocid1.subnet.oc1.x", Shape: "VM.Standard.E5.Flex", OCPUs: 1, MemoryGiB: 4}},
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
		if httpRequest.URL.Query().Get("page") == "" {
			return testHTTPResponse(http.StatusOK, `{"items":[]}`, http.Header{"Opc-Next-Page": {"page-2"}}), nil
		}
		body := `{"items":[{"id":"ocid1.instance.oc1.x","compartmentId":"ocid1.compartment.oc1.x","lifecycleState":"PROVISIONING","freeformTags":{"terrascale-operation":"` + request.Mutation.OperationID.Value + `","terrascale-intent":"` + request.Mutation.Fingerprint + `"}}]}`
		return testHTTPResponse(http.StatusOK, body, nil), nil
	})
	adapter, err := NewOCIComputeAdapter(transport, journal)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := adapter.LaunchInstance(context.Background(), request)
	if err != nil || instance.ID != "ocid1.instance.oc1.x" || pageCalls != 2 {
		t.Fatalf("paged reconciliation instance=%+v calls=%d err=%v", instance, pageCalls, err)
	}
}
