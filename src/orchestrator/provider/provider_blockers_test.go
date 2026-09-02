package provider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestOCIObserveParsesAndValidatesRunnerIdentityTags(t *testing.T) {
	bootstrap := []byte("#cloud-config\nruncmd: []\n")
	digest := sha256.Sum256(bootstrap)
	demand, err := NewOciCiRunnerDemand("runner-identity", TrustTrustedBuild, 9, base64.StdEncoding.EncodeToString(bootstrap), hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	template, err := NewOciCiRunnerLaunchTemplate("ocid1.compartment.oc1..x", "AD-1", "FD-1", "ocid1.subnet.oc1.sa-saopaulo-1.x", []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.x"}, "ocid1.image.oc1.sa-saopaulo-1.x", 4)
	if err != nil {
		t.Fatal(err)
	}
	tags := RunnerTags(demand, template.Generation)
	responseTags := tags
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := `[{"id":"ocid1.instance.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..x","lifecycleState":"RUNNING","timeCreated":"2026-08-30T12:00:00Z","freeformTags":` + string(mustJSON(responseTags)) + `}]`
		if request.URL.Path == "/20160918/instances/ocid1.instance.oc1.sa-saopaulo-1.x" {
			body = `{"id":"ocid1.instance.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..x"}`
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Etag": {"instance-etag"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	cfg, err := NewOCITransportConfig("gru", "https://iaas.gru.oraclecloud.com")
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewOCIHTTPTransport(cfg, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	compute, err := NewOCIComputeClient(transport)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := compute.Observe(context.Background(), template)
	if err != nil || len(observed) != 1 {
		t.Fatalf("observe = %+v, %v", observed, err)
	}
	if observed[0].Runner != demand.Runner || observed[0].Sequence != demand.Sequence || observed[0].ETag != "instance-etag" || !observed[0].Preemptible || observed[0].PreserveBootVolume || !RunnerMatches(observed[0], demand, template) {
		t.Fatalf("runner identity was not populated from validated tags: %+v", observed[0])
	}
	responseTags[runnerSequenceTag] = "not-a-sequence"
	if _, err := compute.Observe(context.Background(), template); err == nil {
		t.Fatal("malformed runner tags must fail closed")
	}
}

func TestOCIObserveCapsPageLimitAtOracleMaximum(t *testing.T) {
	template, err := NewOciCiRunnerLaunchTemplate("ocid1.compartment.oc1..x", "AD-1", "FD-1", "ocid1.subnet.oc1.sa-saopaulo-1.x", []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.x"}, "ocid1.image.oc1.sa-saopaulo-1.x", 4)
	if err != nil {
		t.Fatal(err)
	}
	seenLimit := ""
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		seenLimit = request.URL.Query().Get("limit")
		return testHTTPResponse(http.StatusOK, `[]`, nil), nil
	})
	compute, err := NewOCIComputeClient(transport)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compute.Observe(context.Background(), template); err != nil {
		t.Fatal(err)
	}
	if seenLimit != "1000" {
		t.Fatalf("OCI list page limit = %q, want 1000", seenLimit)
	}
}

func TestOCIRunnerStateHandlesOracleTransitionalStates(t *testing.T) {
	for _, state := range []string{"MOVING", "CREATING_IMAGE"} {
		got, ok := ociRunnerState(state)
		if !ok || got != RunnerLaunching {
			t.Fatalf("OCI lifecycle %s = %v, %v", state, got, ok)
		}
	}
}

func TestOCIObserveRejectsMissingCreationTime(t *testing.T) {
	template, err := NewOciCiRunnerLaunchTemplate("ocid1.compartment.oc1..x", "AD-1", "FD-1", "ocid1.subnet.oc1.sa-saopaulo-1.x", []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.x"}, "ocid1.image.oc1.sa-saopaulo-1.x", 4)
	if err != nil {
		t.Fatal(err)
	}
	transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusOK, `[{"id":"ocid1.instance.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..x","lifecycleState":"RUNNING"}]`, nil), nil
	})
	compute, err := NewOCIComputeClient(transport)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compute.Observe(context.Background(), template); err == nil {
		t.Fatal("OCI observation accepted an instance without mandatory timeCreated")
	}
}

func TestRunnerCapacityNeverUsesTagsWithoutOwnership(t *testing.T) {
	now := time.Unix(1_777_000_000, 0)
	bootstrap := []byte("#cloud-config\n")
	digest := sha256.Sum256(bootstrap)
	demand, err := NewOciCiRunnerDemand("runner-identity", TrustTrustedBuild, 9, base64.StdEncoding.EncodeToString(bootstrap), hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	template, err := NewOciCiRunnerLaunchTemplate("ocid1.compartment.oc1..x", "AD-1", "FD-1", "ocid1.subnet.oc1.sa-saopaulo-1.x", []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.x"}, "ocid1.image.oc1.sa-saopaulo-1.x", 4)
	if err != nil {
		t.Fatal(err)
	}
	obs := OciCiRunnerNodeObservation{InstanceId: "ocid1.instance.oc1.sa-saopaulo-1.x", ETag: "etag-1", Runner: demand.Runner, Sequence: demand.Sequence, State: RunnerStopped, LastActivity: now.Add(-time.Hour), FreeformTags: RunnerTags(demand, template.Generation), Preemptible: true}
	request, err := NewOciCiRunnerCapacityRequest(now, time.Minute, 1, template, []OciCiRunnerDemand{demand}, nil, []OciCiRunnerNodeObservation{obs})
	if err != nil {
		t.Fatal(err)
	}
	actions, err := DecideRunnerCapacity(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 0 {
		t.Fatalf("provider tags alone authorized lifecycle action: %+v", actions)
	}

	request.OwnershipRecords = []ProviderOwnershipRecord{{ResourceId: ProviderResourceId{Value: obs.InstanceId}, CellId: ProviderCellId{Value: "gru"}, CompartmentId: templateCompartment(template), Generation: ProviderGeneration{uint64(template.Generation)}}}
	actions, err = DecideRunnerCapacity(request)
	if err != nil || len(actions) != 1 {
		t.Fatalf("authoritatively owned stopped runner was not recognized: %+v, %v", actions, err)
	}
	request.Desired = nil
	actions, err = DecideRunnerCapacity(request)
	if err != nil || len(actions) != 1 {
		t.Fatalf("authoritatively owned idle runner was not terminated: %+v, %v", actions, err)
	}
}

func templateCompartment(t OciCiRunnerLaunchTemplate) ProviderCompartmentId {
	return ProviderCompartmentId{Value: t.CompartmentId}
}

func TestOCINodeCreateRequiresResolvedLaunchConfiguration(t *testing.T) {
	bootstrap := []byte("#cloud-config\nruncmd: []\n")
	digest := sha256.Sum256(bootstrap)
	params := CreateNodeProviderParameters{TemplateId: ProviderTemplateId{Value: "template-1"}, PlacementId: ProviderPlacementId{Value: "placement-1"}, BootstrapEnvelopeDigest: ProviderBootstrapEnvelopeDigest{Sha256: hex.EncodeToString(digest[:])}}
	contextValue, err := NewProviderOperationContext(ProviderOperationId{Value: "operation-1"}, ProviderCellId{Value: "gru"}, ProviderCompartmentId{Value: "ocid1.compartment.oc1..x"}, ProviderEpoch{Value: 1}, ResourceNode, ActionCreateNode, IdempotentProviderCreate{Key: ProviderCreateKey{Value: "create-1"}}, ProviderGeneration{Value: 1}, ObservedAbsent, TerminalPresent, nil, DeadlineEvidence{Status: DeadlineValid, EvidenceGeneration: ProviderGeneration{Value: 1}}, ProviderIdempotencyKey{Value: "idempotency-1"}, nil, params)
	if err != nil {
		t.Fatal(err)
	}
	binding := CreateNodeReceiptBinding{CreateKey: "create-1", CompartmentId: "ocid1.compartment.oc1..x", TemplateId: "template-1", PlacementId: "placement-1", BootstrapEnvelopeDigest: params.BootstrapEnvelopeDigest.Sha256, OperationId: "operation-1", IdempotencyKey: "idempotency-1", Generation: 1}
	var posts int
	var body []byte
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		posts++
		body, _ = io.ReadAll(request.Body)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Opc-Work-Request-Id": []string{"work-1"}}, Body: io.NopCloser(strings.NewReader(`{"id":"ocid1.instance.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..x"}`))}, nil
	})}
	cfg, err := NewOCITransportConfig("gru", "https://iaas.gru.oraclecloud.com")
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewOCIHTTPTransport(cfg, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	compute := &OCIComputeNodeClient{OCI: transport, LaunchResolver: OciNodeLaunchResolverFunc(func(context.Context, ProviderTemplateId, ProviderPlacementId, ProviderBootstrapEnvelopeDigest) (OciNodeLaunchSpec, error) {
		return OciNodeLaunchSpec{CompartmentId: "ocid1.compartment.oc1..x", AvailabilityDomain: "AD-1", FaultDomain: "FD-1", SubnetId: "ocid1.subnet.oc1.sa-saopaulo-1.x", ImageId: "ocid1.image.oc1.sa-saopaulo-1.x", Shape: "VM.Standard.A1.Flex", NetworkSecurityGroupIds: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.x"}, Ocpus: 4, MemoryGB: 24, BootstrapBase64: base64.StdEncoding.EncodeToString(bootstrap)}, nil
	})}
	response, err := compute.CreateNode(context.Background(), CreateNodeProviderRequest{Context: contextValue, Parameters: params, Binding: binding})
	if err != nil || response.NodeId.Value != "ocid1.instance.oc1.sa-saopaulo-1.x" || posts != 1 {
		t.Fatalf("resolved OCI node create = %+v, posts = %d, err = %v", response, posts, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["sourceDetails"].(map[string]any)["imageId"] != "ocid1.image.oc1.sa-saopaulo-1.x" || decoded["createVnicDetails"].(map[string]any)["subnetId"] != "ocid1.subnet.oc1.sa-saopaulo-1.x" || decoded["metadata"].(map[string]any)["user_data"] != base64.StdEncoding.EncodeToString(bootstrap) {
		t.Fatalf("resolved OCI node create omitted launch details: %s", body)
	}

	missingWorkCalls := 0
	missingWorkTransport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		missingWorkCalls++
		if request.Method != http.MethodPost {
			t.Fatalf("direct OCI client attempted unauthenticated recovery with %s", request.Method)
		}
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.instance.oc1.sa-saopaulo-1.x","compartmentId":"ocid1.compartment.oc1..x","etag":"not-a-work-request"}`, http.Header{"Etag": {"instance-etag"}}), nil
	})
	compute.OCI = missingWorkTransport
	if _, err := compute.CreateNode(context.Background(), CreateNodeProviderRequest{Context: contextValue, Parameters: params, Binding: binding}); err == nil || missingWorkCalls != 1 {
		t.Fatalf("direct OCI node create accepted or reconciled a missing work request: calls=%d err=%v", missingWorkCalls, err)
	}

	recoveryCalls := 0
	compute.OCI = testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		recoveryCalls++
		return nil, errors.New("direct reconciliation must not call OCI")
	})
	reconciled, err := compute.ReconcileCreateNode(context.Background(), CreateNodeProviderRequest{Context: contextValue, Parameters: params, Binding: binding})
	if err != nil || reconciled.Status != CreateNodeUnknown || reconciled.Response != nil || reconciled.Proof != nil || recoveryCalls != 0 {
		t.Fatalf("direct recovery = %+v, calls=%d, %v", reconciled, recoveryCalls, err)
	}
}

type testCreateNodeJournal struct {
	consumed       int
	capability     CreateNodeAuthoritativeInvocationCapability
	binding        CreateNodeReceiptBinding
	consumedAt     time.Time
	requestDigest  string
	consumptionErr error
}

type recordFailingOwnership struct {
	DurableOwnershipEvidence
	err error
}

func (o *recordFailingOwnership) Record(context.Context, ProviderOwnershipRecord) error {
	return o.err
}

func (j *testCreateNodeJournal) AuthoritativeDurable() bool { return j != nil }
func (j *testCreateNodeJournal) ConsumeInvocationCapability(_ context.Context, capability CreateNodeAuthoritativeInvocationCapability, binding CreateNodeReceiptBinding, requestDigest string, now time.Time) error {
	if j.consumptionErr != nil {
		return j.consumptionErr
	}
	if requestDigest == "" || now.Before(capability.IssuedAt) || !now.Before(capability.ExpiresAt) || !now.Before(capability.LeaseExpiresAt) {
		return &InvalidOperationError{Message: "test journal rejected an impossible invocation consumption"}
	}
	j.consumed++
	j.capability = capability
	j.binding = binding
	j.consumedAt = now
	j.requestDigest = requestDigest
	return nil
}
func (j *testCreateNodeJournal) InvocationCapabilityConsumption(_ context.Context, capability CreateNodeAuthoritativeInvocationCapability, binding CreateNodeReceiptBinding) (CreateNodeInvocationConsumption, bool, error) {
	if j.consumptionErr != nil {
		return CreateNodeInvocationConsumption{}, false, j.consumptionErr
	}
	return CreateNodeInvocationConsumption{ConsumedAt: j.consumedAt, ProviderRequestDigest: j.requestDigest}, j.consumed > 0 && j.capability == capability && j.binding == binding, nil
}

type authorizedCreateNodeFixture struct {
	request        CreateNodeProviderRequest
	keys           *ReceiptKeyRing
	proofSigner    *CreateNodeProviderProofSigner
	receiptSigner  *CreateNodeHandoffReceiptSigner
	invocationSigner *CreateNodeAuthoritativeInvocationCapabilitySigner
	launchResolver OciNodeLaunchResolver
	now            time.Time
}

func newAuthorizedCreateNodeFixture(t *testing.T) authorizedCreateNodeFixture {
	t.Helper()
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := NewReceiptKeyRing(map[string][]byte{"node-authority": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := []byte("#cloud-config\nruncmd: []\n")
	digest := sha256.Sum256(bootstrap)
	parameters := CreateNodeProviderParameters{
		TemplateId:              ProviderTemplateId{Value: "template-1"},
		PlacementId:             ProviderPlacementId{Value: "placement-1"},
		BootstrapEnvelopeDigest: ProviderBootstrapEnvelopeDigest{Sha256: hex.EncodeToString(digest[:])},
	}
	operationContext, err := NewProviderOperationContext(
		ProviderOperationId{Value: "operation-1"}, ProviderCellId{Value: "gru"}, ProviderCompartmentId{Value: "ocid1.compartment.oc1..x"},
		ProviderEpoch{Value: 1}, ResourceNode, ActionCreateNode, IdempotentProviderCreate{Key: ProviderCreateKey{Value: "create-1"}},
		ProviderGeneration{Value: 7}, ObservedAbsent, TerminalPresent, nil,
		DeadlineEvidence{Status: DeadlineValid, EvidenceGeneration: ProviderGeneration{Value: 7}}, ProviderIdempotencyKey{Value: "idempotency-1"}, nil, parameters,
	)
	if err != nil {
		t.Fatal(err)
	}
	binding := CreateNodeReceiptBinding{
		OperationId: "operation-1", TenantId: "tenant-1", NodeRequestId: "node-request-1", IdempotencyKey: "idempotency-1",
		CreateKey: "create-1", CellId: "gru", CompartmentId: "ocid1.compartment.oc1..x", TemplateId: "template-1", PlacementId: "placement-1",
		BootstrapEnvelopeDigest: parameters.BootstrapEnvelopeDigest.Sha256, AuthorizationDigest: "authorization-digest",
		ProviderContextFingerprint: operationContext.Fingerprint(), Generation: 7, Epoch: 1, AuthorizationSequence: 1,
	}
	receiptSigner, err := NewCreateNodeHandoffReceiptSigner("node-authority", key)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := receiptSigner.Sign(binding, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	invocationSigner, err := NewInvocationCapabilitySigner("node-authority", key)
	if err != nil {
		t.Fatal(err)
	}
	capability, err := invocationSigner.Sign(CreateNodeAuthoritativeInvocationCapability{
		OperationId: binding.OperationId, BindingDigest: binding.Digest(), JournalVersion: 1, LeaseOwner: "controller-1", LeaseToken: "lease-1", Nonce: "nonce-1",
		LeaseExpiresAt: now.Add(5 * time.Minute), IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	recoverySigner, err := NewCreateNodeRecoveryLookupSigner("node-authority", key)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := recoverySigner.Sign(binding, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	proofSigner, err := NewCreateNodeProviderProofSigner("node-authority", key)
	if err != nil {
		t.Fatal(err)
	}
	resolver := OciNodeLaunchResolverFunc(func(context.Context, ProviderTemplateId, ProviderPlacementId, ProviderBootstrapEnvelopeDigest) (OciNodeLaunchSpec, error) {
		return OciNodeLaunchSpec{
			CompartmentId: "ocid1.compartment.oc1..x", AvailabilityDomain: "AD-1", FaultDomain: "FD-1", SubnetId: "ocid1.subnet.oc1.sa-saopaulo-1.x",
			ImageId: "ocid1.image.oc1.sa-saopaulo-1.x", Shape: "VM.Standard.A1.Flex", NetworkSecurityGroupIds: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.x"},
			Ocpus: 4, MemoryGB: 24, BootstrapBase64: base64.StdEncoding.EncodeToString(bootstrap),
		}, nil
	})
	return authorizedCreateNodeFixture{
		request: CreateNodeProviderRequest{Context: operationContext, Parameters: parameters, Binding: binding, Receipt: receipt, RecoveryAuthority: recovery, InvocationCapability: &capability},
		keys: keys, proofSigner: proofSigner, receiptSigner: receiptSigner, invocationSigner: invocationSigner, launchResolver: resolver, now: now,
	}
}

func authorizedCreateNodeRequestDigest(t *testing.T, fixture authorizedCreateNodeFixture, transport *OCIHTTPTransport) string {
	t.Helper()
	client := &OCIComputeNodeClient{OCI: transport, LaunchResolver: fixture.launchResolver}
	launch, err := client.prepareNodeLaunch(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	return launch.digest()
}

func TestOCINodeCreateReplaysExactRequestAfterTransportLoss(t *testing.T) {
	fixture := newAuthorizedCreateNodeFixture(t)
	instanceID := "ocid1.instance.oc1.sa-saopaulo-1.recovered"
	var bodies [][]byte
	var tokens []string
	posts := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/20160918/instances" {
			t.Fatalf("unexpected OCI request %s %s", request.Method, request.URL.String())
		}
		posts++
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		bodies = append(bodies, body)
		tokens = append(tokens, request.Header.Get("opc-retry-token"))
		if posts == 1 {
			return nil, io.ErrUnexpectedEOF
		}
		return testHTTPResponse(http.StatusOK, `{"id":"`+instanceID+`","compartmentId":"ocid1.compartment.oc1..x"}`, http.Header{"Opc-Work-Request-Id": {"work-recovered"}}), nil
	})
	ownership := testOwnership(t)
	journal := &testCreateNodeJournal{}
	resolverCalls := 0
	resolver := OciNodeLaunchResolverFunc(func(ctx context.Context, template ProviderTemplateId, placement ProviderPlacementId, digest ProviderBootstrapEnvelopeDigest) (OciNodeLaunchSpec, error) {
		resolverCalls++
		return fixture.launchResolver.Resolve(ctx, template, placement, digest)
	})
	provider := &OciCreateNodeProvider{
		Enabled: true, OCI: transport, ProofSigner: fixture.proofSigner, Keys: fixture.keys, InvocationKeys: fixture.keys,
		Journal: journal, Clock: func() time.Time { return fixture.now }, LaunchResolver: resolver, Ownership: ownership,
	}
	response, err := provider.CreateNode(context.Background(), fixture.request)
	if err != nil || response.NodeId.Value != instanceID || response.WorkRequestId.Value != "work-recovered" || journal.consumed != 1 {
		t.Fatalf("authorized create replay = %+v, consumed=%d, err=%v", response, journal.consumed, err)
	}
	if posts != 2 || resolverCalls != 1 || len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) || len(tokens) != 2 || tokens[0] != "idempotency-1" || tokens[1] != tokens[0] {
		t.Fatalf("launch replay changed request: posts=%d resolverCalls=%d tokens=%v bodiesEqual=%v", posts, resolverCalls, tokens, len(bodies) == 2 && bytes.Equal(bodies[0], bodies[1]))
	}
	record, found, err := ownership.Lookup(context.Background(), response.NodeId)
	want := ProviderOwnershipRecord{ResourceId: response.NodeId, CellId: fixture.request.Context.CellId, CompartmentId: ProviderCompartmentId{Value: fixture.request.Binding.CompartmentId}, Generation: ProviderGeneration{Value: fixture.request.Binding.Generation}}
	if err != nil || !found || record != want {
		t.Fatalf("replayed create ownership = %+v, found=%v, err=%v", record, found, err)
	}
}

func TestOCINodeCreateRecordsExactOwnershipOnSuccess(t *testing.T) {
	fixture := newAuthorizedCreateNodeFixture(t)
	instanceID := "ocid1.instance.oc1.sa-saopaulo-1.created"
	posts := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost {
			t.Fatalf("successful create sent %s", request.Method)
		}
		posts++
		return testHTTPResponse(http.StatusOK, `{"id":"`+instanceID+`","compartmentId":"ocid1.compartment.oc1..x"}`, http.Header{"Opc-Work-Request-Id": {"work-created"}}), nil
	})
	journal := &testCreateNodeJournal{}
	ownership := testOwnership(t)
	provider := &OciCreateNodeProvider{
		Enabled: true, OCI: transport, ProofSigner: fixture.proofSigner, Keys: fixture.keys, InvocationKeys: fixture.keys,
		Journal: journal, Clock: func() time.Time { return fixture.now }, LaunchResolver: fixture.launchResolver, Ownership: ownership,
	}
	response, err := provider.CreateNode(context.Background(), fixture.request)
	if err != nil || posts != 1 || journal.consumed != 1 || response.NodeId.Value != instanceID || response.WorkRequestId.Value != "work-created" {
		t.Fatalf("successful create = %+v, posts=%d consumed=%d err=%v", response, posts, journal.consumed, err)
	}
	record, found, err := ownership.Lookup(context.Background(), response.NodeId)
	want := ProviderOwnershipRecord{ResourceId: response.NodeId, CellId: fixture.request.Context.CellId, CompartmentId: ProviderCompartmentId{Value: fixture.request.Binding.CompartmentId}, Generation: ProviderGeneration{Value: fixture.request.Binding.Generation}}
	if err != nil || !found || record != want {
		t.Fatalf("successful create ownership = %+v, found=%v, err=%v", record, found, err)
	}
}

func TestOCINodeCreateRetryableResponseExhaustionHasOneTotalAttemptBudget(t *testing.T) {
	fixture := newAuthorizedCreateNodeFixture(t)
	posts := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost {
			t.Fatalf("retryable create sent %s", request.Method)
		}
		posts++
		return testHTTPResponse(http.StatusServiceUnavailable, `{"code":"ServiceUnavailable"}`, nil), nil
	})
	transport.Config.MaxRetries = 2
	transport.retryDelay = func(context.Context, int) error { return nil }
	journal := &testCreateNodeJournal{}
	provider := &OciCreateNodeProvider{
		Enabled: true, OCI: transport, ProofSigner: fixture.proofSigner, Keys: fixture.keys, InvocationKeys: fixture.keys,
		Journal: journal, Clock: func() time.Time { return fixture.now }, LaunchResolver: fixture.launchResolver, Ownership: testOwnership(t),
	}
	response, err := provider.CreateNode(context.Background(), fixture.request)
	if response != (CreateNodeProviderResponse{}) || !errors.As(err, new(*ProviderOutcomeUnknownError)) || posts != transport.Config.MaxRetries+1 || journal.consumed != 1 {
		t.Fatalf("retry exhaustion response=%+v posts=%d consumed=%d err=%v", response, posts, journal.consumed, err)
	}
}

func TestOCINodeCreateOwnershipRecordFailureNeverReturnsSuccess(t *testing.T) {
	fixture := newAuthorizedCreateNodeFixture(t)
	instanceID := "ocid1.instance.oc1.sa-saopaulo-1.unrecorded"
	posts := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		posts++
		return testHTTPResponse(http.StatusOK, `{"id":"`+instanceID+`","compartmentId":"ocid1.compartment.oc1..x"}`, http.Header{"Opc-Work-Request-Id": {"work-unrecorded"}}), nil
	})
	recordErr := errors.New("durable ownership store unavailable")
	provider := &OciCreateNodeProvider{
		Enabled: true, OCI: transport, ProofSigner: fixture.proofSigner, Keys: fixture.keys, InvocationKeys: fixture.keys,
		Journal: &testCreateNodeJournal{}, Clock: func() time.Time { return fixture.now }, LaunchResolver: fixture.launchResolver,
		Ownership: &recordFailingOwnership{DurableOwnershipEvidence: testOwnership(t), err: recordErr},
	}
	response, err := provider.CreateNode(context.Background(), fixture.request)
	if response != (CreateNodeProviderResponse{}) || !errors.As(err, new(*ProviderOutcomeUnknownError)) || posts != 1 {
		t.Fatalf("ownership failure response=%+v posts=%d err=%v", response, posts, err)
	}
}

func TestOCINodeRecoveryRejectsRestartAuthorityDriftWithoutPosting(t *testing.T) {
	fixture := newAuthorizedCreateNodeFixture(t)
	original := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
		return nil, errors.New("original transport is digest-only")
	})
	journal := &testCreateNodeJournal{}
	if err := journal.ConsumeInvocationCapability(context.Background(), *fixture.request.InvocationCapability, fixture.request.Binding, authorizedCreateNodeRequestDigest(t, fixture, original), fixture.now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	config, err := NewOCITransportConfig("us-sanjose-1", "https://iaas.us-sanjose-1.oraclecloud.com")
	if err != nil {
		t.Fatal(err)
	}
	posts := 0
	restarted, err := NewOCIHTTPTransport(config, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		posts++
		return nil, errors.New("authority-drifted request must not be sent")
	})}, nil)
	if err != nil {
		t.Fatal(err)
	}
	provider := &OciCreateNodeProvider{
		Enabled: true, OCI: restarted, ProofSigner: fixture.proofSigner, Keys: fixture.keys, RecoveryKeys: fixture.keys, InvocationKeys: fixture.keys,
		Journal: journal, Clock: func() time.Time { return fixture.now }, LaunchResolver: fixture.launchResolver, Ownership: testOwnership(t),
	}
	reconciliation, err := provider.ReconcileCreateNode(context.Background(), fixture.request)
	if err != nil || reconciliation.Status != CreateNodeUnknown || posts != 0 {
		t.Fatalf("authority-drift recovery=%+v posts=%d err=%v", reconciliation, posts, err)
	}
}

func TestOCINodeRecoveryConsumptionTimeIsStrictlyBounded(t *testing.T) {
	tests := []struct {
		name      string
		configure func(t *testing.T, fixture *authorizedCreateNodeFixture) (time.Time, time.Time)
	}{
		{
			name: "before capability and receipt issuance",
			configure: func(_ *testing.T, fixture *authorizedCreateNodeFixture) (time.Time, time.Time) {
				return fixture.request.InvocationCapability.IssuedAt.Add(-time.Nanosecond), fixture.now
			},
		},
		{
			name: "before receipt issuance",
			configure: func(t *testing.T, fixture *authorizedCreateNodeFixture) (time.Time, time.Time) {
				issued := fixture.now.Add(-30 * time.Second)
				receipt, err := fixture.receiptSigner.Sign(fixture.request.Binding, issued, fixture.now.Add(time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				fixture.request.Receipt = receipt
				return issued.Add(-time.Nanosecond), fixture.now
			},
		},
		{
			name: "at capability expiry",
			configure: func(t *testing.T, fixture *authorizedCreateNodeFixture) (time.Time, time.Time) {
				capability := *fixture.request.InvocationCapability
				capability.ExpiresAt = fixture.now
				capability.LeaseExpiresAt = fixture.now.Add(time.Minute)
				signed, err := fixture.invocationSigner.Sign(capability)
				if err != nil {
					t.Fatal(err)
				}
				fixture.request.InvocationCapability = &signed
				return capability.ExpiresAt, fixture.now
			},
		},
		{
			name: "after capability expiry",
			configure: func(t *testing.T, fixture *authorizedCreateNodeFixture) (time.Time, time.Time) {
				capability := *fixture.request.InvocationCapability
				capability.ExpiresAt = fixture.now
				capability.LeaseExpiresAt = fixture.now.Add(time.Minute)
				signed, err := fixture.invocationSigner.Sign(capability)
				if err != nil {
					t.Fatal(err)
				}
				fixture.request.InvocationCapability = &signed
				return capability.ExpiresAt.Add(time.Nanosecond), fixture.now.Add(time.Nanosecond)
			},
		},
		{
			name: "at lease expiry",
			configure: func(t *testing.T, fixture *authorizedCreateNodeFixture) (time.Time, time.Time) {
				capability := *fixture.request.InvocationCapability
				capability.LeaseExpiresAt = fixture.now
				capability.ExpiresAt = fixture.now.Add(time.Minute)
				signed, err := fixture.invocationSigner.Sign(capability)
				if err != nil {
					t.Fatal(err)
				}
				fixture.request.InvocationCapability = &signed
				return capability.LeaseExpiresAt, fixture.now
			},
		},
		{
			name: "after lease expiry",
			configure: func(t *testing.T, fixture *authorizedCreateNodeFixture) (time.Time, time.Time) {
				capability := *fixture.request.InvocationCapability
				capability.LeaseExpiresAt = fixture.now
				capability.ExpiresAt = fixture.now.Add(time.Minute)
				signed, err := fixture.invocationSigner.Sign(capability)
				if err != nil {
					t.Fatal(err)
				}
				fixture.request.InvocationCapability = &signed
				return capability.LeaseExpiresAt.Add(time.Nanosecond), fixture.now.Add(time.Nanosecond)
			},
		},
		{
			name: "in the future",
			configure: func(_ *testing.T, fixture *authorizedCreateNodeFixture) (time.Time, time.Time) {
				return fixture.now.Add(time.Nanosecond), fixture.now
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAuthorizedCreateNodeFixture(t)
			consumedAt, recoveryNow := test.configure(t, &fixture)
			calls := 0
			transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
				calls++
				return nil, errors.New("invalid consumption time must not call OCI")
			})
			journal := &testCreateNodeJournal{
				consumed: 1, capability: *fixture.request.InvocationCapability, binding: fixture.request.Binding,
				consumedAt: consumedAt, requestDigest: authorizedCreateNodeRequestDigest(t, fixture, transport),
			}
			provider := &OciCreateNodeProvider{
				Enabled: true, OCI: transport, ProofSigner: fixture.proofSigner, Keys: fixture.keys, RecoveryKeys: fixture.keys, InvocationKeys: fixture.keys,
				Journal: journal, Clock: func() time.Time { return recoveryNow }, LaunchResolver: fixture.launchResolver, Ownership: testOwnership(t),
			}
			reconciliation, err := provider.ReconcileCreateNode(context.Background(), fixture.request)
			if err != nil || reconciliation.Status != CreateNodeUnknown || calls != 0 {
				t.Fatalf("bounded recovery=%+v calls=%d err=%v", reconciliation, calls, err)
			}
		})
	}
}

func TestOCINodeRecoveryJournalLookupFailureDoesNotPost(t *testing.T) {
	fixture := newAuthorizedCreateNodeFixture(t)
	lookupErr := errors.New("journal lookup unavailable")
	calls := 0
	transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("journal failure must not call OCI")
	})
	provider := &OciCreateNodeProvider{
		Enabled: true, OCI: transport, ProofSigner: fixture.proofSigner, Keys: fixture.keys, RecoveryKeys: fixture.keys, InvocationKeys: fixture.keys,
		Journal: &testCreateNodeJournal{consumptionErr: lookupErr}, Clock: func() time.Time { return fixture.now }, LaunchResolver: fixture.launchResolver, Ownership: testOwnership(t),
	}
	reconciliation, err := provider.ReconcileCreateNode(context.Background(), fixture.request)
	if !errors.Is(err, lookupErr) || reconciliation != (CreateNodeReconciliation{}) || calls != 0 {
		t.Fatalf("journal-failed recovery=%+v calls=%d err=%v", reconciliation, calls, err)
	}
}

func TestOCINodeRecoveryRequiresConsumedInvocationAndRecentRetryToken(t *testing.T) {
	t.Run("lookup authority cannot mutate", func(t *testing.T) {
		fixture := newAuthorizedCreateNodeFixture(t)
		calls := 0
		transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("lookup authority must not call OCI")
		})
		ownership := testOwnership(t)
		journal := &testCreateNodeJournal{}
		provider := &OciCreateNodeProvider{
			Enabled: true, OCI: transport, ProofSigner: fixture.proofSigner, Keys: fixture.keys, RecoveryKeys: fixture.keys, InvocationKeys: fixture.keys,
			Journal: journal, Clock: func() time.Time { return fixture.now }, LaunchResolver: fixture.launchResolver, Ownership: ownership,
		}
		reconciliation, err := provider.ReconcileCreateNode(context.Background(), fixture.request)
		if err != nil || reconciliation.Status != CreateNodeUnknown || calls != 0 {
			t.Fatalf("lookup-only recovery = %+v, calls=%d err=%v", reconciliation, calls, err)
		}
	})

	t.Run("consumed recent invocation replays and records ownership", func(t *testing.T) {
		fixture := newAuthorizedCreateNodeFixture(t)
		instanceID := "ocid1.instance.oc1.sa-saopaulo-1.crashrecovered"
		posts := 0
		transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodPost {
				t.Fatalf("unexpected recovery method %s", request.Method)
			}
			posts++
			if request.Header.Get("opc-retry-token") != fixture.request.Binding.IdempotencyKey {
				t.Fatalf("recovery token = %q", request.Header.Get("opc-retry-token"))
			}
			return testHTTPResponse(http.StatusOK, `{"id":"`+instanceID+`","compartmentId":"ocid1.compartment.oc1..x"}`, http.Header{"Opc-Work-Request-Id": {"work-crash-recovered"}}), nil
		})
		journal := &testCreateNodeJournal{}
		if err := journal.ConsumeInvocationCapability(context.Background(), *fixture.request.InvocationCapability, fixture.request.Binding, authorizedCreateNodeRequestDigest(t, fixture, transport), fixture.now.Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		ownership := testOwnership(t)
		provider := &OciCreateNodeProvider{
			Enabled: true, OCI: transport, ProofSigner: fixture.proofSigner, Keys: fixture.keys, RecoveryKeys: fixture.keys, InvocationKeys: fixture.keys,
			Journal: journal, Clock: func() time.Time { return fixture.now }, LaunchResolver: fixture.launchResolver, Ownership: ownership,
		}
		reconciliation, err := provider.ReconcileCreateNode(context.Background(), fixture.request)
		if err != nil || reconciliation.Status != CreateNodeFound || reconciliation.Response == nil || reconciliation.Response.NodeId.Value != instanceID || reconciliation.Proof == nil || posts != 1 {
			t.Fatalf("journal-authorized recovery = %+v, posts=%d err=%v", reconciliation, posts, err)
		}
		if !VerifyCreateNodeProviderProof(*reconciliation.Proof, fixture.keys, fixture.request.Binding) {
			t.Fatal("recovery proof did not bind the provider-returned identity")
		}
		record, found, lookupErr := ownership.Lookup(context.Background(), ProviderResourceId{Value: instanceID})
		want := ProviderOwnershipRecord{ResourceId: ProviderResourceId{Value: instanceID}, CellId: fixture.request.Context.CellId, CompartmentId: ProviderCompartmentId{Value: fixture.request.Binding.CompartmentId}, Generation: ProviderGeneration{Value: fixture.request.Binding.Generation}}
		if lookupErr != nil || !found || record != want {
			t.Fatalf("crash-recovered ownership = %+v, found=%v, err=%v", record, found, lookupErr)
		}
	})

	t.Run("expired retry window remains unknown", func(t *testing.T) {
		fixture := newAuthorizedCreateNodeFixture(t)
		oldReceipt, err := fixture.receiptSigner.Sign(fixture.request.Binding, fixture.now.Add(-ociRetryTokenValidity), fixture.now.Add(-ociRetryTokenValidity+time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		fixture.request.Receipt = oldReceipt
		calls := 0
		transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("expired recovery must not call OCI")
		})
		journal := &testCreateNodeJournal{}
		if err := journal.ConsumeInvocationCapability(context.Background(), *fixture.request.InvocationCapability, fixture.request.Binding, authorizedCreateNodeRequestDigest(t, fixture, transport), fixture.now.Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		ownership := testOwnership(t)
		provider := &OciCreateNodeProvider{
			Enabled: true, OCI: transport, ProofSigner: fixture.proofSigner, Keys: fixture.keys, RecoveryKeys: fixture.keys, InvocationKeys: fixture.keys,
			Journal: journal, Clock: func() time.Time { return fixture.now }, LaunchResolver: fixture.launchResolver, Ownership: ownership,
		}
		reconciliation, err := provider.ReconcileCreateNode(context.Background(), fixture.request)
		if err != nil || reconciliation.Status != CreateNodeUnknown || calls != 0 {
			t.Fatalf("expired recovery = %+v, calls=%d err=%v", reconciliation, calls, err)
		}
	})

	t.Run("changed resolved launch after restart remains unknown", func(t *testing.T) {
		fixture := newAuthorizedCreateNodeFixture(t)
		posts := 0
		transport := testOCITransport(t, OCIServiceCore, func(*http.Request) (*http.Response, error) {
			posts++
			return nil, errors.New("changed request must not be posted")
		})
		journal := &testCreateNodeJournal{}
		if err := journal.ConsumeInvocationCapability(context.Background(), *fixture.request.InvocationCapability, fixture.request.Binding, authorizedCreateNodeRequestDigest(t, fixture, transport), fixture.now.Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		changedResolver := OciNodeLaunchResolverFunc(func(ctx context.Context, template ProviderTemplateId, placement ProviderPlacementId, digest ProviderBootstrapEnvelopeDigest) (OciNodeLaunchSpec, error) {
			spec, err := fixture.launchResolver.Resolve(ctx, template, placement, digest)
			spec.Shape = "VM.Standard.E5.Flex"
			return spec, err
		})
		ownership := testOwnership(t)
		provider := &OciCreateNodeProvider{
			Enabled: true, OCI: transport, ProofSigner: fixture.proofSigner, Keys: fixture.keys, RecoveryKeys: fixture.keys, InvocationKeys: fixture.keys,
			Journal: journal, Clock: func() time.Time { return fixture.now }, LaunchResolver: changedResolver, Ownership: ownership,
		}
		reconciliation, err := provider.ReconcileCreateNode(context.Background(), fixture.request)
		if err != nil || reconciliation.Status != CreateNodeUnknown || posts != 0 {
			t.Fatalf("changed launch recovery = %+v, posts=%d err=%v", reconciliation, posts, err)
		}
	})
}

func TestOCINodeRecoveryNeverAdoptsRetaggedPreownedInstance(t *testing.T) {
	fixture := newAuthorizedCreateNodeFixture(t)
	attackID := "ocid1.instance.oc1.sa-saopaulo-1.retagged"
	calls := 0
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		calls++
		return testHTTPResponse(http.StatusOK, `[{"id":"`+attackID+`","compartmentId":"ocid1.compartment.oc1..x","freeformTags":{"terrascale-create-key":"create-1","terrascale-operation":"operation-1","terrascale-idempotency-key":"idempotency-1"}}]`, nil), nil
	})
	journal := &testCreateNodeJournal{}
	ownership := testOwnership(t)
	want := ProviderOwnershipRecord{
		ResourceId: ProviderResourceId{Value: attackID}, CellId: fixture.request.Context.CellId,
		CompartmentId: ProviderCompartmentId{Value: fixture.request.Binding.CompartmentId}, Generation: ProviderGeneration{Value: fixture.request.Binding.Generation},
	}
	if err := ownership.Record(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	provider := &OciCreateNodeProvider{
		Enabled: true, OCI: transport, ProofSigner: fixture.proofSigner, Keys: fixture.keys, RecoveryKeys: fixture.keys, InvocationKeys: fixture.keys,
		Journal: journal, Clock: func() time.Time { return fixture.now }, LaunchResolver: fixture.launchResolver, Ownership: ownership,
	}
	reconciliation, err := provider.ReconcileCreateNode(context.Background(), fixture.request)
	if err != nil || reconciliation.Status != CreateNodeUnknown || calls != 0 {
		t.Fatalf("retagged recovery = %+v, calls=%d err=%v", reconciliation, calls, err)
	}
	record, found, lookupErr := ownership.Lookup(context.Background(), want.ResourceId)
	if lookupErr != nil || !found || record != want {
		t.Fatalf("retagged ownership changed: %+v, found=%v err=%v", record, found, lookupErr)
	}
}
