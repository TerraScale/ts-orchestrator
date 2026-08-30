package provider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	template, err := NewOciCiRunnerLaunchTemplate("ocid1.compartment.oc1.x", "AD-1", "FD-1", "ocid1.subnet.oc1.x", []string{"ocid1.networksecuritygroup.oc1.x"}, "ocid1.image.oc1.x", 4)
	if err != nil {
		t.Fatal(err)
	}
	tags := RunnerTags(demand, template.Generation)
	responseTags := tags
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		body := `{"items":[{"id":"ocid1.instance.oc1.x","compartmentId":"ocid1.compartment.oc1.x","lifecycleState":"RUNNING","timeCreated":"2026-08-30T12:00:00Z","freeformTags":` + string(mustJSON(responseTags)) + `}]}`
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
	if observed[0].Runner != demand.Runner || observed[0].Sequence != demand.Sequence || !observed[0].Preemptible || observed[0].PreserveBootVolume || !RunnerMatches(observed[0], demand, template) {
		t.Fatalf("runner identity was not populated from validated tags: %+v", observed[0])
	}
	responseTags[runnerSequenceTag] = "not-a-sequence"
	if _, err := compute.Observe(context.Background(), template); err == nil {
		t.Fatal("malformed runner tags must fail closed")
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
	template, err := NewOciCiRunnerLaunchTemplate("ocid1.compartment.oc1.x", "AD-1", "FD-1", "ocid1.subnet.oc1.x", []string{"ocid1.networksecuritygroup.oc1.x"}, "ocid1.image.oc1.x", 4)
	if err != nil {
		t.Fatal(err)
	}
	obs := OciCiRunnerNodeObservation{InstanceId: "ocid1.instance.oc1.x", ETag: "etag-1", Runner: demand.Runner, Sequence: demand.Sequence, State: RunnerStopped, LastActivity: now.Add(-time.Hour), FreeformTags: RunnerTags(demand, template.Generation), Preemptible: true}
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
	contextValue, err := NewProviderOperationContext(ProviderOperationId{Value: "operation-1"}, ProviderCellId{Value: "gru"}, ProviderCompartmentId{Value: "ocid1.compartment.oc1.x"}, ProviderEpoch{Value: 1}, ResourceNode, ActionCreateNode, IdempotentProviderCreate{Key: ProviderCreateKey{Value: "create-1"}}, ProviderGeneration{Value: 1}, ObservedAbsent, TerminalPresent, nil, DeadlineEvidence{Status: DeadlineValid, EvidenceGeneration: ProviderGeneration{Value: 1}}, ProviderIdempotencyKey{Value: "idempotency-1"}, nil, params)
	if err != nil {
		t.Fatal(err)
	}
	binding := CreateNodeReceiptBinding{CreateKey: "create-1", CompartmentId: "ocid1.compartment.oc1.x", TemplateId: "template-1", PlacementId: "placement-1", BootstrapEnvelopeDigest: params.BootstrapEnvelopeDigest.Sha256, OperationId: "operation-1", IdempotencyKey: "idempotency-1"}
	var posts int
	var body []byte
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		posts++
		body, _ = io.ReadAll(request.Body)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Opc-Work-Request-Id": []string{"work-1"}}, Body: io.NopCloser(strings.NewReader(`{"id":"ocid1.instance.oc1.x"}`))}, nil
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
		return OciNodeLaunchSpec{CompartmentId: "ocid1.compartment.oc1.x", AvailabilityDomain: "AD-1", FaultDomain: "FD-1", SubnetId: "ocid1.subnet.oc1.x", ImageId: "ocid1.image.oc1.x", Shape: "VM.Standard.A1.Flex", NetworkSecurityGroupIds: []string{"ocid1.networksecuritygroup.oc1.x"}, Ocpus: 4, MemoryGB: 24, BootstrapBase64: base64.StdEncoding.EncodeToString(bootstrap)}, nil
	})}
	response, err := compute.CreateNode(context.Background(), CreateNodeProviderRequest{Context: contextValue, Parameters: params, Binding: binding})
	if err != nil || response.NodeId.Value != "ocid1.instance.oc1.x" || posts != 1 {
		t.Fatalf("resolved OCI node create = %+v, posts = %d, err = %v", response, posts, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["sourceDetails"].(map[string]any)["imageId"] != "ocid1.image.oc1.x" || decoded["createVnicDetails"].(map[string]any)["subnetId"] != "ocid1.subnet.oc1.x" || decoded["metadata"].(map[string]any)["user_data"] != base64.StdEncoding.EncodeToString(bootstrap) {
		t.Fatalf("resolved OCI node create omitted launch details: %s", body)
	}
}
