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
)

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
