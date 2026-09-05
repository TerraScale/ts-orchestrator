package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

type ociInstanceDocument struct {
	ID            string            `json:"id"`
	CompartmentID string            `json:"compartmentId"`
	Lifecycle     string            `json:"lifecycleState"`
	ETag          string            `json:"etag"`
	TimeCreated   time.Time         `json:"timeCreated"`
	FreeformTags  map[string]string `json:"freeformTags"`
}

func CheckOCIStatus(resp *http.Response, operation string) error {
	if resp == nil {
		return &InvalidDataError{Message: "OCI request returned no response"}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	// Consume and discard the provider body. Error strings must never carry
	// response text because OCI errors can echo request metadata.
	_, _ = ReadBoundedBody(resp, 64<<10)
	return &InvalidDataError{Message: "OCI request failed"}
}

func safeHeader(resp *http.Response, key string) string {
	if resp == nil {
		return ""
	}
	v := resp.Header.Get(key)
	if len(v) > 256 || strings.ContainsAny(v, "\r\n") {
		return ""
	}
	return v
}

// OCIComputeNodeClient implements the node create/recovery client used by
// OciCreateNodeProvider. Template and placement IDs remain opaque controller
// identities, while all cloud identities are validated before transmission.
type OCIComputeNodeClient struct {
	OCI            *OCIHTTPTransport
	ProofSigner    *CreateNodeProviderProofSigner
	LaunchResolver OciNodeLaunchResolver
	Ownership      DurableOwnershipEvidence
}

func (c *OCIComputeNodeClient) CreateNode(ctx context.Context, r CreateNodeProviderRequest) (CreateNodeProviderResponse, error) {
	if c == nil || c.OCI == nil {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI node client is unavailable"}
	}
	if ctx == nil {
		return CreateNodeProviderResponse{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return CreateNodeProviderResponse{}, err
	}
	if err := validateCreateRequestShape(r); err != nil {
		return CreateNodeProviderResponse{}, err
	}
	parameters, ok := r.Context.ActionParameters.(CreateNodeProviderParameters)
	if !ok || parameters != r.Parameters || parameters.TemplateId.Value != r.Binding.TemplateId || parameters.PlacementId.Value != r.Binding.PlacementId || parameters.BootstrapEnvelopeDigest.Sha256 != r.Binding.BootstrapEnvelopeDigest {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI node create parameters are not bound to the authorized request"}
	}
	if c.LaunchResolver == nil {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI node create requires an injected launch resolver"}
	}
	spec, err := c.LaunchResolver.Resolve(ctx, parameters.TemplateId, parameters.PlacementId, parameters.BootstrapEnvelopeDigest)
	if err != nil {
		return CreateNodeProviderResponse{}, err
	}
	if err := validateOciNodeLaunchSpec(spec, r); err != nil {
		return CreateNodeProviderResponse{}, err
	}
	target := r.Context.Target.(IdempotentProviderCreate)
	payload := struct {
		CompartmentID string `json:"compartmentId"`
		DisplayName   string `json:"displayName"`
		Availability  string `json:"availabilityDomain"`
		FaultDomain   string `json:"faultDomain,omitempty"`
		Shape         string `json:"shape"`
		ShapeConfig   struct {
			OCPUs       float64 `json:"ocpus"`
			MemoryInGBs float64 `json:"memoryInGBs"`
		} `json:"shapeConfig"`
		CreateVnicDetails struct {
			SubnetID                string   `json:"subnetId"`
			NetworkSecurityGroupIDs []string `json:"nsgIds,omitempty"`
		} `json:"createVnicDetails"`
		SourceDetails struct {
			SourceType string `json:"sourceType"`
			ImageID    string `json:"imageId"`
		} `json:"sourceDetails"`
		Metadata     map[string]string `json:"metadata"`
		FreeformTags map[string]string `json:"freeformTags"`
	}{CompartmentID: spec.CompartmentId, DisplayName: "terrascale-node-" + r.Binding.CreateKey, Availability: spec.AvailabilityDomain, FaultDomain: spec.FaultDomain, Shape: spec.Shape, ShapeConfig: struct {
		OCPUs       float64 `json:"ocpus"`
		MemoryInGBs float64 `json:"memoryInGBs"`
	}{OCPUs: spec.Ocpus, MemoryInGBs: spec.MemoryGB}, CreateVnicDetails: struct {
		SubnetID                string   `json:"subnetId"`
		NetworkSecurityGroupIDs []string `json:"nsgIds,omitempty"`
	}{SubnetID: spec.SubnetId, NetworkSecurityGroupIDs: append([]string(nil), spec.NetworkSecurityGroupIds...)}, SourceDetails: struct {
		SourceType string `json:"sourceType"`
		ImageID    string `json:"imageId"`
	}{SourceType: "image", ImageID: spec.ImageId}, Metadata: map[string]string{"user_data": spec.BootstrapBase64}, FreeformTags: map[string]string{"terrascale-operation": r.Context.OperationId.Value, "terrascale-create-key": target.Key.Value, "terrascale-idempotency-key": r.Context.IdempotencyKey.Value}}
	resp, err := c.OCI.DoWithHeaders(ctx, http.MethodPost, "/20160918/instances", bytes.NewReader(mustJSON(payload)), map[string]string{"opc-retry-token": r.Context.IdempotencyKey.Value})
	if err != nil {
		if IsOutcomeIndeterminate(err) {
			if recovered, recoveryErr := c.reconcileNodeCreate(ctx, r); recoveryErr == nil {
				return recovered, nil
			}
		}
		return CreateNodeProviderResponse{}, err
	}
	if err := CheckOCIStatus(resp, "node create"); err != nil {
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			if recovered, recoveryErr := c.reconcileNodeCreate(ctx, r); recoveryErr == nil {
				return recovered, nil
			}
		}
		return CreateNodeProviderResponse{}, err
	}
	body, err := ReadBoundedBody(resp, c.OCI.Config.MaxBodyBytes)
	if err != nil {
		if recovered, recoveryErr := c.reconcileNodeCreate(ctx, r); recoveryErr == nil {
			return recovered, nil
		}
		return CreateNodeProviderResponse{}, err
	}
	var item ociInstanceDocument
	if json.Unmarshal(body, &item) != nil || !IsOCID(item.ID, "instance") {
		if recovered, recoveryErr := c.reconcileNodeCreate(ctx, r); recoveryErr == nil {
			return recovered, nil
		}
		return CreateNodeProviderResponse{}, &InvalidDataError{Message: "OCI node create response is invalid"}
	}
	work := safeHeader(resp, "opc-work-request-id")
	if work == "" {
		work = item.ETag
	}
	if work == "" {
		return CreateNodeProviderResponse{}, &InvalidDataError{Message: "OCI node create response has no work request"}
	}
	return CreateNodeProviderResponse{NodeId: ProviderResourceId{Value: item.ID}, WorkRequestId: ProviderWorkRequestId{Value: work}}, nil
}

func validateCreateRequestShape(r CreateNodeProviderRequest) error {
	if r.Context.Action != ActionCreateNode || r.Context.ResourceKind != ResourceNode || !IsOCID(r.Context.CompartmentId.Value, "compartment") || r.Context.Target == nil {
		return &errs.Argument{Message: "OCI node create request is invalid"}
	}
	target, ok := r.Context.Target.(IdempotentProviderCreate)
	if !ok || target.Key.Value == "" || target.Key.Value != r.Binding.CreateKey || r.Context.OperationId.Value == "" || r.Context.IdempotencyKey.Value == "" || r.Context.CompartmentId.Value != r.Binding.CompartmentId {
		return &errs.Argument{Message: "OCI node create request has no create key"}
	}
	if _, err := canonicalToken(target.Key.Value, "createKey"); err != nil {
		return err
	}
	return nil
}

func validateOciNodeLaunchSpec(spec OciNodeLaunchSpec, r CreateNodeProviderRequest) error {
	if !IsOCID(spec.CompartmentId, "compartment") || spec.CompartmentId != r.Context.CompartmentId.Value || !IsOCID(spec.SubnetId, "subnet") || !IsOCID(spec.ImageId, "image") {
		return &InvalidDataError{Message: "OCI node launch resolution has invalid resource scope"}
	}
	if len(spec.AvailabilityDomain) == 0 || len(spec.AvailabilityDomain) > 128 || strings.IndexFunc(spec.AvailabilityDomain, func(ch rune) bool { return ch < 0x20 || ch == 0x7f }) >= 0 || len(spec.FaultDomain) > 64 || strings.IndexFunc(spec.FaultDomain, func(ch rune) bool { return ch < 0x20 || ch == 0x7f }) >= 0 {
		return &InvalidDataError{Message: "OCI node launch resolution has invalid placement"}
	}
	if len(spec.Shape) == 0 || len(spec.Shape) > 128 || strings.IndexFunc(spec.Shape, func(ch rune) bool { return ch < 0x20 || ch == 0x7f }) >= 0 || math.IsNaN(spec.Ocpus) || math.IsInf(spec.Ocpus, 0) || spec.Ocpus <= 0 || spec.Ocpus > 192 || math.IsNaN(spec.MemoryGB) || math.IsInf(spec.MemoryGB, 0) || spec.MemoryGB <= 0 || spec.MemoryGB > 2048 {
		return &InvalidDataError{Message: "OCI node launch resolution has invalid shape"}
	}
	if len(spec.NetworkSecurityGroupIds) > 5 {
		return &InvalidDataError{Message: "OCI node launch resolution has too many network groups"}
	}
	seen := map[string]bool{}
	for _, id := range spec.NetworkSecurityGroupIds {
		if !IsOCID(id, "networksecuritygroup") || seen[id] {
			return &InvalidDataError{Message: "OCI node launch resolution has invalid network groups"}
		}
		seen[id] = true
	}
	raw, err := base64.StdEncoding.DecodeString(spec.BootstrapBase64)
	if err != nil || len(raw) == 0 || len(raw) > 32*1024 {
		return &InvalidDataError{Message: "OCI node launch resolution has invalid bootstrap"}
	}
	txt := string(raw)
	if (!strings.HasPrefix(txt, "#cloud-config") && !strings.HasPrefix(txt, "#!")) || strings.Contains(strings.ToUpper(txt), "PRIVATE KEY-----") || strings.Contains(strings.ToUpper(txt), "BEGIN NATS USER JWT") || strings.Contains(strings.ToUpper(txt), "BEGIN USER NKEY SEED") {
		return &InvalidDataError{Message: "OCI node launch resolution bootstrap contains invalid content"}
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != r.Parameters.BootstrapEnvelopeDigest.Sha256 {
		return &InvalidDataError{Message: "OCI node launch resolution bootstrap does not match the authorized digest"}
	}
	return nil
}

func (c *OCIComputeNodeClient) ReconcileCreateNode(ctx context.Context, r CreateNodeProviderRequest) (CreateNodeReconciliation, error) {
	if c == nil || c.OCI == nil || c.ProofSigner == nil {
		return CreateNodeReconciliation{}, &InvalidOperationError{Message: "OCI node client is unavailable"}
	}
	if c.Ownership == nil || !c.Ownership.AuthoritativeDurable() {
		return CreateNodeReconciliation{}, &InvalidOperationError{Message: "OCI node reconciliation requires authoritative ownership evidence"}
	}
	if err := validateCreateRequestShape(r); err != nil {
		return CreateNodeReconciliation{}, err
	}
	items, err := c.listNodeInstances(ctx, r.Context.CompartmentId.Value)
	if err != nil {
		return CreateNodeReconciliation{}, err
	}
	for _, item := range items {
		if item.FreeformTags["terrascale-create-key"] != r.Binding.CreateKey || item.FreeformTags["terrascale-operation"] != r.Context.OperationId.Value {
			continue
		}
		if !IsOCID(item.ID, "instance") {
			return CreateNodeReconciliation{}, &InvalidDataError{Message: "OCI node reconciliation identity is invalid"}
		}
		record, owned, lookupErr := c.Ownership.Lookup(ctx, ProviderResourceId{Value: item.ID})
		if lookupErr != nil {
			return CreateNodeReconciliation{}, lookupErr
		}
		if !owned || record.CompartmentId.Value != r.Context.CompartmentId.Value || record.Generation.Value != r.Binding.Generation {
			continue
		}
		response := CreateNodeProviderResponse{NodeId: ProviderResourceId{Value: item.ID}, WorkRequestId: ProviderWorkRequestId{Value: item.ETag}}
		if response.WorkRequestId.Value == "" {
			response.WorkRequestId.Value = "recovered-" + r.Binding.CreateKey
		}
		if response.WorkRequestId.Value == "" {
			return CreateNodeReconciliation{}, &InvalidDataError{Message: "OCI node reconciliation has no work request"}
		}
		proof, err := c.ProofSigner.Sign(r.Binding, response)
		if err != nil {
			return CreateNodeReconciliation{}, err
		}
		return CreateNodeReconciliation{Status: CreateNodeFound, Response: &response, Proof: &proof}, nil
	}
	return CreateNodeReconciliation{Status: CreateNodeNotFound}, nil
}

func (c *OCIComputeNodeClient) listNodeInstances(ctx context.Context, compartment string) ([]ociInstanceDocument, error) {
	v := url.Values{}
	v.Set("compartmentId", compartment)
	v.Set("limit", "1000")
	list, err := ReadOCIResourceList[ociInstanceDocument](ctx, c.OCI, "/20160918/instances", v, func(item ociInstanceDocument) string { return item.ID })
	if err != nil {
		return nil, err
	}
	if len(list) > 1000 {
		return nil, &InvalidDataError{Message: "OCI node reconciliation response is invalid"}
	}
	return list, nil
}

func (c *OCIComputeNodeClient) reconcileNodeCreate(ctx context.Context, r CreateNodeProviderRequest) (CreateNodeProviderResponse, error) {
	if c == nil || c.Ownership == nil || !c.Ownership.AuthoritativeDurable() {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI node create recovery requires authoritative ownership evidence"}
	}
	items, err := c.listNodeInstances(ctx, r.Context.CompartmentId.Value)
	if err != nil {
		return CreateNodeProviderResponse{}, err
	}
	for _, item := range items {
		if item.FreeformTags["terrascale-create-key"] == r.Binding.CreateKey && item.FreeformTags["terrascale-operation"] == r.Context.OperationId.Value && IsOCID(item.ID, "instance") {
			record, owned, lookupErr := c.Ownership.Lookup(ctx, ProviderResourceId{Value: item.ID})
			if lookupErr != nil {
				return CreateNodeProviderResponse{}, lookupErr
			}
			if !owned || record.CompartmentId.Value != r.Context.CompartmentId.Value || record.Generation.Value != r.Binding.Generation {
				continue
			}
			work := item.ETag
			if work == "" {
				work = "recovered-" + r.Binding.CreateKey
			}
			return CreateNodeProviderResponse{NodeId: ProviderResourceId{Value: item.ID}, WorkRequestId: ProviderWorkRequestId{Value: work}}, nil
		}
	}
	return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI node create outcome is unknown"}
}

var _ OciCreateNodeClient = (*OCIComputeNodeClient)(nil)
