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
	"strconv"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

const maxOCIInstanceResults = 1024

type ociInstanceDocument struct {
	ID            string            `json:"id"`
	CompartmentID string            `json:"compartmentId"`
	Lifecycle     string            `json:"lifecycleState"`
	ETag          string            `json:"etag"`
	TimeCreated   time.Time         `json:"timeCreated"`
	FreeformTags  map[string]string `json:"freeformTags"`
}

type ociInstanceList struct {
	Items []ociInstanceDocument `json:"items"`
}

func ociStatus(resp *http.Response, operation string) error {
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

func validInstanceTemplate(t OciCiRunnerLaunchTemplate) bool {
	return validRunnerLaunchTemplate(t)
}

// OCIComputeClient is the concrete instance-principal HTTP client used by
// the CI runner controller. It has no SDK or shell dependency.
type OCIComputeClient struct {
	OCI          *OCIHTTPTransport
	MaxInstances int
	// Ownership is the authoritative regional journal. It is deliberately
	// optional for observation-only use, but every lifecycle mutation and
	// lost-response recovery fails closed when it is absent.
	Ownership DurableOwnershipEvidence
}

func NewOCIComputeClient(oci *OCIHTTPTransport) (*OCIComputeClient, error) {
	if oci == nil {
		return nil, &errs.Argument{Param: "oci", Message: "OCI transport is required"}
	}
	return &OCIComputeClient{OCI: oci, MaxInstances: maxOCIInstanceResults}, nil
}

func (c *OCIComputeClient) Observe(ctx context.Context, t OciCiRunnerLaunchTemplate) ([]OciCiRunnerNodeObservation, error) {
	if c == nil || c.OCI == nil {
		return nil, &InvalidOperationError{Message: "OCI compute client is unavailable"}
	}
	if !validInstanceTemplate(t) {
		return nil, &errs.Argument{Message: "OCI instance observation scope is invalid"}
	}
	limit := c.MaxInstances
	if limit < 1 || limit > maxOCIInstanceResults {
		limit = maxOCIInstanceResults
	}
	v := url.Values{}
	v.Set("compartmentId", t.CompartmentId)
	v.Set("limit", strconv.Itoa(limit))
	resp, err := c.OCI.Do(ctx, http.MethodGet, "/20160918/instances?"+v.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if err := ociStatus(resp, "instance observation"); err != nil {
		return nil, err
	}
	body, err := ReadBoundedBody(resp, c.OCI.Config.MaxBodyBytes)
	if err != nil {
		return nil, err
	}
	var list ociInstanceList
	if json.Unmarshal(body, &list) != nil || len(list.Items) > limit {
		return nil, &InvalidDataError{Message: "OCI instance observation response is invalid"}
	}
	out := make([]OciCiRunnerNodeObservation, 0, len(list.Items))
	for _, item := range list.Items {
		if !isOCID(item.ID, "instance") || !isOCID(item.CompartmentID, "compartment") || item.CompartmentID != t.CompartmentId || len(item.FreeformTags) > 32 || !validFreeformTags(item.FreeformTags) {
			return nil, &InvalidDataError{Message: "OCI instance observation contains invalid identity"}
		}
		state, ok := ociRunnerState(item.Lifecycle)
		if !ok {
			return nil, &InvalidDataError{Message: "OCI instance observation contains unknown lifecycle state"}
		}
		etag := item.ETag
		// OCI list responses do not consistently include per-instance ETags.
		// Never use a collection ETag as a resource fence: preserve an empty
		// fence so the capacity planner refuses destructive work.
		if etag != "" && !isSafeETag(etag) {
			return nil, &InvalidDataError{Message: "OCI instance observation contains an invalid ETag"}
		}
		last := item.TimeCreated
		if last.IsZero() {
			last = time.Unix(1, 0)
		}
		tags := cloneTags(item.FreeformTags)
		runner, sequence, _, _, preemptible, preserve, tagged, valid := parseRunnerTags(tags)
		if tagged && !valid {
			return nil, &InvalidDataError{Message: "OCI instance observation contains malformed runner tags"}
		}
		if !tagged {
			runner, sequence, preemptible, preserve = "", 0, false, false
		}
		out = append(out, OciCiRunnerNodeObservation{InstanceId: item.ID, ETag: etag, Runner: runner, Sequence: sequence, State: state, LastActivity: last, FreeformTags: tags, Preemptible: preemptible, PreserveBootVolume: preserve})
	}
	return out, nil
}

func cloneTags(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if len(k) <= 128 && len(v) <= 1024 && !strings.ContainsAny(k+v, "\r\n") {
			out[k] = v
		}
	}
	return out
}

func validFreeformTags(in map[string]string) bool {
	for key, value := range in {
		if len(key) == 0 || len(key) > 128 || len(value) > 1024 || strings.ContainsAny(key+value, "\r\n") {
			return false
		}
	}
	return true
}

func ociRunnerState(value string) (OciCiRunnerNodeState, bool) {
	switch value {
	case "PROVISIONING", "STARTING":
		return RunnerLaunching, true
	case "RUNNING":
		return RunnerRunning, true
	case "STOPPING", "STOPPED":
		return RunnerStopped, true
	case "TERMINATING":
		return RunnerTerminating, true
	case "TERMINATED":
		return RunnerTerminated, true
	default:
		return 0, false
	}
}

func (c *OCIComputeClient) Execute(ctx context.Context, action OciCiRunnerCapacityAction) (OciCiRunnerMutationReceipt, error) {
	if c == nil || c.OCI == nil {
		return OciCiRunnerMutationReceipt{}, &InvalidOperationError{Message: "OCI compute client is unavailable"}
	}
	switch a := action.(type) {
	case LaunchOciCiRunnerAction:
		return c.launch(ctx, a)
	case TerminateOciCiRunnerAction:
		return c.terminate(ctx, a)
	default:
		return OciCiRunnerMutationReceipt{}, &errs.Argument{Message: "unsupported CI runner action"}
	}
}

func (c *OCIComputeClient) launch(ctx context.Context, a LaunchOciCiRunnerAction) (OciCiRunnerMutationReceipt, error) {
	if !validInstanceTemplate(a.Template) || a.Demand.IdempotencyToken == "" {
		return OciCiRunnerMutationReceipt{}, &errs.Argument{Message: "OCI runner launch request is invalid"}
	}
	r := CompileRunnerLaunch(a)
	payload := struct {
		CompartmentID string `json:"compartmentId"`
		Availability  string `json:"availabilityDomain"`
		FaultDomain   string `json:"faultDomain,omitempty"`
		Shape         string `json:"shape"`
		ShapeConfig   struct {
			OCPUs       float64 `json:"ocpus"`
			MemoryInGBs float64 `json:"memoryInGBs"`
		} `json:"shapeConfig"`
		DisplayName       string `json:"displayName"`
		Hostname          string `json:"hostnameLabel"`
		CreateVnicDetails struct {
			SubnetID                string   `json:"subnetId"`
			NetworkSecurityGroupIDs []string `json:"nsgIds"`
		} `json:"createVnicDetails"`
		SourceDetails struct {
			SourceType string `json:"sourceType"`
			ImageID    string `json:"imageId"`
		} `json:"sourceDetails"`
		Metadata     map[string]string `json:"metadata"`
		FreeformTags map[string]string `json:"freeformTags"`
	}{
		CompartmentID: r.CompartmentId,
		Availability:  r.AvailabilityDomain,
		FaultDomain:   r.FaultDomain,
		Shape:         r.Shape,
		ShapeConfig: struct {
			OCPUs       float64 `json:"ocpus"`
			MemoryInGBs float64 `json:"memoryInGBs"`
		}{OCPUs: r.Ocpus, MemoryInGBs: r.MemoryGB},
		DisplayName: r.DisplayName,
		Hostname:    r.HostnameLabel,
		CreateVnicDetails: struct {
			SubnetID                string   `json:"subnetId"`
			NetworkSecurityGroupIDs []string `json:"nsgIds"`
		}{SubnetID: r.SubnetId, NetworkSecurityGroupIDs: r.NsgIds},
		SourceDetails: struct {
			SourceType string `json:"sourceType"`
			ImageID    string `json:"imageId"`
		}{SourceType: "image", ImageID: r.ImageId},
		Metadata:     map[string]string{"user_data": r.BootstrapBase64},
		FreeformTags: r.Tags,
	}
	resp, err := c.OCI.DoWithHeaders(ctx, http.MethodPost, "/20160918/instances", bytes.NewReader(mustJSON(payload)), map[string]string{"opc-retry-token": a.Demand.IdempotencyToken})
	if err != nil {
		if indeterminate(err) {
			return c.reconcileLaunch(ctx, a)
		}
		return OciCiRunnerMutationReceipt{}, err
	}
	if err := ociStatus(resp, "runner launch"); err != nil {
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			return c.reconcileLaunch(ctx, a)
		}
		return OciCiRunnerMutationReceipt{}, err
	}
	body, err := ReadBoundedBody(resp, c.OCI.Config.MaxBodyBytes)
	if err != nil {
		return c.reconcileLaunch(ctx, a)
	}
	var item ociInstanceDocument
	if len(body) != 0 && json.Unmarshal(body, &item) != nil {
		return c.reconcileLaunch(ctx, a)
	}
	if !isOCID(item.ID, "instance") {
		return c.reconcileLaunch(ctx, a)
	}
	return OciCiRunnerMutationReceipt{InstanceId: item.ID, ETag: item.ETag, OpcRequestId: safeHeader(resp, "opc-request-id"), OpcWorkRequestId: safeHeader(resp, "opc-work-request-id")}, nil
}

func (c *OCIComputeClient) reconcileLaunch(ctx context.Context, a LaunchOciCiRunnerAction) (OciCiRunnerMutationReceipt, error) {
	if c == nil || c.Ownership == nil || !c.Ownership.AuthoritativeDurable() {
		return OciCiRunnerMutationReceipt{}, &InvalidOperationError{Message: "OCI runner launch recovery requires authoritative ownership evidence"}
	}
	items, err := c.Observe(ctx, a.Template)
	if err != nil {
		return OciCiRunnerMutationReceipt{}, err
	}
	for _, item := range items {
		if !RunnerMatches(item, a.Demand, a.Template) {
			continue
		}
		record, ok, lookupErr := c.Ownership.Lookup(ctx, ProviderResourceId{Value: item.InstanceId})
		if lookupErr != nil {
			return OciCiRunnerMutationReceipt{}, lookupErr
		}
		if ok && record.CompartmentId.Value == a.Template.CompartmentId && record.Generation.Value == uint64(a.Template.Generation) {
			return OciCiRunnerMutationReceipt{InstanceId: item.InstanceId, ETag: item.ETag}, nil
		}
	}
	return OciCiRunnerMutationReceipt{}, &InvalidOperationError{Message: "OCI runner launch outcome is unknown"}
}

func (c *OCIComputeClient) terminate(ctx context.Context, a TerminateOciCiRunnerAction) (OciCiRunnerMutationReceipt, error) {
	if !isOCID(a.InstanceId, "instance") || !isSafeETag(a.ETag) {
		return OciCiRunnerMutationReceipt{}, &errs.Argument{Message: "OCI runner termination request is invalid"}
	}
	if c.Ownership == nil || !c.Ownership.AuthoritativeDurable() {
		return OciCiRunnerMutationReceipt{}, &InvalidOperationError{Message: "OCI runner termination requires authoritative ownership evidence"}
	}
	record, ok, err := c.Ownership.Lookup(ctx, ProviderResourceId{Value: a.InstanceId})
	if err != nil {
		return OciCiRunnerMutationReceipt{}, err
	} else if !ok || record.ResourceId.Value != a.InstanceId || !isOCID(record.CompartmentId.Value, "compartment") || record.Generation.Value == 0 {
		return OciCiRunnerMutationReceipt{}, &InvalidOperationError{Message: "OCI runner termination ownership is not recorded"}
	}
	resp, err := c.OCI.DoWithHeaders(ctx, http.MethodDelete, "/20160918/instances/"+url.PathEscape(a.InstanceId), nil, map[string]string{"If-Match": a.ETag})
	if err != nil {
		if indeterminate(err) {
			return c.reconcileTermination(ctx, a)
		}
		return OciCiRunnerMutationReceipt{}, err
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		_, _ = ReadBoundedBody(resp, 64<<10)
		return OciCiRunnerMutationReceipt{InstanceId: a.InstanceId, ETag: a.ETag, OpcRequestId: safeHeader(resp, "opc-request-id"), OpcWorkRequestId: safeHeader(resp, "opc-work-request-id")}, nil
	}
	if err := ociStatus(resp, "runner termination"); err != nil {
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			return c.reconcileTermination(ctx, a)
		}
		return OciCiRunnerMutationReceipt{}, err
	}
	return OciCiRunnerMutationReceipt{InstanceId: a.InstanceId, ETag: a.ETag}, nil
}

func (c *OCIComputeClient) reconcileTermination(ctx context.Context, a TerminateOciCiRunnerAction) (OciCiRunnerMutationReceipt, error) {
	resp, err := c.OCI.Do(ctx, http.MethodGet, "/20160918/instances/"+url.PathEscape(a.InstanceId), nil)
	if err != nil {
		return OciCiRunnerMutationReceipt{}, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_, _ = ReadBoundedBody(resp, 64<<10)
		return OciCiRunnerMutationReceipt{InstanceId: a.InstanceId, ETag: a.ETag}, nil
	}
	_, _ = ReadBoundedBody(resp, 64<<10)
	return OciCiRunnerMutationReceipt{}, &InvalidOperationError{Message: "OCI runner termination outcome is unknown"}
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
		if indeterminate(err) {
			if recovered, recoveryErr := c.reconcileNodeCreate(ctx, r); recoveryErr == nil {
				return recovered, nil
			}
		}
		return CreateNodeProviderResponse{}, err
	}
	if err := ociStatus(resp, "node create"); err != nil {
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
	if json.Unmarshal(body, &item) != nil || !isOCID(item.ID, "instance") {
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
	if r.Context.Action != ActionCreateNode || r.Context.ResourceKind != ResourceNode || !isOCID(r.Context.CompartmentId.Value, "compartment") || r.Context.Target == nil {
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
	if !isOCID(spec.CompartmentId, "compartment") || spec.CompartmentId != r.Context.CompartmentId.Value || !isOCID(spec.SubnetId, "subnet") || !isOCID(spec.ImageId, "image") {
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
		if !isOCID(id, "networksecuritygroup") || seen[id] {
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
		if !isOCID(item.ID, "instance") {
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
	resp, err := c.OCI.Do(ctx, http.MethodGet, "/20160918/instances?"+v.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if err := ociStatus(resp, "node reconciliation"); err != nil {
		return nil, err
	}
	body, err := ReadBoundedBody(resp, c.OCI.Config.MaxBodyBytes)
	if err != nil {
		return nil, err
	}
	var list ociInstanceList
	if json.Unmarshal(body, &list) != nil || len(list.Items) > 1000 {
		return nil, &InvalidDataError{Message: "OCI node reconciliation response is invalid"}
	}
	return list.Items, nil
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
		if item.FreeformTags["terrascale-create-key"] == r.Binding.CreateKey && item.FreeformTags["terrascale-operation"] == r.Context.OperationId.Value && isOCID(item.ID, "instance") {
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

var _ RunnerCapacityAdapter = (*OCIComputeClient)(nil)
var _ OciCreateNodeClient = (*OCIComputeNodeClient)(nil)
