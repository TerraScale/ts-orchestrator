package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
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
	return isOCID(t.CompartmentId, "compartment") && isOCID(t.SubnetId, "subnet") && isOCID(t.ImageId, "image") && t.AvailabilityDomain != "" && t.Generation > 0
}

// OCIComputeClient is the concrete instance-principal HTTP client used by
// the CI runner controller. It has no SDK or shell dependency.
type OCIComputeClient struct {
	OCI          *OCIHTTPTransport
	MaxInstances int
}

func NewOCIComputeClient(oci *OCIHTTPTransport) (*OCIComputeClient, error) {
	if oci == nil {
		return nil, &ArgumentError{Param: "oci", Message: "OCI transport is required"}
	}
	return &OCIComputeClient{OCI: oci, MaxInstances: maxOCIInstanceResults}, nil
}

func (c *OCIComputeClient) Observe(ctx context.Context, t OciCiRunnerLaunchTemplate) ([]OciCiRunnerNodeObservation, error) {
	if c == nil || c.OCI == nil {
		return nil, &InvalidOperationError{Message: "OCI compute client is unavailable"}
	}
	if !validInstanceTemplate(t) {
		return nil, &ArgumentError{Message: "OCI instance observation scope is invalid"}
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
		if !isOCID(item.ID, "instance") || !isOCID(item.CompartmentID, "compartment") || item.CompartmentID != t.CompartmentId || len(item.FreeformTags) > 32 {
			return nil, &InvalidDataError{Message: "OCI instance observation contains invalid identity"}
		}
		state, ok := ociRunnerState(item.Lifecycle)
		if !ok {
			return nil, &InvalidDataError{Message: "OCI instance observation contains unknown lifecycle state"}
		}
		etag := item.ETag
		if etag == "" {
			etag = resp.Header.Get("ETag")
		}
		// OCI list responses do not consistently include per-instance ETags.
		// Preserve an empty fence so the capacity planner can refuse a
		// destructive action, rather than pretending that the list is mutable.
		if etag != "" && !isSafeETag(etag) {
			return nil, &InvalidDataError{Message: "OCI instance observation contains an invalid ETag"}
		}
		last := item.TimeCreated
		if last.IsZero() {
			last = time.Unix(1, 0)
		}
		out = append(out, OciCiRunnerNodeObservation{InstanceId: item.ID, ETag: etag, State: state, LastActivity: last, FreeformTags: cloneTags(item.FreeformTags), Preemptible: item.FreeformTags["terrascale-preemptible"] == "true", PreserveBootVolume: item.FreeformTags["terrascale-preserve-boot-volume"] == "true"})
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
		return OciCiRunnerMutationReceipt{}, &ArgumentError{Message: "unsupported CI runner action"}
	}
}

func (c *OCIComputeClient) launch(ctx context.Context, a LaunchOciCiRunnerAction) (OciCiRunnerMutationReceipt, error) {
	if !validInstanceTemplate(a.Template) || a.Demand.IdempotencyToken == "" {
		return OciCiRunnerMutationReceipt{}, &ArgumentError{Message: "OCI runner launch request is invalid"}
	}
	r := CompileRunnerLaunch(a)
	payload := struct {
		CompartmentID string            `json:"compartmentId"`
		Availability  string            `json:"availabilityDomain"`
		SubnetID      string            `json:"subnetId"`
		ImageID       string            `json:"imageId"`
		Shape         string            `json:"shape"`
		DisplayName   string            `json:"displayName"`
		Hostname      string            `json:"hostnameLabel"`
		FreeformTags  map[string]string `json:"freeformTags"`
	}{r.CompartmentId, r.AvailabilityDomain, r.SubnetId, r.ImageId, r.Shape, r.DisplayName, r.HostnameLabel, r.Tags}
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
	items, err := c.Observe(ctx, a.Template)
	if err != nil {
		return OciCiRunnerMutationReceipt{}, err
	}
	for _, item := range items {
		if item.FreeformTags["terrascale-runner"] == a.Demand.Runner && item.FreeformTags["terrascale-runner-sequence"] == strconv.FormatInt(a.Demand.Sequence, 10) && item.FreeformTags["terrascale-bootstrap-sha256"] == a.Demand.BootstrapSha256 {
			return OciCiRunnerMutationReceipt{InstanceId: item.InstanceId, ETag: item.ETag}, nil
		}
	}
	return OciCiRunnerMutationReceipt{}, &InvalidOperationError{Message: "OCI runner launch outcome is unknown"}
}

func (c *OCIComputeClient) terminate(ctx context.Context, a TerminateOciCiRunnerAction) (OciCiRunnerMutationReceipt, error) {
	if !isOCID(a.InstanceId, "instance") || !isSafeETag(a.ETag) {
		return OciCiRunnerMutationReceipt{}, &ArgumentError{Message: "OCI runner termination request is invalid"}
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
	OCI         *OCIHTTPTransport
	ProofSigner *CreateNodeProviderProofSigner
}

func (c *OCIComputeNodeClient) CreateNode(ctx context.Context, r CreateNodeProviderRequest) (CreateNodeProviderResponse, error) {
	if c == nil || c.OCI == nil {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI node client is unavailable"}
	}
	if err := validateCreateRequestShape(r); err != nil {
		return CreateNodeProviderResponse{}, err
	}
	target := r.Context.Target.(IdempotentProviderCreate)
	payload := struct {
		CompartmentID string            `json:"compartmentId"`
		DisplayName   string            `json:"displayName"`
		FreeformTags  map[string]string `json:"freeformTags"`
	}{r.Context.CompartmentId.Value, "terrascale-node-" + r.Binding.CreateKey, map[string]string{"terrascale-operation": r.Context.OperationId.Value, "terrascale-create-key": target.Key.Value, "terrascale-idempotency-key": r.Context.IdempotencyKey.Value}}
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
		return &ArgumentError{Message: "OCI node create request is invalid"}
	}
	if _, ok := r.Context.Target.(IdempotentProviderCreate); !ok {
		return &ArgumentError{Message: "OCI node create request has no create key"}
	}
	return nil
}

func (c *OCIComputeNodeClient) ReconcileCreateNode(ctx context.Context, r CreateNodeProviderRequest) (CreateNodeReconciliation, error) {
	if c == nil || c.OCI == nil || c.ProofSigner == nil {
		return CreateNodeReconciliation{}, &InvalidOperationError{Message: "OCI node client is unavailable"}
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
	items, err := c.listNodeInstances(ctx, r.Context.CompartmentId.Value)
	if err != nil {
		return CreateNodeProviderResponse{}, err
	}
	for _, item := range items {
		if item.FreeformTags["terrascale-create-key"] == r.Binding.CreateKey && item.FreeformTags["terrascale-operation"] == r.Context.OperationId.Value && isOCID(item.ID, "instance") {
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
