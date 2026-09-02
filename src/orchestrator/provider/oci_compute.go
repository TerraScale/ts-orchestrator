package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	ETag          string            `json:"-"`
	TimeCreated   time.Time         `json:"timeCreated"`
	FreeformTags  map[string]string `json:"freeformTags"`
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
	pageLimit := limit
	if pageLimit > maximumOCIListResults {
		pageLimit = maximumOCIListResults
	}
	v.Set("limit", strconv.Itoa(pageLimit))
	items := make([]ociInstanceDocument, 0, limit)
	for page, pageCount := "", 0; ; pageCount++ {
		resp, err := c.OCI.Do(ctx, http.MethodGet, "/20160918/instances?"+cloneOCIQuery(v, page), nil)
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
		pageItems, err := decodeOCIList[ociInstanceDocument](body)
		if err != nil || len(pageItems) > limit || len(items)+len(pageItems) > limit {
			return nil, &InvalidDataError{Message: "OCI instance observation response is invalid"}
		}
		for _, item := range pageItems {
			if !isOCID(item.ID, "instance") || !isOCID(item.CompartmentID, "compartment") || item.CompartmentID != t.CompartmentId {
				return nil, &InvalidDataError{Message: "OCI instance observation contains an out-of-scope resource"}
			}
			items = append(items, item)
		}
		next, err := nextOCIPage(resp, page, pageCount+1)
		if err != nil {
			return nil, err
		}
		if next == "" {
			break
		}
		page = next
	}
	out := make([]OciCiRunnerNodeObservation, 0, len(items))
	for _, item := range items {
		if !isOCID(item.ID, "instance") || !isOCID(item.CompartmentID, "compartment") || item.CompartmentID != t.CompartmentId || item.TimeCreated.IsZero() || len(item.FreeformTags) > 32 || !validFreeformTags(item.FreeformTags) {
			return nil, &InvalidDataError{Message: "OCI instance observation contains invalid identity"}
		}
		state, ok := ociRunnerState(item.Lifecycle)
		if !ok {
			return nil, &InvalidDataError{Message: "OCI instance observation contains unknown lifecycle state"}
		}
		tags := cloneTags(item.FreeformTags)
		runner, sequence, _, _, preemptible, preserve, tagged, valid := parseRunnerTags(tags)
		if tagged && !valid {
			return nil, &InvalidDataError{Message: "OCI instance observation contains malformed runner tags"}
		}
		etag := ""
		if tagged {
			fence, found, err := c.getInstanceETag(ctx, item.ID, t.CompartmentId)
			if err != nil {
				return nil, err
			}
			if !found {
				continue
			}
			etag = fence
		}
		if !tagged {
			runner, sequence, preemptible, preserve = "", 0, false, false
		}
		out = append(out, OciCiRunnerNodeObservation{InstanceId: item.ID, ETag: etag, Runner: runner, Sequence: sequence, State: state, LastActivity: item.TimeCreated, FreeformTags: tags, Preemptible: preemptible, PreserveBootVolume: preserve})
	}
	return out, nil
}

func (c *OCIComputeClient) getInstanceETag(ctx context.Context, id, compartment string) (string, bool, error) {
	resp, err := c.OCI.Do(ctx, http.MethodGet, "/20160918/instances/"+url.PathEscape(id), nil)
	if err != nil {
		return "", false, err
	}
	if resp.StatusCode == http.StatusNotFound {
		drainClose(resp.Body)
		return "", false, &InvalidOperationError{Message: "OCI instance fence read could not distinguish absence from missing authority"}
	}
	if err := ociStatus(resp, "instance fence read"); err != nil {
		return "", false, err
	}
	body, err := ReadBoundedBody(resp, c.OCI.Config.MaxBodyBytes)
	if err != nil {
		return "", false, err
	}
	var item ociInstanceDocument
	etag := safeHeader(resp, "etag")
	if json.Unmarshal(body, &item) != nil || item.ID != id || item.CompartmentID != compartment || !isSafeETag(etag) {
		return "", false, &InvalidDataError{Message: "OCI instance fence response is invalid"}
	}
	return etag, true, nil
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
	case "MOVING", "PROVISIONING", "STARTING", "CREATING_IMAGE":
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
	item.ETag = safeHeader(resp, "etag")
	if !isOCID(item.ID, "instance") || item.CompartmentID != a.Template.CompartmentId || !isSafeETag(item.ETag) {
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
	if resp.StatusCode == http.StatusNotFound {
		_, _ = ReadBoundedBody(resp, 64<<10)
		return c.reconcileTermination(ctx, a)
	}
	if resp.StatusCode == http.StatusAccepted {
		_, _ = ReadBoundedBody(resp, 64<<10)
		work := safeHeader(resp, "opc-work-request-id")
		if !validWorkRequestID(work) {
			return OciCiRunnerMutationReceipt{}, &ProviderOutcomeUnknownError{Message: "OCI runner termination returned no valid work request"}
		}
		return OciCiRunnerMutationReceipt{InstanceId: a.InstanceId, ETag: a.ETag, OpcRequestId: safeHeader(resp, "opc-request-id"), OpcWorkRequestId: work}, nil
	}
	if resp.StatusCode == http.StatusNoContent {
		_, _ = ReadBoundedBody(resp, 64<<10)
		return c.reconcileTermination(ctx, a)
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
	if c == nil || c.Ownership == nil || !c.Ownership.AuthoritativeDurable() {
		return OciCiRunnerMutationReceipt{}, &InvalidOperationError{Message: "OCI runner termination recovery requires authoritative ownership evidence"}
	}
	record, owned, err := c.Ownership.Lookup(ctx, ProviderResourceId{Value: a.InstanceId})
	if err != nil {
		return OciCiRunnerMutationReceipt{}, err
	}
	if !owned || record.ResourceId.Value != a.InstanceId || !isOCID(record.CompartmentId.Value, "compartment") {
		return OciCiRunnerMutationReceipt{}, &InvalidOperationError{Message: "OCI runner termination recovery ownership is not recorded"}
	}
	exists, err := c.instanceExistsInCompartment(ctx, a.InstanceId, record.CompartmentId.Value)
	if err != nil {
		return OciCiRunnerMutationReceipt{}, err
	}
	if !exists {
		return OciCiRunnerMutationReceipt{InstanceId: a.InstanceId, ETag: a.ETag}, nil
	}
	return OciCiRunnerMutationReceipt{}, &InvalidOperationError{Message: "OCI runner termination outcome is unknown"}
}

func (c *OCIComputeClient) instanceExistsInCompartment(ctx context.Context, id, compartment string) (bool, error) {
	if c == nil || c.OCI == nil || !isOCID(id, "instance") || !isOCID(compartment, "compartment") {
		return false, &errs.Argument{Message: "OCI instance absence scope is invalid"}
	}
	query := url.Values{"compartmentId": {compartment}, "limit": {strconv.Itoa(maximumOCIListResults)}}
	for page, pageCount := "", 0; ; pageCount++ {
		resp, err := c.OCI.Do(ctx, http.MethodGet, "/20160918/instances?"+cloneOCIQuery(query, page), nil)
		if err != nil {
			return false, err
		}
		if err := ociStatus(resp, "instance absence verification"); err != nil {
			return false, err
		}
		body, err := ReadBoundedBody(resp, c.OCI.Config.MaxBodyBytes)
		if err != nil {
			return false, err
		}
		items, err := decodeOCIList[ociInstanceDocument](body)
		if err != nil || len(items) > maximumOCIListResults {
			return false, &InvalidDataError{Message: "OCI instance absence verification response is invalid"}
		}
		for _, item := range items {
			if !isOCID(item.ID, "instance") || item.CompartmentID != compartment {
				return false, &InvalidDataError{Message: "OCI instance absence verification escaped its compartment"}
			}
			if item.ID == id {
				return true, nil
			}
		}
		next, err := nextOCIPage(resp, page, pageCount+1)
		if err != nil {
			return false, err
		}
		if next == "" {
			return false, nil
		}
		page = next
	}
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

type ociNodeLaunchRequest struct {
	authority     string
	service       OCIService
	region        string
	compartmentID string
	body          []byte
	headers       map[string]string
}

func (r ociNodeLaunchRequest) digest() string {
	return digestCanonical("oci-node-launch-request-v2", r.authority, string(r.service), r.region, http.MethodPost, "/20160918/instances", r.compartmentID, string(r.body), r.headers["opc-retry-token"])
}

func (c *OCIComputeNodeClient) transportBinding() (string, OCIService, string, error) {
	if c == nil || c.OCI == nil || c.OCI.Config.Endpoint == nil {
		return "", "", "", &InvalidOperationError{Message: "OCI node client is unavailable"}
	}
	config := c.OCI.Config
	if config.Service != OCIServiceCore || config.Endpoint.Scheme != "https" || config.Endpoint.User != nil ||
		config.Endpoint.RawQuery != "" || config.Endpoint.Fragment != "" || config.Endpoint.Opaque != "" ||
		config.Endpoint.RawPath != "" || (config.Endpoint.Path != "" && config.Endpoint.Path != "/") ||
		!regionPattern.MatchString(config.Region) || !validOCIServiceHost(config.Service, config.Region, config.Endpoint.Host) {
		return "", "", "", &InvalidOperationError{Message: "OCI node client authority is invalid"}
	}
	return config.Endpoint.Host, config.Service, config.Region, nil
}

func (c *OCIComputeNodeClient) CreateNode(ctx context.Context, r CreateNodeProviderRequest) (CreateNodeProviderResponse, error) {
	launch, err := c.prepareNodeLaunch(ctx, r)
	if err != nil {
		return CreateNodeProviderResponse{}, err
	}
	return c.executeNodeLaunch(ctx, launch)
}

func (c *OCIComputeNodeClient) prepareNodeLaunch(ctx context.Context, r CreateNodeProviderRequest) (ociNodeLaunchRequest, error) {
	if c == nil || c.OCI == nil {
		return ociNodeLaunchRequest{}, &InvalidOperationError{Message: "OCI node client is unavailable"}
	}
	if ctx == nil {
		return ociNodeLaunchRequest{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return ociNodeLaunchRequest{}, err
	}
	authority, service, region, err := c.transportBinding()
	if err != nil {
		return ociNodeLaunchRequest{}, err
	}
	if err := validateCreateRequestShape(r); err != nil {
		return ociNodeLaunchRequest{}, err
	}
	parameters, ok := r.Context.ActionParameters.(CreateNodeProviderParameters)
	if !ok || parameters != r.Parameters || parameters.TemplateId.Value != r.Binding.TemplateId || parameters.PlacementId.Value != r.Binding.PlacementId || parameters.BootstrapEnvelopeDigest.Sha256 != r.Binding.BootstrapEnvelopeDigest {
		return ociNodeLaunchRequest{}, &InvalidOperationError{Message: "OCI node create parameters are not bound to the authorized request"}
	}
	if c.LaunchResolver == nil {
		return ociNodeLaunchRequest{}, &InvalidOperationError{Message: "OCI node create requires an injected launch resolver"}
	}
	spec, err := c.LaunchResolver.Resolve(ctx, parameters.TemplateId, parameters.PlacementId, parameters.BootstrapEnvelopeDigest)
	if err != nil {
		return ociNodeLaunchRequest{}, err
	}
	if err := validateOciNodeLaunchSpec(spec, r); err != nil {
		return ociNodeLaunchRequest{}, err
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
	return ociNodeLaunchRequest{
		authority:     authority,
		service:       service,
		region:        region,
		compartmentID: r.Context.CompartmentId.Value,
		body:          mustJSON(payload),
		headers:       map[string]string{"opc-retry-token": r.Context.IdempotencyKey.Value},
	}, nil
}

func (c *OCIComputeNodeClient) executeNodeLaunch(ctx context.Context, launch ociNodeLaunchRequest) (CreateNodeProviderResponse, error) {
	if c == nil || c.OCI == nil {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI node client is unavailable"}
	}
	if ctx == nil {
		return CreateNodeProviderResponse{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return CreateNodeProviderResponse{}, err
	}
	authority, service, region, err := c.transportBinding()
	if err != nil {
		return CreateNodeProviderResponse{}, err
	}
	if launch.authority != authority || launch.service != service || launch.region != region ||
		!isOCID(launch.compartmentID, "compartment") || len(launch.body) == 0 || launch.headers["opc-retry-token"] == "" {
		return CreateNodeProviderResponse{}, &InvalidOperationError{Message: "OCI node launch request is unavailable"}
	}
	resp, err := c.OCI.DoWithHeaders(ctx, http.MethodPost, "/20160918/instances", bytes.NewReader(launch.body), launch.headers)
	if err != nil {
		var unknown *ProviderOutcomeUnknownError
		if errors.As(err, &unknown) {
			return CreateNodeProviderResponse{}, err
		}
		if indeterminate(err) {
			return CreateNodeProviderResponse{}, &ProviderOutcomeUnknownError{Message: "OCI node create outcome is unknown"}
		}
		return CreateNodeProviderResponse{}, err
	}
	if err := ociStatus(resp, "node create"); err != nil {
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			return CreateNodeProviderResponse{}, &ProviderOutcomeUnknownError{Message: "OCI node create outcome is unknown"}
		}
		return CreateNodeProviderResponse{}, err
	}
	body, err := ReadBoundedBody(resp, c.OCI.Config.MaxBodyBytes)
	if err != nil {
		return CreateNodeProviderResponse{}, &ProviderOutcomeUnknownError{Message: "OCI node create outcome is unknown"}
	}
	var item ociInstanceDocument
	if json.Unmarshal(body, &item) != nil || !isOCID(item.ID, "instance") || item.CompartmentID != launch.compartmentID {
		return CreateNodeProviderResponse{}, &ProviderOutcomeUnknownError{Message: "OCI node create response is invalid and its outcome is unknown"}
	}
	work := safeHeader(resp, "opc-work-request-id")
	if !validWorkRequestID(work) {
		return CreateNodeProviderResponse{}, &ProviderOutcomeUnknownError{Message: "OCI node create response has no work request and its outcome is unknown"}
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
	if c == nil || c.OCI == nil {
		return CreateNodeReconciliation{}, &InvalidOperationError{Message: "OCI node client is unavailable"}
	}
	if ctx == nil {
		return CreateNodeReconciliation{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return CreateNodeReconciliation{}, err
	}
	if err := validateCreateRequestShape(r); err != nil {
		return CreateNodeReconciliation{}, err
	}
	// OCI does not expose a create-operation binding on an instance. Tags and
	// broad lifecycle ownership cannot identify the result of this exact
	// launch, so direct reconciliation must remain unknown. The provider
	// wrapper may use only its journal-bound exact opc-retry-token replay.
	return CreateNodeReconciliation{Status: CreateNodeUnknown}, nil
}

var _ RunnerCapacityAdapter = (*OCIComputeClient)(nil)
var _ OciCreateNodeClient = (*OCIComputeNodeClient)(nil)
