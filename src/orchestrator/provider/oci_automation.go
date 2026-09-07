package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

const maximumOCIListResults = 1000

func fingerprintJSON(action string, value any) string {
	raw, _ := json.Marshal(value)
	return ProviderMutationFingerprint(action, string(raw))
}

func expectJSONMutation(intent ProviderMutationIntent, action, scope string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return &errs.Argument{Message: "provider mutation request cannot be fingerprinted"}
	}
	return expectMutation(intent, action, scope, string(raw))
}

func validateOCIAdapter(transport *OCIHTTPTransport, service OCIService, journal ProviderMutationJournal) error {
	if transport == nil || transport.Config.Endpoint == nil || transport.Config.Service != service {
		return &InvalidOperationError{Message: "OCI adapter transport is unavailable or has the wrong service authority"}
	}
	if journal == nil || !journal.AuthoritativeDurable() {
		return &InvalidOperationError{Message: "OCI adapter requires an authoritative durable mutation journal"}
	}
	return nil
}

func requireOwnedResource(ctx context.Context, ownership DurableOwnershipEvidence, id, compartment string) error {
	if ownership == nil || !ownership.AuthoritativeDurable() {
		return &InvalidOperationError{Message: "provider mutation requires authoritative ownership evidence"}
	}
	record, found, err := ownership.Lookup(ctx, ProviderResourceId{Value: id})
	if err != nil {
		return err
	}
	if !found || record.ResourceId.Value != id || record.Generation.Value == 0 ||
		(compartment != "" && record.CompartmentId.Value != compartment) {
		return &InvalidOperationError{Message: "provider resource ownership is not recorded in the required scope"}
	}
	return nil
}

func safeFreeformTags(tags map[string]string, allowOwnership bool) (map[string]string, error) {
	if len(tags) > 32 {
		return nil, &errs.Argument{Message: "provider tags exceed limit"}
	}
	result := make(map[string]string, len(tags)+2)
	for key, value := range tags {
		if len(key) < 1 || len(key) > 128 || len(value) > 256 || strings.ContainsAny(key+value, "\r\n") {
			return nil, &errs.Argument{Message: "provider tag is invalid"}
		}
		if strings.HasPrefix(key, "terrascale-") && !(allowOwnership && (key == OCIManagedTag || key == OCIScopeTag)) {
			return nil, &errs.Argument{Message: "provider tag uses a reserved name"}
		}
		result[key] = value
	}
	return result, nil
}

func bindMutationTags(tags map[string]string, intent ProviderMutationIntent) map[string]string {
	result := make(map[string]string, len(tags)+2)
	for key, value := range tags {
		result[key] = value
	}
	result["terrascale-operation"] = intent.OperationID.Value
	result["terrascale-intent"] = intent.Fingerprint
	return result
}

func derivedRetryToken(intent ProviderMutationIntent, suffix string) string {
	return ProviderMutationFingerprint(intent.IdempotencyKey.Value, intent.Fingerprint, suffix)
}

func mutationResultFromHeaders(resp *http.Response, resourceID, etag string) ProviderMutationResult {
	return ProviderMutationResult{ResourceID: resourceID, ETag: etag, WorkRequestID: safeHeader(resp, "opc-work-request-id")}
}

func finishUnknown(ctx context.Context, journal ProviderMutationJournal, intent ProviderMutationIntent) error {
	if _, err := journal.MarkUnknown(ctx, intent); err != nil {
		return err
	}
	return &ProviderOutcomeUnknownError{}
}

func knownFailure(ctx context.Context, journal ProviderMutationJournal, intent ProviderMutationIntent, code string) error {
	if _, err := journal.MarkFailed(ctx, intent, code); err != nil {
		return err
	}
	return &InvalidOperationError{Message: "OCI provider rejected the mutation"}
}

func markSucceeded(ctx context.Context, journal ProviderMutationJournal, intent ProviderMutationIntent, result ProviderMutationResult) error {
	_, err := journal.MarkSucceeded(ctx, intent, result)
	return err
}

func readOCIErrorCode(resp *http.Response) (string, error) {
	if resp == nil {
		return "", &InvalidDataError{Message: "OCI request returned no response"}
	}
	raw, err := ReadBoundedBody(resp, 64<<10)
	if err != nil {
		return "", err
	}
	var body struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(raw, &body) != nil || len(body.Code) > 96 || strings.ContainsAny(body.Code, "\r\n") {
		return "", nil
	}
	return body.Code, nil
}

func capacityCode(code string) bool {
	switch strings.ToLower(code) {
	case "outofhostcapacity", "outofcapacity", "capacitynotavailable", "shapenotavailable":
		return true
	default:
		return false
	}
}

func ociMutationFailure(ctx context.Context, journal ProviderMutationJournal, intent ProviderMutationIntent, resp *http.Response) error {
	if resp == nil || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		if resp != nil {
			_, _ = ReadBoundedBody(resp, 64<<10)
		}
		return finishUnknown(ctx, journal, intent)
	}
	_, _ = ReadBoundedBody(resp, 64<<10)
	return knownFailure(ctx, journal, intent, "provider-rejected")
}

type OCIComputeAdapter struct {
	Core      *OCIHTTPTransport
	Journal   ProviderMutationJournal
	Ownership DurableOwnershipEvidence
}

func NewOCIComputeAdapter(core *OCIHTTPTransport, journal ProviderMutationJournal) (*OCIComputeAdapter, error) {
	if err := validateOCIAdapter(core, OCIServiceCore, journal); err != nil {
		return nil, err
	}
	return &OCIComputeAdapter{Core: core, Journal: journal}, nil
}

type computeLaunchFingerprint struct {
	CompartmentID, DisplayName, ServerIdentity, Environment, Cluster, MemberID, CellID, BootstrapBase64 string
	Generation                                                                                          uint64
	NSGIDs                                                                                              []string
	Candidates                                                                                          []ComputeCapacityCandidate
	Tags                                                                                                map[string]string
}

func computeLaunchBinding(request ComputeLaunchRequest) computeLaunchFingerprint {
	return computeLaunchFingerprint{request.CompartmentID, request.DisplayName, request.ServerIdentity, request.Environment, request.Cluster, request.MemberID, request.CellID, request.BootstrapBase64, request.Generation, append([]string(nil), request.NSGIDs...), append([]ComputeCapacityCandidate(nil), request.Candidates...), request.Tags}
}

func ComputeLaunchMutationFingerprint(request ComputeLaunchRequest) string {
	return fingerprintJSON("compute.launch", computeLaunchBinding(request))
}

func ComputeLaunchMutationScope(request ComputeLaunchRequest) string {
	return ProviderMutationScope("compute", request.CompartmentID, request.DisplayName)
}

func validateComputeLaunch(request ComputeLaunchRequest) error {
	if !IsOCID(request.CompartmentID, "compartment") {
		return &errs.Argument{Message: "compute launch resource identity is invalid"}
	}
	if err := validateBoundedName(request.DisplayName, "compute display name", 128); err != nil {
		return err
	}
	if request.ServerIdentity != "" || request.Environment != "" || request.Cluster != "" || request.MemberID != "" || request.CellID != "" {
		if !validServerIdentity(request.ServerIdentity) || !validBindingPart(request.Environment) || !validBindingPart(request.Cluster) || !validBindingPart(request.MemberID) || !validBindingPart(request.CellID) {
			return &errs.Argument{Message: "compute launch authenticated member identity is incomplete"}
		}
	}
	if len(request.NSGIDs) > 5 || len(request.Candidates) < 1 || len(request.Candidates) > 12 {
		return &errs.Argument{Message: "compute launch placement set is invalid"}
	}
	seenNSG := map[string]bool{}
	for _, id := range request.NSGIDs {
		if !IsOCID(id, "networksecuritygroup") || seenNSG[id] {
			return &errs.Argument{Message: "compute launch network security group is invalid"}
		}
		seenNSG[id] = true
	}
	bootstrap, err := base64.StdEncoding.DecodeString(request.BootstrapBase64)
	if err != nil || len(bootstrap) == 0 || len(bootstrap) > 32*1024 {
		return &errs.Argument{Message: "compute launch bootstrap is invalid"}
	}
	for _, candidate := range request.Candidates {
		if candidate.Architecture != "arm64" && candidate.Architecture != "amd64" {
			return &errs.Argument{Message: "compute launch candidate architecture is not admitted"}
		}
		shapeArchitecture := computeShapeArchitecture(candidate.Shape)
		if shapeArchitecture != "" && shapeArchitecture != candidate.Architecture {
			return &errs.Argument{Message: "compute launch candidate architecture does not match its shape"}
		}
		if len(candidate.AvailabilityDomain) < 1 || len(candidate.AvailabilityDomain) > 128 ||
			!IsOCID(candidate.SubnetID, "subnet") ||
			len(candidate.FaultDomain) > 64 || len(candidate.Shape) < 1 || len(candidate.Shape) > 128 ||
			len(candidate.Architecture) < 1 || len(candidate.Architecture) > 32 || !IsOCID(candidate.ImageID, "image") ||
			strings.ContainsAny(candidate.AvailabilityDomain+candidate.FaultDomain+candidate.Shape+candidate.Architecture, "\r\n") ||
			math.IsNaN(candidate.OCPUs) || math.IsInf(candidate.OCPUs, 0) || candidate.OCPUs <= 0 || candidate.OCPUs > 192 ||
			math.IsNaN(candidate.MemoryGiB) || math.IsInf(candidate.MemoryGiB, 0) || candidate.MemoryGiB <= 0 || candidate.MemoryGiB > 2048 {
			return &errs.Argument{Message: "compute launch capacity candidate is invalid"}
		}
	}
	if _, err := safeFreeformTags(request.Tags, false); err != nil {
		return err
	}
	return expectJSONMutation(request.Mutation, "compute.launch", ComputeLaunchMutationScope(request), computeLaunchBinding(request))
}

func computeShapeArchitecture(shape string) string {
	switch {
	case strings.HasPrefix(shape, "VM.Standard.A1"):
		return "arm64"
	case strings.HasPrefix(shape, "VM.Standard.E3"), strings.HasPrefix(shape, "VM.Standard.E4"), strings.HasPrefix(shape, "VM.Standard.E5"):
		return "amd64"
	default:
		return ""
	}
}

type ociAutomatedInstance struct {
	CompartmentID      string            `json:"compartmentId"`
	ID                 string            `json:"id"`
	LifecycleState     string            `json:"lifecycleState"`
	ETag               string            `json:"etag"`
	AvailabilityDomain string            `json:"availabilityDomain"`
	Shape              string            `json:"shape"`
	FreeformTags       map[string]string `json:"freeformTags"`
}

func (a *OCIComputeAdapter) LaunchInstance(ctx context.Context, request ComputeLaunchRequest) (ComputeInstance, error) {
	if a == nil || validateOCIAdapter(a.Core, OCIServiceCore, a.Journal) != nil {
		return ComputeInstance{}, &InvalidOperationError{Message: "OCI compute adapter is unavailable"}
	}
	if ctx == nil {
		return ComputeInstance{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return ComputeInstance{}, err
	}
	if err := validateComputeLaunch(request); err != nil {
		return ComputeInstance{}, err
	}
	if a.Ownership != nil && (request.Generation == 0 || !validServerIdentity(request.ServerIdentity) || !validBindingPart(request.Environment) || !validBindingPart(request.Cluster) || !validBindingPart(request.MemberID) || !validBindingPart(request.CellID)) {
		return ComputeInstance{}, &errs.Argument{Message: "durable compute launch requires authenticated member identity"}
	}
	record, err := prepareMutation(ctx, a.Journal, request.Mutation)
	if err != nil {
		return ComputeInstance{}, err
	}
	if result, done, err := completedMutation(record); done {
		if err != nil {
			return ComputeInstance{}, err
		}
		return mutationResultInstance(result)
	}
	if record.State == MutationSubmitted || record.State == MutationUnknown {
		instance, found, err := a.findInstanceForIntent(ctx, request)
		if err != nil {
			return ComputeInstance{}, err
		}
		if found {
			result := ProviderMutationResult{ResourceID: instance.ID, ETag: instance.ETag, WorkRequestID: instance.WorkRequestID}
			if err := markSucceeded(ctx, a.Journal, request.Mutation, result); err != nil {
				return ComputeInstance{}, err
			}
			return instance, nil
		}
		return ComputeInstance{}, &ProviderOutcomeUnknownError{}
	}
	tags, _ := safeFreeformTags(request.Tags, true)
	// Ownership tags are generated by this adapter from the canonical member
	// display name; callers cannot supply or override them through request.Tags.
	if strings.HasPrefix(request.DisplayName, "terrascale-") {
		parts := strings.Split(strings.TrimPrefix(request.DisplayName, "terrascale-"), "-")
		if len(parts) >= 2 {
			tags[OCIManagedTag] = "member"
			tags[OCIScopeTag] = strings.Join(parts[:len(parts)-1], "-")
			tags["terrascale-member-index"] = parts[len(parts)-1]
		}
	}
	tags = bindMutationTags(tags, request.Mutation)
	if record.NextAttempt >= len(request.Candidates) {
		return ComputeInstance{}, &InvalidDataError{Message: "compute launch capacity cursor is invalid"}
	}
	for index := record.NextAttempt; index < len(request.Candidates); index++ {
		candidate := request.Candidates[index]
		payload := struct {
			CompartmentID      string `json:"compartmentId"`
			AvailabilityDomain string `json:"availabilityDomain"`
			FaultDomain        string `json:"faultDomain,omitempty"`
			Shape              string `json:"shape"`
			ShapeConfig        struct {
				OCPUs       float64 `json:"ocpus"`
				MemoryInGBs float64 `json:"memoryInGBs"`
			} `json:"shapeConfig"`
			DisplayName       string `json:"displayName"`
			CreateVnicDetails struct {
				SubnetID string   `json:"subnetId"`
				NSGIDs   []string `json:"nsgIds,omitempty"`
			} `json:"createVnicDetails"`
			SourceDetails struct {
				SourceType string `json:"sourceType"`
				ImageID    string `json:"imageId"`
			} `json:"sourceDetails"`
			Metadata     map[string]string `json:"metadata"`
			FreeformTags map[string]string `json:"freeformTags"`
		}{CompartmentID: request.CompartmentID, AvailabilityDomain: candidate.AvailabilityDomain, FaultDomain: candidate.FaultDomain, Shape: candidate.Shape, ShapeConfig: struct {
			OCPUs       float64 `json:"ocpus"`
			MemoryInGBs float64 `json:"memoryInGBs"`
		}{candidate.OCPUs, candidate.MemoryGiB}, DisplayName: request.DisplayName, CreateVnicDetails: struct {
			SubnetID string   `json:"subnetId"`
			NSGIDs   []string `json:"nsgIds,omitempty"`
		}{candidate.SubnetID, request.NSGIDs}, SourceDetails: struct {
			SourceType string `json:"sourceType"`
			ImageID    string `json:"imageId"`
		}{"image", candidate.ImageID}, Metadata: map[string]string{"user_data": request.BootstrapBase64}, FreeformTags: tags}
		if _, err := a.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
			return ComputeInstance{}, err
		}
		resp, err := a.Core.DoWithHeaders(ctx, http.MethodPost, "/20160918/instances", bytes.NewReader(mustJSON(payload)), map[string]string{"opc-retry-token": derivedRetryToken(request.Mutation, strconv.Itoa(index))})
		if err != nil {
			if IsOutcomeIndeterminate(err) {
				return ComputeInstance{}, finishUnknown(ctx, a.Journal, request.Mutation)
			}
			return ComputeInstance{}, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			code, readErr := readOCIErrorCode(resp)
			if readErr != nil {
				return ComputeInstance{}, finishUnknown(ctx, a.Journal, request.Mutation)
			}
			if capacityCode(code) {
				if index+1 < len(request.Candidates) {
					if _, err := a.Journal.MarkAttemptRejected(ctx, request.Mutation, index); err != nil {
						return ComputeInstance{}, err
					}
				}
				continue
			}
			return ComputeInstance{}, ociMutationFailure(ctx, a.Journal, request.Mutation, &http.Response{StatusCode: resp.StatusCode, Body: http.NoBody, Header: resp.Header})
		}
		body, err := ReadBoundedBody(resp, a.Core.Config.MaxBodyBytes)
		if err != nil {
			return ComputeInstance{}, finishUnknown(ctx, a.Journal, request.Mutation)
		}
		var item ociAutomatedInstance
		if json.Unmarshal(body, &item) != nil || !IsOCID(item.ID, "instance") {
			return ComputeInstance{}, finishUnknown(ctx, a.Journal, request.Mutation)
		}
		if item.ETag == "" {
			item.ETag = safeHeader(resp, "etag")
		}
		instance := ComputeInstance{ID: item.ID, LifecycleState: item.LifecycleState, ETag: item.ETag, WorkRequestID: safeHeader(resp, "opc-work-request-id"), AvailabilityDomain: item.AvailabilityDomain, Shape: item.Shape}
		result := ProviderMutationResult{ResourceID: item.ID, ETag: item.ETag, WorkRequestID: instance.WorkRequestID}
		if err := markSucceeded(ctx, a.Journal, request.Mutation, result); err != nil {
			return ComputeInstance{}, err
		}
		if a.Ownership != nil {
			if err := a.Ownership.Record(ctx, ProviderOwnershipRecord{ResourceId: ProviderResourceId{Value: item.ID}, CellId: ProviderCellId{Value: request.CellID}, CompartmentId: ProviderCompartmentId{Value: request.CompartmentID}, Generation: ProviderGeneration{Value: request.Generation}, ServerIdentity: request.ServerIdentity, MemberID: request.MemberID}); err != nil {
				return ComputeInstance{}, err
			}
		}
		return instance, nil
	}
	if _, err := a.Journal.MarkFailed(ctx, request.Mutation, "capacity-unavailable"); err != nil {
		return ComputeInstance{}, err
	}
	return ComputeInstance{}, &ProviderCapacityError{Attempts: len(request.Candidates)}
}

func (a *OCIComputeAdapter) findInstanceForIntent(ctx context.Context, request ComputeLaunchRequest) (ComputeInstance, bool, error) {
	query := url.Values{"compartmentId": {request.CompartmentID}, "limit": {strconv.Itoa(maximumOCIListResults)}}
	items, err := ReadOCIResourceList[ociAutomatedInstance](ctx, a.Core, "/20160918/instances", query, func(item ociAutomatedInstance) string { return item.ID })
	if err != nil || len(items) > maximumOCIListResults {
		return ComputeInstance{}, false, &InvalidDataError{Message: "OCI instance reconciliation response is invalid"}
	}
	var matches []ociAutomatedInstance
	for _, item := range items {
		if item.FreeformTags["terrascale-operation"] == request.Mutation.OperationID.Value && item.FreeformTags["terrascale-intent"] == request.Mutation.Fingerprint {
			matches = append(matches, item)
		}
	}
	if len(matches) > 1 {
		return ComputeInstance{}, false, &InvalidOperationError{Message: "OCI instance reconciliation found duplicate intent results"}
	}
	if len(matches) == 0 {
		return ComputeInstance{}, false, nil
	}
	item := matches[0]
	if !IsOCID(item.ID, "instance") {
		return ComputeInstance{}, false, &InvalidDataError{Message: "OCI instance reconciliation identity is invalid"}
	}
	return ComputeInstance{ID: item.ID, LifecycleState: item.LifecycleState, ETag: item.ETag, AvailabilityDomain: item.AvailabilityDomain, Shape: item.Shape}, true, nil
}

func (a *OCIComputeAdapter) GetInstance(ctx context.Context, id string) (ComputeInstance, bool, error) {
	if a == nil || a.Core == nil || !IsOCID(id, "instance") {
		return ComputeInstance{}, false, &errs.Argument{Message: "compute instance identity is invalid"}
	}
	resp, err := a.Core.Do(ctx, http.MethodGet, "/20160918/instances/"+url.PathEscape(id), nil)
	if err != nil {
		return ComputeInstance{}, false, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_, _ = ReadBoundedBody(resp, 64<<10)
		return ComputeInstance{}, false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = ReadBoundedBody(resp, 64<<10)
		return ComputeInstance{}, false, &InvalidOperationError{Message: "OCI compute read failed"}
	}
	body, err := ReadBoundedBody(resp, a.Core.Config.MaxBodyBytes)
	if err != nil {
		return ComputeInstance{}, false, err
	}
	var item ociAutomatedInstance
	if json.Unmarshal(body, &item) != nil || item.ID != id {
		return ComputeInstance{}, false, &InvalidDataError{Message: "OCI compute response is invalid"}
	}
	return ComputeInstance{ID: item.ID, LifecycleState: item.LifecycleState, ETag: resp.Header.Get("ETag"), CompartmentID: item.CompartmentID, AvailabilityDomain: item.AvailabilityDomain, Shape: item.Shape}, true, nil
}

func computeTerminateBinding(request ComputeTerminateRequest) any {
	return struct{ InstanceID, IfMatch string }{request.InstanceID, request.IfMatch}
}

func ComputeTerminateMutationFingerprint(request ComputeTerminateRequest) string {
	return fingerprintJSON("compute.terminate", computeTerminateBinding(request))
}

func ComputeTerminateMutationScope(request ComputeTerminateRequest) string {
	return ProviderMutationScope("compute", request.InstanceID)
}

func (a *OCIComputeAdapter) TerminateInstance(ctx context.Context, request ComputeTerminateRequest) error {
	if a == nil || validateOCIAdapter(a.Core, OCIServiceCore, a.Journal) != nil {
		return &InvalidOperationError{Message: "OCI compute adapter is unavailable"}
	}
	if !IsOCID(request.InstanceID, "instance") || !isSafeETag(request.IfMatch) {
		return &errs.Argument{Message: "compute termination fence is invalid"}
	}
	if err := requireOwnedResource(ctx, a.Ownership, request.InstanceID, ""); err != nil {
		return err
	}
	if err := expectJSONMutation(request.Mutation, "compute.terminate", ComputeTerminateMutationScope(request), computeTerminateBinding(request)); err != nil {
		return err
	}
	record, err := prepareMutation(ctx, a.Journal, request.Mutation)
	if err != nil {
		return err
	}
	if _, done, err := completedMutation(record); done {
		return err
	}
	_, found, err := a.GetInstance(ctx, request.InstanceID)
	if err != nil {
		return err
	}
	if !found {
		return markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: request.InstanceID, ETag: request.IfMatch})
	}
	if record.State == MutationUnknown {
		return &ProviderOutcomeUnknownError{}
	}
	if _, err := a.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
		return err
	}
	resp, err := a.Core.DoWithHeaders(ctx, http.MethodDelete, "/20160918/instances/"+url.PathEscape(request.InstanceID), nil, map[string]string{"If-Match": request.IfMatch})
	if err != nil {
		if IsOutcomeIndeterminate(err) {
			if _, found, readErr := a.GetInstance(ctx, request.InstanceID); readErr == nil && !found {
				return markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: request.InstanceID, ETag: request.IfMatch})
			}
			return finishUnknown(ctx, a.Journal, request.Mutation)
		}
		return err
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		_, _ = ReadBoundedBody(resp, 64<<10)
		return markSucceeded(ctx, a.Journal, request.Mutation, mutationResultFromHeaders(resp, request.InstanceID, request.IfMatch))
	}
	return ociMutationFailure(ctx, a.Journal, request.Mutation, resp)
}

func objectSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func sortedMapPairs(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func drainClose(reader io.ReadCloser) {
	if reader != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(reader, 64<<10))
		_ = reader.Close()
	}
}

var (
	_ ComputeProvider = (*OCIComputeAdapter)(nil)
)
