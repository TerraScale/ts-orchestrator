package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

type OCIBlockStorageAdapter struct {
	Core         *OCIHTTPTransport
	Journal      ProviderMutationJournal
	Ownership    DurableOwnershipEvidence
	WorkRequests WorkRequestProvider
}

func NewOCIBlockStorageAdapter(core *OCIHTTPTransport, journal ProviderMutationJournal, workRequests ...WorkRequestProvider) (*OCIBlockStorageAdapter, error) {
	if err := validateOCIAdapter(core, OCIServiceCore, journal); err != nil {
		return nil, err
	}
	if len(workRequests) > 1 {
		return nil, &errs.Argument{Message: "OCI block storage adapter accepts at most one work request provider"}
	}
	var provider WorkRequestProvider
	if len(workRequests) == 1 {
		provider = workRequests[0]
	}
	return &OCIBlockStorageAdapter{Core: core, Journal: journal, WorkRequests: provider}, nil
}

type volumeCreateFingerprint struct {
	CompartmentID, AvailabilityDomain, DisplayName string
	SizeGiB, VPUsPerGiB                            uint64
	Tags                                           map[string]string
}

func volumeCreateBinding(request VolumeCreateRequest) volumeCreateFingerprint {
	return volumeCreateFingerprint{request.CompartmentID, request.AvailabilityDomain, request.DisplayName, request.SizeGiB, request.VPUsPerGiB, request.Tags}
}

func VolumeCreateMutationFingerprint(request VolumeCreateRequest) string {
	return fingerprintJSON("volume.create", volumeCreateBinding(request))
}

func VolumeCreateMutationScope(request VolumeCreateRequest) string {
	return ProviderMutationScope("volume", request.CompartmentID, request.DisplayName)
}

func validateVolumeCreate(request VolumeCreateRequest) error {
	if !isOCID(request.CompartmentID, "compartment") || len(request.AvailabilityDomain) < 1 || len(request.AvailabilityDomain) > 128 {
		return &errs.Argument{Message: "volume create placement is invalid"}
	}
	if err := validateBoundedName(request.DisplayName, "volume display name", 128); err != nil {
		return err
	}
	if request.SizeGiB < 50 || request.SizeGiB > 32*1024 || request.VPUsPerGiB < 10 || request.VPUsPerGiB > 120 {
		return &errs.Argument{Message: "volume create size or performance is invalid"}
	}
	if _, err := safeFreeformTags(request.Tags); err != nil {
		return err
	}
	return expectJSONMutation(request.Mutation, "volume.create", VolumeCreateMutationScope(request), volumeCreateBinding(request))
}

type ociAutomatedVolume struct {
	ID                 string            `json:"id"`
	CompartmentID      string            `json:"compartmentId"`
	AvailabilityDomain string            `json:"availabilityDomain"`
	DisplayName        string            `json:"displayName"`
	LifecycleState     string            `json:"lifecycleState"`
	SizeGiB            uint64            `json:"sizeInGBs"`
	VPUsPerGiB         uint64            `json:"vpusPerGB"`
	ETag               string            `json:"-"`
	FreeformTags       map[string]string `json:"freeformTags"`
}

func blockVolumeFromOCI(item ociAutomatedVolume, work string) (BlockVolume, error) {
	if !isOCID(item.ID, "volume") || !isOCID(item.CompartmentID, "compartment") || item.SizeGiB == 0 || !validCanonicalETag(item.ETag) ||
		(work != "" && !validWorkRequestID(work)) {
		return BlockVolume{}, &InvalidDataError{Message: "OCI block volume response is invalid"}
	}
	return BlockVolume{ID: item.ID, CompartmentID: item.CompartmentID, LifecycleState: item.LifecycleState, SizeGiB: item.SizeGiB, VPUsPerGiB: item.VPUsPerGiB, ETag: item.ETag, WorkRequestID: work}, nil
}

func volumeMatchesCreateRequest(item ociAutomatedVolume, request VolumeCreateRequest) bool {
	tags, err := safeFreeformTags(request.Tags)
	return err == nil && item.CompartmentID == request.CompartmentID && item.AvailabilityDomain == request.AvailabilityDomain &&
		item.DisplayName == request.DisplayName && item.SizeGiB == request.SizeGiB && item.VPUsPerGiB == request.VPUsPerGiB &&
		equalStringMap(item.FreeformTags, bindMutationTags(tags, request.Mutation))
}

func equalStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func (a *OCIBlockStorageAdapter) CreateVolume(ctx context.Context, request VolumeCreateRequest) (BlockVolume, error) {
	if a == nil || validateOCIAdapter(a.Core, OCIServiceCore, a.Journal) != nil {
		return BlockVolume{}, &InvalidOperationError{Message: "OCI block storage adapter is unavailable"}
	}
	if err := validateVolumeCreate(request); err != nil {
		return BlockVolume{}, err
	}
	record, err := prepareMutation(ctx, a.Journal, request.Mutation)
	if err != nil {
		return BlockVolume{}, err
	}
	if result, done, err := completedMutation(record); done {
		if err != nil {
			return BlockVolume{}, err
		}
		return mutationResultVolume(result)
	}
	if record.State == MutationSubmitted || record.State == MutationUnknown {
		return a.resumeVolumeCreate(ctx, request, record)
	}
	tags, _ := safeFreeformTags(request.Tags)
	payload := struct {
		CompartmentID      string            `json:"compartmentId"`
		AvailabilityDomain string            `json:"availabilityDomain"`
		DisplayName        string            `json:"displayName"`
		SizeGiB            uint64            `json:"sizeInGBs"`
		VPUsPerGiB         uint64            `json:"vpusPerGB"`
		FreeformTags       map[string]string `json:"freeformTags"`
	}{request.CompartmentID, request.AvailabilityDomain, request.DisplayName, request.SizeGiB, request.VPUsPerGiB, bindMutationTags(tags, request.Mutation)}
	if _, err := a.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
		return BlockVolume{}, err
	}
	resp, err := a.Core.DoWithHeaders(ctx, http.MethodPost, "/20160918/volumes", bytes.NewReader(mustJSON(payload)), map[string]string{"opc-retry-token": derivedRetryToken(request.Mutation, "volume")})
	if err != nil {
		if indeterminate(err) {
			return BlockVolume{}, finishUnknown(ctx, a.Journal, request.Mutation)
		}
		return BlockVolume{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return BlockVolume{}, ociMutationFailure(ctx, a.Journal, request.Mutation, resp)
	}
	work, workErr := optionalOCIWorkRequestID(resp)
	etag, etagErr := canonicalOCIETag(resp)
	headerResult := ProviderMutationResult{}
	if workErr == nil {
		headerResult.WorkRequestID = work
	}
	if etagErr == nil {
		headerResult.ETag = etag
	}
	body, err := ReadBoundedBody(resp, a.Core.Config.MaxBodyBytes)
	if err != nil {
		return BlockVolume{}, finishUnboundMutationResult(ctx, a.Journal, request.Mutation, headerResult, a.work, a.waitPolicy)
	}
	var item ociAutomatedVolume
	if json.Unmarshal(body, &item) != nil {
		return BlockVolume{}, finishUnboundMutationResult(ctx, a.Journal, request.Mutation, headerResult, a.work, a.waitPolicy)
	}
	if workErr != nil || etagErr != nil {
		result := headerResult
		if isOCID(item.ID, "volume") && volumeMatchesCreateRequest(item, request) {
			result.ResourceID = item.ID
		}
		return BlockVolume{}, finishUnboundMutationResult(ctx, a.Journal, request.Mutation, result, a.work, a.waitPolicy)
	}
	item.ETag = etag
	volume, err := blockVolumeFromOCI(item, work)
	if err != nil || !volumeMatchesCreateRequest(item, request) {
		result := ProviderMutationResult{WorkRequestID: work}
		if isOCID(item.ID, "volume") {
			result.ResourceID = item.ID
			result.ETag = etag
		}
		return BlockVolume{}, finishUnboundMutationResult(ctx, a.Journal, request.Mutation, result, a.work, a.waitPolicy)
	}
	if volume.CompartmentID != request.CompartmentID {
		return BlockVolume{}, finishUnknown(ctx, a.Journal, request.Mutation)
	}
	if err := finalizeOCIWorkRequest(ctx, a.WorkRequests, a.Journal, request.Mutation, volume.WorkRequestID); err != nil {
		return BlockVolume{}, err
	}
	if err := markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: volume.ID, ETag: volume.ETag, WorkRequestID: volume.WorkRequestID}); err != nil {
		return BlockVolume{}, err
	}
	return volume, nil
}

func (a *OCIBlockStorageAdapter) resumeVolumeCreate(ctx context.Context, request VolumeCreateRequest, record ProviderMutationRecord) (BlockVolume, error) {
	prior := record.Result
	workSucceeded := false
	if validWorkRequestID(prior.WorkRequestID) {
		if _, err := observeAsyncMutation(ctx, a.Journal, request.Mutation, prior, a.work, a.waitPolicy); err != nil {
			return BlockVolume{}, err
		}
		workSucceeded = true
	}
	var volume BlockVolume
	var found bool
	var err error
	if prior.ResourceID != "" {
		volume, found, err = a.getBlockVolumeInCompartment(ctx, prior.ResourceID, request.CompartmentID, &request)
	} else {
		volume, found, err = a.findVolumeForIntent(ctx, request)
	}
	if err != nil {
		return BlockVolume{}, err
	}
	if !found {
		return BlockVolume{}, &ProviderOutcomeUnknownError{Message: "OCI volume create result is not authoritatively visible"}
	}
	result := ProviderMutationResult{ResourceID: volume.ID, ETag: volume.ETag, WorkRequestID: prior.WorkRequestID}
	if prior.ResourceID != "" && prior.ResourceID != volume.ID {
		return BlockVolume{}, &ProviderOutcomeUnknownError{Message: "OCI volume create result identity changed"}
	}
	if workSucceeded && prior.ResourceID == volume.ID && validCanonicalETag(prior.ETag) {
		result.ETag = prior.ETag
	}
	if err := markSucceeded(ctx, a.Journal, request.Mutation, result); err != nil {
		return BlockVolume{}, err
	}
	volume.ETag = result.ETag
	volume.WorkRequestID = result.WorkRequestID
	return volume, nil
}

func (a *OCIBlockStorageAdapter) findVolumeForIntent(ctx context.Context, request VolumeCreateRequest) (BlockVolume, bool, error) {
	query := url.Values{"compartmentId": {request.CompartmentID}, "limit": {strconv.Itoa(maximumOCIListResults)}}
	items, err := a.listVolumes(ctx, query)
	if err != nil {
		return BlockVolume{}, false, err
	}
	var match *ociAutomatedVolume
	for index := range items {
		item := &items[index]
		if !isOCID(item.ID, "volume") || !isOCID(item.CompartmentID, "compartment") || item.CompartmentID != request.CompartmentID {
			return BlockVolume{}, false, &InvalidDataError{Message: "OCI volume reconciliation response is outside the requested compartment"}
		}
		if item.FreeformTags["terrascale-operation"] == request.Mutation.OperationID.Value && item.FreeformTags["terrascale-intent"] == request.Mutation.Fingerprint {
			if !volumeMatchesCreateRequest(*item, request) {
				return BlockVolume{}, false, &InvalidDataError{Message: "OCI volume reconciliation result does not match its durable intent"}
			}
			if match != nil {
				return BlockVolume{}, false, &InvalidOperationError{Message: "OCI volume reconciliation found duplicate intent results"}
			}
			match = item
		}
	}
	if match == nil {
		return BlockVolume{}, false, nil
	}
	return a.getBlockVolumeInCompartment(ctx, match.ID, request.CompartmentID, &request)
}

func (a *OCIBlockStorageAdapter) listVolumes(ctx context.Context, query url.Values) ([]ociAutomatedVolume, error) {
	items := make([]ociAutomatedVolume, 0)
	seenPages := make(map[string]struct{}, maximumOCIPages-1)
	for page, pagesRead := "", 1; ; pagesRead++ {
		resp, err := a.Core.Do(ctx, http.MethodGet, "/20160918/volumes?"+cloneOCIQuery(query, page), nil)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_, _ = ReadBoundedBody(resp, 64<<10)
			return nil, &InvalidOperationError{Message: "OCI volume reconciliation failed"}
		}
		body, err := ReadBoundedBody(resp, a.Core.Config.MaxBodyBytes)
		if err != nil {
			return nil, err
		}
		pageItems, err := decodeOCIList[ociAutomatedVolume](body)
		if err != nil || len(pageItems) > maximumOCIListResults || len(items)+len(pageItems) > maximumOCIListResults*maximumOCIPages {
			return nil, &InvalidDataError{Message: "OCI volume reconciliation response is invalid"}
		}
		for _, item := range pageItems {
			if !isOCID(item.ID, "volume") || item.CompartmentID != query.Get("compartmentId") {
				return nil, &InvalidDataError{Message: "OCI volume reconciliation response is outside the requested compartment"}
			}
		}
		items = append(items, pageItems...)
		next, err := nextOCIPage(resp, seenPages, pagesRead)
		if err != nil {
			return nil, err
		}
		if next == "" {
			return items, nil
		}
		page = next
	}
}

func (a *OCIBlockStorageAdapter) GetBlockVolume(ctx context.Context, id string) (BlockVolume, bool, error) {
	if a == nil || a.Core == nil {
		return BlockVolume{}, false, &InvalidOperationError{Message: "OCI block storage adapter is unavailable"}
	}
	if !isOCID(id, "volume") {
		return BlockVolume{}, false, &errs.Argument{Message: "block volume identity is invalid"}
	}
	compartment, err := ownedResourceCompartment(ctx, a.Ownership, id, "")
	if err != nil {
		return BlockVolume{}, false, err
	}
	return a.getBlockVolumeInCompartment(ctx, id, compartment, nil)
}

func (a *OCIBlockStorageAdapter) getBlockVolumeInCompartment(ctx context.Context, id, compartment string, request *VolumeCreateRequest) (BlockVolume, bool, error) {
	if a == nil || a.Core == nil || !isOCID(id, "volume") {
		return BlockVolume{}, false, &errs.Argument{Message: "block volume identity is invalid"}
	}
	resp, err := a.Core.Do(ctx, http.MethodGet, "/20160918/volumes/"+url.PathEscape(id), nil)
	if err != nil {
		return BlockVolume{}, false, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_, _ = ReadBoundedBody(resp, 64<<10)
		if compartment == "" {
			return BlockVolume{}, false, nil
		}
		exists, listErr := a.volumeExistsInCompartment(ctx, id, compartment)
		if listErr != nil || !exists {
			return BlockVolume{}, false, listErr
		}
		return BlockVolume{}, false, &InvalidOperationError{Message: "OCI volume read was denied for a listed resource"}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = ReadBoundedBody(resp, 64<<10)
		return BlockVolume{}, false, &InvalidOperationError{Message: "OCI volume read failed"}
	}
	body, err := ReadBoundedBody(resp, a.Core.Config.MaxBodyBytes)
	if err != nil {
		return BlockVolume{}, false, err
	}
	var item ociAutomatedVolume
	etag, headerErr := canonicalOCIETag(resp)
	if json.Unmarshal(body, &item) != nil || item.ID != id || headerErr != nil {
		return BlockVolume{}, false, &InvalidDataError{Message: "OCI volume response is invalid"}
	}
	item.ETag = etag
	volume, err := blockVolumeFromOCI(item, "")
	if err == nil && compartment != "" && volume.CompartmentID != compartment {
		return BlockVolume{}, false, &InvalidDataError{Message: "OCI volume response is outside the requested compartment"}
	}
	if err == nil && request != nil && !volumeMatchesCreateRequest(item, *request) {
		return BlockVolume{}, false, &InvalidDataError{Message: "OCI volume response does not match its durable intent"}
	}
	return volume, err == nil, err
}

func (a *OCIBlockStorageAdapter) volumeExistsInCompartment(ctx context.Context, id, compartment string) (bool, error) {
	if !isOCID(id, "volume") || !isOCID(compartment, "compartment") {
		return false, &errs.Argument{Message: "block volume absence scope is invalid"}
	}
	items, err := a.listVolumes(ctx, url.Values{"compartmentId": {compartment}, "limit": {strconv.Itoa(maximumOCIListResults)}})
	if err != nil {
		return false, err
	}
	for _, item := range items {
		if item.ID == id {
			return true, nil
		}
	}
	return false, nil
}

func volumeDeleteBinding(request VolumeDeleteRequest) any {
	return struct{ VolumeID, IfMatch string }{request.VolumeID, request.IfMatch}
}

func VolumeDeleteMutationFingerprint(request VolumeDeleteRequest) string {
	return fingerprintJSON("volume.delete", volumeDeleteBinding(request))
}

func VolumeDeleteMutationScope(request VolumeDeleteRequest) string {
	return ProviderMutationScope("volume", request.VolumeID)
}

func (a *OCIBlockStorageAdapter) DeleteVolume(ctx context.Context, request VolumeDeleteRequest) error {
	if a == nil || validateOCIAdapter(a.Core, OCIServiceCore, a.Journal) != nil {
		return &InvalidOperationError{Message: "OCI block storage adapter is unavailable"}
	}
	if !isOCID(request.VolumeID, "volume") || !isSafeETag(request.IfMatch) {
		return &errs.Argument{Message: "volume delete fence is invalid"}
	}
	compartment, err := ownedResourceCompartment(ctx, a.Ownership, request.VolumeID, "")
	if err != nil {
		return err
	}
	if err := expectJSONMutation(request.Mutation, "volume.delete", VolumeDeleteMutationScope(request), volumeDeleteBinding(request)); err != nil {
		return err
	}
	record, err := prepareMutation(ctx, a.Journal, request.Mutation)
	if err != nil {
		return err
	}
	if _, done, err := completedMutation(record); done {
		return err
	}
	if (record.State == MutationSubmitted || record.State == MutationUnknown) && validWorkRequestID(record.Result.WorkRequestID) {
		return finishAsyncMutation(ctx, a.Journal, request.Mutation, record.Result, a.work, a.waitPolicy)
	}
	_, found, err := a.getBlockVolumeInCompartment(ctx, request.VolumeID, compartment, nil)
	if err != nil {
		return err
	}
	baseResult := ProviderMutationResult{ResourceID: request.VolumeID, ETag: request.IfMatch}
	if !found {
		if record.Result != (ProviderMutationResult{}) {
			baseResult = record.Result
		}
		return markSucceeded(ctx, a.Journal, request.Mutation, baseResult)
	}
	if record.State == MutationSubmitted || record.State == MutationUnknown {
		if record.Result != (ProviderMutationResult{}) {
			baseResult = record.Result
		}
		return finishUnknownWithResult(ctx, a.Journal, request.Mutation, baseResult)
	}
	if _, err := a.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
		return err
	}
	resp, err := a.Core.DoWithHeaders(ctx, http.MethodDelete, "/20160918/volumes/"+url.PathEscape(request.VolumeID), nil, map[string]string{"If-Match": request.IfMatch})
	if err != nil {
		if indeterminate(err) {
			if exists, readErr := a.volumeExistsInCompartment(ctx, request.VolumeID, compartment); readErr == nil && !exists {
				return markSucceeded(ctx, a.Journal, request.Mutation, baseResult)
			}
			return finishUnknownWithResult(ctx, a.Journal, request.Mutation, baseResult)
		}
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		_, _ = ReadBoundedBody(resp, 64<<10)
		exists, readErr := a.volumeExistsInCompartment(ctx, request.VolumeID, compartment)
		if readErr != nil {
			return finishUnknownWithResult(ctx, a.Journal, request.Mutation, baseResult)
		}
		if !exists {
			return markSucceeded(ctx, a.Journal, request.Mutation, baseResult)
		}
		return knownFailure(ctx, a.Journal, request.Mutation, "provider-not-authorized")
	}
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		_, _ = ReadBoundedBody(resp, 64<<10)
		work, workErr := optionalOCIWorkRequestID(resp)
		result := baseResult
		result.WorkRequestID = work
		if workErr != nil {
			return finishUnknownWithResult(ctx, a.Journal, request.Mutation, baseResult)
		}
		if work != "" {
			return finishAsyncMutation(ctx, a.Journal, request.Mutation, result, a.work, a.waitPolicy)
		}
		exists, readErr := a.volumeExistsInCompartment(ctx, request.VolumeID, compartment)
		if readErr != nil || exists {
			return finishUnknownWithResult(ctx, a.Journal, request.Mutation, result)
		}
		return markSucceeded(ctx, a.Journal, request.Mutation, result)
	}
	return ociMutationFailure(ctx, a.Journal, request.Mutation, resp)
}

type OCIVolumeAttachmentAdapter struct {
	Core         *OCIHTTPTransport
	Journal      ProviderMutationJournal
	Ownership    DurableOwnershipEvidence
	WorkRequests WorkRequestProvider
}

func NewOCIVolumeAttachmentAdapter(core *OCIHTTPTransport, journal ProviderMutationJournal, workRequests ...WorkRequestProvider) (*OCIVolumeAttachmentAdapter, error) {
	if err := validateOCIAdapter(core, OCIServiceCore, journal); err != nil {
		return nil, err
	}
	if len(workRequests) > 1 {
		return nil, &errs.Argument{Message: "OCI volume attachment adapter accepts at most one work request provider"}
	}
	var provider WorkRequestProvider
	if len(workRequests) == 1 {
		provider = workRequests[0]
	}
	return &OCIVolumeAttachmentAdapter{Core: core, Journal: journal, WorkRequests: provider}, nil
}

func volumeAttachBinding(request VolumeAttachRequest) any {
	return struct {
		CompartmentID, InstanceID, VolumeID, DisplayName string
		ReadOnly                                         bool
	}{request.CompartmentID, request.InstanceID, request.VolumeID, request.DisplayName, request.ReadOnly}
}

func VolumeAttachMutationFingerprint(request VolumeAttachRequest) string {
	return fingerprintJSON("attachment.create", volumeAttachBinding(request))
}

func VolumeAttachMutationScope(request VolumeAttachRequest) string {
	return ProviderMutationScope("attachment", request.VolumeID, request.InstanceID)
}

type ociAutomatedAttachment struct {
	ID             string          `json:"id"`
	CompartmentID  string          `json:"compartmentId"`
	InstanceID     string          `json:"instanceId"`
	VolumeID       string          `json:"volumeId"`
	DisplayName    string          `json:"displayName"`
	IsReadOnly     requiredOCIBool `json:"isReadOnly"`
	LifecycleState string          `json:"lifecycleState"`
	ETag           string          `json:"-"`
}

type requiredOCIBool struct {
	value bool
	set   bool
}

func (value *requiredOCIBool) UnmarshalJSON(raw []byte) error {
	if value == nil || value.set {
		return &InvalidDataError{Message: "OCI response contains a duplicate required boolean"}
	}
	value.set = true
	switch string(bytes.TrimSpace(raw)) {
	case "false":
		value.value = false
	case "true":
		value.value = true
	default:
		return &InvalidDataError{Message: "OCI response required boolean is invalid"}
	}
	return nil
}

func attachmentFromOCI(item ociAutomatedAttachment, work string) (VolumeAttachment, error) {
	if !isOCID(item.ID, "volumeattachment") || !isOCID(item.CompartmentID, "compartment") || !isOCID(item.InstanceID, "instance") || !isOCID(item.VolumeID, "volume") ||
		!item.IsReadOnly.set || !validCanonicalETag(item.ETag) || (work != "" && !validWorkRequestID(work)) {
		return VolumeAttachment{}, &InvalidDataError{Message: "OCI volume attachment response is invalid"}
	}
	return VolumeAttachment{ID: item.ID, CompartmentID: item.CompartmentID, InstanceID: item.InstanceID, VolumeID: item.VolumeID, LifecycleState: item.LifecycleState, ETag: item.ETag, WorkRequestID: work}, nil
}

func attachmentMatchesCreateRequest(item ociAutomatedAttachment, request VolumeAttachRequest) bool {
	return item.CompartmentID == request.CompartmentID && item.InstanceID == request.InstanceID && item.VolumeID == request.VolumeID &&
		item.DisplayName == request.DisplayName && item.IsReadOnly.set && item.IsReadOnly.value == request.ReadOnly
}

func (a *OCIVolumeAttachmentAdapter) AttachVolume(ctx context.Context, request VolumeAttachRequest) (VolumeAttachment, error) {
	if a == nil || validateOCIAdapter(a.Core, OCIServiceCore, a.Journal) != nil {
		return VolumeAttachment{}, &InvalidOperationError{Message: "OCI volume attachment adapter is unavailable"}
	}
	if !isOCID(request.CompartmentID, "compartment") || !isOCID(request.InstanceID, "instance") || !isOCID(request.VolumeID, "volume") {
		return VolumeAttachment{}, &errs.Argument{Message: "volume attachment identity is invalid"}
	}
	if err := requireOwnedResource(ctx, a.Ownership, request.InstanceID, request.CompartmentID); err != nil {
		return VolumeAttachment{}, err
	}
	if err := requireOwnedResource(ctx, a.Ownership, request.VolumeID, request.CompartmentID); err != nil {
		return VolumeAttachment{}, err
	}
	if err := validateBoundedName(request.DisplayName, "volume attachment display name", 128); err != nil {
		return VolumeAttachment{}, err
	}
	if err := expectJSONMutation(request.Mutation, "attachment.create", VolumeAttachMutationScope(request), volumeAttachBinding(request)); err != nil {
		return VolumeAttachment{}, err
	}
	record, err := prepareMutation(ctx, a.Journal, request.Mutation)
	if err != nil {
		return VolumeAttachment{}, err
	}
	if result, done, err := completedMutation(record); done {
		if err != nil {
			return VolumeAttachment{}, err
		}
		return mutationResultAttachment(result)
	}
	if record.State == MutationSubmitted || record.State == MutationUnknown {
		return a.resumeAttachmentCreate(ctx, request, record)
	}
	payload := struct {
		Type          string `json:"type"`
		CompartmentID string `json:"compartmentId"`
		InstanceID    string `json:"instanceId"`
		VolumeID      string `json:"volumeId"`
		DisplayName   string `json:"displayName"`
		IsReadOnly    bool   `json:"isReadOnly"`
	}{"iscsi", request.CompartmentID, request.InstanceID, request.VolumeID, request.DisplayName, request.ReadOnly}
	if _, err := a.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
		return VolumeAttachment{}, err
	}
	resp, err := a.Core.DoWithHeaders(ctx, http.MethodPost, "/20160918/volumeAttachments", bytes.NewReader(mustJSON(payload)), map[string]string{"opc-retry-token": derivedRetryToken(request.Mutation, "attachment")})
	if err != nil {
		if indeterminate(err) {
			return VolumeAttachment{}, finishUnknown(ctx, a.Journal, request.Mutation)
		}
		return VolumeAttachment{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return VolumeAttachment{}, ociMutationFailure(ctx, a.Journal, request.Mutation, resp)
	}
	work, workErr := optionalOCIWorkRequestID(resp)
	etag, etagErr := canonicalOCIETag(resp)
	headerResult := ProviderMutationResult{}
	if workErr == nil {
		headerResult.WorkRequestID = work
	}
	if etagErr == nil {
		headerResult.ETag = etag
	}
	body, err := ReadBoundedBody(resp, a.Core.Config.MaxBodyBytes)
	if err != nil {
		return VolumeAttachment{}, finishUnboundMutationResult(ctx, a.Journal, request.Mutation, headerResult, a.work, a.waitPolicy)
	}
	var item ociAutomatedAttachment
	if json.Unmarshal(body, &item) != nil {
		return VolumeAttachment{}, finishUnboundMutationResult(ctx, a.Journal, request.Mutation, headerResult, a.work, a.waitPolicy)
	}
	if workErr != nil || etagErr != nil {
		result := headerResult
		if isOCID(item.ID, "volumeattachment") && attachmentMatchesCreateRequest(item, request) {
			result.ResourceID = item.ID
		}
		return VolumeAttachment{}, finishUnboundMutationResult(ctx, a.Journal, request.Mutation, result, a.work, a.waitPolicy)
	}
	item.ETag = etag
	attachment, err := attachmentFromOCI(item, work)
	if err != nil || !attachmentMatchesCreateRequest(item, request) {
		result := ProviderMutationResult{WorkRequestID: work}
		if isOCID(item.ID, "volumeattachment") {
			result.ResourceID = item.ID
			result.ETag = etag
		}
		return VolumeAttachment{}, finishUnboundMutationResult(ctx, a.Journal, request.Mutation, result, a.work, a.waitPolicy)
	}
	if attachment.CompartmentID != request.CompartmentID || attachment.InstanceID != request.InstanceID || attachment.VolumeID != request.VolumeID {
		return VolumeAttachment{}, finishUnknown(ctx, a.Journal, request.Mutation)
	}
	if err := finalizeOCIWorkRequest(ctx, a.WorkRequests, a.Journal, request.Mutation, attachment.WorkRequestID); err != nil {
		return VolumeAttachment{}, err
	}
	if err := markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: attachment.ID, ETag: attachment.ETag, WorkRequestID: attachment.WorkRequestID}); err != nil {
		return VolumeAttachment{}, err
	}
	return attachment, nil
}

func (a *OCIVolumeAttachmentAdapter) resumeAttachmentCreate(ctx context.Context, request VolumeAttachRequest, record ProviderMutationRecord) (VolumeAttachment, error) {
	prior := record.Result
	workSucceeded := false
	if validWorkRequestID(prior.WorkRequestID) {
		if _, err := observeAsyncMutation(ctx, a.Journal, request.Mutation, prior, a.work, a.waitPolicy); err != nil {
			return VolumeAttachment{}, err
		}
		workSucceeded = true
	}
	var attachment VolumeAttachment
	var found bool
	var err error
	if prior.ResourceID != "" {
		attachment, found, err = a.getVolumeAttachmentInCompartment(ctx, prior.ResourceID, request.CompartmentID, &request)
	} else {
		attachment, found, err = a.findAttachment(ctx, request)
	}
	if err != nil {
		return VolumeAttachment{}, err
	}
	if !found {
		return VolumeAttachment{}, &ProviderOutcomeUnknownError{Message: "OCI attachment create result is not authoritatively visible"}
	}
	result := ProviderMutationResult{ResourceID: attachment.ID, ETag: attachment.ETag, WorkRequestID: prior.WorkRequestID}
	if prior.ResourceID != "" && prior.ResourceID != attachment.ID {
		return VolumeAttachment{}, &ProviderOutcomeUnknownError{Message: "OCI attachment create result identity changed"}
	}
	if workSucceeded && prior.ResourceID == attachment.ID && validCanonicalETag(prior.ETag) {
		result.ETag = prior.ETag
	}
	if err := markSucceeded(ctx, a.Journal, request.Mutation, result); err != nil {
		return VolumeAttachment{}, err
	}
	attachment.ETag = result.ETag
	attachment.WorkRequestID = result.WorkRequestID
	return attachment, nil
}

func (a *OCIVolumeAttachmentAdapter) findAttachment(ctx context.Context, request VolumeAttachRequest) (VolumeAttachment, bool, error) {
	query := url.Values{"compartmentId": {request.CompartmentID}, "instanceId": {request.InstanceID}, "volumeId": {request.VolumeID}, "limit": {strconv.Itoa(maximumOCIListResults)}}
	list, err := a.listAttachments(ctx, query)
	if err != nil {
		return VolumeAttachment{}, false, err
	}
	if len(list) == 0 {
		return VolumeAttachment{}, false, nil
	}
	if len(list) != 1 {
		return VolumeAttachment{}, false, &InvalidOperationError{Message: "OCI attachment reconciliation found duplicate results"}
	}
	if !attachmentMatchesCreateRequest(list[0], request) {
		return VolumeAttachment{}, false, &InvalidDataError{Message: "OCI attachment reconciliation result does not match its durable intent"}
	}
	return a.getVolumeAttachmentInCompartment(ctx, list[0].ID, request.CompartmentID, &request)
}

func (a *OCIVolumeAttachmentAdapter) listAttachments(ctx context.Context, query url.Values) ([]ociAutomatedAttachment, error) {
	items := make([]ociAutomatedAttachment, 0)
	seenPages := make(map[string]struct{}, maximumOCIPages-1)
	for page, pagesRead := "", 1; ; pagesRead++ {
		resp, err := a.Core.Do(ctx, http.MethodGet, "/20160918/volumeAttachments?"+cloneOCIQuery(query, page), nil)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_, _ = ReadBoundedBody(resp, 64<<10)
			return nil, &InvalidOperationError{Message: "OCI attachment reconciliation failed"}
		}
		body, err := ReadBoundedBody(resp, a.Core.Config.MaxBodyBytes)
		if err != nil {
			return nil, err
		}
		pageItems, err := decodeOCIList[ociAutomatedAttachment](body)
		if err != nil || len(pageItems) > maximumOCIListResults || len(items)+len(pageItems) > maximumOCIListResults*maximumOCIPages {
			return nil, &InvalidDataError{Message: "OCI attachment reconciliation response is invalid"}
		}
		compartment, instance, volume := query.Get("compartmentId"), query.Get("instanceId"), query.Get("volumeId")
		for _, item := range pageItems {
			if !isOCID(item.ID, "volumeattachment") || item.CompartmentID != compartment || !isOCID(item.InstanceID, "instance") ||
				!isOCID(item.VolumeID, "volume") || (instance != "" && item.InstanceID != instance) || (volume != "" && item.VolumeID != volume) {
				return nil, &InvalidDataError{Message: "OCI attachment reconciliation response is outside the requested scope"}
			}
		}
		items = append(items, pageItems...)
		next, err := nextOCIPage(resp, seenPages, pagesRead)
		if err != nil {
			return nil, err
		}
		if next == "" {
			return items, nil
		}
		page = next
	}
}

func (a *OCIVolumeAttachmentAdapter) GetVolumeAttachment(ctx context.Context, id string) (VolumeAttachment, bool, error) {
	if a == nil || a.Core == nil {
		return VolumeAttachment{}, false, &InvalidOperationError{Message: "OCI volume attachment adapter is unavailable"}
	}
	if !isOCID(id, "volumeattachment") {
		return VolumeAttachment{}, false, &errs.Argument{Message: "volume attachment identity is invalid"}
	}
	compartment, err := ownedResourceCompartment(ctx, a.Ownership, id, "")
	if err != nil {
		return VolumeAttachment{}, false, err
	}
	return a.getVolumeAttachmentInCompartment(ctx, id, compartment, nil)
}

func (a *OCIVolumeAttachmentAdapter) getVolumeAttachmentInCompartment(ctx context.Context, id, compartment string, request *VolumeAttachRequest) (VolumeAttachment, bool, error) {
	if a == nil || a.Core == nil || !isOCID(id, "volumeattachment") {
		return VolumeAttachment{}, false, &errs.Argument{Message: "volume attachment identity is invalid"}
	}
	resp, err := a.Core.Do(ctx, http.MethodGet, "/20160918/volumeAttachments/"+url.PathEscape(id), nil)
	if err != nil {
		return VolumeAttachment{}, false, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_, _ = ReadBoundedBody(resp, 64<<10)
		if compartment == "" {
			return VolumeAttachment{}, false, nil
		}
		exists, listErr := a.attachmentExistsInCompartment(ctx, id, compartment)
		if listErr != nil || !exists {
			return VolumeAttachment{}, false, listErr
		}
		return VolumeAttachment{}, false, &InvalidOperationError{Message: "OCI attachment read was denied for a listed resource"}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = ReadBoundedBody(resp, 64<<10)
		return VolumeAttachment{}, false, &InvalidOperationError{Message: "OCI attachment read failed"}
	}
	body, err := ReadBoundedBody(resp, a.Core.Config.MaxBodyBytes)
	if err != nil {
		return VolumeAttachment{}, false, err
	}
	var item ociAutomatedAttachment
	etag, headerErr := canonicalOCIETag(resp)
	if json.Unmarshal(body, &item) != nil || item.ID != id || headerErr != nil {
		return VolumeAttachment{}, false, &InvalidDataError{Message: "OCI attachment response is invalid"}
	}
	item.ETag = etag
	attachment, err := attachmentFromOCI(item, "")
	if err == nil && compartment != "" && attachment.CompartmentID != compartment {
		return VolumeAttachment{}, false, &InvalidDataError{Message: "OCI attachment response is outside the requested compartment"}
	}
	if err == nil && request != nil && !attachmentMatchesCreateRequest(item, *request) {
		return VolumeAttachment{}, false, &InvalidDataError{Message: "OCI attachment response does not match its durable intent"}
	}
	return attachment, err == nil, err
}

func (a *OCIVolumeAttachmentAdapter) attachmentExistsInCompartment(ctx context.Context, id, compartment string) (bool, error) {
	if !isOCID(id, "volumeattachment") || !isOCID(compartment, "compartment") {
		return false, &errs.Argument{Message: "volume attachment absence scope is invalid"}
	}
	items, err := a.listAttachments(ctx, url.Values{"compartmentId": {compartment}, "limit": {strconv.Itoa(maximumOCIListResults)}})
	if err != nil {
		return false, err
	}
	for _, item := range items {
		if item.ID == id {
			return true, nil
		}
	}
	return false, nil
}

func volumeDetachBinding(request VolumeDetachRequest) any {
	return struct{ AttachmentID, IfMatch string }{request.AttachmentID, request.IfMatch}
}

func VolumeDetachMutationFingerprint(request VolumeDetachRequest) string {
	return fingerprintJSON("attachment.delete", volumeDetachBinding(request))
}

func VolumeDetachMutationScope(request VolumeDetachRequest) string {
	return ProviderMutationScope("attachment", request.AttachmentID)
}

func (a *OCIVolumeAttachmentAdapter) DetachVolume(ctx context.Context, request VolumeDetachRequest) error {
	if a == nil || validateOCIAdapter(a.Core, OCIServiceCore, a.Journal) != nil {
		return &InvalidOperationError{Message: "OCI volume attachment adapter is unavailable"}
	}
	if !isOCID(request.AttachmentID, "volumeattachment") || !isSafeETag(request.IfMatch) {
		return &errs.Argument{Message: "volume detach fence is invalid"}
	}
	compartment, err := ownedResourceCompartment(ctx, a.Ownership, request.AttachmentID, "")
	if err != nil {
		return err
	}
	if err := expectJSONMutation(request.Mutation, "attachment.delete", VolumeDetachMutationScope(request), volumeDetachBinding(request)); err != nil {
		return err
	}
	record, err := prepareMutation(ctx, a.Journal, request.Mutation)
	if err != nil {
		return err
	}
	if _, done, err := completedMutation(record); done {
		return err
	}
	if (record.State == MutationSubmitted || record.State == MutationUnknown) && validWorkRequestID(record.Result.WorkRequestID) {
		return finishAsyncMutation(ctx, a.Journal, request.Mutation, record.Result, a.work, a.waitPolicy)
	}
	_, found, err := a.getVolumeAttachmentInCompartment(ctx, request.AttachmentID, compartment, nil)
	if err != nil {
		return err
	}
	baseResult := ProviderMutationResult{ResourceID: request.AttachmentID, ETag: request.IfMatch}
	if !found {
		if record.Result != (ProviderMutationResult{}) {
			baseResult = record.Result
		}
		return markSucceeded(ctx, a.Journal, request.Mutation, baseResult)
	}
	if record.State == MutationSubmitted || record.State == MutationUnknown {
		if record.Result != (ProviderMutationResult{}) {
			baseResult = record.Result
		}
		return finishUnknownWithResult(ctx, a.Journal, request.Mutation, baseResult)
	}
	if _, err := a.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
		return err
	}
	resp, err := a.Core.DoWithHeaders(ctx, http.MethodDelete, "/20160918/volumeAttachments/"+url.PathEscape(request.AttachmentID), nil, map[string]string{"If-Match": request.IfMatch})
	if err != nil {
		if indeterminate(err) {
			if exists, readErr := a.attachmentExistsInCompartment(ctx, request.AttachmentID, compartment); readErr == nil && !exists {
				return markSucceeded(ctx, a.Journal, request.Mutation, baseResult)
			}
			return finishUnknownWithResult(ctx, a.Journal, request.Mutation, baseResult)
		}
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		_, _ = ReadBoundedBody(resp, 64<<10)
		exists, readErr := a.attachmentExistsInCompartment(ctx, request.AttachmentID, compartment)
		if readErr != nil {
			return finishUnknownWithResult(ctx, a.Journal, request.Mutation, baseResult)
		}
		if !exists {
			return markSucceeded(ctx, a.Journal, request.Mutation, baseResult)
		}
		return knownFailure(ctx, a.Journal, request.Mutation, "provider-not-authorized")
	}
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		_, _ = ReadBoundedBody(resp, 64<<10)
		work, workErr := optionalOCIWorkRequestID(resp)
		result := baseResult
		result.WorkRequestID = work
		if workErr != nil {
			return finishUnknownWithResult(ctx, a.Journal, request.Mutation, baseResult)
		}
		if work != "" {
			return finishAsyncMutation(ctx, a.Journal, request.Mutation, result, a.work, a.waitPolicy)
		}
		exists, readErr := a.attachmentExistsInCompartment(ctx, request.AttachmentID, compartment)
		if readErr != nil || exists {
			return finishUnknownWithResult(ctx, a.Journal, request.Mutation, result)
		}
		return markSucceeded(ctx, a.Journal, request.Mutation, result)
	}
	return ociMutationFailure(ctx, a.Journal, request.Mutation, resp)
}

var (
	_ BlockVolumeProvider      = (*OCIBlockStorageAdapter)(nil)
	_ VolumeAttachmentProvider = (*OCIVolumeAttachmentAdapter)(nil)
)
