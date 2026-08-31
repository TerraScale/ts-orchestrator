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
	Core      *OCIHTTPTransport
	Journal   ProviderMutationJournal
	Ownership DurableOwnershipEvidence
}

func NewOCIBlockStorageAdapter(core *OCIHTTPTransport, journal ProviderMutationJournal) (*OCIBlockStorageAdapter, error) {
	if err := validateOCIAdapter(core, OCIServiceCore, journal); err != nil {
		return nil, err
	}
	return &OCIBlockStorageAdapter{Core: core, Journal: journal}, nil
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
	ID             string            `json:"id"`
	CompartmentID  string            `json:"compartmentId"`
	LifecycleState string            `json:"lifecycleState"`
	SizeGiB        uint64            `json:"sizeInGBs"`
	VPUsPerGiB     uint64            `json:"vpusPerGB"`
	ETag           string            `json:"etag"`
	FreeformTags   map[string]string `json:"freeformTags"`
}

func blockVolumeFromOCI(item ociAutomatedVolume, work string) (BlockVolume, error) {
	if !isOCID(item.ID, "volume") || !isOCID(item.CompartmentID, "compartment") || item.SizeGiB == 0 {
		return BlockVolume{}, &InvalidDataError{Message: "OCI block volume response is invalid"}
	}
	return BlockVolume{ID: item.ID, CompartmentID: item.CompartmentID, LifecycleState: item.LifecycleState, SizeGiB: item.SizeGiB, VPUsPerGiB: item.VPUsPerGiB, ETag: item.ETag, WorkRequestID: work}, nil
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
		volume, found, err := a.findVolumeForIntent(ctx, request)
		if err != nil {
			return BlockVolume{}, err
		}
		if !found {
			return BlockVolume{}, &ProviderOutcomeUnknownError{}
		}
		result := ProviderMutationResult{ResourceID: volume.ID, ETag: volume.ETag, WorkRequestID: volume.WorkRequestID}
		if err := markSucceeded(ctx, a.Journal, request.Mutation, result); err != nil {
			return BlockVolume{}, err
		}
		return volume, nil
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
	body, err := ReadBoundedBody(resp, a.Core.Config.MaxBodyBytes)
	if err != nil {
		return BlockVolume{}, finishUnknown(ctx, a.Journal, request.Mutation)
	}
	var item ociAutomatedVolume
	if json.Unmarshal(body, &item) != nil {
		return BlockVolume{}, finishUnknown(ctx, a.Journal, request.Mutation)
	}
	if item.ETag == "" {
		item.ETag = safeHeader(resp, "etag")
	}
	volume, err := blockVolumeFromOCI(item, safeHeader(resp, "opc-work-request-id"))
	if err != nil {
		return BlockVolume{}, finishUnknown(ctx, a.Journal, request.Mutation)
	}
	if err := markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: volume.ID, ETag: volume.ETag, WorkRequestID: volume.WorkRequestID}); err != nil {
		return BlockVolume{}, err
	}
	return volume, nil
}

func (a *OCIBlockStorageAdapter) findVolumeForIntent(ctx context.Context, request VolumeCreateRequest) (BlockVolume, bool, error) {
	query := url.Values{"compartmentId": {request.CompartmentID}, "limit": {strconv.Itoa(maximumOCIListResults)}}
	resp, err := a.Core.Do(ctx, http.MethodGet, "/20160918/volumes?"+query.Encode(), nil)
	if err != nil {
		return BlockVolume{}, false, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = ReadBoundedBody(resp, 64<<10)
		return BlockVolume{}, false, &InvalidOperationError{Message: "OCI volume reconciliation failed"}
	}
	body, err := ReadBoundedBody(resp, a.Core.Config.MaxBodyBytes)
	if err != nil {
		return BlockVolume{}, false, err
	}
	items, err := decodeOCIList[ociAutomatedVolume](body)
	if err != nil || len(items) > maximumOCIListResults {
		return BlockVolume{}, false, &InvalidDataError{Message: "OCI volume reconciliation response is invalid"}
	}
	var match *ociAutomatedVolume
	for index := range items {
		item := &items[index]
		if item.FreeformTags["terrascale-operation"] == request.Mutation.OperationID.Value && item.FreeformTags["terrascale-intent"] == request.Mutation.Fingerprint {
			if match != nil {
				return BlockVolume{}, false, &InvalidOperationError{Message: "OCI volume reconciliation found duplicate intent results"}
			}
			match = item
		}
	}
	if match == nil {
		return BlockVolume{}, false, nil
	}
	volume, err := blockVolumeFromOCI(*match, "")
	return volume, err == nil, err
}

func (a *OCIBlockStorageAdapter) GetBlockVolume(ctx context.Context, id string) (BlockVolume, bool, error) {
	if a == nil || a.Core == nil || !isOCID(id, "volume") {
		return BlockVolume{}, false, &errs.Argument{Message: "block volume identity is invalid"}
	}
	resp, err := a.Core.Do(ctx, http.MethodGet, "/20160918/volumes/"+url.PathEscape(id), nil)
	if err != nil {
		return BlockVolume{}, false, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_, _ = ReadBoundedBody(resp, 64<<10)
		return BlockVolume{}, false, nil
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
	if json.Unmarshal(body, &item) != nil || item.ID != id {
		return BlockVolume{}, false, &InvalidDataError{Message: "OCI volume response is invalid"}
	}
	volume, err := blockVolumeFromOCI(item, "")
	return volume, err == nil, err
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
	if err := requireOwnedResource(ctx, a.Ownership, request.VolumeID, ""); err != nil {
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
	_, found, err := a.GetBlockVolume(ctx, request.VolumeID)
	if err != nil {
		return err
	}
	if !found {
		return markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: request.VolumeID, ETag: request.IfMatch})
	}
	if record.State == MutationUnknown {
		return &ProviderOutcomeUnknownError{}
	}
	if _, err := a.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
		return err
	}
	resp, err := a.Core.DoWithHeaders(ctx, http.MethodDelete, "/20160918/volumes/"+url.PathEscape(request.VolumeID), nil, map[string]string{"If-Match": request.IfMatch})
	if err != nil {
		if indeterminate(err) {
			if _, found, readErr := a.GetBlockVolume(ctx, request.VolumeID); readErr == nil && !found {
				return markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: request.VolumeID, ETag: request.IfMatch})
			}
			return finishUnknown(ctx, a.Journal, request.Mutation)
		}
		return err
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		_, _ = ReadBoundedBody(resp, 64<<10)
		return markSucceeded(ctx, a.Journal, request.Mutation, mutationResultFromHeaders(resp, request.VolumeID, request.IfMatch))
	}
	return ociMutationFailure(ctx, a.Journal, request.Mutation, resp)
}

type OCIVolumeAttachmentAdapter struct {
	Core      *OCIHTTPTransport
	Journal   ProviderMutationJournal
	Ownership DurableOwnershipEvidence
}

func NewOCIVolumeAttachmentAdapter(core *OCIHTTPTransport, journal ProviderMutationJournal) (*OCIVolumeAttachmentAdapter, error) {
	if err := validateOCIAdapter(core, OCIServiceCore, journal); err != nil {
		return nil, err
	}
	return &OCIVolumeAttachmentAdapter{Core: core, Journal: journal}, nil
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
	ID             string `json:"id"`
	CompartmentID  string `json:"compartmentId"`
	InstanceID     string `json:"instanceId"`
	VolumeID       string `json:"volumeId"`
	LifecycleState string `json:"lifecycleState"`
	ETag           string `json:"etag"`
}

func attachmentFromOCI(item ociAutomatedAttachment, work string) (VolumeAttachment, error) {
	if !isOCID(item.ID, "volumeattachment") || !isOCID(item.CompartmentID, "compartment") || !isOCID(item.InstanceID, "instance") || !isOCID(item.VolumeID, "volume") {
		return VolumeAttachment{}, &InvalidDataError{Message: "OCI volume attachment response is invalid"}
	}
	return VolumeAttachment{ID: item.ID, CompartmentID: item.CompartmentID, InstanceID: item.InstanceID, VolumeID: item.VolumeID, LifecycleState: item.LifecycleState, ETag: item.ETag, WorkRequestID: work}, nil
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
		attachment, found, err := a.findAttachment(ctx, request)
		if err != nil {
			return VolumeAttachment{}, err
		}
		if !found {
			return VolumeAttachment{}, &ProviderOutcomeUnknownError{}
		}
		if err := markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: attachment.ID, ETag: attachment.ETag, WorkRequestID: attachment.WorkRequestID}); err != nil {
			return VolumeAttachment{}, err
		}
		return attachment, nil
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
	body, err := ReadBoundedBody(resp, a.Core.Config.MaxBodyBytes)
	if err != nil {
		return VolumeAttachment{}, finishUnknown(ctx, a.Journal, request.Mutation)
	}
	var item ociAutomatedAttachment
	if json.Unmarshal(body, &item) != nil {
		return VolumeAttachment{}, finishUnknown(ctx, a.Journal, request.Mutation)
	}
	if item.ETag == "" {
		item.ETag = safeHeader(resp, "etag")
	}
	attachment, err := attachmentFromOCI(item, safeHeader(resp, "opc-work-request-id"))
	if err != nil {
		return VolumeAttachment{}, finishUnknown(ctx, a.Journal, request.Mutation)
	}
	if err := markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: attachment.ID, ETag: attachment.ETag, WorkRequestID: attachment.WorkRequestID}); err != nil {
		return VolumeAttachment{}, err
	}
	return attachment, nil
}

func (a *OCIVolumeAttachmentAdapter) findAttachment(ctx context.Context, request VolumeAttachRequest) (VolumeAttachment, bool, error) {
	query := url.Values{"compartmentId": {request.CompartmentID}, "instanceId": {request.InstanceID}, "volumeId": {request.VolumeID}, "limit": {strconv.Itoa(maximumOCIListResults)}}
	resp, err := a.Core.Do(ctx, http.MethodGet, "/20160918/volumeAttachments?"+query.Encode(), nil)
	if err != nil {
		return VolumeAttachment{}, false, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = ReadBoundedBody(resp, 64<<10)
		return VolumeAttachment{}, false, &InvalidOperationError{Message: "OCI attachment reconciliation failed"}
	}
	body, err := ReadBoundedBody(resp, a.Core.Config.MaxBodyBytes)
	if err != nil {
		return VolumeAttachment{}, false, err
	}
	list, err := decodeOCIList[ociAutomatedAttachment](body)
	if err != nil || len(list) > maximumOCIListResults {
		return VolumeAttachment{}, false, &InvalidDataError{Message: "OCI attachment reconciliation response is invalid"}
	}
	if len(list) == 0 {
		return VolumeAttachment{}, false, nil
	}
	if len(list) != 1 {
		return VolumeAttachment{}, false, &InvalidOperationError{Message: "OCI attachment reconciliation found duplicate results"}
	}
	attachment, err := attachmentFromOCI(list[0], "")
	if err == nil && (attachment.CompartmentID != request.CompartmentID || attachment.InstanceID != request.InstanceID || attachment.VolumeID != request.VolumeID) {
		return VolumeAttachment{}, false, &InvalidDataError{Message: "OCI attachment reconciliation returned a resource outside the requested scope"}
	}
	return attachment, err == nil, err
}

func (a *OCIVolumeAttachmentAdapter) GetVolumeAttachment(ctx context.Context, id string) (VolumeAttachment, bool, error) {
	if a == nil || a.Core == nil || !isOCID(id, "volumeattachment") {
		return VolumeAttachment{}, false, &errs.Argument{Message: "volume attachment identity is invalid"}
	}
	resp, err := a.Core.Do(ctx, http.MethodGet, "/20160918/volumeAttachments/"+url.PathEscape(id), nil)
	if err != nil {
		return VolumeAttachment{}, false, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_, _ = ReadBoundedBody(resp, 64<<10)
		return VolumeAttachment{}, false, nil
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
	if json.Unmarshal(body, &item) != nil || item.ID != id {
		return VolumeAttachment{}, false, &InvalidDataError{Message: "OCI attachment response is invalid"}
	}
	attachment, err := attachmentFromOCI(item, "")
	return attachment, err == nil, err
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
	if err := requireOwnedResource(ctx, a.Ownership, request.AttachmentID, ""); err != nil {
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
	_, found, err := a.GetVolumeAttachment(ctx, request.AttachmentID)
	if err != nil {
		return err
	}
	if !found {
		return markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: request.AttachmentID, ETag: request.IfMatch})
	}
	if record.State == MutationUnknown {
		return &ProviderOutcomeUnknownError{}
	}
	if _, err := a.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
		return err
	}
	resp, err := a.Core.DoWithHeaders(ctx, http.MethodDelete, "/20160918/volumeAttachments/"+url.PathEscape(request.AttachmentID), nil, map[string]string{"If-Match": request.IfMatch})
	if err != nil {
		if indeterminate(err) {
			if _, found, readErr := a.GetVolumeAttachment(ctx, request.AttachmentID); readErr == nil && !found {
				return markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: request.AttachmentID, ETag: request.IfMatch})
			}
			return finishUnknown(ctx, a.Journal, request.Mutation)
		}
		return err
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		_, _ = ReadBoundedBody(resp, 64<<10)
		return markSucceeded(ctx, a.Journal, request.Mutation, mutationResultFromHeaders(resp, request.AttachmentID, request.IfMatch))
	}
	return ociMutationFailure(ctx, a.Journal, request.Mutation, resp)
}

var (
	_ BlockVolumeProvider      = (*OCIBlockStorageAdapter)(nil)
	_ VolumeAttachmentProvider = (*OCIVolumeAttachmentAdapter)(nil)
)
