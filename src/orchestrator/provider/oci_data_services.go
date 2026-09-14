package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

type OCIObjectStorageBinding struct {
	Namespace    string
	LedgerBucket string
	BackupBucket string
	namespace    string
	buckets      map[string]struct{}
}

func NewOCIObjectStorageBinding(namespace, ledgerBucket, backupBucket string) (*OCIObjectStorageBinding, error) {
	if !validObjectPart(namespace, 128, false) || !validObjectPart(ledgerBucket, 256, false) || !validObjectPart(backupBucket, 256, false) || ledgerBucket == backupBucket {
		return nil, &errs.Argument{Message: "OCI Object Storage estate buckets are invalid"}
	}
	return &OCIObjectStorageBinding{
		Namespace: namespace, LedgerBucket: ledgerBucket, BackupBucket: backupBucket,
		namespace: namespace, buckets: map[string]struct{}{ledgerBucket: {}, backupBucket: {}},
	}, nil
}

type OCIObjectStorageAdapter struct {
	ObjectStorage *OCIHTTPTransport
	Journal       ProviderMutationJournal
	Binding       *OCIObjectStorageBinding
}

// OCIObjectStorageScopedAdapter is the production Object Storage seam. It
// requires durable ownership evidence and a request signer before any
// provider call, including reads.
type OCIObjectStorageScopedAdapter struct {
	ObjectStorage *OCIObjectStorageAdapter
	Ownership     DurableOwnershipEvidence
	MaxReadBytes  int64
}

const defaultOCIObjectReadCap int64 = 64 << 20

func NewOCIObjectStorageAdapter(transport *OCIHTTPTransport, journal ProviderMutationJournal) (*OCIObjectStorageAdapter, error) {
	if err := validateOCIAdapter(transport, OCIServiceObjectStorage, journal); err != nil {
		return nil, err
	}
	if transport.Signer == nil {
		return nil, &InvalidOperationError{Message: "OCI Object Storage adapter requires a request signer"}
	}
	return &OCIObjectStorageAdapter{ObjectStorage: transport, Journal: journal}, nil
}

// NewOCIObjectStorageScopedAdapter constructs the ownership-fenced
// production adapter. A nil signer is rejected because Object Storage never
// accepts anonymous control-plane traffic.
func NewOCIObjectStorageScopedAdapter(transport *OCIHTTPTransport, journal ProviderMutationJournal, ownership DurableOwnershipEvidence, maxReadBytes int64) (*OCIObjectStorageScopedAdapter, error) {
	if err := validateOCIAdapter(transport, OCIServiceObjectStorage, journal); err != nil {
		return nil, err
	}
	if transport.Signer == nil {
		return nil, &InvalidOperationError{Message: "OCI Object Storage production adapter requires a request signer"}
	}
	if ownership == nil || !ownership.AuthoritativeDurable() {
		return nil, &InvalidOperationError{Message: "OCI Object Storage production adapter requires authoritative ownership evidence"}
	}
	if maxReadBytes == 0 {
		maxReadBytes = defaultOCIObjectReadCap
	}
	if maxReadBytes < 0 || maxReadBytes > 64<<30 {
		return nil, &errs.ArgumentOutOfRangeError{Param: "maxReadBytes"}
	}
	adapter, err := NewOCIObjectStorageAdapter(transport, journal)
	if err != nil {
		return nil, err
	}
	return &OCIObjectStorageScopedAdapter{ObjectStorage: adapter, Ownership: ownership, MaxReadBytes: maxReadBytes}, nil
}

func objectStorageIdentity(object ObjectRef) string {
	return object.Namespace + "/" + object.Bucket + "/" + object.Name
}

// ObjectStorageResourceID returns the ownership-journal identity for an
// object. Callers must record this identity before using scoped operations.
func ObjectStorageResourceID(object ObjectRef) string {
	return objectStorageIdentity(object)
}

func scopedObjectBinding(compartment string, object ObjectRef) any {
	return struct {
		CompartmentID string
		Object        ObjectRef
	}{compartment, object}
}

func scopedObjectPutBinding(request ObjectPutScopedRequest) any {
	return struct {
		CompartmentID string
		Object        ObjectRef
		SHA256        string
		Size          int
	}{request.CompartmentID, request.Object, request.SHA256, len(request.Content)}
}

func scopedObjectDeleteBinding(request ObjectDeleteScopedRequest) any {
	return struct {
		CompartmentID string
		Object        ObjectRef
		IfMatch       string
	}{request.CompartmentID, request.Object, request.IfMatch}
}

func ObjectHeadMutationFingerprint(request ObjectHeadRequest) string {
	return fingerprintJSON("object.head", scopedObjectBinding(request.CompartmentID, request.Object))
}

func ObjectHeadMutationScope(request ObjectHeadRequest) string {
	return ProviderMutationScope("object-head", request.CompartmentID, request.Object.Namespace, request.Object.Bucket, request.Object.Name)
}

func ObjectGetMutationFingerprint(request ObjectGetRequest) string {
	return fingerprintJSON("object.get", struct {
		CompartmentID string
		Object        ObjectRef
		MaxBytes      int64
	}{request.CompartmentID, request.Object, request.MaxBytes})
}

func ObjectGetMutationScope(request ObjectGetRequest) string {
	return ProviderMutationScope("object-get", request.CompartmentID, request.Object.Namespace, request.Object.Bucket, request.Object.Name)
}

func ObjectPutScopedMutationFingerprint(request ObjectPutScopedRequest) string {
	return fingerprintJSON("object.put", scopedObjectPutBinding(request))
}

func ObjectPutScopedMutationScope(request ObjectPutScopedRequest) string {
	return ProviderMutationScope("object-put", request.CompartmentID, request.Object.Namespace, request.Object.Bucket, request.Object.Name)
}

func ObjectDeleteScopedMutationFingerprint(request ObjectDeleteScopedRequest) string {
	return fingerprintJSON("object.delete", scopedObjectDeleteBinding(request))
}

func ObjectDeleteScopedMutationScope(request ObjectDeleteScopedRequest) string {
	return ProviderMutationScope("object-delete", request.CompartmentID, request.Object.Namespace, request.Object.Bucket, request.Object.Name)
}

func scopedObjectIdentityCheck(compartment string, object ObjectRef) (string, error) {
	if !isOCID(compartment, "compartment") {
		return "", &errs.Argument{Message: "Object Storage compartment is invalid"}
	}
	if err := validateObjectRef(object); err != nil {
		return "", err
	}
	return objectStorageIdentity(object), nil
}

func (a *OCIObjectStorageScopedAdapter) prepare(ctx context.Context, intent ProviderMutationIntent, action, scope string, binding any, object ObjectRef, compartment string) (ProviderMutationRecord, error) {
	if a == nil || a.ObjectStorage == nil || a.ObjectStorage.ObjectStorage == nil || validateOCIAdapter(a.ObjectStorage.ObjectStorage, OCIServiceObjectStorage, a.ObjectStorage.Journal) != nil || a.ObjectStorage.ObjectStorage.Signer == nil {
		return ProviderMutationRecord{}, &InvalidOperationError{Message: "OCI Object Storage production adapter is unavailable"}
	}
	resource, err := scopedObjectIdentityCheck(compartment, object)
	if err != nil {
		return ProviderMutationRecord{}, err
	}
	if err := requireOwnedResource(ctx, a.Ownership, resource, compartment); err != nil {
		return ProviderMutationRecord{}, err
	}
	if err := expectJSONMutation(intent, action, scope, binding); err != nil {
		return ProviderMutationRecord{}, err
	}
	return prepareMutation(ctx, a.ObjectStorage.Journal, intent)
}

func markObjectUnknown(ctx context.Context, journal ProviderMutationJournal, intent ProviderMutationIntent, cause error) error {
	if _, err := journal.MarkUnknown(ctx, intent, ProviderMutationResult{}); err != nil {
		return err
	}
	return cause
}

func (a *OCIObjectStorageScopedAdapter) HeadObjectScoped(ctx context.Context, request ObjectHeadRequest) (ObjectMetadata, bool, error) {
	resource, err := scopedObjectIdentityCheck(request.CompartmentID, request.Object)
	if err != nil {
		return ObjectMetadata{}, false, err
	}
	record, err := a.prepare(ctx, request.Mutation, "object.head", ObjectHeadMutationScope(request), scopedObjectBinding(request.CompartmentID, request.Object), request.Object, request.CompartmentID)
	if err != nil {
		return ObjectMetadata{}, false, err
	}
	if _, done, err := completedMutation(record); done && err != nil {
		return ObjectMetadata{}, false, err
	}
	if record.State == MutationPrepared {
		if _, err := a.ObjectStorage.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
			return ObjectMetadata{}, false, err
		}
	}
	metadata, found, err := a.ObjectStorage.HeadObject(ctx, request.Object)
	if err != nil {
		return ObjectMetadata{}, false, markObjectUnknown(ctx, a.ObjectStorage.Journal, request.Mutation, err)
	}
	result := ProviderMutationResult{ResourceID: resource}
	if found {
		result.ETag = metadata.ETag
	}
	if err := markSucceeded(ctx, a.ObjectStorage.Journal, request.Mutation, result); err != nil {
		return ObjectMetadata{}, false, err
	}
	return metadata, found, nil
}

func (a *OCIObjectStorageScopedAdapter) GetObjectScoped(ctx context.Context, request ObjectGetRequest) (io.ReadCloser, ObjectMetadata, error) {
	if request.MaxBytes <= 0 {
		return nil, ObjectMetadata{}, &errs.ArgumentOutOfRangeError{Param: "maxBytes"}
	}
	if a == nil || request.MaxBytes > a.MaxReadBytes {
		return nil, ObjectMetadata{}, &errs.ArgumentOutOfRangeError{Param: "maxBytes"}
	}
	resource, err := scopedObjectIdentityCheck(request.CompartmentID, request.Object)
	if err != nil {
		return nil, ObjectMetadata{}, err
	}
	record, err := a.prepare(ctx, request.Mutation, "object.get", ObjectGetMutationScope(request), struct {
		CompartmentID string
		Object        ObjectRef
		MaxBytes      int64
	}{request.CompartmentID, request.Object, request.MaxBytes}, request.Object, request.CompartmentID)
	if err != nil {
		return nil, ObjectMetadata{}, err
	}
	if _, done, err := completedMutation(record); done && err != nil {
		return nil, ObjectMetadata{}, err
	}
	if record.State == MutationPrepared {
		if _, err := a.ObjectStorage.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
			return nil, ObjectMetadata{}, err
		}
	}
	reader, metadata, err := a.ObjectStorage.GetObject(ctx, request.Object)
	if err != nil {
		return nil, ObjectMetadata{}, markObjectUnknown(ctx, a.ObjectStorage.Journal, request.Mutation, err)
	}
	if metadata.Size > request.MaxBytes {
		_ = reader.Close()
		return nil, ObjectMetadata{}, markObjectUnknown(ctx, a.ObjectStorage.Journal, request.Mutation, &InvalidDataError{Message: "OCI Object Storage streamed read exceeds limit"})
	}
	return &objectScopedReadCloser{source: reader, ctx: ctx, journal: a.ObjectStorage.Journal, intent: request.Mutation, result: ProviderMutationResult{ResourceID: resource, ETag: metadata.ETag}, maxBytes: request.MaxBytes}, metadata, nil
}

func (a *OCIObjectStorageScopedAdapter) PutObjectScoped(ctx context.Context, request ObjectPutScopedRequest) (ObjectMetadata, error) {
	if a == nil || a.ObjectStorage == nil || a.ObjectStorage.ObjectStorage == nil {
		return ObjectMetadata{}, &InvalidOperationError{Message: "OCI Object Storage production adapter is unavailable"}
	}
	resource, err := scopedObjectIdentityCheck(request.CompartmentID, request.Object)
	if err != nil {
		return ObjectMetadata{}, err
	}
	if len(request.Content) == 0 || int64(len(request.Content)) > a.ObjectStorage.ObjectStorage.Config.MaxBodyBytes || !validSHA256Hex(request.SHA256) || objectSHA256(request.Content) != request.SHA256 {
		return ObjectMetadata{}, &errs.Argument{Message: "object storage content binding is invalid"}
	}
	record, err := a.prepare(ctx, request.Mutation, "object.put", ObjectPutScopedMutationScope(request), scopedObjectPutBinding(request), request.Object, request.CompartmentID)
	if err != nil {
		return ObjectMetadata{}, err
	}
	if result, done, err := completedMutation(record); done {
		if err != nil {
			return ObjectMetadata{}, err
		}
		return ObjectMetadata{ETag: result.ETag, SHA256: request.SHA256, Size: int64(len(request.Content))}, nil
	}
	if record.State == MutationSubmitted || record.State == MutationUnknown {
		metadata, found, headErr := a.ObjectStorage.HeadObject(ctx, request.Object)
		if headErr != nil {
			return ObjectMetadata{}, markObjectUnknown(ctx, a.ObjectStorage.Journal, request.Mutation, headErr)
		}
		if !found || metadata.SHA256 != request.SHA256 || metadata.Size != int64(len(request.Content)) {
			return ObjectMetadata{}, &ProviderOutcomeUnknownError{Message: "scoped Object Storage write requires reconciliation"}
		}
		if err := markSucceeded(ctx, a.ObjectStorage.Journal, request.Mutation, ProviderMutationResult{ResourceID: resource, ETag: metadata.ETag}); err != nil {
			return ObjectMetadata{}, err
		}
		return metadata, nil
	}
	if _, err := a.ObjectStorage.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
		return ObjectMetadata{}, err
	}
	resp, err := a.ObjectStorage.ObjectStorage.DoWithHeaders(ctx, http.MethodPut, objectStoragePath(request.Object), bytes.NewReader(request.Content), map[string]string{"Content-Type": "application/octet-stream", "If-None-Match": "*", "opc-meta-terrascale-sha256": request.SHA256})
	if err != nil {
		if indeterminate(err) {
			return ObjectMetadata{}, finishUnknown(ctx, a.ObjectStorage.Journal, request.Mutation)
		}
		return ObjectMetadata{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusPreconditionFailed {
			drainClose(resp.Body)
			metadata, found, headErr := a.ObjectStorage.HeadObject(ctx, request.Object)
			if headErr == nil && found && metadata.SHA256 == request.SHA256 && metadata.Size == int64(len(request.Content)) {
				if err := markSucceeded(ctx, a.ObjectStorage.Journal, request.Mutation, ProviderMutationResult{ResourceID: resource, ETag: metadata.ETag}); err != nil {
					return ObjectMetadata{}, err
				}
				return metadata, nil
			}
			return ObjectMetadata{}, knownFailure(ctx, a.ObjectStorage.Journal, request.Mutation, "object-conflict")
		}
		return ObjectMetadata{}, ociMutationFailure(ctx, a.ObjectStorage.Journal, request.Mutation, resp)
	}
	drainClose(resp.Body)
	metadata := ObjectMetadata{ETag: safeHeader(resp, "etag"), SHA256: request.SHA256, Size: int64(len(request.Content))}
	if metadata.ETag == "" {
		return ObjectMetadata{}, finishUnknown(ctx, a.ObjectStorage.Journal, request.Mutation)
	}
	if err := markSucceeded(ctx, a.ObjectStorage.Journal, request.Mutation, ProviderMutationResult{ResourceID: resource, ETag: metadata.ETag}); err != nil {
		return ObjectMetadata{}, err
	}
	return metadata, nil
}

func (a *OCIObjectStorageScopedAdapter) DeleteObjectScoped(ctx context.Context, request ObjectDeleteScopedRequest) error {
	resource, err := scopedObjectIdentityCheck(request.CompartmentID, request.Object)
	if err != nil {
		return err
	}
	if !isSafeETag(request.IfMatch) {
		return &errs.Argument{Message: "object delete ETag fence is invalid"}
	}
	record, err := a.prepare(ctx, request.Mutation, "object.delete", ObjectDeleteScopedMutationScope(request), scopedObjectDeleteBinding(request), request.Object, request.CompartmentID)
	if err != nil {
		return err
	}
	if _, done, err := completedMutation(record); done {
		return err
	}
	_, found, err := a.ObjectStorage.HeadObject(ctx, request.Object)
	if err != nil {
		return markObjectUnknown(ctx, a.ObjectStorage.Journal, request.Mutation, err)
	}
	if !found {
		return markSucceeded(ctx, a.ObjectStorage.Journal, request.Mutation, ProviderMutationResult{ResourceID: resource, ETag: request.IfMatch})
	}
	if record.State == MutationUnknown {
		return &ProviderOutcomeUnknownError{}
	}
	if _, err := a.ObjectStorage.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
		return err
	}
	resp, err := a.ObjectStorage.ObjectStorage.DoWithHeaders(ctx, http.MethodDelete, objectStoragePath(request.Object), nil, map[string]string{"If-Match": request.IfMatch})
	if err != nil {
		if indeterminate(err) {
			return finishUnknown(ctx, a.ObjectStorage.Journal, request.Mutation)
		}
		return err
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent {
		drainClose(resp.Body)
		return markSucceeded(ctx, a.ObjectStorage.Journal, request.Mutation, ProviderMutationResult{ResourceID: resource, ETag: request.IfMatch})
	}
	return ociMutationFailure(ctx, a.ObjectStorage.Journal, request.Mutation, resp)
}

type objectScopedReadCloser struct {
	source    io.ReadCloser
	ctx       context.Context
	journal   ProviderMutationJournal
	intent    ProviderMutationIntent
	result    ProviderMutationResult
	maxBytes  int64
	readBytes int64
	completed bool
}

func (r *objectScopedReadCloser) finish(err error) error {
	if r.completed {
		return nil
	}
	r.completed = true
	if err != nil {
		return markObjectUnknown(r.ctx, r.journal, r.intent, err)
	}
	return markSucceeded(r.ctx, r.journal, r.intent, r.result)
}

func (r *objectScopedReadCloser) Read(buffer []byte) (int, error) {
	if r.readBytes >= r.maxBytes && r.maxBytes > 0 {
		var probe [1]byte
		n, err := r.source.Read(probe[:])
		if n > 0 {
			return 0, r.finish(&InvalidDataError{Message: "OCI Object Storage streamed read exceeds limit"})
		}
		if err == io.EOF {
			return 0, r.finish(nil)
		}
		if err != nil {
			return 0, r.finish(err)
		}
		return 0, nil
	}
	if remaining := r.maxBytes - r.readBytes; int64(len(buffer)) > remaining {
		buffer = buffer[:int(remaining)]
	}
	n, err := r.source.Read(buffer)
	r.readBytes += int64(n)
	if err == io.EOF {
		if finishErr := r.finish(nil); finishErr != nil {
			return n, finishErr
		}
	} else if err != nil {
		if finishErr := r.finish(err); finishErr != nil {
			return n, finishErr
		}
	}
	return n, err
}

func (r *objectScopedReadCloser) Close() error {
	closeErr := r.source.Close()
	finishErr := r.finish(&ProviderOutcomeUnknownError{Message: "OCI Object Storage read was closed before verification"})
	if closeErr != nil {
		return closeErr
	}
	return finishErr
}

func validateObjectRef(object ObjectRef) error {
	if len(object.Namespace) < 1 || len(object.Namespace) > 128 || len(object.Bucket) < 1 || len(object.Bucket) > 256 ||
		len(object.Name) < 1 || len(object.Name) > 1024 || strings.ContainsAny(object.Namespace+object.Bucket+object.Name, "\r\n") ||
		strings.Contains(object.Namespace, "/") || strings.Contains(object.Bucket, "/") {
		return &errs.Argument{Message: "object storage identity is invalid"}
	}
	return nil
}

func objectStoragePath(object ObjectRef) string {
	return "/n/" + url.PathEscape(object.Namespace) + "/b/" + url.PathEscape(object.Bucket) + "/o/" + url.PathEscape(object.Name)
}

func (a *OCIObjectStorageAdapter) requireObjectAuthority(ctx context.Context, object ObjectRef) error {
	if a == nil || a.objectStorage == nil || a.journal == nil || !a.journal.AuthoritativeDurable() ||
		a.authority == nil || !a.authority.AuthoritativeDurable() {
		return &InvalidOperationError{Message: "OCI Object Storage adapter is unavailable"}
	}
	if err := validateObjectRef(object); err != nil {
		return err
	}
	if object.Namespace != a.namespace {
		return &InvalidOperationError{Message: "object storage namespace is outside durable scope"}
	}
	if _, allowed := a.buckets[object.Bucket]; !allowed {
		return &InvalidOperationError{Message: "object storage bucket is outside durable scope"}
	}
	reservation, found, err := a.authority.LookupObject(ctx, object)
	if err != nil {
		return err
	}
	if !found || reservation.Object != object {
		return &InvalidOperationError{Message: "object storage object has no exact durable reservation"}
	}
	return nil
}

func objectPutBinding(request ObjectPutRequest) any {
	return struct {
		Object ObjectRef
		SHA256 string
		Size   int
	}{request.Object, request.SHA256, len(request.Content)}
}

func ObjectPutMutationFingerprint(request ObjectPutRequest) string {
	return fingerprintJSON("object.put", objectPutBinding(request))
}

func ObjectPutMutationScope(request ObjectPutRequest) string {
	return ProviderMutationScope("object", request.Object.Namespace, request.Object.Bucket, request.Object.Name)
}

func mergeObjectMutationResult(prior, next ProviderMutationResult, path string) (ProviderMutationResult, error) {
	if path == "" || (prior.ResourceID != "" && prior.ResourceID != path) || (next.ResourceID != "" && next.ResourceID != path) ||
		(prior.ETag != "" && !validCanonicalETag(prior.ETag)) || (next.ETag != "" && !validCanonicalETag(next.ETag)) ||
		(prior.ETag != "" && next.ETag != "" && prior.ETag != next.ETag) ||
		(prior.WorkRequestID != "" && !validWorkRequestID(prior.WorkRequestID)) || (next.WorkRequestID != "" && !validWorkRequestID(next.WorkRequestID)) ||
		(prior.WorkRequestID != "" && next.WorkRequestID != "" && prior.WorkRequestID != next.WorkRequestID) {
		return ProviderMutationResult{}, &InvalidDataError{Message: "object storage mutation result changed identity"}
	}
	result := prior
	result.ResourceID = path
	if result.ETag == "" {
		result.ETag = next.ETag
	}
	if result.WorkRequestID == "" {
		result.WorkRequestID = next.WorkRequestID
	}
	return result, nil
}

func (a *OCIObjectStorageAdapter) markObjectUnknown(ctx context.Context, intent ProviderMutationIntent, record ProviderMutationRecord, next ProviderMutationResult) (ProviderMutationResult, error) {
	result, err := mergeObjectMutationResult(record.Result, next, next.ResourceID)
	if err != nil {
		return ProviderMutationResult{}, err
	}
	if record.State == MutationUnknown {
		return result, nil
	}
	updated, err := a.journal.MarkUnknown(ctx, intent, result)
	if err != nil {
		return ProviderMutationResult{}, err
	}
	return updated.Result, nil
}

func objectPutMatches(request ObjectPutRequest, metadata ObjectMetadata) bool {
	return metadata.ETag != "" && metadata.SHA256 == request.SHA256 && metadata.Size == int64(len(request.Content))
}

func (a *OCIObjectStorageAdapter) reconcileObjectPut(ctx context.Context, request ObjectPutRequest, prior ProviderMutationResult) (ObjectMetadata, error) {
	metadata, found, err := a.HeadObject(ctx, request.Object)
	if err != nil || !found || !objectPutMatches(request, metadata) {
		return ObjectMetadata{}, &ProviderOutcomeUnknownError{Message: "OCI Object Storage PUT requires authoritative reconciliation"}
	}
	result, err := mergeObjectMutationResult(prior, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: metadata.ETag}, objectStoragePath(request.Object))
	if err != nil {
		return ObjectMetadata{}, &ProviderOutcomeUnknownError{Message: "OCI Object Storage PUT result changed during reconciliation"}
	}
	if err := markSucceeded(ctx, a.journal, request.Mutation, result); err != nil {
		return ObjectMetadata{}, err
	}
	if !a.allowsObject(request.Object) {
		return ObjectMetadata{}, &InvalidOperationError{Message: "OCI Object Storage object is outside the verified estate buckets"}
	}
	if len(request.Content) == 0 || int64(len(request.Content)) > a.ObjectStorage.Config.MaxBodyBytes || !validSHA256Hex(request.SHA256) || objectSHA256(request.Content) != request.SHA256 {
		return ObjectMetadata{}, &errs.Argument{Message: "object storage content binding is invalid"}
	}
	if err := expectJSONMutation(request.Mutation, "object.put", ObjectPutMutationScope(request), objectPutBinding(request)); err != nil {
		return ObjectMetadata{}, err
	}
	record, err := prepareMutation(ctx, a.journal, request.Mutation)
	if err != nil {
		return ObjectMetadata{}, err
	}
	if result, done, terminalErr := completedMutation(record); done {
		if terminalErr != nil {
			return ObjectMetadata{}, terminalErr
		}
		result, err = mergeObjectMutationResult(result, ProviderMutationResult{}, objectStoragePath(request.Object))
		if err != nil || result.ETag == "" {
			return ObjectMetadata{}, &InvalidDataError{Message: "object storage completed PUT result is invalid"}
		}
		return ObjectMetadata{ETag: result.ETag, SHA256: request.SHA256, Size: int64(len(request.Content))}, nil
	}
	if record.State == MutationSubmitted || record.State == MutationUnknown {
		return a.reconcileObjectPut(ctx, request, record.Result)
	}
	record, err = a.journal.MarkSubmitted(ctx, request.Mutation)
	if err != nil {
		return ObjectMetadata{}, err
	}
	path := objectStoragePath(request.Object)
	resp, err := a.objectStorage.DoOnceWithHeaders(ctx, http.MethodPut, path, bytes.NewReader(request.Content), map[string]string{
		"Content-Type":               "application/octet-stream",
		"If-None-Match":              "*",
		"opc-meta-terrascale-sha256": request.SHA256,
	})
	if err != nil {
		if !indeterminate(err) {
			return ObjectMetadata{}, err
		}
		result, markErr := a.markObjectUnknown(ctx, request.Mutation, record, ProviderMutationResult{ResourceID: path})
		if markErr != nil {
			return ObjectMetadata{}, markErr
		}
		return a.reconcileObjectPut(ctx, request, result)
	}
	workID, workErr := optionalOCIWorkRequestID(resp)
	if resp.StatusCode == http.StatusOK {
		etag, etagErr := canonicalOCIETag(resp)
		drainClose(resp.Body)
		candidate := ProviderMutationResult{ResourceID: path, WorkRequestID: workID}
		if etagErr == nil {
			candidate.ETag = etag
		}
		result, markErr := a.markObjectUnknown(ctx, request.Mutation, record, candidate)
		if markErr != nil {
			return ObjectMetadata{}, markErr
		}
		if workErr != nil || etagErr != nil {
			return ObjectMetadata{}, &ProviderOutcomeUnknownError{Message: "OCI Object Storage PUT response metadata is invalid"}
		}
		return a.reconcileObjectPut(ctx, request, result)
	}
	if resp.StatusCode == http.StatusPreconditionFailed {
		drainClose(resp.Body)
		if workErr != nil || workID != "" {
			result, markErr := a.markObjectUnknown(ctx, request.Mutation, record, ProviderMutationResult{ResourceID: path, WorkRequestID: workID})
			if markErr != nil {
				return ObjectMetadata{}, markErr
			}
			return a.reconcileObjectPut(ctx, request, result)
		}
		metadata, found, readErr := a.HeadObject(ctx, request.Object)
		if readErr != nil || !found {
			result, markErr := a.markObjectUnknown(ctx, request.Mutation, record, ProviderMutationResult{ResourceID: path})
			if markErr != nil {
				return ObjectMetadata{}, markErr
			}
			return a.reconcileObjectPut(ctx, request, result)
		}
		if !objectPutMatches(request, metadata) {
			return ObjectMetadata{}, knownFailure(ctx, a.journal, request.Mutation, "object-conflict")
		}
		result, mergeErr := mergeObjectMutationResult(record.Result, ProviderMutationResult{ResourceID: path, ETag: metadata.ETag}, path)
		if mergeErr != nil {
			return ObjectMetadata{}, mergeErr
		}
		if err := markSucceeded(ctx, a.journal, request.Mutation, result); err != nil {
			return ObjectMetadata{}, err
		}
		return metadata, nil
	}
	if workErr != nil || workID != "" || (resp.StatusCode >= 200 && resp.StatusCode < 300) {
		drainClose(resp.Body)
		result, markErr := a.markObjectUnknown(ctx, request.Mutation, record, ProviderMutationResult{ResourceID: path, WorkRequestID: workID})
		if markErr != nil {
			return ObjectMetadata{}, markErr
		}
		if workErr != nil {
			return ObjectMetadata{}, &ProviderOutcomeUnknownError{Message: "OCI Object Storage PUT work request metadata is invalid"}
		}
		return a.reconcileObjectPut(ctx, request, result)
	}
	return ObjectMetadata{}, ociMutationFailure(ctx, a.journal, request.Mutation, resp)
}

func objectMetadataFromResponse(resp *http.Response) (ObjectMetadata, error) {
	if resp == nil {
		return ObjectMetadata{}, &InvalidDataError{Message: "OCI Object Storage response is missing"}
	}
	contentLength, err := singleObjectResponseHeader(resp, "Content-Length")
	if err != nil {
		return ObjectMetadata{}, err
	}
	size, err := strconv.ParseInt(contentLength, 10, 64)
	if err != nil || size < 0 || strconv.FormatInt(size, 10) != contentLength {
		return ObjectMetadata{}, &InvalidDataError{Message: "OCI Object Storage content length is invalid"}
	}
	etag, err := singleObjectResponseHeader(resp, "ETag")
	if err != nil || !isSafeETag(etag) {
		return ObjectMetadata{}, &InvalidDataError{Message: "OCI Object Storage metadata is incomplete"}
	}
	digest, err := singleObjectResponseHeader(resp, "opc-meta-terrascale-sha256")
	if err != nil || !validSHA256Hex(digest) {
		return ObjectMetadata{}, &InvalidDataError{Message: "OCI Object Storage metadata is incomplete"}
	}
	metadata := ObjectMetadata{ETag: etag, SHA256: digest, Size: size}
	return metadata, nil
}

func singleObjectResponseHeader(resp *http.Response, name string) (string, error) {
	if resp == nil {
		return "", &InvalidDataError{Message: "OCI Object Storage response is missing"}
	}
	values := resp.Header.Values(name)
	if len(values) != 1 || values[0] == "" || strings.ContainsAny(values[0], "\r\n") {
		return "", &InvalidDataError{Message: "OCI Object Storage response header is invalid"}
	}
	return values[0], nil
}

func (a *OCIObjectStorageAdapter) HeadObject(ctx context.Context, object ObjectRef) (ObjectMetadata, bool, error) {
	if err := a.requireObjectAuthority(ctx, object); err != nil {
		return ObjectMetadata{}, false, err
	}
	if !a.allowsObject(object) {
		return ObjectMetadata{}, false, &InvalidOperationError{Message: "OCI Object Storage object is outside the verified estate buckets"}
	}
	resp, err := a.ObjectStorage.Do(ctx, http.MethodHead, objectStoragePath(object), nil)
	if err != nil {
		return ObjectMetadata{}, false, err
	}
	if resp.StatusCode == http.StatusNotFound {
		drainClose(resp.Body)
		found, listErr := a.objectExistsByExactList(ctx, object)
		if listErr != nil {
			return ObjectMetadata{}, false, listErr
		}
		if found {
			return ObjectMetadata{}, false, &InvalidDataError{Message: "OCI Object Storage HEAD contradicted exact list"}
		}
		return ObjectMetadata{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		drainClose(resp.Body)
		return ObjectMetadata{}, false, &InvalidOperationError{Message: "OCI Object Storage metadata read failed"}
	}
	metadata, err := objectMetadataFromResponse(resp)
	drainClose(resp.Body)
	return metadata, err == nil, err
}

func validObjectListCursor(value string) bool {
	return len(value) > 0 && len(value) <= 1024 && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, func(ch rune) bool { return ch < 0x20 || ch == 0x7f }) < 0
}

func (a *OCIObjectStorageAdapter) objectExistsAuthorized(ctx context.Context, object ObjectRef) (bool, error) {
	if a == nil || a.ObjectStorage == nil {
		return false, &InvalidOperationError{Message: "OCI Object Storage adapter is unavailable"}
	}
	if err := validateObjectRef(object); err != nil {
		return false, err
	}
	basePath := "/n/" + url.PathEscape(object.Namespace) + "/b/" + url.PathEscape(object.Bucket) + "/o"
	query := url.Values{"prefix": {object.Name}, "fields": {"name"}, "limit": {strconv.Itoa(maximumOCIListResults)}}
	seen := map[string]bool{}
	start := ""
	for page := 0; page < maximumOCIPages; page++ {
		if start == "" {
			query.Del("start")
		} else {
			query.Set("start", start)
		}
		resp, err := a.ObjectStorage.Do(ctx, http.MethodGet, basePath+"?"+query.Encode(), nil)
		if err != nil {
			return false, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			drainClose(resp.Body)
			return false, &InvalidOperationError{Message: "OCI Object Storage absence verification failed"}
		}
		body, err := ReadBoundedBody(resp, a.ObjectStorage.Config.MaxBodyBytes)
		if err != nil {
			return false, err
		}
		var document struct {
			Objects []struct {
				Name string `json:"name"`
			} `json:"objects"`
			NextStartWith string `json:"nextStartWith"`
		}
		if json.Unmarshal(body, &document) != nil || document.Objects == nil || len(document.Objects) > maximumOCIListResults {
			return false, &InvalidDataError{Message: "OCI Object Storage absence verification response is invalid"}
		}
		for _, item := range document.Objects {
			if !validObjectPart(item.Name, 1024, true) || !strings.HasPrefix(item.Name, object.Name) {
				return false, &InvalidDataError{Message: "OCI Object Storage absence verification escaped its prefix"}
			}
			if item.Name == object.Name {
				return true, nil
			}
		}
		next := document.NextStartWith
		if next == "" {
			return false, nil
		}
		if !validObjectListCursor(next) || next == start || seen[next] || page+1 == maximumOCIPages {
			return false, &InvalidDataError{Message: "OCI Object Storage absence verification pagination is invalid"}
		}
		seen[next] = true
		start = next
	}
	return false, &InvalidDataError{Message: "OCI Object Storage absence verification exceeded its bound"}
}

func (a *OCIObjectStorageAdapter) GetObject(ctx context.Context, object ObjectRef) (io.ReadCloser, ObjectMetadata, error) {
	if err := a.requireObjectAuthority(ctx, object); err != nil {
		return nil, ObjectMetadata{}, err
	}
	if !a.allowsObject(object) {
		return nil, ObjectMetadata{}, &InvalidOperationError{Message: "OCI Object Storage object is outside the verified estate buckets"}
	}
	resp, err := a.ObjectStorage.Do(ctx, http.MethodGet, objectStoragePath(object), nil)
	if err != nil {
		return nil, ObjectMetadata{}, err
	}
	if resp.StatusCode != http.StatusOK || resp.Body == nil {
		drainClose(resp.Body)
		return nil, ObjectMetadata{}, &InvalidOperationError{Message: "OCI Object Storage object read failed"}
	}
	metadata, err := objectMetadataFromResponse(resp)
	if err != nil {
		drainClose(resp.Body)
		return nil, ObjectMetadata{}, err
	}
	return newLengthDigestVerifyingReadCloser(resp.Body, metadata.SHA256, metadata.Size), metadata, nil
}

func objectDeleteBinding(request ObjectDeleteRequest) any {
	return struct {
		Object  ObjectRef
		IfMatch string
	}{request.Object, request.IfMatch}
}

func ObjectDeleteMutationFingerprint(request ObjectDeleteRequest) string {
	return fingerprintJSON("object.delete", objectDeleteBinding(request))
}

func ObjectDeleteMutationScope(request ObjectDeleteRequest) string {
	return ProviderMutationScope("object", request.Object.Namespace, request.Object.Bucket, request.Object.Name)
}

func (a *OCIObjectStorageAdapter) reconcileObjectDelete(ctx context.Context, request ObjectDeleteRequest, prior ProviderMutationResult) error {
	_, found, err := a.HeadObject(ctx, request.Object)
	if err != nil || found {
		return &ProviderOutcomeUnknownError{Message: "OCI Object Storage DELETE requires authoritative absence proof"}
	}
	result, err := mergeObjectMutationResult(prior, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: request.IfMatch}, objectStoragePath(request.Object))
	if err != nil {
		return &ProviderOutcomeUnknownError{Message: "OCI Object Storage DELETE result changed during reconciliation"}
	}
	return markSucceeded(ctx, a.journal, request.Mutation, result)
}

func (a *OCIObjectStorageAdapter) DeleteObject(ctx context.Context, request ObjectDeleteRequest) error {
	if err := a.requireObjectAuthority(ctx, request.Object); err != nil {
		return err
	}
	if !a.allowsObject(request.Object) {
		return &InvalidOperationError{Message: "OCI Object Storage object is outside the verified estate buckets"}
	}
	if !isSafeETag(request.IfMatch) {
		return &errs.Argument{Message: "object delete ETag fence is invalid"}
	}
	if err := expectJSONMutation(request.Mutation, "object.delete", ObjectDeleteMutationScope(request), objectDeleteBinding(request)); err != nil {
		return err
	}
	record, err := prepareMutation(ctx, a.journal, request.Mutation)
	if err != nil {
		return err
	}
	if result, done, terminalErr := completedMutation(record); done {
		if terminalErr != nil {
			return terminalErr
		}
		result, err = mergeObjectMutationResult(result, ProviderMutationResult{ETag: request.IfMatch}, objectStoragePath(request.Object))
		if err != nil || result.ETag != request.IfMatch {
			return &InvalidDataError{Message: "object storage completed DELETE result is invalid"}
		}
		return nil
	}
	if record.State == MutationSubmitted || record.State == MutationUnknown {
		return a.reconcileObjectDelete(ctx, request, record.Result)
	}
	_, found, err := a.HeadObject(ctx, request.Object)
	if err != nil {
		return err
	}
	if !found {
		return markAbsentDeleteSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: request.IfMatch})
	}
	if record.State == MutationUnknown {
		return &ProviderOutcomeUnknownError{}
	}
	if _, err := a.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
		return err
	}
	resp, err := a.ObjectStorage.DoWithHeaders(ctx, http.MethodDelete, objectStoragePath(request.Object), nil, map[string]string{"If-Match": request.IfMatch})
	if err != nil {
		if indeterminate(err) {
			if _, found, readErr := a.HeadObject(ctx, request.Object); readErr == nil && !found {
				return markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: request.IfMatch})
			}
			return finishUnknown(ctx, a.Journal, request.Mutation)
		}
		return markSucceeded(ctx, a.journal, request.Mutation, result)
	}
	record, err = a.journal.MarkSubmitted(ctx, request.Mutation)
	if err != nil {
		return err
	}
	path := objectStoragePath(request.Object)
	resp, err := a.objectStorage.DoOnceWithHeaders(ctx, http.MethodDelete, path, nil, map[string]string{"If-Match": request.IfMatch})
	if err != nil {
		if !indeterminate(err) {
			return err
		}
		result, markErr := a.markObjectUnknown(ctx, request.Mutation, record, ProviderMutationResult{ResourceID: path, ETag: request.IfMatch})
		if markErr != nil {
			return markErr
		}
		return a.reconcileObjectDelete(ctx, request, result)
	}
	workID, workErr := optionalOCIWorkRequestID(resp)
	candidate := ProviderMutationResult{ResourceID: path, ETag: request.IfMatch, WorkRequestID: workID}
	if resp.StatusCode == http.StatusNoContent && workErr == nil && workID == "" {
		drainClose(resp.Body)
		result, mergeErr := mergeObjectMutationResult(record.Result, candidate, path)
		if mergeErr != nil {
			return mergeErr
		}
		return markSucceeded(ctx, a.journal, request.Mutation, result)
	}
	if resp.StatusCode == http.StatusNotFound || workErr != nil || workID != "" || (resp.StatusCode >= 200 && resp.StatusCode < 300) {
		drainClose(resp.Body)
		result, markErr := a.markObjectUnknown(ctx, request.Mutation, record, candidate)
		if markErr != nil {
			return markErr
		}
		if workErr != nil {
			return &ProviderOutcomeUnknownError{Message: "OCI Object Storage DELETE work request metadata is invalid"}
		}
		return a.reconcileObjectDelete(ctx, request, result)
	}
	return ociMutationFailure(ctx, a.journal, request.Mutation, resp)
}

const (
	ociImageManifestMediaType    = "application/vnd.oci.image.manifest.v1+json"
	ociImageIndexMediaType       = "application/vnd.oci.image.index.v1+json"
	dockerImageManifestMediaType = "application/vnd.docker.distribution.manifest.v2+json"
	dockerImageListMediaType     = "application/vnd.docker.distribution.manifest.list.v2+json"
	registryManifestAccept       = ociImageManifestMediaType + ", " + ociImageIndexMediaType + ", " + dockerImageManifestMediaType + ", " + dockerImageListMediaType
)

// OCIRegistryScope limits the pull adapter to one OCIR namespace and the
// exact repositories assigned to this process. Repository values are
// relative to Namespace, for example "terrascale/member".
type OCIRegistryScope struct {
	Namespace    string
	Repositories []string
}

type OCIRegistryAdapter struct {
	registry     *OCIHTTPTransport
	namespace    string
	repositories map[string]struct{}
}

// OCIRegistryTokenSigner supplies the Docker Registry v2 basic credential
// expected by OCIR. The token stays process-local and errors never include it.
type OCIRegistryTokenSigner struct{ namespace, username, token string }

func (s *OCIRegistryTokenSigner) String() string   { return "OCIRegistryTokenSigner{<redacted>}" }
func (s *OCIRegistryTokenSigner) GoString() string { return "OCIRegistryTokenSigner{<redacted>}" }

func NewOCIRegistryTokenSigner(username, token string) (*OCIRegistryTokenSigner, error) {
	if len(username) < 1 || len(username) > 256 || len(token) < 1 || len(token) > 4096 ||
		strings.TrimSpace(username) != username || strings.ContainsAny(username+token, "\r\n") {
		return nil, &errs.Argument{Message: "OCI registry credential is invalid"}
	}
	return &OCIRegistryTokenSigner{namespace: namespace, username: username, token: token}, nil
}

func (s *OCIRegistryTokenSigner) Sign(request *http.Request) error {
	if s == nil || s.username == "" || s.token == "" || request == nil {
		return &InvalidOperationError{Message: "OCI registry credential is unavailable"}
	}
	request.SetBasicAuth(s.username, s.token)
	return nil
}

func NewOCIRegistryAdapter(transport *OCIHTTPTransport, scope OCIRegistryScope) (*OCIRegistryAdapter, error) {
	if transport == nil || transport.Client == nil || transport.Config.Endpoint == nil || transport.Config.Service != OCIServiceRegistry ||
		transport.Config.Endpoint.Scheme != "https" || transport.Config.Endpoint.User != nil || transport.Config.Endpoint.RawQuery != "" ||
		transport.Config.Endpoint.Fragment != "" || transport.Config.Endpoint.Opaque != "" || transport.Config.Endpoint.RawPath != "" ||
		(transport.Config.Endpoint.Path != "" && transport.Config.Endpoint.Path != "/") ||
		!validOCIServiceHost(OCIServiceRegistry, transport.Config.Region, transport.Config.Endpoint.Host) {
		return nil, &InvalidOperationError{Message: "OCI registry transport is unavailable or has the wrong authority"}
	}
	signer, ok := transport.Signer.(*OCIRegistryTokenSigner)
	if !ok || signer == nil || signer.namespace != scope.Namespace || !validRegistryNamespace(scope.Namespace) ||
		len(scope.Repositories) < 1 || len(scope.Repositories) > 64 {
		return nil, &InvalidOperationError{Message: "OCI registry scope or credential is unavailable"}
	}
	repositories := make(map[string]struct{}, len(scope.Repositories))
	for _, repository := range scope.Repositories {
		canonical, err := canonicalRegistryRepository(repository, false)
		if err != nil {
			return nil, err
		}
		if _, exists := repositories[canonical]; exists {
			return nil, &errs.Argument{Message: "OCI registry repository scope is duplicated"}
		}
		repositories[canonical] = struct{}{}
	}
	// Snapshot every authority-bearing transport value. Registry credentials
	// must not follow later mutation of caller-owned config, endpoint, client,
	// cookie jar, redirect policy, or signer fields.
	endpoint := *transport.Config.Endpoint
	config := transport.Config
	config.Endpoint = &endpoint
	client := *transport.Client
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	signerCopy := *signer
	registry := *transport
	registry.Config = config
	registry.Client = &client
	registry.Signer = &signerCopy
	return &OCIRegistryAdapter{registry: &registry, namespace: scope.Namespace, repositories: repositories}, nil
}

// OCIRegistryPullAdapter adds a durable, compartment-scoped fence around the
// immutable registry reads. The underlying OCIRegistryAdapter remains the
// raw HTTP protocol implementation; this layer records the same request
// intent while a controller retries or resumes a read.
type OCIRegistryPullAdapter struct {
	Registry  *OCIRegistryAdapter
	Journal   ProviderMutationJournal
	Ownership DurableOwnershipEvidence
}

func NewOCIRegistryPullAdapter(transport *OCIHTTPTransport, journal ProviderMutationJournal, ownership DurableOwnershipEvidence) (*OCIRegistryPullAdapter, error) {
	if err := validateOCIAdapter(transport, OCIServiceRegistry, journal); err != nil {
		return nil, err
	}
	registry, err := NewOCIRegistryAdapter(transport)
	if err != nil {
		return nil, err
	}
	return &OCIRegistryPullAdapter{Registry: registry, Journal: journal, Ownership: ownership}, nil
}

func registryPullBinding(compartment, repository, reference string) any {
	return struct {
		CompartmentID, Repository, Reference string
	}{compartment, repository, reference}
}

func registryBlobPullBinding(compartment, repository, digest string) any {
	return struct {
		CompartmentID, Repository, Digest string
	}{compartment, repository, digest}
}

func registryTagListBinding(compartment, repository string) any {
	return struct {
		CompartmentID, Repository string
	}{compartment, repository}
}

// RegistryManifestPullMutationFingerprint binds the complete scoped manifest
// read intent for callers constructing a durable mutation.
func RegistryManifestPullMutationFingerprint(request RegistryPullRequest) string {
	return fingerprintJSON("registry.manifest.pull", registryPullBinding(request.CompartmentID, request.Repository, request.Reference))
}

// RegistryManifestPullMutationScope returns the durable manifest resource
// fence derived from the provider-visible request fields.
func RegistryManifestPullMutationScope(request RegistryPullRequest) string {
	return ProviderMutationScope("registry-manifest", request.CompartmentID, request.Repository, request.Reference)
}

// RegistryBlobPullMutationFingerprint binds the complete scoped blob read
// intent for callers constructing a durable mutation.
func RegistryBlobPullMutationFingerprint(request RegistryBlobPullRequest) string {
	return fingerprintJSON("registry.blob.pull", registryBlobPullBinding(request.CompartmentID, request.Repository, request.Digest))
}

// RegistryBlobPullMutationScope returns the durable blob resource fence
// derived from the provider-visible request fields.
func RegistryBlobPullMutationScope(request RegistryBlobPullRequest) string {
	return ProviderMutationScope("registry-blob", request.CompartmentID, request.Repository, request.Digest)
}

// RegistryTagListMutationFingerprint binds the complete scoped tag-list read
// intent for callers constructing a durable mutation.
func RegistryTagListMutationFingerprint(request RegistryTagListRequest) string {
	return fingerprintJSON("registry.tags.list", registryTagListBinding(request.CompartmentID, request.Repository))
}

// RegistryTagListMutationScope returns the durable tag-list resource fence
// derived from the provider-visible request fields.
func RegistryTagListMutationScope(request RegistryTagListRequest) string {
	return ProviderMutationScope("registry-tags", request.CompartmentID, request.Repository)
}

func registryPullResource(repository, value string) string {
	return "registry/" + repository + "@" + value
}

func (a *OCIRegistryPullAdapter) prepare(ctx context.Context, intent ProviderMutationIntent, action, scope string, binding any, repository, compartment string) (ProviderMutationRecord, error) {
	if a == nil || a.Registry == nil || a.Registry.Registry == nil || validateOCIAdapter(a.Registry.Registry, OCIServiceRegistry, a.Journal) != nil {
		return ProviderMutationRecord{}, &InvalidOperationError{Message: "OCI registry pull adapter is unavailable"}
	}
	if err := requireOwnedResource(ctx, a.Ownership, repository, compartment); err != nil {
		return ProviderMutationRecord{}, err
	}
	if err := expectJSONMutation(intent, action, scope, binding); err != nil {
		return ProviderMutationRecord{}, err
	}
	return prepareMutation(ctx, a.Journal, intent)
}

func registryPullRequestIdentity(compartment, repository, reference string) (string, error) {
	if !isOCID(compartment, "compartment") {
		return "", &errs.Argument{Message: "registry pull compartment is invalid"}
	}
	if _, err := registryRepositoryPath(repository); err != nil || !validRegistryReference(reference) {
		return "", &errs.Argument{Message: "registry pull request is invalid"}
	}
	return registryPullResource(repository, reference), nil
}

func registryBlobPullRequestIdentity(compartment, repository, digest string) (string, error) {
	if !isOCID(compartment, "compartment") {
		return "", &errs.Argument{Message: "registry pull compartment is invalid"}
	}
	if _, err := registryRepositoryPath(repository); err != nil || !strings.HasPrefix(digest, "sha256:") || !validSHA256Hex(strings.TrimPrefix(digest, "sha256:")) {
		return "", &errs.Argument{Message: "registry blob pull request is invalid"}
	}
	return registryPullResource(repository, digest), nil
}

func registryTagListRequestIdentity(compartment, repository string) (string, error) {
	if !isOCID(compartment, "compartment") {
		return "", &errs.Argument{Message: "registry pull compartment is invalid"}
	}
	if _, err := registryRepositoryPath(repository); err != nil {
		return "", &errs.Argument{Message: "registry tag list request is invalid"}
	}
	return registryPullResource(repository, "tags"), nil
}

func markRegistryPullUnknown(ctx context.Context, journal ProviderMutationJournal, intent ProviderMutationIntent, result ProviderMutationResult, cause error) error {
	if _, err := journal.MarkUnknown(ctx, intent, result); err != nil {
		return err
	}
	return cause
}

func (a *OCIRegistryPullAdapter) PullManifestScoped(ctx context.Context, request RegistryPullRequest) (RegistryManifest, error) {
	resource, err := registryPullRequestIdentity(request.CompartmentID, request.Repository, request.Reference)
	if err != nil {
		return RegistryManifest{}, err
	}
	binding := registryPullBinding(request.CompartmentID, request.Repository, request.Reference)
	record, err := a.prepare(ctx, request.Mutation, "registry.manifest.pull", RegistryManifestPullMutationScope(request), binding, request.Repository, request.CompartmentID)
	if err != nil {
		return RegistryManifest{}, err
	}
	if _, done, err := completedMutation(record); done {
		if err != nil {
			return RegistryManifest{}, err
		}
	}
	if record.State == MutationPrepared {
		if _, err := a.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
			return RegistryManifest{}, err
		}
	}
	manifest, err := a.Registry.PullManifest(ctx, RegistryManifestRequest{Repository: request.Repository, Reference: request.Reference})
	if err != nil {
		return RegistryManifest{}, markRegistryPullUnknown(ctx, a.Journal, request.Mutation, ProviderMutationResult{}, err)
	}
	result := ProviderMutationResult{ResourceID: resource, ETag: manifest.Digest}
	if err := markSucceeded(ctx, a.Journal, request.Mutation, result); err != nil {
		return RegistryManifest{}, err
	}
	return manifest, nil
}

func (a *OCIRegistryPullAdapter) PullBlobScoped(ctx context.Context, request RegistryBlobPullRequest) (io.ReadCloser, int64, error) {
	resource, err := registryBlobPullRequestIdentity(request.CompartmentID, request.Repository, request.Digest)
	if err != nil {
		return nil, 0, err
	}
	binding := registryBlobPullBinding(request.CompartmentID, request.Repository, request.Digest)
	record, err := a.prepare(ctx, request.Mutation, "registry.blob.pull", RegistryBlobPullMutationScope(request), binding, request.Repository, request.CompartmentID)
	if err != nil {
		return nil, 0, err
	}
	if _, done, err := completedMutation(record); done && err != nil {
		return nil, 0, err
	}
	if record.State == MutationPrepared {
		if _, err := a.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
			return nil, 0, err
		}
	}
	reader, size, err := a.Registry.PullBlob(ctx, RegistryBlobRequest{Repository: request.Repository, Digest: request.Digest})
	if err != nil {
		return nil, 0, markRegistryPullUnknown(ctx, a.Journal, request.Mutation, ProviderMutationResult{}, err)
	}
	return &registryPullReadCloser{source: reader, ctx: ctx, journal: a.Journal, intent: request.Mutation, result: ProviderMutationResult{ResourceID: resource, ETag: request.Digest}}, size, nil
}

type registryPullReadCloser struct {
	source    io.ReadCloser
	ctx       context.Context
	journal   ProviderMutationJournal
	intent    ProviderMutationIntent
	result    ProviderMutationResult
	completed bool
}

func (r *registryPullReadCloser) finish(err error) error {
	if r.completed {
		return nil
	}
	r.completed = true
	if err != nil {
		return markRegistryPullUnknown(r.ctx, r.journal, r.intent, ProviderMutationResult{}, err)
	}
	if markErr := markSucceeded(r.ctx, r.journal, r.intent, r.result); markErr != nil {
		return markErr
	}
	return nil
}

func (r *registryPullReadCloser) Read(buffer []byte) (int, error) {
	n, err := r.source.Read(buffer)
	if err == io.EOF {
		if finishErr := r.finish(nil); finishErr != nil {
			return n, finishErr
		}
	} else if err != nil {
		if finishErr := r.finish(err); finishErr != nil {
			return n, finishErr
		}
	}
	return n, err
}

func (r *registryPullReadCloser) Close() error {
	closeErr := r.source.Close()
	finishErr := r.finish(&ProviderOutcomeUnknownError{Message: "OCI registry blob pull was closed before verification"})
	if closeErr != nil {
		return closeErr
	}
	if r.completed && finishErr != nil {
		return finishErr
	}
	return nil
}

func (a *OCIRegistryPullAdapter) ListTagsScoped(ctx context.Context, request RegistryTagListRequest) ([]string, error) {
	resource, err := registryTagListRequestIdentity(request.CompartmentID, request.Repository)
	if err != nil {
		return nil, err
	}
	binding := registryTagListBinding(request.CompartmentID, request.Repository)
	record, err := a.prepare(ctx, request.Mutation, "registry.tags.list", RegistryTagListMutationScope(request), binding, request.Repository, request.CompartmentID)
	if err != nil {
		return nil, err
	}
	if _, done, err := completedMutation(record); done && err != nil {
		return nil, err
	}
	if record.State == MutationPrepared {
		if _, err := a.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
			return nil, err
		}
	}
	repository, err := registryRepositoryPath(request.Repository)
	if err != nil {
		return nil, err
	}
	path := "/v2/" + repository + "/tags/list"
	tags := make([]string, 0)
	seen := make(map[string]struct{})
	seenCursors := make(map[string]struct{})
	last := ""
	for page := 1; page <= maximumOCIPages; page++ {
		query := url.Values{"n": {strconv.Itoa(maximumOCIListResults)}}
		if last != "" {
			query.Set("last", last)
		}
		resp, err := a.Registry.Registry.Do(ctx, http.MethodGet, path+"?"+query.Encode(), nil)
		if err != nil {
			return nil, markRegistryPullUnknown(ctx, a.Journal, request.Mutation, ProviderMutationResult{}, err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			drainClose(resp.Body)
			return nil, markRegistryPullUnknown(ctx, a.Journal, request.Mutation, ProviderMutationResult{}, &InvalidOperationError{Message: "OCI registry tag listing failed"})
		}
		body, err := ReadBoundedBody(resp, a.Registry.Registry.Config.MaxBodyBytes)
		if err != nil {
			return nil, markRegistryPullUnknown(ctx, a.Journal, request.Mutation, ProviderMutationResult{}, err)
		}
		var payload struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		}
		if rejectDuplicateJSONKeys(body) != nil || json.Unmarshal(body, &payload) != nil || payload.Name != request.Repository || payload.Tags == nil || len(payload.Tags) > maximumOCIListResults {
			return nil, markRegistryPullUnknown(ctx, a.Journal, request.Mutation, ProviderMutationResult{}, &InvalidDataError{Message: "OCI registry tag listing response is invalid"})
		}
		for _, tag := range payload.Tags {
			if !validRegistryTag(tag) {
				return nil, markRegistryPullUnknown(ctx, a.Journal, request.Mutation, ProviderMutationResult{}, &InvalidDataError{Message: "OCI registry tag listing response is invalid"})
			}
			if _, duplicate := seen[tag]; duplicate {
				return nil, markRegistryPullUnknown(ctx, a.Journal, request.Mutation, ProviderMutationResult{}, &InvalidDataError{Message: "OCI registry tag listing response is invalid"})
			}
			seen[tag] = struct{}{}
			tags = append(tags, tag)
			if len(tags) > maximumOCIListResults*maximumOCIPages {
				return nil, markRegistryPullUnknown(ctx, a.Journal, request.Mutation, ProviderMutationResult{}, &InvalidDataError{Message: "OCI registry tag listing exceeds its bound"})
			}
		}
		next, err := nextRegistryTagPage(resp, path)
		if err != nil {
			return nil, markRegistryPullUnknown(ctx, a.Journal, request.Mutation, ProviderMutationResult{}, err)
		}
		if next == "" {
			if err := markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: resource}); err != nil {
				return nil, err
			}
			return tags, nil
		}
		if _, duplicate := seenCursors[next]; duplicate || next == last {
			return nil, markRegistryPullUnknown(ctx, a.Journal, request.Mutation, ProviderMutationResult{}, &InvalidDataError{Message: "OCI registry tag pagination is invalid"})
		}
		seenCursors[next] = struct{}{}
		last = next
	}
	return nil, markRegistryPullUnknown(ctx, a.Journal, request.Mutation, ProviderMutationResult{}, &InvalidDataError{Message: "OCI registry tag listing pagination exceeds its bound"})
}

func registryRepositoryPath(repository string) (string, error) {
	if len(repository) < 1 || len(repository) > 512 || strings.ContainsAny(repository, "\r\n\\") {
		return "", &errs.Argument{Message: "registry repository is invalid"}
	}
	parts := strings.Split(repository, "/")
	for index, part := range parts {
		if len(part) < 1 || len(part) > 128 || strings.Contains(part, "..") {
			return "", &errs.Argument{Message: "registry repository is invalid"}
		}
	}
	return strings.Join(parts, "/"), nil
}

func (a *OCIRegistryAdapter) registryRepositoryPath(repository string) (string, error) {
	canonical, err := canonicalRegistryRepository(repository, true)
	if err != nil {
		return "", err
	}
	prefix := a.namespace + "/"
	if !strings.HasPrefix(canonical, prefix) {
		return "", &InvalidOperationError{Message: "registry repository is outside the configured namespace"}
	}
	relative := strings.TrimPrefix(canonical, prefix)
	if _, allowed := a.repositories[relative]; !allowed {
		return "", &InvalidOperationError{Message: "registry repository is outside the configured scope"}
	}
	return canonical, nil
}

func validRegistryDigest(reference string) bool {
	return len(reference) == len("sha256:")+sha256.Size*2 && strings.HasPrefix(reference, "sha256:") &&
		validSHA256Hex(strings.TrimPrefix(reference, "sha256:"))
}

func supportedRegistryManifestMediaType(mediaType string) bool {
	switch mediaType {
	case ociImageManifestMediaType, ociImageIndexMediaType, dockerImageManifestMediaType, dockerImageListMediaType:
		return true
	default:
		return false
	}
}

func registryIdentityEncoding(resp *http.Response) bool {
	_, err := canonicalOCIHeader(resp, "Content-Encoding", false, func(value string) bool { return value == "identity" })
	return err == nil
}

func canonicalRegistryDigest(resp *http.Response, required bool) (string, error) {
	return canonicalOCIHeader(resp, "Docker-Content-Digest", required, validRegistryDigest)
}

func canonicalRegistryManifestMediaType(resp *http.Response) (string, error) {
	return canonicalOCIHeader(resp, "Content-Type", true, supportedRegistryManifestMediaType)
}

func canonicalRegistryBlobMediaType(resp *http.Response) (string, error) {
	return canonicalOCIHeader(resp, "Content-Type", true, func(value string) bool { return value == "application/octet-stream" })
}

func registryJSONHasDuplicateProperties(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	duplicate, err := scanRegistryJSONValue(decoder, 0)
	if err != nil || duplicate {
		return true
	}
	var trailing any
	return decoder.Decode(&trailing) != io.EOF
}

func scanRegistryJSONValue(decoder *json.Decoder, depth int) (bool, error) {
	if depth > 64 {
		return false, &InvalidDataError{Message: "registry manifest JSON nesting exceeds limit"}
	}
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return false, nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return false, err
			}
			name, ok := key.(string)
			if !ok {
				return false, &InvalidDataError{Message: "registry manifest JSON is invalid"}
			}
			canonicalName := strings.ToLower(name)
			if _, exists := seen[canonicalName]; exists {
				return true, nil
			}
			seen[canonicalName] = struct{}{}
			duplicate, err := scanRegistryJSONValue(decoder, depth+1)
			if err != nil || duplicate {
				return duplicate, err
			}
		}
		_, err = decoder.Token()
		return false, err
	case '[':
		for decoder.More() {
			duplicate, err := scanRegistryJSONValue(decoder, depth+1)
			if err != nil || duplicate {
				return duplicate, err
			}
		}
		_, err = decoder.Token()
		return false, err
	default:
		return false, &InvalidDataError{Message: "registry manifest JSON is invalid"}
	}
}

func validRegistryManifestEnvelope(raw []byte, mediaType string) bool {
	if len(raw) == 0 || registryJSONHasDuplicateProperties(raw) {
		return false
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil || envelope == nil {
		return false
	}
	var schemaVersion int
	var bodyMediaType string
	if json.Unmarshal(envelope["schemaVersion"], &schemaVersion) != nil || schemaVersion != 2 ||
		json.Unmarshal(envelope["mediaType"], &bodyMediaType) != nil {
		return false
	}
	if bodyMediaType != mediaType {
		return false
	}
	switch mediaType {
	case ociImageManifestMediaType, dockerImageManifestMediaType:
		if _, hasIndex := envelope["manifests"]; hasIndex {
			return false
		}
		config, hasConfig := envelope["config"]
		layers, hasLayers := envelope["layers"]
		return hasConfig && hasLayers && validRegistryDescriptor(config) && validRegistryDescriptorList(layers, true)
	case ociImageIndexMediaType, dockerImageListMediaType:
		if _, hasConfig := envelope["config"]; hasConfig {
			return false
		}
		if _, hasLayers := envelope["layers"]; hasLayers {
			return false
		}
		manifests, present := envelope["manifests"]
		return present && validRegistryDescriptorList(manifests, false)
	default:
		return false
	}
}

func validRegistryDescriptor(raw json.RawMessage) bool {
	var descriptor map[string]json.RawMessage
	if json.Unmarshal(raw, &descriptor) != nil || descriptor == nil {
		return false
	}
	if _, external := descriptor["urls"]; external {
		return false
	}
	if _, embedded := descriptor["data"]; embedded {
		return false
	}
	var mediaType, digest string
	var size int64
	if json.Unmarshal(descriptor["mediaType"], &mediaType) != nil || json.Unmarshal(descriptor["digest"], &digest) != nil ||
		json.Unmarshal(descriptor["size"], &size) != nil || len(mediaType) < 1 || len(mediaType) > 256 ||
		strings.TrimSpace(mediaType) != mediaType || containsASCIIControl(mediaType) || !validRegistryDigest(digest) || size < 0 || size > 64<<30 {
		return false
	}
	return true
}

func validRegistryDescriptorList(raw json.RawMessage, allowEmpty bool) bool {
	var descriptors []json.RawMessage
	if json.Unmarshal(raw, &descriptors) != nil || descriptors == nil || len(descriptors) > 1024 || (!allowEmpty && len(descriptors) == 0) {
		return false
	}
	for _, descriptor := range descriptors {
		if !validRegistryDescriptor(descriptor) {
			return false
		}
	}
	return true
}

func validRegistryTag(tag string) bool {
	if len(tag) < 1 || len(tag) > 128 {
		return false
	}
	for index, value := range tag {
		if index == 0 && ((value < 'A' || value > 'Z') && (value < 'a' || value > 'z') && (value < '0' || value > '9') && value != '_') {
			return false
		}
		if (value < 'A' || value > 'Z') && (value < 'a' || value > 'z') && (value < '0' || value > '9') && value != '_' && value != '.' && value != '-' {
			return false
		}
	}
	return true
}

func validRegistryManifestContent(raw []byte) bool {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return false
	}
	var payload struct {
		SchemaVersion int               `json:"schemaVersion"`
		Config        json.RawMessage   `json:"config"`
		Layers        []json.RawMessage `json:"layers"`
		Manifests     []json.RawMessage `json:"manifests"`
	}
	if json.Unmarshal(raw, &payload) != nil || payload.SchemaVersion != 2 {
		return false
	}
	if payload.Config != nil && len(payload.Config) == 0 {
		return false
	}
	return len(payload.Layers) <= maximumOCIListResults && len(payload.Manifests) <= maximumOCIListResults &&
		len(payload.Layers)+len(payload.Manifests) <= maximumOCIListResults
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return &InvalidDataError{Message: "JSON contains trailing data"}
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return &InvalidDataError{Message: "JSON object key is invalid"}
			}
			if _, duplicate := seen[name]; duplicate {
				return &InvalidDataError{Message: "JSON object contains a duplicate key"}
			}
			seen[name] = struct{}{}
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return &InvalidDataError{Message: "JSON delimiter is invalid"}
	}
	end, err := decoder.Token()
	if err != nil {
		return err
	}
	closing := json.Delim('}')
	if delimiter == '[' {
		closing = ']'
	}
	if end != closing {
		return &InvalidDataError{Message: "JSON container is unterminated"}
	}
	return nil
}

func nextRegistryTagPage(resp *http.Response, path string) (string, error) {
	if resp == nil {
		return "", &InvalidDataError{Message: "OCI registry tag pagination is invalid"}
	}
	values := resp.Header.Values("link")
	if len(values) == 0 {
		return "", nil
	}
	if len(values) != 1 {
		return "", &InvalidDataError{Message: "OCI registry tag pagination is invalid"}
	}
	parts := strings.Split(values[0], ";")
	if len(parts) != 2 || strings.TrimSpace(parts[1]) != `rel="next"` {
		return "", &InvalidDataError{Message: "OCI registry tag pagination is invalid"}
	}
	target := strings.TrimSpace(parts[0])
	if len(target) < 2 || target[0] != '<' || target[len(target)-1] != '>' {
		return "", &InvalidDataError{Message: "OCI registry tag pagination is invalid"}
	}
	u, err := url.Parse(target[1 : len(target)-1])
	if err != nil || u.IsAbs() || u.Host != "" || u.Opaque != "" || u.Fragment != "" || u.Path != path {
		return "", &InvalidDataError{Message: "OCI registry tag pagination is invalid"}
	}
	query := u.Query()
	for key := range query {
		if key != "n" && key != "last" {
			return "", &InvalidDataError{Message: "OCI registry tag pagination is invalid"}
		}
	}
	if query.Get("n") != strconv.Itoa(maximumOCIListResults) || len(query["n"]) != 1 || len(query["last"]) != 1 || !validRegistryTag(query.Get("last")) {
		return "", &InvalidDataError{Message: "OCI registry tag pagination is invalid"}
	}
	return query.Get("last"), nil
}

func (a *OCIRegistryAdapter) PullManifest(ctx context.Context, request RegistryManifestRequest) (RegistryManifest, error) {
	if a == nil || a.registry == nil {
		return RegistryManifest{}, &InvalidOperationError{Message: "OCI registry adapter is unavailable"}
	}
	repository, err := registryRepositoryPath(request.Repository)
	if err != nil || !validRegistryReference(request.Reference) {
		return RegistryManifest{}, &errs.Argument{Message: "registry manifest request is invalid"}
	}
	resp, err := a.Registry.DoWithHeaders(ctx, http.MethodGet, "/v2/"+repository+"/manifests/"+url.PathEscape(request.Reference), nil, map[string]string{"Accept": "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json"})
	if err != nil {
		return RegistryManifest{}, err
	}
	if !validRegistryDigest(request.Reference) {
		return RegistryManifest{}, &errs.Argument{Message: "registry manifest request is invalid"}
	}
	resp, err := a.registry.DoWithHeaders(ctx, http.MethodGet, "/v2/"+repository+"/manifests/"+url.PathEscape(request.Reference), nil, map[string]string{
		"Accept":          registryManifestAccept,
		"Accept-Encoding": "identity",
	})
	if err != nil {
		return RegistryManifest{}, err
	}
	if !validRegistryManifestContent(body) {
		return RegistryManifest{}, &InvalidDataError{Message: "OCI registry manifest response is invalid"}
	}
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	headerDigest, digestErr := canonicalRegistryDigest(resp, true)
	if digestErr != nil || headerDigest != digest || request.Reference != digest {
		return RegistryManifest{}, &InvalidDataError{Message: "OCI registry manifest digest is invalid"}
	}
	mediaType, mediaErr := canonicalRegistryManifestMediaType(resp)
	if mediaErr != nil || !validRegistryManifestEnvelope(body, mediaType) {
		return RegistryManifest{}, &InvalidDataError{Message: "OCI registry manifest media type is invalid"}
	}
	return RegistryManifest{Digest: digest, MediaType: mediaType, Content: body}, nil
}

func (a *OCIRegistryAdapter) PullBlob(ctx context.Context, request RegistryBlobRequest) (io.ReadCloser, int64, error) {
	if a == nil || a.registry == nil {
		return nil, 0, &InvalidOperationError{Message: "OCI registry adapter is unavailable"}
	}
	repository, err := registryRepositoryPath(request.Repository)
	if err != nil || !strings.HasPrefix(request.Digest, "sha256:") || !validSHA256Hex(strings.TrimPrefix(request.Digest, "sha256:")) {
		return nil, 0, &errs.Argument{Message: "registry blob request is invalid"}
	}
	resp, err := a.Registry.Do(ctx, http.MethodGet, "/v2/"+repository+"/blobs/"+url.PathEscape(request.Digest), nil)
	if err != nil {
		return nil, 0, err
	}
	if !validRegistryDigest(request.Digest) {
		return nil, 0, &errs.Argument{Message: "registry blob request is invalid"}
	}
	resp, err := a.registry.DoWithHeaders(ctx, http.MethodGet, "/v2/"+repository+"/blobs/"+url.PathEscape(request.Digest), nil, map[string]string{
		"Accept":          "application/octet-stream",
		"Accept-Encoding": "identity",
	})
	if err != nil {
		return nil, 0, err
	}
	redirected := false
	if resp.StatusCode == http.StatusTemporaryRedirect {
		location, valid := singleRegistryRedirectLocation(resp)
		drainClose(resp.Body)
		if !valid {
			return nil, 0, &InvalidDataError{Message: "OCI registry blob redirect is invalid"}
		}
		target, valid := parseRegistryBlobRedirect(location, a.registry.Config.Region, a.namespace)
		if !valid {
			return nil, 0, &InvalidDataError{Message: "OCI registry blob redirect is invalid"}
		}
		redirectRequest, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if requestErr != nil {
			return nil, 0, &InvalidDataError{Message: "OCI registry blob redirect is invalid"}
		}
		redirectRequest.Header.Set("Accept", "application/octet-stream")
		redirectRequest.Header.Set("Accept-Encoding", "identity")
		redirectRequest.Header.Del("Authorization")
		redirectRequest.Header.Del("Cookie")
		client := *a.registry.Client
		client.Jar = nil
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err = client.Do(redirectRequest)
		if err != nil {
			if resp != nil {
				drainClose(resp.Body)
			}
			if ctx.Err() != nil {
				return nil, 0, ctx.Err()
			}
			return nil, 0, &InvalidOperationError{Message: "OCI registry blob redirect failed"}
		}
		redirected = true
	}
	if resp.StatusCode != http.StatusOK || !registryIdentityEncoding(resp) {
		drainClose(resp.Body)
		return nil, 0, &InvalidOperationError{Message: "OCI registry blob pull failed"}
	}
	size, valid := registryBlobContentLength(resp)
	headerDigest, digestErr := canonicalRegistryDigest(resp, !redirected)
	_, mediaTypeErr := canonicalRegistryBlobMediaType(resp)
	if !valid || digestErr != nil || mediaTypeErr != nil || (headerDigest != "" && headerDigest != request.Digest) {
		drainClose(resp.Body)
		return nil, 0, &InvalidDataError{Message: "OCI registry blob metadata is invalid"}
	}
	return newLengthDigestVerifyingReadCloser(resp.Body, strings.TrimPrefix(request.Digest, "sha256:"), size), size, nil
}

func singleRegistryRedirectLocation(resp *http.Response) (string, bool) {
	if resp == nil {
		return "", false
	}
	values := resp.Header.Values("Location")
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && len(returnValue) > 0 && len(returnValue) <= 8192 && !strings.ContainsAny(returnValue, "\r\n")
}

func parseRegistryBlobRedirect(raw, region, namespace string) (*url.URL, bool) {
	target, err := url.Parse(raw)
	if err != nil || !target.IsAbs() || target.Scheme != "https" || target.Opaque != "" || target.User != nil || target.Host == "" || target.Fragment != "" ||
		!validRegistryNamespace(namespace) {
		return nil, false
	}
	host := target.Hostname()
	if target.Host != host || host != strings.ToLower(host) || !validRegistryBlobRedirectAuthority(target, region, namespace) {
		return nil, false
	}
	return target, true
}

func validRegistryBlobRedirectAuthority(target *url.URL, region, namespace string) bool {
	if target == nil {
		return false
	}
	host := target.Hostname()
	namespacedHost := namespace + ".objectstorage." + region + ".oci.customer-oci.com"
	genericHost := host == "objectstorage."+region+".oraclecloud.com" || host == "objectstorage."+region+".oci.customer-oci.com"
	if host != namespacedHost && !genericHost {
		return false
	}
	parts := strings.Split(target.EscapedPath(), "/")
	pathNamespacePresent := false
	pathNamespaceMatches := false
	for _, index := range []int{1, 3} {
		if index+4 >= len(parts) || parts[index] != "n" || parts[index+2] != "b" || parts[index+4] != "o" {
			continue
		}
		pathNamespacePresent = true
		pathNamespaceMatches = parts[index+1] == namespace
		break
	}
	if pathNamespacePresent && !pathNamespaceMatches {
		return false
	}
	return host == namespacedHost || (genericHost && pathNamespacePresent && pathNamespaceMatches)
}

func registryBlobContentLength(resp *http.Response) (int64, bool) {
	if resp == nil {
		return 0, false
	}
	values := resp.Header.Values("Content-Length")
	if len(values) != 1 || len(values[0]) < 1 || len(values[0]) > 20 {
		return 0, false
	}
	for _, value := range values[0] {
		if value < '0' || value > '9' {
			return 0, false
		}
	}
	size, err := strconv.ParseUint(values[0], 10, 64)
	if err != nil || strconv.FormatUint(size, 10) != values[0] || size > 64<<30 {
		return 0, false
	}
	return int64(size), true
}

func registryBlobDigestHeader(resp *http.Response) (string, bool, bool) {
	if resp == nil {
		return "", false, false
	}
	values := resp.Header.Values("Docker-Content-Digest")
	if len(values) == 0 {
		return "", false, true
	}
	if len(values) != 1 || !strings.HasPrefix(values[0], "sha256:") || !validSHA256Hex(strings.TrimPrefix(values[0], "sha256:")) {
		return "", true, false
	}
	return values[0], true, true
}

type lengthDigestVerifyingReadCloser struct {
	source    io.ReadCloser
	digest    hash.Hash
	expected  string
	remaining int64
	done      bool
	terminal  error
}

func newLengthDigestVerifyingReadCloser(source io.ReadCloser, expected string, size int64) io.ReadCloser {
	return &lengthDigestVerifyingReadCloser{source: source, digest: sha256.New(), expected: expected, remaining: size}
}

func (r *lengthDigestVerifyingReadCloser) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if r.done {
		return 0, r.terminal
	}
	if r.remaining == 0 {
		return 0, r.finish()
	}
	limit := int64(len(buffer))
	if limit > r.remaining {
		limit = r.remaining
	}
	n, err := r.source.Read(buffer[:int(limit)])
	if n > 0 {
		_, _ = r.digest.Write(buffer[:n])
		r.remaining -= int64(n)
	}
	if err != nil && err != io.EOF {
		r.done = true
		r.terminal = err
		return n, err
	}
	if err == io.EOF && r.remaining > 0 {
		r.done = true
		r.terminal = &InvalidDataError{Message: "provider content length does not match"}
		return n, r.terminal
	}
	if r.remaining == 0 {
		return n, r.finish()
	}
	return n, nil
}

func (r *lengthDigestVerifyingReadCloser) finish() error {
	var probe [1]byte
	n, err := r.source.Read(probe[:])
	if n > 0 {
		r.done = true
		r.terminal = &InvalidDataError{Message: "provider content length does not match"}
		return r.terminal
	}
	if err == nil {
		return nil
	}
	r.done = true
	if err != io.EOF {
		r.terminal = err
		return err
	}
	if hex.EncodeToString(r.digest.Sum(nil)) != r.expected {
		r.terminal = &InvalidDataError{Message: "provider content digest does not match"}
		return r.terminal
	}
	r.terminal = io.EOF
	return io.EOF
}

func (r *lengthDigestVerifyingReadCloser) Close() error {
	closeErr := r.source.Close()
	if !r.done {
		return &InvalidDataError{Message: "provider content was not read to verified EOF"}
	}
	if r.terminal != io.EOF {
		return r.terminal
	}
	return closeErr
}

var (
	_ ObjectStorageProvider       = (*OCIObjectStorageAdapter)(nil)
	_ ScopedObjectStorageProvider = (*OCIObjectStorageScopedAdapter)(nil)
	_ RegistryPullProvider        = (*OCIRegistryAdapter)(nil)
	_ RegistryTagPullProvider     = (*OCIRegistryPullAdapter)(nil)
	_ RequestSigner               = (*OCIRegistryTokenSigner)(nil)
)
