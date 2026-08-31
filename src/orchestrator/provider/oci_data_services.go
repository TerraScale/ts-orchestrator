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
	"unicode/utf8"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

type OCIObjectStorageScope struct {
	Namespace    string
	LedgerBucket string
	BackupBucket string
}

type OCIObjectStorageAdapter struct {
	objectStorage *OCIHTTPTransport
	journal       ProviderMutationJournal
	authority     DurableObjectStorageAuthority
	namespace     string
	buckets       map[string]struct{}
}

func NewOCIObjectStorageAdapter(transport *OCIHTTPTransport, journal ProviderMutationJournal, scope OCIObjectStorageScope, authority DurableObjectStorageAuthority) (*OCIObjectStorageAdapter, error) {
	if err := validateOCIAdapter(transport, OCIServiceObjectStorage, journal); err != nil || transport.Client == nil ||
		transport.Config.Endpoint.Scheme != "https" || !validOCIServiceHost(OCIServiceObjectStorage, transport.Config.Region, transport.Config.Endpoint.Host) {
		return nil, &InvalidOperationError{Message: "OCI Object Storage transport is unavailable or has the wrong authority"}
	}
	if authority == nil || !authority.AuthoritativeDurable() || !validObjectStoragePart(scope.Namespace, 128, false) ||
		!validObjectStoragePart(scope.LedgerBucket, 256, false) || !validObjectStoragePart(scope.BackupBucket, 256, false) ||
		scope.LedgerBucket == scope.BackupBucket {
		return nil, &InvalidOperationError{Message: "OCI Object Storage durable scope is unavailable"}
	}
	signer, ok := transport.Signer.(*InstancePrincipalSigner)
	if !ok {
		return nil, &InvalidOperationError{Message: "OCI Object Storage instance-principal signer is unavailable"}
	}
	signerSnapshot, err := signer.snapshot()
	if err != nil {
		return nil, err
	}
	endpoint := *transport.Config.Endpoint
	config := transport.Config
	config.Endpoint = &endpoint
	client := *transport.Client
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	objectStorage := *transport
	objectStorage.Config = config
	objectStorage.Client = &client
	objectStorage.Signer = signerSnapshot
	return &OCIObjectStorageAdapter{
		objectStorage: &objectStorage,
		journal:       journal,
		authority:     authority,
		namespace:     scope.Namespace,
		buckets:       map[string]struct{}{scope.LedgerBucket: {}, scope.BackupBucket: {}},
	}, nil
}

func validObjectStoragePart(value string, maximum int, allowSlash bool) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.Contains(value, "\\") {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f || (!allowSlash && character == '/') {
			return false
		}
	}
	if allowSlash {
		for _, segment := range strings.Split(value, "/") {
			if segment == "" || segment == "." || segment == ".." {
				return false
			}
		}
	}
	return true
}

func validateObjectRef(object ObjectRef) error {
	if !validObjectStoragePart(object.Namespace, 128, false) || !validObjectStoragePart(object.Bucket, 256, false) ||
		!validObjectStoragePart(object.Name, 1024, true) {
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
	return metadata, nil
}

func (a *OCIObjectStorageAdapter) PutObject(ctx context.Context, request ObjectPutRequest) (ObjectMetadata, error) {
	if err := a.requireObjectAuthority(ctx, request.Object); err != nil {
		return ObjectMetadata{}, err
	}
	if int64(len(request.Content)) > a.objectStorage.Config.MaxBodyBytes || !validSHA256Hex(request.SHA256) || objectSHA256(request.Content) != request.SHA256 {
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
	etag, etagErr := canonicalOCIETag(resp)
	digest, digestErr := canonicalOCIHeader(resp, "opc-meta-terrascale-sha256", true, validSHA256Hex)
	size, validSize := registryBlobContentLength(resp)
	_, mediaErr := canonicalOCIHeader(resp, "Content-Type", true, func(value string) bool { return value == "application/octet-stream" })
	_, encodingErr := canonicalOCIHeader(resp, "Content-Encoding", true, func(value string) bool { return value == "identity" })
	if etagErr != nil || digestErr != nil || !validSize || mediaErr != nil || encodingErr != nil {
		return ObjectMetadata{}, &InvalidDataError{Message: "OCI Object Storage metadata is incomplete"}
	}
	return ObjectMetadata{ETag: etag, SHA256: digest, Size: size}, nil
}

type objectListPage struct {
	Names            []string
	NextStartWith    string
	HasNextStartWith bool
}

func decodeObjectListPage(raw []byte, object ObjectRef) (objectListPage, error) {
	if len(raw) == 0 || registryJSONHasDuplicateProperties(raw) {
		return objectListPage{}, &InvalidDataError{Message: "OCI Object Storage list response is invalid"}
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil || envelope == nil || len(envelope) < 1 || len(envelope) > 2 {
		return objectListPage{}, &InvalidDataError{Message: "OCI Object Storage list response is invalid"}
	}
	objectsRaw, present := envelope["objects"]
	if !present {
		return objectListPage{}, &InvalidDataError{Message: "OCI Object Storage list response has no objects"}
	}
	for key := range envelope {
		if key != "objects" && key != "nextStartWith" {
			return objectListPage{}, &InvalidDataError{Message: "OCI Object Storage list response has unknown data"}
		}
	}
	var entries []json.RawMessage
	if json.Unmarshal(objectsRaw, &entries) != nil || entries == nil || len(entries) > maximumOCIListResults {
		return objectListPage{}, &InvalidDataError{Message: "OCI Object Storage list objects are invalid"}
	}
	page := objectListPage{Names: make([]string, 0, len(entries))}
	for _, entry := range entries {
		var fields map[string]json.RawMessage
		if json.Unmarshal(entry, &fields) != nil || fields == nil || len(fields) != 1 {
			return objectListPage{}, &InvalidDataError{Message: "OCI Object Storage list object is invalid"}
		}
		var name string
		if json.Unmarshal(fields["name"], &name) != nil || !validObjectStoragePart(name, 1024, true) || !strings.HasPrefix(name, object.Name) {
			return objectListPage{}, &InvalidDataError{Message: "OCI Object Storage list object is outside requested prefix"}
		}
		page.Names = append(page.Names, name)
	}
	nextRaw, hasNext := envelope["nextStartWith"]
	if !hasNext {
		return page, nil
	}
	var next string
	if json.Unmarshal(nextRaw, &next) != nil || !validOCIPageToken(next) || !validObjectStoragePart(next, 1024, true) || !strings.HasPrefix(next, object.Name) {
		return objectListPage{}, &InvalidDataError{Message: "OCI Object Storage continuation is invalid"}
	}
	page.NextStartWith = next
	page.HasNextStartWith = true
	return page, nil
}

func objectStorageListPath(object ObjectRef, start string) string {
	query := url.Values{"fields": {"name"}, "limit": {strconv.Itoa(maximumOCIListResults)}, "prefix": {object.Name}}
	if start != "" {
		query.Set("start", start)
	}
	return "/n/" + url.PathEscape(object.Namespace) + "/b/" + url.PathEscape(object.Bucket) + "/o?" + query.Encode()
}

func (a *OCIObjectStorageAdapter) objectExistsByExactList(ctx context.Context, object ObjectRef) (bool, error) {
	if err := a.requireObjectAuthority(ctx, object); err != nil {
		return false, err
	}
	seenTokens := make(map[string]struct{})
	seenNames := make(map[string]struct{})
	start := ""
	for pagesRead := 1; pagesRead <= maximumOCIPages; pagesRead++ {
		resp, err := a.objectStorage.DoWithHeaders(ctx, http.MethodGet, objectStorageListPath(object, start), nil, map[string]string{
			"Accept":          "application/json",
			"Accept-Encoding": "identity",
		})
		if err != nil {
			return false, err
		}
		if resp.StatusCode != http.StatusOK {
			drainClose(resp.Body)
			return false, &InvalidOperationError{Message: "OCI Object Storage exact list failed"}
		}
		declaredLength, validLength := registryBlobContentLength(resp)
		_, mediaErr := canonicalOCIHeader(resp, "Content-Type", true, func(value string) bool { return value == "application/json" })
		_, encodingErr := canonicalOCIHeader(resp, "Content-Encoding", true, func(value string) bool { return value == "identity" })
		if !validLength || mediaErr != nil || encodingErr != nil {
			drainClose(resp.Body)
			return false, &InvalidDataError{Message: "OCI Object Storage list metadata is invalid"}
		}
		raw, err := ReadBoundedBody(resp, a.objectStorage.Config.MaxBodyBytes)
		if err != nil {
			return false, err
		}
		if int64(len(raw)) != declaredLength {
			return false, &InvalidDataError{Message: "OCI Object Storage list length does not match"}
		}
		page, err := decodeObjectListPage(raw, object)
		if err != nil {
			return false, err
		}
		for _, name := range page.Names {
			if _, duplicate := seenNames[name]; duplicate {
				return false, &InvalidDataError{Message: "OCI Object Storage list repeated an object"}
			}
			seenNames[name] = struct{}{}
			if name == object.Name {
				return true, nil
			}
		}
		if !page.HasNextStartWith {
			return false, nil
		}
		if pagesRead == maximumOCIPages {
			return false, &InvalidDataError{Message: "OCI Object Storage list exceeded page bound"}
		}
		if _, duplicate := seenTokens[page.NextStartWith]; duplicate {
			return false, &InvalidDataError{Message: "OCI Object Storage list continuation cycled"}
		}
		if _, duplicateObject := seenNames[page.NextStartWith]; duplicateObject {
			return false, &InvalidDataError{Message: "OCI Object Storage continuation repeated an object"}
		}
		seenTokens[page.NextStartWith] = struct{}{}
		start = page.NextStartWith
	}
	return false, &InvalidDataError{Message: "OCI Object Storage list did not complete"}
}

func (a *OCIObjectStorageAdapter) HeadObject(ctx context.Context, object ObjectRef) (ObjectMetadata, bool, error) {
	if err := a.requireObjectAuthority(ctx, object); err != nil {
		return ObjectMetadata{}, false, err
	}
	resp, err := a.objectStorage.DoWithHeaders(ctx, http.MethodHead, objectStoragePath(object), nil, map[string]string{"Accept-Encoding": "identity"})
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

func (a *OCIObjectStorageAdapter) GetObject(ctx context.Context, object ObjectRef) (io.ReadCloser, ObjectMetadata, error) {
	if err := a.requireObjectAuthority(ctx, object); err != nil {
		return nil, ObjectMetadata{}, err
	}
	resp, err := a.objectStorage.DoWithHeaders(ctx, http.MethodGet, objectStoragePath(object), nil, map[string]string{
		"Accept":          "application/octet-stream",
		"Accept-Encoding": "identity",
	})
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
	if !validCanonicalETag(request.IfMatch) {
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
		result, mergeErr := mergeObjectMutationResult(record.Result, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: request.IfMatch}, objectStoragePath(request.Object))
		if mergeErr != nil {
			return mergeErr
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

func NewOCIRegistryTokenSigner(username, token string) (*OCIRegistryTokenSigner, error) {
	namespace, principal, found := strings.Cut(username, "/")
	if !found || !validRegistryNamespace(namespace) || !validRegistryPrincipal(principal) || len(username) > 256 || len(token) < 1 || len(token) > 4096 ||
		strings.TrimSpace(username) != username || strings.TrimSpace(token) != token || strings.Contains(username, ":") ||
		containsASCIIControl(username) || containsASCIIControl(token) {
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

func containsASCIIControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func validRegistryNamespace(namespace string) bool {
	if len(namespace) < 1 || len(namespace) > 63 {
		return false
	}
	for _, character := range namespace {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validRegistryPrincipal(principal string) bool {
	if len(principal) < 1 || strings.HasPrefix(principal, "/") || strings.HasSuffix(principal, "/") || strings.Contains(principal, "//") {
		return false
	}
	for _, character := range principal {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

func validRegistryRepositoryComponent(component string) bool {
	if len(component) < 1 || len(component) > 128 {
		return false
	}
	alphaNumeric := func(value byte) bool {
		return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9')
	}
	index := 0
	for index < len(component) && alphaNumeric(component[index]) {
		index++
	}
	if index == 0 {
		return false
	}
	for index < len(component) {
		switch component[index] {
		case '.':
			index++
		case '_':
			index++
			if index < len(component) && component[index] == '_' {
				index++
			}
		case '-':
			for index < len(component) && component[index] == '-' {
				index++
			}
		default:
			return false
		}
		start := index
		for index < len(component) && alphaNumeric(component[index]) {
			index++
		}
		if start == index {
			return false
		}
	}
	return true
}

func canonicalRegistryRepository(repository string, includeNamespace bool) (string, error) {
	if len(repository) < 1 || len(repository) > 255 || strings.TrimSpace(repository) != repository || containsASCIIControl(repository) ||
		strings.Contains(repository, "\\") {
		return "", &errs.Argument{Message: "registry repository is invalid"}
	}
	parts := strings.Split(repository, "/")
	minimum := 1
	if includeNamespace {
		minimum = 2
	}
	if len(parts) < minimum || len(parts) > 8 {
		return "", &errs.Argument{Message: "registry repository is invalid"}
	}
	for _, part := range parts {
		if !validRegistryRepositoryComponent(part) {
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

func (a *OCIRegistryAdapter) PullManifest(ctx context.Context, request RegistryManifestRequest) (RegistryManifest, error) {
	if a == nil || a.registry == nil {
		return RegistryManifest{}, &InvalidOperationError{Message: "OCI registry adapter is unavailable"}
	}
	repository, err := a.registryRepositoryPath(request.Repository)
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
	if resp.StatusCode != http.StatusOK || !registryIdentityEncoding(resp) {
		drainClose(resp.Body)
		return RegistryManifest{}, &InvalidOperationError{Message: "OCI registry manifest pull failed"}
	}
	declaredLength, validLength := registryBlobContentLength(resp)
	if !validLength || declaredLength > a.registry.Config.MaxBodyBytes {
		drainClose(resp.Body)
		return RegistryManifest{}, &InvalidDataError{Message: "OCI registry manifest content length is invalid"}
	}
	body, err := ReadBoundedBody(resp, a.registry.Config.MaxBodyBytes)
	if err != nil {
		return RegistryManifest{}, err
	}
	if int64(len(body)) != declaredLength {
		return RegistryManifest{}, &InvalidDataError{Message: "OCI registry manifest content length is invalid"}
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
	repository, err := a.registryRepositoryPath(request.Repository)
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

type digestVerifyingReadCloser struct {
	source   io.ReadCloser
	digest   hash.Hash
	expected string
	done     bool
}

func newDigestVerifyingReadCloser(source io.ReadCloser, expected string) io.ReadCloser {
	return &digestVerifyingReadCloser{source: source, digest: sha256.New(), expected: expected}
}

func (r *digestVerifyingReadCloser) Read(buffer []byte) (int, error) {
	n, err := r.source.Read(buffer)
	if n > 0 {
		_, _ = r.digest.Write(buffer[:n])
	}
	if err == io.EOF && !r.done {
		r.done = true
		if hex.EncodeToString(r.digest.Sum(nil)) != r.expected {
			return n, &InvalidDataError{Message: "provider content digest does not match"}
		}
	}
	return n, err
}

func (r *digestVerifyingReadCloser) Close() error { return r.source.Close() }

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
	_ ObjectStorageProvider = (*OCIObjectStorageAdapter)(nil)
	_ RegistryPullProvider  = (*OCIRegistryAdapter)(nil)
	_ RequestSigner         = (*OCIRegistryTokenSigner)(nil)
)
