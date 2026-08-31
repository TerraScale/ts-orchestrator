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

type OCIObjectStorageAdapter struct {
	ObjectStorage *OCIHTTPTransport
	Journal       ProviderMutationJournal
}

func NewOCIObjectStorageAdapter(transport *OCIHTTPTransport, journal ProviderMutationJournal) (*OCIObjectStorageAdapter, error) {
	if err := validateOCIAdapter(transport, OCIServiceObjectStorage, journal); err != nil {
		return nil, err
	}
	return &OCIObjectStorageAdapter{ObjectStorage: transport, Journal: journal}, nil
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

func (a *OCIObjectStorageAdapter) PutObject(ctx context.Context, request ObjectPutRequest) (ObjectMetadata, error) {
	if a == nil || validateOCIAdapter(a.ObjectStorage, OCIServiceObjectStorage, a.Journal) != nil {
		return ObjectMetadata{}, &InvalidOperationError{Message: "OCI Object Storage adapter is unavailable"}
	}
	if err := validateObjectRef(request.Object); err != nil {
		return ObjectMetadata{}, err
	}
	if len(request.Content) == 0 || int64(len(request.Content)) > a.ObjectStorage.Config.MaxBodyBytes || !validSHA256Hex(request.SHA256) || objectSHA256(request.Content) != request.SHA256 {
		return ObjectMetadata{}, &errs.Argument{Message: "object storage content binding is invalid"}
	}
	if err := expectJSONMutation(request.Mutation, "object.put", ObjectPutMutationScope(request), objectPutBinding(request)); err != nil {
		return ObjectMetadata{}, err
	}
	record, err := prepareMutation(ctx, a.Journal, request.Mutation)
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
		metadata, found, err := a.HeadObject(ctx, request.Object)
		if err != nil {
			return ObjectMetadata{}, err
		}
		if !found || metadata.SHA256 != request.SHA256 || metadata.Size != int64(len(request.Content)) {
			return ObjectMetadata{}, &ProviderOutcomeUnknownError{}
		}
		if err := markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: metadata.ETag}); err != nil {
			return ObjectMetadata{}, err
		}
		return metadata, nil
	}
	if _, err := a.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
		return ObjectMetadata{}, err
	}
	resp, err := a.ObjectStorage.DoWithHeaders(ctx, http.MethodPut, objectStoragePath(request.Object), bytes.NewReader(request.Content), map[string]string{
		"Content-Type":               "application/octet-stream",
		"If-None-Match":              "*",
		"opc-meta-terrascale-sha256": request.SHA256,
	})
	if err != nil {
		if indeterminate(err) {
			metadata, found, readErr := a.HeadObject(ctx, request.Object)
			if readErr == nil && found && metadata.SHA256 == request.SHA256 && metadata.Size == int64(len(request.Content)) {
				if err := markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: metadata.ETag}); err != nil {
					return ObjectMetadata{}, err
				}
				return metadata, nil
			}
			return ObjectMetadata{}, finishUnknown(ctx, a.Journal, request.Mutation)
		}
		return ObjectMetadata{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusPreconditionFailed {
			drainClose(resp.Body)
			metadata, found, readErr := a.HeadObject(ctx, request.Object)
			if readErr == nil && found && metadata.SHA256 == request.SHA256 && metadata.Size == int64(len(request.Content)) {
				if err := markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: metadata.ETag}); err != nil {
					return ObjectMetadata{}, err
				}
				return metadata, nil
			}
			return ObjectMetadata{}, knownFailure(ctx, a.Journal, request.Mutation, "object-conflict")
		}
		return ObjectMetadata{}, ociMutationFailure(ctx, a.Journal, request.Mutation, resp)
	}
	drainClose(resp.Body)
	metadata := ObjectMetadata{ETag: safeHeader(resp, "etag"), SHA256: request.SHA256, Size: int64(len(request.Content))}
	if metadata.ETag == "" {
		return ObjectMetadata{}, finishUnknown(ctx, a.Journal, request.Mutation)
	}
	if err := markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: metadata.ETag}); err != nil {
		return ObjectMetadata{}, err
	}
	return metadata, nil
}

func objectMetadataFromResponse(resp *http.Response) (ObjectMetadata, error) {
	if resp == nil {
		return ObjectMetadata{}, &InvalidDataError{Message: "OCI Object Storage response is missing"}
	}
	size, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err != nil || size < 0 {
		return ObjectMetadata{}, &InvalidDataError{Message: "OCI Object Storage content length is invalid"}
	}
	metadata := ObjectMetadata{ETag: safeHeader(resp, "etag"), SHA256: safeHeader(resp, "opc-meta-terrascale-sha256"), Size: size}
	if metadata.ETag == "" || !validSHA256Hex(metadata.SHA256) {
		return ObjectMetadata{}, &InvalidDataError{Message: "OCI Object Storage metadata is incomplete"}
	}
	return metadata, nil
}

func (a *OCIObjectStorageAdapter) HeadObject(ctx context.Context, object ObjectRef) (ObjectMetadata, bool, error) {
	if a == nil || a.ObjectStorage == nil {
		return ObjectMetadata{}, false, &InvalidOperationError{Message: "OCI Object Storage adapter is unavailable"}
	}
	if err := validateObjectRef(object); err != nil {
		return ObjectMetadata{}, false, err
	}
	resp, err := a.ObjectStorage.Do(ctx, http.MethodHead, objectStoragePath(object), nil)
	if err != nil {
		return ObjectMetadata{}, false, err
	}
	if resp.StatusCode == http.StatusNotFound {
		drainClose(resp.Body)
		exists, listErr := a.objectExistsAuthorized(ctx, object)
		if listErr != nil || !exists {
			return ObjectMetadata{}, false, listErr
		}
		return ObjectMetadata{}, false, &InvalidOperationError{Message: "OCI Object Storage metadata read was denied for a listed object"}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
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
	if a == nil || a.ObjectStorage == nil {
		return nil, ObjectMetadata{}, &InvalidOperationError{Message: "OCI Object Storage adapter is unavailable"}
	}
	if err := validateObjectRef(object); err != nil {
		return nil, ObjectMetadata{}, err
	}
	resp, err := a.ObjectStorage.Do(ctx, http.MethodGet, objectStoragePath(object), nil)
	if err != nil {
		return nil, ObjectMetadata{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		drainClose(resp.Body)
		return nil, ObjectMetadata{}, &InvalidOperationError{Message: "OCI Object Storage object read failed"}
	}
	metadata, err := objectMetadataFromResponse(resp)
	if err != nil {
		drainClose(resp.Body)
		return nil, ObjectMetadata{}, err
	}
	return newDigestVerifyingReadCloser(resp.Body, metadata.SHA256), metadata, nil
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

func (a *OCIObjectStorageAdapter) DeleteObject(ctx context.Context, request ObjectDeleteRequest) error {
	if a == nil || validateOCIAdapter(a.ObjectStorage, OCIServiceObjectStorage, a.Journal) != nil {
		return &InvalidOperationError{Message: "OCI Object Storage adapter is unavailable"}
	}
	if err := validateObjectRef(request.Object); err != nil {
		return err
	}
	if !isSafeETag(request.IfMatch) {
		return &errs.Argument{Message: "object delete ETag fence is invalid"}
	}
	if err := expectJSONMutation(request.Mutation, "object.delete", ObjectDeleteMutationScope(request), objectDeleteBinding(request)); err != nil {
		return err
	}
	record, err := prepareMutation(ctx, a.Journal, request.Mutation)
	if err != nil {
		return err
	}
	if _, done, err := completedMutation(record); done {
		return err
	}
	_, found, err := a.HeadObject(ctx, request.Object)
	if err != nil {
		return err
	}
	if !found {
		return markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: request.IfMatch})
	}
	if record.State == MutationSubmitted || record.State == MutationUnknown {
		return finishUnknownWithResult(ctx, a.Journal, request.Mutation, record.Result)
	}
	if _, err := a.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
		return err
	}
	resp, err := a.ObjectStorage.DoWithHeaders(ctx, http.MethodDelete, objectStoragePath(request.Object), nil, map[string]string{"If-Match": request.IfMatch})
	if err != nil {
		if indeterminate(err) {
			if exists, readErr := a.objectExistsAuthorized(ctx, request.Object); readErr == nil && !exists {
				return markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: request.IfMatch})
			}
			return finishUnknown(ctx, a.Journal, request.Mutation)
		}
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		drainClose(resp.Body)
		exists, readErr := a.objectExistsAuthorized(ctx, request.Object)
		if readErr != nil {
			return finishUnknown(ctx, a.Journal, request.Mutation)
		}
		if !exists {
			return markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: request.IfMatch})
		}
		return knownFailure(ctx, a.Journal, request.Mutation, "provider-not-authorized")
	}
	if resp.StatusCode == http.StatusNoContent {
		drainClose(resp.Body)
		result := ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: request.IfMatch}
		exists, readErr := a.objectExistsAuthorized(ctx, request.Object)
		if readErr != nil || exists {
			return finishUnknownWithResult(ctx, a.Journal, request.Mutation, result)
		}
		return markSucceeded(ctx, a.Journal, request.Mutation, result)
	}
	return ociMutationFailure(ctx, a.Journal, request.Mutation, resp)
}

type OCIRegistryAdapter struct{ Registry *OCIHTTPTransport }

// OCIRegistryTokenSigner supplies the Docker Registry v2 basic credential
// expected by OCIR. The token stays process-local and errors never include it.
type OCIRegistryTokenSigner struct{ username, token string }

func (s *OCIRegistryTokenSigner) String() string   { return "OCIRegistryTokenSigner{<redacted>}" }
func (s *OCIRegistryTokenSigner) GoString() string { return "OCIRegistryTokenSigner{<redacted>}" }

func NewOCIRegistryTokenSigner(username, token string) (*OCIRegistryTokenSigner, error) {
	if len(username) < 1 || len(username) > 256 || len(token) < 1 || len(token) > 4096 ||
		strings.TrimSpace(username) != username || strings.ContainsAny(username+token, "\r\n") {
		return nil, &errs.Argument{Message: "OCI registry credential is invalid"}
	}
	return &OCIRegistryTokenSigner{username: username, token: token}, nil
}

func (s *OCIRegistryTokenSigner) Sign(request *http.Request) error {
	if s == nil || s.username == "" || s.token == "" || request == nil {
		return &InvalidOperationError{Message: "OCI registry credential is unavailable"}
	}
	request.SetBasicAuth(s.username, s.token)
	return nil
}

func NewOCIRegistryAdapter(transport *OCIHTTPTransport) (*OCIRegistryAdapter, error) {
	if transport == nil || transport.Config.Service != OCIServiceRegistry {
		return nil, &InvalidOperationError{Message: "OCI registry transport is unavailable or has the wrong authority"}
	}
	return &OCIRegistryAdapter{Registry: transport}, nil
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
		parts[index] = url.PathEscape(part)
	}
	return strings.Join(parts, "/"), nil
}

func validRegistryReference(reference string) bool {
	if len(reference) < 1 || len(reference) > 128 || strings.ContainsAny(reference, "\r\n/") {
		return false
	}
	if strings.HasPrefix(reference, "sha256:") {
		return validSHA256Hex(strings.TrimPrefix(reference, "sha256:"))
	}
	return true
}

func (a *OCIRegistryAdapter) PullManifest(ctx context.Context, request RegistryManifestRequest) (RegistryManifest, error) {
	if a == nil || a.Registry == nil {
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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		drainClose(resp.Body)
		return RegistryManifest{}, &InvalidOperationError{Message: "OCI registry manifest pull failed"}
	}
	body, err := ReadBoundedBody(resp, a.Registry.Config.MaxBodyBytes)
	if err != nil {
		return RegistryManifest{}, err
	}
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if header := safeHeader(resp, "Docker-Content-Digest"); header == "" || header != digest || (strings.HasPrefix(request.Reference, "sha256:") && request.Reference != digest) {
		return RegistryManifest{}, &InvalidDataError{Message: "OCI registry manifest digest is invalid"}
	}
	mediaType := safeHeader(resp, "Content-Type")
	if mediaType == "" || len(mediaType) > 256 {
		return RegistryManifest{}, &InvalidDataError{Message: "OCI registry manifest media type is invalid"}
	}
	return RegistryManifest{Digest: digest, MediaType: mediaType, Content: body}, nil
}

func (a *OCIRegistryAdapter) PullBlob(ctx context.Context, request RegistryBlobRequest) (io.ReadCloser, int64, error) {
	if a == nil || a.Registry == nil {
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
	redirected := false
	if resp.StatusCode == http.StatusTemporaryRedirect {
		target, redirectErr := registryBlobRedirectTarget(resp, a.Registry.Config.Region)
		drainClose(resp.Body)
		if redirectErr != nil {
			return nil, 0, redirectErr
		}
		redirectRequest, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if requestErr != nil {
			return nil, 0, &InvalidDataError{Message: "OCI registry blob redirect is invalid"}
		}
		redirectRequest.Header.Set("Accept", "application/octet-stream")
		// OCIR Basic credentials authorize only the registry authority. Build a
		// new request and disable the jar so neither Authorization nor registry
		// cookies can reach the presigned Object Storage target.
		redirectClient := *a.Registry.Client
		redirectClient.Jar = nil
		redirectClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err = redirectClient.Do(redirectRequest)
		if err != nil {
			return nil, 0, redactOCIError(err, "OCI registry blob redirect failed")
		}
		redirected = true
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		drainClose(resp.Body)
		return nil, 0, &InvalidOperationError{Message: "OCI registry blob pull failed"}
	}
	size, err := registryBlobContentLength(resp)
	responseDigest, digestPresent, digestErr := registryBlobResponseDigest(resp)
	if err != nil || digestErr != nil || (!redirected && (!digestPresent || responseDigest != request.Digest)) || (redirected && digestPresent && responseDigest != request.Digest) {
		drainClose(resp.Body)
		return nil, 0, &InvalidDataError{Message: "OCI registry blob metadata is invalid"}
	}
	return newBoundedDigestVerifyingReadCloser(resp.Body, strings.TrimPrefix(request.Digest, "sha256:"), size), size, nil
}

func registryBlobRedirectTarget(resp *http.Response, region string) (*url.URL, error) {
	if resp == nil {
		return nil, &InvalidDataError{Message: "OCI registry blob redirect is invalid"}
	}
	locations := resp.Header.Values("Location")
	if len(locations) != 1 || len(locations[0]) < 1 || len(locations[0]) > 8192 || strings.ContainsAny(locations[0], "\r\n") {
		return nil, &InvalidDataError{Message: "OCI registry blob redirect is invalid"}
	}
	target, err := url.Parse(locations[0])
	if err != nil || !target.IsAbs() || target.Opaque != "" || target.Scheme != "https" || target.User != nil ||
		target.Host == "" || target.Host != target.Hostname() || target.Fragment != "" || !validRegistryBlobRedirectHost(region, target.Host) {
		return nil, &InvalidDataError{Message: "OCI registry blob redirect is invalid"}
	}
	return target, nil
}

func validRegistryBlobRedirectHost(region, host string) bool {
	if host == "objectstorage."+region+".oraclecloud.com" {
		return true
	}
	base := "objectstorage." + region + ".oci.customer-oci.com"
	if host == base {
		return true
	}
	suffix := "." + base
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	namespace := strings.TrimSuffix(host, suffix)
	if len(namespace) < 1 || len(namespace) > 63 || namespace[0] == '-' || namespace[len(namespace)-1] == '-' {
		return false
	}
	for _, ch := range namespace {
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
			return false
		}
	}
	return true
}

func registryBlobContentLength(resp *http.Response) (int64, error) {
	if resp == nil {
		return 0, &InvalidDataError{Message: "OCI registry blob metadata is invalid"}
	}
	values := resp.Header.Values("Content-Length")
	if len(values) != 1 || len(values[0]) < 1 || len(values[0]) > 20 {
		return 0, &InvalidDataError{Message: "OCI registry blob metadata is invalid"}
	}
	size, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil || size < 0 || size > 64<<30 || strconv.FormatInt(size, 10) != values[0] {
		return 0, &InvalidDataError{Message: "OCI registry blob metadata is invalid"}
	}
	return size, nil
}

func registryBlobResponseDigest(resp *http.Response) (string, bool, error) {
	if resp == nil {
		return "", false, &InvalidDataError{Message: "OCI registry blob metadata is invalid"}
	}
	values := resp.Header.Values("Docker-Content-Digest")
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 || len(values[0]) != len("sha256:")+64 || !strings.HasPrefix(values[0], "sha256:") || !validSHA256Hex(strings.TrimPrefix(values[0], "sha256:")) {
		return "", false, &InvalidDataError{Message: "OCI registry blob metadata is invalid"}
	}
	return values[0], true, nil
}

type digestVerifyingReadCloser struct {
	source       io.ReadCloser
	digest       hash.Hash
	expected     string
	expectedSize int64
	read         int64
	done         bool
}

func newDigestVerifyingReadCloser(source io.ReadCloser, expected string) io.ReadCloser {
	return &digestVerifyingReadCloser{source: source, digest: sha256.New(), expected: expected, expectedSize: -1}
}

func newBoundedDigestVerifyingReadCloser(source io.ReadCloser, expected string, expectedSize int64) io.ReadCloser {
	return &digestVerifyingReadCloser{source: source, digest: sha256.New(), expected: expected, expectedSize: expectedSize}
}

func (r *digestVerifyingReadCloser) Read(buffer []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	if r.expectedSize >= 0 {
		remaining := r.expectedSize - r.read
		if int64(len(buffer)) > remaining+1 {
			buffer = buffer[:remaining+1]
		}
	}
	n, err := r.source.Read(buffer)
	if r.expectedSize >= 0 {
		remaining := r.expectedSize - r.read
		if int64(n) > remaining {
			contentBytes := int(remaining)
			if contentBytes > 0 {
				r.read += int64(contentBytes)
				_, _ = r.digest.Write(buffer[:contentBytes])
			}
			r.done = true
			return contentBytes, &InvalidDataError{Message: "provider content length does not match"}
		}
	}
	if n > 0 {
		r.read += int64(n)
		_, _ = r.digest.Write(buffer[:n])
	}
	if err == io.EOF && !r.done {
		r.done = true
		if r.expectedSize >= 0 && r.read != r.expectedSize {
			return n, &InvalidDataError{Message: "provider content length does not match"}
		}
		if hex.EncodeToString(r.digest.Sum(nil)) != r.expected {
			return n, &InvalidDataError{Message: "provider content digest does not match"}
		}
	}
	return n, err
}

func (r *digestVerifyingReadCloser) Close() error { return r.source.Close() }

var (
	_ ObjectStorageProvider = (*OCIObjectStorageAdapter)(nil)
	_ RegistryPullProvider  = (*OCIRegistryAdapter)(nil)
	_ RequestSigner         = (*OCIRegistryTokenSigner)(nil)
)
