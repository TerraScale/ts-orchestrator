package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
		return ObjectMetadata{}, false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		drainClose(resp.Body)
		return ObjectMetadata{}, false, &InvalidOperationError{Message: "OCI Object Storage metadata read failed"}
	}
	metadata, err := objectMetadataFromResponse(resp)
	drainClose(resp.Body)
	return metadata, err == nil, err
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
		return err
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent {
		drainClose(resp.Body)
		return markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: request.IfMatch})
	}
	return ociMutationFailure(ctx, a.Journal, request.Mutation, resp)
}

type OCIRegistryAdapter struct{ Registry *OCIHTTPTransport }

// OCIRegistryTokenSigner supplies the Docker Registry v2 basic credential
// expected by OCIR. The token stays process-local and errors never include it.
type OCIRegistryTokenSigner struct{ username, token string }

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
		location, valid := singleRegistryRedirectLocation(resp)
		drainClose(resp.Body)
		if !valid {
			return nil, 0, &InvalidDataError{Message: "OCI registry blob redirect is invalid"}
		}
		target, valid := parseRegistryBlobRedirect(location, a.Registry.Config.Region)
		if !valid {
			return nil, 0, &InvalidDataError{Message: "OCI registry blob redirect is invalid"}
		}
		redirectRequest, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if requestErr != nil {
			return nil, 0, &InvalidDataError{Message: "OCI registry blob redirect is invalid"}
		}
		redirectRequest.Header.Set("Accept", "application/octet-stream")
		redirectRequest.Header.Del("Authorization")
		redirectRequest.Header.Del("Cookie")
		client := *a.Registry.Client
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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		drainClose(resp.Body)
		return nil, 0, &InvalidOperationError{Message: "OCI registry blob pull failed"}
	}
	size, valid := registryBlobContentLength(resp)
	headerDigest, digestPresent, digestValid := registryBlobDigestHeader(resp)
	if !valid || !digestValid || (!redirected && !digestPresent) || (digestPresent && headerDigest != request.Digest) {
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

func parseRegistryBlobRedirect(raw, region string) (*url.URL, bool) {
	target, err := url.Parse(raw)
	if err != nil || !target.IsAbs() || target.Scheme != "https" || target.Opaque != "" || target.User != nil || target.Host == "" || target.Fragment != "" {
		return nil, false
	}
	host := target.Hostname()
	if target.Host != host || host != strings.ToLower(host) || !validRegistryBlobRedirectHost(host, region) {
		return nil, false
	}
	return target, true
}

func validRegistryBlobRedirectHost(host, region string) bool {
	if host == "objectstorage."+region+".oraclecloud.com" || host == "objectstorage."+region+".oci.customer-oci.com" {
		return true
	}
	suffix := ".objectstorage." + region + ".oci.customer-oci.com"
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	namespace := strings.TrimSuffix(host, suffix)
	if len(namespace) < 1 || len(namespace) > 63 || namespace[0] == '-' || namespace[len(namespace)-1] == '-' {
		return false
	}
	for _, value := range namespace {
		if (value < 'a' || value > 'z') && (value < '0' || value > '9') && value != '-' {
			return false
		}
	}
	return true
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

func (r *lengthDigestVerifyingReadCloser) Close() error { return r.source.Close() }

var (
	_ ObjectStorageProvider = (*OCIObjectStorageAdapter)(nil)
	_ RegistryPullProvider  = (*OCIRegistryAdapter)(nil)
	_ RequestSigner         = (*OCIRegistryTokenSigner)(nil)
)
