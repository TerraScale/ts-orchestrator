package provider

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// OCIBucketObservation is provider evidence, not ownership authorization. Callers
// compare every identity and ownership tag against the signed destination before
// adding durable ownership records or reading objects.
type OCIBucketObservation struct {
	ID            string            `json:"id"`
	CompartmentID string            `json:"compartmentId"`
	Namespace     string            `json:"namespace"`
	Name          string            `json:"name"`
	FreeformTags  map[string]string `json:"freeformTags"`
}

func ObserveOCIBucket(ctx context.Context, transport *OCIHTTPTransport, namespace, bucket string) (OCIBucketObservation, bool, error) {
	var result OCIBucketObservation
	if err := validateObjectRef(ObjectRef{Namespace: namespace, Bucket: bucket, Name: "observation"}); err != nil {
		return result, false, err
	}
	safe, err := objectReadTransport(transport)
	if err != nil {
		return result, false, err
	}
	response, err := safe.Do(ctx, http.MethodGet, "/n/"+url.PathEscape(namespace)+"/b/"+url.PathEscape(bucket), nil)
	if err != nil {
		return result, false, err
	}
	if response.StatusCode == http.StatusNotFound {
		drainClose(response.Body)
		return result, false, nil
	}
	if response.StatusCode != http.StatusOK {
		drainClose(response.Body)
		return result, false, errors.New("provider: OCI bucket observation failed")
	}
	body, err := ReadBoundedBody(response, 256<<10)
	if err != nil {
		return result, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	// OCI adds unrelated bucket fields; only its exact required identity and
	// ownership evidence are projected here.
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF || result.ID == "" || result.CompartmentID == "" || result.Namespace != namespace || result.Name != bucket || len(result.FreeformTags) > 64 {
		return OCIBucketObservation{}, false, errors.New("provider: invalid OCI bucket observation")
	}
	for k, v := range result.FreeformTags {
		if k == "" || len(k) > 256 || len(v) > 1024 || strings.ContainsAny(k+v, "\x00\r\n") {
			return OCIBucketObservation{}, false, errors.New("provider: invalid OCI bucket ownership tags")
		}
	}
	return result, true, nil
}

type ObjectReadScope struct {
	Namespace, Bucket, Prefix string
	MaxObjectBytes            int64
}

// OCIObjectStorageReader has no mutation methods or mutation journal. The
// capability is bounded to one bucket and object prefix at construction.
type OCIObjectStorageReader struct {
	objects *OCIObjectStorageAdapter
	scope   ObjectReadScope
}

func NewOCIObjectStorageReader(transport *OCIHTTPTransport, scope ObjectReadScope) (*OCIObjectStorageReader, error) {
	if validateObjectRef(ObjectRef{Namespace: scope.Namespace, Bucket: scope.Bucket, Name: "scope"}) != nil || scope.MaxObjectBytes < 1 || scope.MaxObjectBytes > 1<<30 || scope.Prefix == "" || len(scope.Prefix) > 768 || strings.HasPrefix(scope.Prefix, "/") || !strings.HasSuffix(scope.Prefix, "/") || path.Clean(scope.Prefix)+"/" != scope.Prefix || strings.ContainsAny(scope.Prefix, "\\\x00\r\n") {
		return nil, errors.New("provider: invalid OCI object read scope")
	}
	safe, err := objectReadTransport(transport)
	if err != nil {
		return nil, err
	}
	return &OCIObjectStorageReader{objects: &OCIObjectStorageAdapter{ObjectStorage: safe}, scope: scope}, nil
}

func objectReadTransport(t *OCIHTTPTransport) (*OCIHTTPTransport, error) {
	if t == nil || t.Client == nil || t.Signer == nil || t.Config.Service != OCIServiceObjectStorage {
		return nil, errors.New("provider: signed OCI object transport is required")
	}
	if httpTransport, ok := t.Client.Transport.(*http.Transport); ok && httpTransport.TLSClientConfig != nil && (httpTransport.TLSClientConfig.InsecureSkipVerify || (httpTransport.TLSClientConfig.MinVersion != 0 && httpTransport.TLSClientConfig.MinVersion < tls.VersionTLS12)) {
		return nil, errors.New("provider: OCI TLS verification is required")
	}
	client := *t.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return NewOCIHTTPTransport(t.Config, &client, t.Signer)
}

func (r *OCIObjectStorageReader) check(object ObjectRef) error {
	if r == nil || r.objects == nil || validateObjectRef(object) != nil || object.Namespace != r.scope.Namespace || object.Bucket != r.scope.Bucket || !strings.HasPrefix(object.Name, r.scope.Prefix) || object.Name == r.scope.Prefix || path.Clean(object.Name) != object.Name || strings.ContainsAny(object.Name, "\\\x00") {
		return errors.New("provider: object outside OCI read scope")
	}
	return nil
}
func (r *OCIObjectStorageReader) ObserveBucket(ctx context.Context) (OCIBucketObservation, bool, error) {
	if r == nil || r.objects == nil {
		return OCIBucketObservation{}, false, errors.New("provider: unavailable OCI object reader")
	}
	return ObserveOCIBucket(ctx, r.objects.ObjectStorage, r.scope.Namespace, r.scope.Bucket)
}
func (r *OCIObjectStorageReader) HeadObject(ctx context.Context, object ObjectRef) (ObjectMetadata, bool, error) {
	if err := r.check(object); err != nil {
		return ObjectMetadata{}, false, err
	}
	metadata, found, err := r.objects.HeadObject(ctx, object)
	if err == nil && found && (metadata.Size < 1 || metadata.Size > r.scope.MaxObjectBytes) {
		return ObjectMetadata{}, false, errors.New("provider: OCI object exceeds read bound")
	}
	return metadata, found, err
}
func (r *OCIObjectStorageReader) GetObject(ctx context.Context, object ObjectRef) (io.ReadCloser, ObjectMetadata, error) {
	if err := r.check(object); err != nil {
		return nil, ObjectMetadata{}, err
	}
	body, metadata, err := r.objects.GetObject(ctx, object)
	if err != nil {
		return nil, ObjectMetadata{}, err
	}
	if metadata.Size < 1 || metadata.Size > r.scope.MaxObjectBytes {
		body.Close()
		return nil, ObjectMetadata{}, errors.New("provider: OCI object exceeds read bound")
	}
	return &exactObjectReader{body: body, remaining: metadata.Size}, metadata, nil
}

type exactObjectReader struct {
	body      io.ReadCloser
	remaining int64
	failed    bool
}

func (r *exactObjectReader) Read(p []byte) (int, error) {
	if r.failed {
		return 0, errors.New("provider: invalid OCI object length")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		var extra [1]byte
		n, err := r.body.Read(extra[:])
		if n != 0 {
			r.failed = true
			return 0, errors.New("provider: invalid OCI object length")
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.body.Read(p)
	r.remaining -= int64(n)
	if err == io.EOF && r.remaining != 0 {
		r.failed = true
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
func (r *exactObjectReader) Close() error { return r.body.Close() }
