package provider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestObjectUploadLargeHTTPBodyKeepsControlAPIBound(t *testing.T) {
	content := bytes.Repeat([]byte("large-object"), (17<<20)/12+1)
	hash := sha256.Sum256(content)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "PUT" || r.URL.Path != "/n/ns/b/bucket/o/control/snapshot" || !strings.Contains(r.Header.Get("Authorization"), "Signature version=") {
			t.Error("wrong signed object request")
		}
		actual, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(actual, content) || r.Header.Get("x-content-sha256") != base64.StdEncoding.EncodeToString(hash[:]) || r.ContentLength != int64(len(content)) {
			t.Error("large body binding differs")
		}
		w.Header().Set("Etag", "object-etag")
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewInstancePrincipalSigner("ST$fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := NewOCIServiceTransportConfig(OCIServiceObjectStorage, "sa-saopaulo-1", "https://objectstorage.sa-saopaulo-1.oraclecloud.com")
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxBodyBytes = 16 << 20
	cfg.MaxObjectBytes = 20 << 20
	transport, err := NewOCIHTTPTransport(cfg, &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		copy := r.Clone(r.Context())
		u := *r.URL
		u.Scheme = endpoint.Scheme
		u.Host = endpoint.Host
		copy.URL = &u
		return http.DefaultTransport.RoundTrip(copy)
	})}, signer)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewOCIObjectStorageAdapter(transport, testJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	request := ObjectPutRequest{Object: ObjectRef{Namespace: "ns", Bucket: "bucket", Name: "control/snapshot"}, Content: content, SHA256: objectSHA256(content)}
	request.Mutation = testMutation("object.put", ObjectPutMutationScope(request), ObjectPutMutationFingerprint(request), 1)
	if _, err = adapter.PutObject(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("missing actual HTTP upload")
	}
	for _, path := range []string{"/n/ns/b/bucket", "/n/ns/b/bucket/o/control/snapshot", "/20160918/instances"} {
		if _, err = transport.Do(context.Background(), http.MethodPut, path, bytes.NewReader(content)); err == nil {
			t.Fatal("generic API inherited large object bound")
		}
	}
	if _, err = transport.PutObjectBody(context.Background(), request.Object, io.LimitReader(infiniteObjectBytes{}, (20<<20)+1), nil); err == nil {
		t.Fatal("oversized object accepted")
	}
	if calls.Load() != 1 {
		t.Fatal("overflow reached network")
	}
	core := cfg
	core.Service = OCIServiceCore
	core.Endpoint, _ = url.Parse("https://iaas.sa-saopaulo-1.oraclecloud.com/")
	if _, err = NewOCIHTTPTransport(core, nil, signer); err == nil {
		t.Fatal("large limit admitted for control service")
	}
}

type infiniteObjectBytes struct{}

func (infiniteObjectBytes) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestScopedObjectReaderOwnershipAndActualReadBounds(t *testing.T) {
	body := []byte("snapshot")
	calls := 0
	reportSize := int64(len(body))
	transport := testOCITransport(t, OCIServiceObjectStorage, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path == "/n/ns/b/bucket" {
			return testHTTPResponse(200, `{"id":"bucket-id","compartmentId":"compartment","namespace":"ns","name":"bucket","freeformTags":{"terrascale-managed":"bucket","terrascale-region":"sfo"},"extraProviderField":true}`, nil), nil
		}
		return testHTTPResponse(200, string(body), http.Header{"Etag": {"immutable"}, "Opc-Meta-Terrascale-Sha256": {objectSHA256(body)}, "Content-Length": {fmt.Sprint(reportSize)}}), nil
	}))
	transport.Signer = objectTestSigner{}
	reader, err := NewOCIObjectStorageReader(transport, ObjectReadScope{Namespace: "ns", Bucket: "bucket", Prefix: "control/request/", MaxObjectBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	bucket, found, err := reader.ObserveBucket(context.Background())
	if err != nil || !found || bucket.ID != "bucket-id" || bucket.CompartmentID != "compartment" || !HasOCIOwnershipTags(bucket.FreeformTags, "bucket", "sfo") {
		t.Fatalf("observation: %+v %v", bucket, err)
	}
	object := ObjectRef{Namespace: "ns", Bucket: "bucket", Name: "control/request/snapshot"}
	stream, metadata, err := reader.GetObject(context.Background(), object)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(stream)
	closed := stream.Close()
	if err != nil || closed != nil || !bytes.Equal(got, body) || metadata.Size != 8 {
		t.Fatal("bounded read failed")
	}
	before := calls
	for _, bad := range []ObjectRef{{Namespace: "ns", Bucket: "other", Name: object.Name}, {Namespace: "other", Bucket: "bucket", Name: object.Name}, {Namespace: "ns", Bucket: "bucket", Name: "control/request/../other"}, {Namespace: "ns", Bucket: "bucket", Name: "control/request-substituted/key"}} {
		if _, _, err = reader.HeadObject(context.Background(), bad); err == nil {
			t.Fatal("unscoped read accepted")
		}
	}
	if calls != before {
		t.Fatal("unscoped read reached transport")
	}
	reportSize = 100
	if _, _, err = reader.GetObject(context.Background(), object); err == nil {
		t.Fatal("oversized metadata accepted")
	}
	reportSize = 3
	stream, _, err = reader.GetObject(context.Background(), object)
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(stream)
	stream.Close()
	if err == nil || len(got) != 3 {
		t.Fatal("body overflow not bounded")
	}
	reportSize = 12
	stream, _, err = reader.GetObject(context.Background(), object)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(stream)
	stream.Close()
	if err == nil {
		t.Fatal("truncated body accepted")
	}
}

type objectTestSigner struct{}

func (objectTestSigner) Sign(r *http.Request) error {
	r.Header.Set("Authorization", "fixture")
	return nil
}

func TestBucketObservationRejectsSubstitutionAndRedirect(t *testing.T) {
	for _, body := range []string{`{"id":"id","compartmentId":"c","namespace":"other","name":"bucket"}`, `{"id":"id","compartmentId":"c","namespace":"ns","name":"other"}`, `{"compartmentId":"c","namespace":"ns","name":"bucket"}`, `{"id":"id","namespace":"ns","name":"bucket"}`} {
		transport := testOCITransport(t, OCIServiceObjectStorage, roundTripFunc(func(*http.Request) (*http.Response, error) { return testHTTPResponse(200, body, nil), nil }))
		transport.Signer = objectTestSigner{}
		if _, _, err := ObserveOCIBucket(context.Background(), transport, "ns", "bucket"); err == nil {
			t.Fatal("substituted bucket admitted")
		}
	}
	calls := 0
	transport := testOCITransport(t, OCIServiceObjectStorage, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return testHTTPResponse(307, "", http.Header{"Location": {"https://attacker.invalid/"}}), nil
	}))
	transport.Signer = objectTestSigner{}
	if _, _, err := ObserveOCIBucket(context.Background(), transport, "ns", "bucket"); err == nil || calls != 1 {
		t.Fatal("bucket redirect followed")
	}
}
