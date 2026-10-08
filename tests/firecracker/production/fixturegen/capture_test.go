package fixturegen

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func TestCapturePreservesExactKeyBytesAndCAS(t *testing.T) {
	now := time.Date(2026, 9, 26, 18, 0, 0, 0, time.UTC)
	store, err := NewCapturingObjectStorage(now)
	if err != nil {
		t.Fatal(err)
	}
	key := "private/bootstrap/slot/head.json"
	put := func(body []byte, noneMatch, match *string) (objectstorage.PutObjectResponse, error) {
		digest := sha256.Sum256(body)
		return store.PutObject(t.Context(), objectstorage.PutObjectRequest{
			NamespaceName: new("namespace-a"), BucketName: new("head-bucket"), ObjectName: &key,
			PutObjectBody: io.NopCloser(bytes.NewReader(body)), ContentLength: new(int64(len(body))),
			IfNoneMatch: noneMatch, IfMatch: match, OpcSseKmsKeyId: new("ocid1.key.oc1.sa-saopaulo-1.head"),
			OpcChecksumAlgorithm: objectstorage.PutObjectOpcChecksumAlgorithmSha256,
			OpcContentSha256:     new(base64.StdEncoding.EncodeToString(digest[:])),
		})
	}
	created, err := put([]byte(`{"generation":1}`), new("*"), nil)
	if err != nil || created.ETag == nil {
		t.Fatalf("create exact key: %+v, %v", created, err)
	}
	if _, err := put([]byte(`{"generation":2}`), new("*"), nil); !isCaptureStatus(err, http.StatusPreconditionFailed) {
		t.Fatalf("duplicate immutable create = %v", err)
	}
	if _, err := put([]byte(`{"generation":2}`), nil, new("0000000000RNVXNPAX5Y5BB8RY")); !isCaptureStatus(err, http.StatusPreconditionFailed) {
		t.Fatalf("stale HEAD update = %v", err)
	}
	updated, err := put([]byte(`{"generation":2}`), nil, created.ETag)
	if err != nil || updated.ETag == nil || *updated.ETag == *created.ETag {
		t.Fatalf("CAS HEAD update: %+v, %v", updated, err)
	}
	read, err := store.GetObject(t.Context(), objectstorage.GetObjectRequest{
		NamespaceName: new("namespace-a"), BucketName: new("head-bucket"), ObjectName: &key,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer read.Content.Close()
	body, err := io.ReadAll(read.Content)
	if err != nil || !bytes.Equal(body, []byte(`{"generation":2}`)) || *read.ETag != *updated.ETag ||
		read.LastModified == nil || !read.LastModified.Time.Equal(now) ||
		read.RawResponse.Header.Get("Date") != now.Format(http.TimeFormat) {
		t.Fatalf("captured read lost OCI metadata: body=%q response=%+v error=%v", body, read, err)
	}
	snapshot := store.Snapshot()
	if len(snapshot) != 1 || snapshot[0].ObjectName != key || !bytes.Equal(snapshot[0].Body, body) || store.PutCount() != 2 {
		t.Fatalf("capture inventory mismatch: %+v puts=%d", snapshot, store.PutCount())
	}
	snapshot[0].Body[0] = 'X'
	if got := store.Snapshot()[0].Body[0]; got != '{' {
		t.Fatal("capture snapshot aliases stored body")
	}
	missing := "private/bootstrap/slot/unknown.json"
	_, err = store.GetObject(t.Context(), objectstorage.GetObjectRequest{
		NamespaceName: new("namespace-a"), BucketName: new("head-bucket"), ObjectName: &missing,
	})
	if !isCaptureStatus(err, http.StatusNotFound) {
		t.Fatalf("unknown exact key = %v", err)
	}
	misses := store.MissingSnapshot()
	if len(misses) != 1 || misses[0].ObjectName != missing {
		t.Fatalf("captured exact missing reads = %+v", misses)
	}
}

func isCaptureStatus(err error, status int) bool {
	service, ok := errors.AsType[interface {
		error
		common.ServiceError
	}](err)
	return ok && service.GetHTTPStatusCode() == status
}

func TestCaptureBoundsDistinctExpectedMissingKeys(t *testing.T) {
	store, err := NewCapturingObjectStorage(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for index := range 512 {
		name := fmt.Sprintf("private/bootstrap/missing-%03d.json", index)
		_, err := store.GetObject(t.Context(), objectstorage.GetObjectRequest{
			NamespaceName: new("namespace-a"), BucketName: new("head-bucket"), ObjectName: &name,
		})
		if !isCaptureStatus(err, http.StatusNotFound) {
			t.Fatalf("expected missing %d: %v", index, err)
		}
	}
	if got := len(store.MissingSnapshot()); got != 512 {
		t.Fatalf("captured missing keys = %d", got)
	}
	extra := "private/bootstrap/missing-extra.json"
	_, err = store.GetObject(t.Context(), objectstorage.GetObjectRequest{
		NamespaceName: new("namespace-a"), BucketName: new("head-bucket"), ObjectName: &extra,
	})
	if err == nil || isCaptureStatus(err, http.StatusNotFound) {
		t.Fatalf("unbounded distinct missing key accepted: %v", err)
	}
}
