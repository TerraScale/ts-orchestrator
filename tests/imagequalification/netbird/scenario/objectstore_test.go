package scenario

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func TestObjectStoreCrossesSignedSDKAndProtectsImmutableArchive(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store := &ObjectStore{Root: t.TempDir(), PublicKey: &key.PublicKey}
	server := httptest.NewServer(store)
	defer server.Close()
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..fixture", "ocid1.user.oc1..fixture", "sa-saopaulo-1", "fixture", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	client.Host = server.URL
	policy := common.NoRetryPolicy()
	client.Configuration.RetryPolicy = &policy
	bucket, err := client.GetBucket(t.Context(), objectstorage.GetBucketRequest{NamespaceName: new("tenancy"), BucketName: new("netbird-sfo")})
	if err != nil || bucket.KmsKeyId == nil || !strings.Contains(*bucket.KmsKeyId, "us-sanjose-1") {
		t.Fatalf("signed regional bucket: %v", err)
	}
	wire := []byte("actual fixture archive bytes")
	digest := sha256.Sum256(wire)
	name := "netbird/foundation/20261016T000000.000000000Z/" + hex.EncodeToString(digest[:]) + ".tar"
	put := func(checksum string) error {
		_, err := client.PutObject(t.Context(), objectstorage.PutObjectRequest{NamespaceName: new("tenancy"), BucketName: new("netbird-sfo"), ObjectName: new(name), PutObjectBody: io.NopCloser(bytes.NewReader(wire)), ContentLength: new(int64(len(wire))), IfNoneMatch: new("*"), OpcSseKmsKeyId: new("ocid1.key.oc1.us-sanjose-1.netbird-sfo"), OpcContentSha256: new(checksum)})
		return err
	}
	if err := put(base64.StdEncoding.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	if err := put(base64.StdEncoding.EncodeToString(digest[:])); err == nil {
		t.Fatal("immutable archive overwritten")
	}
	got, err := client.GetObject(t.Context(), objectstorage.GetObjectRequest{NamespaceName: new("tenancy"), BucketName: new("netbird-sfo"), ObjectName: new(name)})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(got.Content)
	if err != nil {
		t.Fatal(err)
	}
	_ = got.Content.Close()
	if !bytes.Equal(body, wire) {
		t.Fatal("signed download changed bytes")
	}
	if err := put(base64.StdEncoding.EncodeToString(make([]byte, 32))); err == nil {
		t.Fatal("wrong checksum accepted")
	}
	response, err := http.Get(server.URL + "/n/tenancy/b/netbird-sfo")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("unsigned request accepted")
	}
}
