package managedmaterial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type repositoryFencer struct {
	guards int
	deny   bool
}

func (fencer *repositoryFencer) Current() authority.Snapshot { return authority.Snapshot{} }
func (fencer *repositoryFencer) Guard(_ context.Context, epoch uint64) error {
	fencer.guards++
	if fencer.deny || epoch != 9 {
		return authority.ErrFenced
	}
	return nil
}

type fakeMaterialObjectClient struct {
	name, bucket, namespace, kms, condition, checksum string
	version, etag, bodySHA                            string
	body                                              []byte
	putCount, getCount                                int
	loseAck                                           bool
}

type fakeMaterialNotFound struct{}

func (fakeMaterialNotFound) Error() string          { return "not found" }
func (fakeMaterialNotFound) GetHTTPStatusCode() int { return 404 }

func (client *fakeMaterialObjectClient) PutObject(_ context.Context, request objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	client.putCount++
	if request.ObjectName == nil || request.BucketName == nil || request.NamespaceName == nil ||
		request.OpcSseKmsKeyId == nil || request.IfNoneMatch == nil || request.OpcContentSha256 == nil ||
		request.ContentLength == nil || request.PutObjectBody == nil {
		return objectstorage.PutObjectResponse{}, errors.New("incomplete OCI material write")
	}
	client.name, client.bucket, client.namespace, client.kms = *request.ObjectName, *request.BucketName,
		*request.NamespaceName, *request.OpcSseKmsKeyId
	client.condition, client.checksum = *request.IfNoneMatch, *request.OpcContentSha256
	body, err := io.ReadAll(request.PutObjectBody)
	if err != nil {
		return objectstorage.PutObjectResponse{}, err
	}
	if err := request.PutObjectBody.Close(); err != nil {
		return objectstorage.PutObjectResponse{}, err
	}
	sum := sha256.Sum256(body)
	if int64(len(body)) != *request.ContentLength || client.checksum != base64.StdEncoding.EncodeToString(sum[:]) ||
		request.OpcChecksumAlgorithm != objectstorage.PutObjectOpcChecksumAlgorithmSha256 || client.condition != "*" {
		return objectstorage.PutObjectResponse{}, errors.New("incomplete create-only KMS request")
	}
	if client.body != nil {
		return objectstorage.PutObjectResponse{}, errors.New("precondition failed")
	}
	client.body = bytes.Clone(body)
	client.bodySHA = hex.EncodeToString(sum[:])
	client.version = "version-one"
	client.etag = `"etag-one"`
	if client.loseAck {
		client.loseAck = false
		return objectstorage.PutObjectResponse{}, errors.New("connection reset after commit")
	}
	return objectstorage.PutObjectResponse{VersionId: new(client.version), ETag: new(client.etag)}, nil
}

func (client *fakeMaterialObjectClient) GetObject(_ context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	client.getCount++
	if client.body == nil {
		return objectstorage.GetObjectResponse{}, fakeMaterialNotFound{}
	}
	if request.ObjectName == nil || *request.ObjectName != client.name ||
		request.NamespaceName == nil || *request.NamespaceName != client.namespace ||
		request.BucketName == nil || *request.BucketName != client.bucket ||
		request.VersionId != nil && *request.VersionId != client.version ||
		request.IfMatch != nil && *request.IfMatch != client.etag {
		return objectstorage.GetObjectResponse{}, errors.New("exact object unavailable")
	}
	length := int64(len(client.body))
	return objectstorage.GetObjectResponse{Content: io.NopCloser(bytes.NewReader(client.body)),
		ContentLength: &length, VersionId: new(client.version), ETag: new(client.etag)}, nil
}

func TestRepositoryUnknownPutAndFencingNeverGrantObjectAuthority(t *testing.T) {
	spec, signer, _ := initialFixture(t)
	_, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := GenerateInitial(spec, signer, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeMaterialObjectClient{loseAck: true}
	fencer := new(repositoryFencer)
	repository, err := NewRepository(RepositoryConfig{Region: oci.RegionGRU, Cell: "gru",
		Namespace: "terrascale", Bucket: "material", KMSKeyID: "ocid1.key.oc1.sa-saopaulo-1.material"}, client, fencer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateInitial(t.Context(), 9, "0000000000Z3WK359G2W66CVT8", spec, bundle, controllerPrivate); err != nil {
		t.Fatalf("lost acknowledgement was not resolved by exact read: %v", err)
	}
	fencer.deny = true
	if _, err := repository.CreateInitial(t.Context(), 9, "0000000000Z3WK359G2W66CVT8", spec, bundle, controllerPrivate); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("fenced create was permitted: %v", err)
	}
	if client.putCount != 1 {
		t.Fatal("fenced create reached OCI")
	}
}
