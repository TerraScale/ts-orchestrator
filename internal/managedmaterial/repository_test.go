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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
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

func TestStoredBundleRejectsSemanticallySubstitutedHostMaterial(t *testing.T) {
	spec, signer, _ := initialSQLFixture(t)
	bundle, err := GenerateInitial(spec, signer, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateBundleForSpec(spec, bundle); err != nil {
		t.Fatalf("valid initial bundle was rejected: %v", err)
	}
	for _, test := range []struct {
		name    string
		file    string
		replace []byte
	}{
		{"client config redirect", "client-config.json", []byte(`{"version":1,"listen_addr":"10.0.0.11:9465","certificate_chain":"/foreign/client-chain.pem","private_key":"/foreign/client-private-key.pem","api_key_registry":"/foreign/client-api-keys.json"}`)},
		{"client manifest mismatch", "client-managed-manifest.json", []byte(`{"version":1,"client_config_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","certificate_chain_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","private_key_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","api_key_registry_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)},
		{"SQL schema bundle substitution", sqlSchemaBundleFileName, []byte("substituted schema bundle")},
		{"extra host file", "foreign.key", []byte("foreign")},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := bundle
			changed.Members[0].Files = make(map[string]File, len(bundle.Members[0].Files))
			for name, file := range bundle.Members[0].Files {
				changed.Members[0].Files[name] = file
			}
			changed.Members[0].Files[test.file] = makeFile(test.replace)
			if err := validateBundleForSpec(spec, changed); err == nil {
				t.Fatal("semantically substituted host material was accepted")
			}
		})
	}
}

func TestRepositoryCreateOnlyPinsKMSVersionETagAndBytes(t *testing.T) {
	spec, signer, _ := initialSQLFixture(t)
	controllerPublic, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := GenerateInitial(spec, signer, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	client := new(fakeMaterialObjectClient)
	fencer := new(repositoryFencer)
	repository, err := NewRepository(RepositoryConfig{Region: oci.RegionGRU, Cell: "gru",
		Namespace: "terrascale", Bucket: "ts-preview-gru-20260926-material",
		KMSKeyID: "ocid1.key.oc1.sa-saopaulo-1.material"}, client, fencer)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := repository.CreateInitial(t.Context(), 9, "partition-a", spec, bundle, controllerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if fencer.guards != 2 || client.putCount != 1 || client.getCount != 1 ||
		client.bucket != "ts-preview-gru-20260926-material" || client.namespace != "terrascale" ||
		client.kms != "ocid1.key.oc1.sa-saopaulo-1.material" || client.condition != "*" ||
		ref.ETag != client.etag || ref.VersionID != client.version || ref.SHA256 != client.bodySHA {
		t.Fatal("repository did not require and reobserve a fenced create-only KMS object")
	}
	receipt, err := SignPreparationReceipt("gru", "partition-a", spec, bundle, ref, controllerPrivate, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPreparationReceipt(receipt, controllerPublic, "gru", "partition-a", bundle); err != nil {
		t.Fatalf("controller preparation receipt did not verify: %v", err)
	}
	tampered := receipt
	tampered.Members[0].Files = map[string]string{"authority.tbca": ref.SHA256}
	if err := VerifyPreparationReceipt(tampered, controllerPublic, "gru", "partition-a", bundle); err == nil {
		t.Fatal("tampered member pins were accepted")
	}
	tampered = receipt
	tampered.Object.VersionID = "other-version"
	if err := VerifyPreparationReceipt(tampered, controllerPublic, "gru", "partition-a", bundle); err == nil {
		t.Fatal("substituted object version was accepted")
	}
	recovered, err := repository.ReadPinned(t.Context(), ref, controllerPublic)
	if err != nil || !bytes.Equal(recovered.Authority.Certificate, bundle.Authority.Certificate) ||
		!bytes.Equal(recovered.Retained.AuthoritySigner, bundle.Retained.AuthoritySigner) {
		t.Fatalf("exact versioned bundle read failed: %v", err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ReadPinned(t.Context(), ref, otherPublic); !errors.Is(err, ErrMaterialConflict) {
		t.Fatalf("different controller signer adopted a pinned object: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*RepositoryConfig)
	}{
		{"namespace", func(config *RepositoryConfig) { config.Namespace = "other-namespace" }},
		{"bucket", func(config *RepositoryConfig) { config.Bucket = "other-bucket" }},
		{"kms key", func(config *RepositoryConfig) { config.KMSKeyID = "ocid1.key.oc1.sa-saopaulo-1.other" }},
	} {
		t.Run("copied object in "+test.name, func(t *testing.T) {
			config := repository.config
			test.change(&config)
			copied := *client
			copied.namespace, copied.bucket = config.Namespace, config.Bucket
			otherRepository, err := NewRepository(config, &copied, new(repositoryFencer))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := otherRepository.LookupInitial(t.Context(), "partition-a", spec, controllerPublic); !errors.Is(err, ErrMaterialConflict) {
				t.Fatalf("copied object was adopted on lookup: %v", err)
			}
			if _, err := otherRepository.ReadPinned(t.Context(), ref, controllerPublic); !errors.Is(err, ErrMaterialConflict) {
				t.Fatalf("copied object was adopted by pinned read: %v", err)
			}
			if _, err := otherRepository.CreateInitial(t.Context(), 9, "partition-a", spec, bundle, controllerPrivate); !errors.Is(err, ErrMaterialConflict) {
				t.Fatalf("copied object was adopted by create reconciliation: %v", err)
			}
		})
	}
	wrong := ref
	wrong.VersionID = "other-version"
	if _, err := repository.ReadPinned(t.Context(), wrong, controllerPublic); err == nil {
		t.Fatal("a different object version was accepted")
	}
	wrong = ref
	wrong.SHA256 = hex.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if _, err := repository.ReadPinned(t.Context(), wrong, controllerPublic); err == nil {
		t.Fatal("a different object digest was accepted")
	}
	// An ambiguous response or a later duplicate create never overwrites the
	// object. Exact byte reobservation is required for both outcomes.
	if _, err := repository.CreateInitial(t.Context(), 9, "partition-a", spec, bundle, controllerPrivate); err != nil {
		t.Fatalf("same immutable bundle retry: %v", err)
	}
	other, err := GenerateInitial(spec, signer, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateInitial(t.Context(), 9, "partition-a", spec, other, controllerPrivate); !errors.Is(err, ErrMaterialConflict) {
		t.Fatalf("different signer attempted same immutable generation: %v", err)
	}
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
	if _, err := repository.CreateInitial(t.Context(), 9, "partition-a", spec, bundle, controllerPrivate); err != nil {
		t.Fatalf("lost acknowledgement was not resolved by exact read: %v", err)
	}
	fencer.deny = true
	if _, err := repository.CreateInitial(t.Context(), 9, "partition-a", spec, bundle, controllerPrivate); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("fenced create was permitted: %v", err)
	}
	if client.putCount != 1 {
		t.Fatal("fenced create reached OCI")
	}
}
