package managedmaterial

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

const (
	nativeTestNamespace = "grxnmoqvrcdv"
	nativeTestBucket    = "ts-preview-gru-20260926-terrabase-live"
	nativeTestEndpoint  = "https://grxnmoqvrcdv.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com"
	nativeTestDigest    = "678dcc5f87692c0885126111c6828c7181bedd6cdb268f655ac442e1846a20cb"
)

func nativeTestTarget(t *testing.T) LiveS3Target {
	t.Helper()
	spec, _, _ := initialFixture(t)
	target := spec.LiveS3
	target.Bucket = nativeTestBucket
	target.Endpoint = nativeTestEndpoint
	target.NativeOCIRoot = &NativeOCIRoot{Namespace: nativeTestNamespace}
	return target
}

func TestGenerateInitialBindsNativeOCIRootForBothMembers(t *testing.T) {
	spec, signer, _ := initialFixture(t)
	spec.LiveS3 = nativeTestTarget(t)
	bundle, err := GenerateInitial(spec, signer, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	config, err := spec.LiveS3.ConfigJSON()
	if err != nil {
		t.Fatal(err)
	}
	configHash := sha256.Sum256(config)
	for index, member := range bundle.Members {
		file := member.Files["signed-v2-s3-config.json"]
		if !bytes.Equal(file.Contents, config) || file.SHA256 != hex.EncodeToString(configHash[:]) {
			t.Fatalf("member %d has different native config or file pin", index)
		}
	}
	input, err := nativeInitialInput(spec, bundle)
	if err != nil || !bytes.Equal(input.SignedV2S3Config, config) || input.ExpectedS3TargetDigest != nativeTestDigest {
		t.Fatalf("native validation input lacks the produced config or target digest: %v", err)
	}
}
