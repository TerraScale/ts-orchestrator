package managedmaterial

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
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

func TestLiveS3ConfigKeepsGenericWireAndDigest(t *testing.T) {
	target := nativeTestTarget(t)
	target.NativeOCIRoot = nil
	wantJSON := `{"version":1,"ack_profile":"object_durable","bucket":"ts-preview-gru-20260926-terrabase-live","region":"sa-saopaulo-1","endpoint":"https://grxnmoqvrcdv.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com"}`
	config, err := target.ConfigJSON()
	if err != nil || string(config) != wantJSON {
		t.Fatalf("generic signed config = %q, error = %v", config, err)
	}
	digest, err := target.Digest()
	if err != nil || digest != "6bde29d3f4f0de935a3d87745240ebce8d4b400a62e1fe16b017b09104964bad" {
		t.Fatalf("generic target digest = %q, error = %v", digest, err)
	}
	target.Credential.VersionNumber++
	rotatedConfig, err := target.ConfigJSON()
	if err != nil || !bytes.Equal(rotatedConfig, config) {
		t.Fatalf("credential rotation changed generic config: %v", err)
	}
	rotatedDigest, err := target.Digest()
	if err != nil || rotatedDigest != digest {
		t.Fatalf("credential rotation changed generic digest: %v", err)
	}
}

func TestNativeOCIRootConfigAndTargetDigest(t *testing.T) {
	target := nativeTestTarget(t)
	wantJSON := `{"version":1,"ack_profile":"object_durable","bucket":"ts-preview-gru-20260926-terrabase-live","region":"sa-saopaulo-1","endpoint":"https://grxnmoqvrcdv.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com","native_oci_root":{"namespace":"grxnmoqvrcdv"}}`
	config, err := target.ConfigJSON()
	if err != nil || string(config) != wantJSON {
		t.Fatalf("native signed config = %q, error = %v", config, err)
	}
	if bytes.Contains(config, []byte(target.Credential.SecretOCID)) {
		t.Fatal("native signed config contains a secret reference")
	}
	digest, err := target.Digest()
	if err != nil || digest != nativeTestDigest {
		t.Fatalf("native target digest = %q, error = %v", digest, err)
	}
	target.Credential.VersionNumber++
	rotatedConfig, err := target.ConfigJSON()
	if err != nil || !bytes.Equal(rotatedConfig, config) {
		t.Fatalf("credential rotation changed native config: %v", err)
	}
	rotatedDigest, err := target.Digest()
	if err != nil || rotatedDigest != digest {
		t.Fatalf("credential rotation changed native digest: %v", err)
	}
}

func TestNativeOCIRootRejectsInvalidNamespaceAndEndpoint(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*LiveS3Target)
	}{
		{"empty namespace", func(target *LiveS3Target) { target.NativeOCIRoot.Namespace = "" }},
		{"uppercase namespace", func(target *LiveS3Target) { target.NativeOCIRoot.Namespace = "GRXNMOQVRCDV" }},
		{"leading hyphen", func(target *LiveS3Target) { target.NativeOCIRoot.Namespace = "-gru" }},
		{"trailing hyphen", func(target *LiveS3Target) { target.NativeOCIRoot.Namespace = "gru-" }},
		{"long namespace", func(target *LiveS3Target) { target.NativeOCIRoot.Namespace = strings.Repeat("a", 65) }},
		{"missing endpoint", func(target *LiveS3Target) { target.Endpoint = "" }},
		{"wrong namespace endpoint", func(target *LiveS3Target) {
			target.Endpoint = "https://other.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com"
		}},
		{"wrong region endpoint", func(target *LiveS3Target) {
			target.Endpoint = "https://grxnmoqvrcdv.compat.objectstorage.us-sanjose-1.oci.customer-oci.com"
		}},
		{"oraclecloud endpoint", func(target *LiveS3Target) {
			target.Endpoint = "https://grxnmoqvrcdv.compat.objectstorage.sa-saopaulo-1.oraclecloud.com"
		}},
		{"endpoint path", func(target *LiveS3Target) { target.Endpoint += "/bucket" }},
		{"uppercase bucket", func(target *LiveS3Target) { target.Bucket = "Uppercase" }},
		{"bucket leading hyphen", func(target *LiveS3Target) { target.Bucket = "-bucket" }},
		{"unsupported region", func(target *LiveS3Target) {
			target.Region = "xx-nowhere-1"
			target.Endpoint = "https://grxnmoqvrcdv.compat.objectstorage.xx-nowhere-1.oci.customer-oci.com"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := nativeTestTarget(t)
			test.edit(&target)
			if err := target.Validate(); err == nil {
				t.Fatal("invalid native root target was accepted")
			}
			if _, err := target.ConfigJSON(); err == nil {
				t.Fatal("invalid native root config was emitted")
			}
			if _, err := target.Digest(); err == nil {
				t.Fatal("invalid native root digest was emitted")
			}
		})
	}
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
