//go:build linux

package managedmaterial

import (
	"bytes"
	"encoding/base64"
	"encoding/json/v2"
	"os"
	"testing"
	"time"
)

// The optional output is consumed by a separate real TerraBase process gate.
// It is built from the same producer bundle and encoder used before OCI Put.
func TestNativeRequestUsesProducedInitialMaterial(t *testing.T) {
	spec, signer, _ := initialFixture(t)
	bundle, err := GenerateInitial(spec, signer, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	input, err := nativeInitialInput(spec, bundle)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeNativeValidationRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	var request nativeValidationRequest
	if err := json.Unmarshal(wire, &request, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	config, err := spec.LiveS3.ConfigJSON()
	if err != nil {
		t.Fatal(err)
	}
	if request.Version != 1 || request.Mode != "alpha_object_durable" ||
		request.AuthorityCertificate != base64.StdEncoding.EncodeToString(bundle.Authority.Certificate) ||
		request.TrustedKey != base64.StdEncoding.EncodeToString(bundle.Authority.TrustedKey) ||
		request.SignedV2S3Config != base64.StdEncoding.EncodeToString(config) ||
		request.Expected.ConfigurationID != bundle.Authority.ConfigurationID ||
		request.Expected.CertificateSHA256 != sha256Hex(bundle.Authority.Certificate) ||
		request.Expected.TrustedKeySHA256 != sha256Hex(bundle.Authority.TrustedKey) ||
		request.Expected.SignedV2S3ConfigSHA256 != sha256Hex(config) ||
		bytes.Contains(wire, []byte(spec.LiveS3.Credential.SecretOCID)) ||
		bytes.Contains(wire, []byte("secret_access_key")) {
		t.Fatal("native request differs from public produced material or carries a secret reference")
	}
	if path := os.Getenv("TS_ALPHA_NATIVE_REQUEST_FILE"); path != "" {
		if err := os.WriteFile(path, wire, 0600); err != nil {
			t.Fatal(err)
		}
		t.Logf("producer-derived native request: %s SHA-256 %s", path, sha256Hex(wire))
	}
}
