package host

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"github.com/oracle/oci-go-sdk/v65/secrets"
)

type fakeS3BundleClient struct {
	requests []secrets.GetSecretBundleRequest
	secretID string
	version  int64
	content  string
	err      error
}

func (client *fakeS3BundleClient) GetSecretBundle(_ context.Context, request secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error) {
	client.requests = append(client.requests, request)
	if client.err != nil {
		return secrets.GetSecretBundleResponse{}, client.err
	}
	return secrets.GetSecretBundleResponse{SecretBundle: secrets.SecretBundle{
		SecretId: new(client.secretID), VersionNumber: new(client.version),
		SecretBundleContent: secrets.Base64SecretBundleContentDetails{Content: new(client.content)},
	}}, nil
}

func TestManagedS3ResolverPinsVersionAndSanitizesFailure(t *testing.T) {
	reference := oci.SecretVersionReference{SecretOCID: "ocid1.secret.oc1.sa-saopaulo-1.alpha", VersionNumber: 3}
	secret := `{"version":1,"access_key_id":"customer-key","secret_access_key":"customer-secret"}`
	client := &fakeS3BundleClient{secretID: reference.SecretOCID, version: reference.VersionNumber,
		content: base64.StdEncoding.EncodeToString([]byte(secret))}
	resolver := &OCIS3CredentialResolver{client: client}
	for range 2 {
		credentials, err := resolver.Resolve(t.Context(), reference)
		if err != nil || credentials.AccessKeyID != "customer-key" || credentials.SecretAccessKey != "customer-secret" {
			t.Fatalf("resolve exact version: %v", err)
		}
	}
	if len(client.requests) != 2 {
		t.Fatal("exact Vault version was not refetched")
	}
	for _, request := range client.requests {
		if request.SecretId == nil || *request.SecretId != reference.SecretOCID ||
			request.VersionNumber == nil || *request.VersionNumber != reference.VersionNumber ||
			request.SecretVersionName != nil || request.Stage != "" {
			t.Fatal("Vault request did not pin the signed numeric version")
		}
	}
	client.version++
	if _, err := resolver.Resolve(t.Context(), reference); err == nil {
		t.Fatal("Vault response substituted a different version")
	}
	client.version = reference.VersionNumber
	client.content = base64.StdEncoding.EncodeToString([]byte(`{"version":1,"access_key_id":"customer-key","secret_access_key":"customer-secret","extra":1}`))
	if _, err := resolver.Resolve(t.Context(), reference); err == nil {
		t.Fatal("unknown secret payload field was accepted")
	}
	client.err = errors.New("provider response leaked customer-secret")
	if _, err := resolver.Resolve(t.Context(), reference); err == nil || strings.Contains(err.Error(), "customer-secret") {
		t.Fatalf("provider error disclosed credentials: %v", err)
	}
}
