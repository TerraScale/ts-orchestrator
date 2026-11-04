package netbird

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/secrets"
)

type fakeBundleClient func(context.Context, secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error)

func (client fakeBundleClient) GetSecretBundle(ctx context.Context, request secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error) {
	return client(ctx, request)
}

func setupKeyBundle(id, key string) secrets.GetSecretBundleResponse {
	encoded := base64.StdEncoding.EncodeToString([]byte(key))
	return secrets.GetSecretBundleResponse{SecretBundle: secrets.SecretBundle{
		SecretId: new(id), VersionNumber: new(int64(7)),
		SecretBundleContent: secrets.Base64SecretBundleContentDetails{Content: new(encoded)},
	}}
}

func TestVaultReadsCurrentSecretWithNoSDKRetriesAndBoundedContext(t *testing.T) {
	id := testConfig().SetupKeySecretID
	client := fakeBundleClient(func(ctx context.Context, request secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error) {
		if request.SecretId == nil || *request.SecretId != id || request.Stage != secrets.GetSecretBundleStageCurrent ||
			request.VersionNumber != nil || request.SecretVersionName != nil || request.RequestMetadata.RetryPolicy == nil {
			t.Fatalf("wrong secret request: %+v", request)
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 15*time.Second {
			t.Fatal("Vault request is not bounded")
		}
		return setupKeyBundle(id, "\n"+testSetupKey+"\n"), nil
	})
	key, err := readCurrentSetupKey(t.Context(), id, client)
	if err != nil || string(key) != testSetupKey {
		t.Fatalf("unexpected key bytes or error: length=%d error=%v", len(key), err)
	}
}

func shortVaultBackoff(t *testing.T) {
	t.Helper()
	previous := vaultBackoff
	vaultBackoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { vaultBackoff = previous })
}

func TestVaultRejectsMismatchedMalformedAndOversizedSecretsWithoutLeaking(t *testing.T) {
	shortVaultBackoff(t)
	id := testConfig().SetupKeySecretID
	for _, scenario := range []string{"error"} {
		t.Run(scenario, func(t *testing.T) {
			client := fakeBundleClient(func(context.Context, secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error) {
				response := setupKeyBundle(id, testSetupKey)
				switch scenario {
				case "error":
					return secrets.GetSecretBundleResponse{}, errors.New("OCI returned sensitive body: " + testSetupKey)
				case "wrong-id":
					response.SecretId = new("ocid1.vaultsecret.oc1.sa-saopaulo-1.another")
				case "missing-version":
					response.VersionNumber = nil
				case "oversized":
					response = setupKeyBundle(id, strings.Repeat("x", 129))
				case "malformed-key":
					response = setupKeyBundle(id, testSetupKey+" injected")
				case "malformed-base64":
					response.SecretBundleContent = secrets.Base64SecretBundleContentDetails{Content: new("not base64")}
				case "missing-content":
					response.SecretBundleContent = nil
				}
				return response, nil
			})
			key, err := readCurrentSetupKey(t.Context(), id, client)
			if err == nil || key != nil || strings.Contains(err.Error(), testSetupKey) {
				t.Fatalf("untrusted secret response accepted or exposed: bytes=%d error=%v", len(key), err)
			}
		})
	}
}
