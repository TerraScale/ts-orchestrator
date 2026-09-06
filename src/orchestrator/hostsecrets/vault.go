package hostsecrets

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

// UnwrapDataKey delegates AES-256-GCM unwrapping to the Region's OCI Vault.
// Instance principal federation uses the same bounded worker and disabled SDK
// logging as host bootstrap. No API-key file or plaintext fallback is accepted.
func UnwrapDataKey(ctx context.Context, region, endpoint, keyID, keyVersionID, ciphertext string, associated map[string]string) ([]byte, error) {
	if ctx == nil || !validCryptoEndpoint(region, endpoint) || !provider.IsOCID(keyID, "key") || !provider.IsOCID(keyVersionID, "keyversion") || len(ciphertext) == 0 || len(ciphertext) > 8192 {
		return nil, ErrFetch
	}
	select {
	case identityWorker <- struct{}{}:
	case <-ctx.Done():
		return nil, ErrFetch
	}
	type result struct {
		key []byte
		err error
	}
	completed := make(chan result)
	go func() {
		defer func() { <-identityWorker }()
		key, err := unwrapDataKey(ctx, region, endpoint, keyID, keyVersionID, ciphertext, associated, credentialTransport())
		select {
		case completed <- result{key, err}:
		case <-ctx.Done():
			erase(key)
		}
	}()
	select {
	case outcome := <-completed:
		return outcome.key, outcome.err
	case <-ctx.Done():
		return nil, ErrFetch
	}
}

func validCryptoEndpoint(region, endpoint string) bool {
	if !provider.ValidOCIRegion(region) {
		return false
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return false
	}
	suffix := "-crypto.kms." + region + ".oraclecloud.com"
	prefix, ok := strings.CutSuffix(u.Host, suffix)
	if !ok || len(prefix) == 0 || len(prefix) > 128 {
		return false
	}
	for _, c := range prefix {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// ValidVaultCryptoEndpoint rejects arbitrary hosts before credentials exist.
func ValidVaultCryptoEndpoint(region, endpoint string) bool {
	return validCryptoEndpoint(region, endpoint)
}

func unwrapDataKey(ctx context.Context, region, endpoint, keyID, keyVersionID, ciphertext string, associated map[string]string, transport http.RoundTripper) ([]byte, error) {
	configuration, err := instanceConfiguration(ctx, region, transport)
	if err != nil {
		return nil, ErrIdentity
	}
	client, err := keymanagement.NewKmsCryptoClientWithConfigurationProvider(configuration, endpoint)
	if err != nil {
		return nil, ErrFetch
	}
	parsed, _ := url.Parse(endpoint)
	client.HTTPClient = boundedDispatcher{client: &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, ctx: ctx, region: region, cryptoHost: parsed.Host}
	noRetry := common.NoRetryPolicy()
	response, err := client.Decrypt(ctx, keymanagement.DecryptRequest{DecryptDataDetails: keymanagement.DecryptDataDetails{Ciphertext: new(ciphertext), KeyId: new(keyID), KeyVersionId: new(keyVersionID), AssociatedData: associated, EncryptionAlgorithm: keymanagement.DecryptDataDetailsEncryptionAlgorithmAes256Gcm}, RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
	if err != nil || response.Plaintext == nil || len(*response.Plaintext) != 44 {
		return nil, ErrFetch
	}
	key, err := base64.StdEncoding.Strict().DecodeString(*response.Plaintext)
	if err != nil || len(key) != 32 {
		erase(key)
		return nil, ErrFetch
	}
	return key, nil
}
