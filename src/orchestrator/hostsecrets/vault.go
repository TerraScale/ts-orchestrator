package hostsecrets

import (
	"context"
	"encoding/base64"
	"golang.org/x/sys/unix"
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
func UnwrapDataKey(ctx context.Context, region, endpoint, keyID, keyVersionID, ciphertext string, associated map[string]string) (*DataKey, error) {
	if ctx == nil || !validCryptoEndpoint(region, endpoint) || !provider.IsOCID(keyID, "key") || !provider.IsOCID(keyVersionID, "keyversion") || len(ciphertext) == 0 || len(ciphertext) > 8192 {
		return nil, ErrFetch
	}
	select {
	case identityWorker <- struct{}{}:
	case <-ctx.Done():
		return nil, ErrFetch
	}
	type result struct {
		key *DataKey
		err error
	}
	completed := make(chan result)
	go func() {
		defer func() { <-identityWorker }()
		key, err := unwrapDataKey(ctx, region, endpoint, keyID, keyVersionID, ciphertext, associated, credentialTransport())
		select {
		case completed <- result{key, err}:
		case <-ctx.Done():
			ReleaseDataKey(key)
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

func unwrapDataKey(ctx context.Context, region, endpoint, keyID, keyVersionID, ciphertext string, associated map[string]string, transport http.RoundTripper) (*DataKey, error) {
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
	locked, err := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return nil, ErrFetch
	}
	if unix.Mlock(locked) != nil || unix.Madvise(locked, unix.MADV_DONTDUMP) != nil {
		unix.Munmap(locked)
		return nil, ErrFetch
	}
	n, err := base64.StdEncoding.Strict().Decode(locked, []byte(*response.Plaintext))
	if err != nil || n != 32 {
		clear(locked)
		unix.Munlock(locked)
		unix.Munmap(locked)
		return nil, ErrFetch
	}
	return &DataKey{page: locked}, nil
}

// WrapDataKey encrypts a caller-owned 32-byte DEK under an explicit regional KEK
// version. Only Vault ciphertext is returned to the durable catalog.
func WrapDataKey(ctx context.Context, region, endpoint, keyID, keyVersionID string, key []byte, associated map[string]string) (string, error) {
	if ctx == nil || len(key) != 32 || !validCryptoEndpoint(region, endpoint) || !provider.IsOCID(keyID, "key") || !provider.IsOCID(keyVersionID, "keyversion") {
		return "", ErrFetch
	}
	select {
	case identityWorker <- struct{}{}:
	case <-ctx.Done():
		return "", ErrFetch
	}
	// The worker owns a separate locked copy until signing/HTTP processing ends;
	// cancellation cannot let the caller erase or unmap storage still in use.
	locked, err := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		<-identityWorker
		return "", ErrFetch
	}
	if unix.Mlock(locked) != nil || unix.Madvise(locked, unix.MADV_DONTDUMP) != nil {
		unix.Munmap(locked)
		<-identityWorker
		return "", ErrFetch
	}
	copy(locked, key)
	type result struct {
		ciphertext string
		err        error
	}
	completed := make(chan result, 1)
	go func() {
		defer func() { clear(locked); unix.Munlock(locked); unix.Munmap(locked); <-identityWorker }()
		transport := credentialTransport()
		configuration, err := instanceConfiguration(ctx, region, transport)
		if err != nil {
			completed <- result{"", ErrIdentity}
			return
		}
		client, err := keymanagement.NewKmsCryptoClientWithConfigurationProvider(configuration, endpoint)
		if err != nil {
			completed <- result{"", ErrFetch}
			return
		}
		parsed, _ := url.Parse(endpoint)
		client.HTTPClient = boundedDispatcher{client: &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, ctx: ctx, region: region, cryptoHost: parsed.Host}
		encoded := base64.StdEncoding.EncodeToString(locked[:32])
		noRetry := common.NoRetryPolicy()
		response, err := client.Encrypt(ctx, keymanagement.EncryptRequest{EncryptDataDetails: keymanagement.EncryptDataDetails{Plaintext: &encoded, KeyId: new(keyID), KeyVersionId: new(keyVersionID), AssociatedData: associated, EncryptionAlgorithm: keymanagement.EncryptDataDetailsEncryptionAlgorithmAes256Gcm}, RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
		if err != nil || response.Ciphertext == nil || len(*response.Ciphertext) == 0 || len(*response.Ciphertext) > 8192 {
			completed <- result{"", ErrFetch}
			return
		}
		completed <- result{*response.Ciphertext, nil}
	}()
	select {
	case outcome := <-completed:
		return outcome.ciphertext, outcome.err
	case <-ctx.Done():
		return "", ErrFetch
	}
}

// DataKey owns locked nondumpable pages holding one AES-256 data key.
// It must not be copied; close it after the lease response has been written.
type DataKey struct{ page []byte }

func (key *DataKey) Bytes() []byte {
	if key == nil || len(key.page) != 4096 {
		return nil
	}
	return key.page[:32]
}
func ReleaseDataKey(key *DataKey) {
	if key == nil || len(key.page) != 4096 {
		return
	}
	clear(key.page)
	unix.Munlock(key.page)
	unix.Munmap(key.page)
	key.page = nil
}

// NewDataKey reserves locked nondumpable memory for an AES-256 key. Allocation
// fails closed if the host cannot provide those memory protections.
func NewDataKey() (*DataKey, error) {
	page, err := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return nil, ErrFetch
	}
	if unix.Mlock(page) != nil || unix.Madvise(page, unix.MADV_DONTDUMP) != nil {
		unix.Munmap(page)
		return nil, ErrFetch
	}
	return &DataKey{page: page}, nil
}
