package hostsecrets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

// UnwrapDataKey delegates AES-256-GCM unwrapping to OCI Vault. Credential
// federation and signing share the bounded instance-principal worker. Callers
// must ReleaseDataKey exactly once after using a successful result.
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
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return false
	}
	prefix, ok := strings.CutSuffix(u.Host, "-crypto.kms."+region+".oraclecloud.com")
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
func ValidVaultCryptoEndpoint(region, endpoint string) bool {
	return validCryptoEndpoint(region, endpoint)
}

type cryptoMetadata struct {
	KeyID               string            `json:"keyId"`
	KeyVersionID        string            `json:"keyVersionId"`
	AssociatedData      map[string]string `json:"associatedData"`
	EncryptionAlgorithm string            `json:"encryptionAlgorithm"`
	Ciphertext          string            `json:"ciphertext,omitempty"`
}

func unwrapDataKey(ctx context.Context, region, endpoint, keyID, keyVersionID, ciphertext string, associated map[string]string, transport http.RoundTripper) (*DataKey, error) {
	configuration, err := instanceConfiguration(ctx, region, transport)
	if err != nil {
		return nil, ErrIdentity
	}
	body, err := json.Marshal(cryptoMetadata{KeyID: keyID, KeyVersionID: keyVersionID, AssociatedData: associated, EncryptionAlgorithm: "AES_256_GCM", Ciphertext: ciphertext})
	if err != nil {
		return nil, ErrFetch
	}
	response, err := cryptoRequest(ctx, endpoint, "decrypt", body, configuration, transport)
	if err != nil {
		return nil, ErrFetch
	}
	defer response.Body.Close()
	key, err := NewDataKey()
	if err != nil {
		return nil, ErrFetch
	}
	// Both the encoded response and the decoded key stay in locked, nondumpable
	// pages. The official SDK response decoder would allocate a plaintext string.
	n, err := readCryptoBody(response.Body, key.page[64:])
	if err != nil {
		ReleaseDataKey(key)
		return nil, ErrFetch
	}
	encoded, err := decryptFields(key.page[64:64+n], keyID, keyVersionID)
	if err != nil || len(encoded) != 44 {
		ReleaseDataKey(key)
		return nil, ErrFetch
	}
	n, err = base64.StdEncoding.Strict().Decode(key.page[:32], encoded)
	clear(key.page[32:])
	if err != nil || n != 32 {
		ReleaseDataKey(key)
		return nil, ErrFetch
	}
	return key, nil
}

// WrapDataKey returns only ciphertext; the operation owns a locked copy until
// signing and transport finish, including when its caller cancels early.
func WrapDataKey(ctx context.Context, region, endpoint, keyID, keyVersionID string, key []byte, associated map[string]string) (string, error) {
	if ctx == nil || len(key) != 32 || !validCryptoEndpoint(region, endpoint) || !provider.IsOCID(keyID, "key") || !provider.IsOCID(keyVersionID, "keyversion") {
		return "", ErrFetch
	}
	select {
	case identityWorker <- struct{}{}:
	case <-ctx.Done():
		return "", ErrFetch
	}
	locked, err := NewDataKey()
	if err != nil {
		<-identityWorker
		return "", ErrFetch
	}
	copy(locked.Bytes(), key)
	type result struct {
		ciphertext string
		err        error
	}
	completed := make(chan result, 1)
	go func() {
		defer func() { ReleaseDataKey(locked); <-identityWorker }()
		ciphertext, err := wrapDataKey(ctx, region, endpoint, keyID, keyVersionID, locked, associated, credentialTransport())
		completed <- result{ciphertext, err}
	}()
	select {
	case outcome := <-completed:
		return outcome.ciphertext, outcome.err
	case <-ctx.Done():
		return "", ErrFetch
	}
}
func wrapDataKey(ctx context.Context, region, endpoint, keyID, keyVersionID string, key *DataKey, associated map[string]string, transport http.RoundTripper) (string, error) {
	configuration, err := instanceConfiguration(ctx, region, transport)
	if err != nil {
		return "", ErrIdentity
	}
	metadata, err := json.Marshal(cryptoMetadata{KeyID: keyID, KeyVersionID: keyVersionID, AssociatedData: associated, EncryptionAlgorithm: "AES_256_GCM"})
	if err != nil || len(metadata) > 3000 {
		return "", ErrFetch
	}
	body := key.page[64:]
	prefix := copy(body, `{"plaintext":"`)
	base64.StdEncoding.Encode(body[prefix:prefix+44], key.Bytes())
	cursor := prefix + 44
	cursor += copy(body[cursor:], `",`)
	cursor += copy(body[cursor:], metadata[1:])
	response, err := cryptoRequest(ctx, endpoint, "encrypt", body[:cursor], configuration, transport)
	if err != nil {
		return "", ErrFetch
	}
	defer response.Body.Close()
	// The encryption response contains ciphertext only and may use ordinary heap
	// decoding. No plaintext response body or request is passed to the SDK codec.
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	if err != nil {
		return "", ErrFetch
	}
	var encrypted struct {
		Ciphertext          string `json:"ciphertext"`
		KeyID               string `json:"keyId"`
		KeyVersionID        string `json:"keyVersionId"`
		EncryptionAlgorithm string `json:"encryptionAlgorithm"`
	}
	if json.Unmarshal(responseBody, &encrypted, json.RejectUnknownMembers(true)) != nil || len(encrypted.Ciphertext) == 0 || len(encrypted.Ciphertext) > 8192 || (encrypted.KeyID != "" && encrypted.KeyID != keyID) || (encrypted.KeyVersionID != "" && encrypted.KeyVersionID != keyVersionID) || (encrypted.EncryptionAlgorithm != "" && encrypted.EncryptionAlgorithm != "AES_256_GCM") {
		return "", ErrFetch
	}
	return encrypted.Ciphertext, nil
}

// cryptoRequest uses the official federated signer while computing the body
// hash in place: the SDK default hash path copies the entire body to Go's heap.
// Include all body headers in the signed generic set and disable only that copy.
func cryptoRequest(ctx context.Context, endpoint, operation string, body []byte, configuration common.ConfigurationProvider, transport http.RoundTripper) (*http.Response, error) {
	protected := &lockedRequestBody{reader: bytes.NewReader(body)}
	defer protected.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(endpoint, "/")+"/20180608/"+operation, protected)
	if err != nil {
		return nil, ErrFetch
	}
	request.ContentLength = int64(len(body))
	request.Header.Set("content-type", "application/json")
	request.Header.Set("content-length", strconv.Itoa(len(body)))
	request.Header.Set("date", time.Now().UTC().Format(http.TimeFormat))
	hash := sha256.Sum256(body)
	request.Header.Set("x-content-sha256", base64.StdEncoding.EncodeToString(hash[:]))
	signer := common.RequestSignerWithBodyHashingPredicate(configuration, []string{"date", "(request-target)", "host", "content-length", "content-type", "x-content-sha256"}, nil, func(*http.Request) bool { return false })
	if signer.Sign(request) != nil {
		return nil, ErrFetch
	}
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return nil, ErrFetch
	}
	if response.Body == nil {
		return nil, ErrFetch
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, ErrFetch
	}
	return response, nil
}
func readCryptoBody(reader io.Reader, destination []byte) (int, error) {
	total := 0
	for total < len(destination) {
		n, err := reader.Read(destination[total:])
		total += n
		if errors.Is(err, io.EOF) {
			return total, nil
		}
		if err != nil || n == 0 {
			return 0, ErrFetch
		}
	}
	return 0, ErrFetch
}

// Decrypt fields are strings without JSON escapes in OCI's wire contract.
// Parse in place, reject duplicates/unknown fields, and never materialize the
// plaintext value as a Go string. Optional echoed identifiers must match.
func decryptFields(body []byte, keyID, keyVersionID string) ([]byte, error) {
	body = bytes.TrimSpace(body)
	if len(body) < 2 || body[0] != '{' || body[len(body)-1] != '}' {
		return nil, ErrFetch
	}
	body = bytes.TrimSpace(body[1 : len(body)-1])
	var plaintext, checksum []byte
	seen := map[string]bool{}
	for len(body) > 0 {
		name, rest, err := cryptoString(body)
		if err != nil {
			return nil, ErrFetch
		}
		label := string(name) // Field names are public schema labels only.
		if seen[label] {
			return nil, ErrFetch
		}
		seen[label] = true
		rest = bytes.TrimSpace(rest)
		if len(rest) == 0 || rest[0] != ':' {
			return nil, ErrFetch
		}
		value, rest, err := cryptoString(bytes.TrimSpace(rest[1:]))
		if err != nil {
			return nil, ErrFetch
		}
		switch label {
		case "plaintext":
			plaintext = value
		case "plaintextChecksum":
			checksum = value
		case "keyId":
			if !bytes.Equal(value, []byte(keyID)) {
				return nil, ErrFetch
			}
		case "keyVersionId":
			if !bytes.Equal(value, []byte(keyVersionID)) {
				return nil, ErrFetch
			}
		case "encryptionAlgorithm":
			if !bytes.Equal(value, []byte("AES_256_GCM")) {
				return nil, ErrFetch
			}
		default:
			return nil, ErrFetch
		}
		rest = bytes.TrimSpace(rest)
		if len(rest) == 0 {
			break
		}
		if rest[0] != ',' {
			return nil, ErrFetch
		}
		body = bytes.TrimSpace(rest[1:])
		if len(body) == 0 {
			return nil, ErrFetch
		}
	}
	if len(plaintext) != 44 || len(checksum) == 0 || len(checksum) > 128 {
		return nil, ErrFetch
	}
	return plaintext, nil
}
func cryptoString(body []byte) ([]byte, []byte, error) {
	if len(body) < 2 || body[0] != '"' {
		return nil, nil, ErrFetch
	}
	for i := 1; i < len(body); i++ {
		if body[i] == '"' {
			return body[1:i], body[i+1:], nil
		}
		if body[i] < 0x20 || body[i] > 0x7e || body[i] == '\\' {
			return nil, nil, ErrFetch
		}
	}
	return nil, nil, ErrFetch
}

// DataKey owns locked nondumpable pages. Do not copy it or retain Bytes after
// ReleaseDataKey. net/http and TLS retain their own transient transport buffers;
// this type controls the application's key and encoded-key storage only.
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

// Close synchronizes with every Read, including a transport still finishing an
// early response. After cryptoRequest returns no transport can read the mapping.
type lockedRequestBody struct {
	mu     sync.Mutex
	reader *bytes.Reader
}

func (body *lockedRequestBody) Read(destination []byte) (int, error) {
	body.mu.Lock()
	defer body.mu.Unlock()
	if body.reader == nil {
		return 0, io.ErrClosedPipe
	}
	return body.reader.Read(destination)
}
func (body *lockedRequestBody) Close() error {
	body.mu.Lock()
	body.reader = nil
	body.mu.Unlock()
	return nil
}

func (*DataKey) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, "[redacted data key]") }
