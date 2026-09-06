package hostsecrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

var ErrIdentitySecret = errors.New("identity service credential authority unavailable")

// IdentitySecretReference is public control metadata. Each generation owns an
// immutable OCI Secret, pinned to version one; no secret-derived digest is used.
type IdentitySecretReference struct {
	SecretID      string `json:"secret_id"`
	VersionNumber int64  `json:"version_number"`
	Generation    uint64 `json:"generation"`
	OperationID   string `json:"operation_id"`
}
type IdentitySecretRequest struct {
	OperationID string
	Generation  uint64
}
type IdentitySecretIssuerConfig struct {
	Provider                              common.ConfigurationProvider
	Region, CompartmentID, VaultID, KeyID string
	Authority                             func(context.Context) error
}
type IdentitySecretIssuer struct {
	config    IdentitySecretIssuerConfig
	transport http.RoundTripper
}

// IdentitySecret owns application plaintext in locked, nondumpable pages.
// Bytes is borrowed until Close, must not be retained, and is never printable.
// TLS necessarily has its own transient record buffers during delivery.
type IdentitySecret struct{ storage *DataKey }

func (s *IdentitySecret) Bytes() []byte {
	if s == nil || s.storage == nil {
		return nil
	}
	return s.storage.page[32:75]
}
func (s *IdentitySecret) Close() {
	if s != nil {
		ReleaseDataKey(s.storage)
		s.storage = nil
	}
}
func (*IdentitySecret) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "[redacted identity service credential]")
}

func NewIdentitySecretIssuer(c IdentitySecretIssuerConfig) (*IdentitySecretIssuer, error) {
	if c.Provider == nil || c.Authority == nil || !provider.ValidOCIRegion(c.Region) || !provider.IsOCID(strings.Replace(c.CompartmentID, "..", ".global.", 1), "compartment") || !provider.IsOCID(c.VaultID, "vault") || !provider.IsOCID(c.KeyID, "key") {
		return nil, ErrIdentitySecret
	}
	return &IdentitySecretIssuer{c, credentialTransport()}, nil
}
func identityOperationValid(operation string) bool {
	if len(operation) < 1 || len(operation) > 128 {
		return false
	}
	for _, c := range operation {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '/') {
			return false
		}
	}
	return true
}
func identitySecretName(r IdentitySecretRequest) string {
	h := sha256.Sum256([]byte(r.OperationID + "/" + strconv.FormatUint(r.Generation, 10)))
	return "ts-identity-service-" + hex.EncodeToString(h[:])
}
func (i *IdentitySecretIssuer) Generate(ctx context.Context, r IdentitySecretRequest) (IdentitySecretReference, error) {
	if ctx == nil || !identityOperationValid(r.OperationID) || r.Generation == 0 {
		return IdentitySecretReference{}, ErrIdentitySecret
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	select {
	case identityWorker <- struct{}{}:
	case <-ctx.Done():
		return IdentitySecretReference{}, ErrIdentitySecret
	}
	type result struct {
		reference IdentitySecretReference
		err       error
	}
	done := make(chan result, 1)
	go func() { defer func() { <-identityWorker }(); ref, err := i.generate(ctx, r); done <- result{ref, err} }()
	select {
	case r := <-done:
		return r.reference, r.err
	case <-ctx.Done():
		return IdentitySecretReference{}, ErrIdentitySecret
	}
}
func (i *IdentitySecretIssuer) Fetch(ctx context.Context, ref IdentitySecretReference) (*IdentitySecret, error) {
	if ctx == nil || !provider.IsOCID(ref.SecretID, "secret") || ref.VersionNumber != 1 || ref.Generation == 0 || !identityOperationValid(ref.OperationID) {
		return nil, ErrIdentitySecret
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	select {
	case identityWorker <- struct{}{}:
	case <-ctx.Done():
		return nil, ErrIdentitySecret
	}
	type result struct {
		secret *IdentitySecret
		err    error
	}
	done := make(chan result)
	go func() {
		defer func() { <-identityWorker }()
		s, e := i.fetch(ctx, ref)
		select {
		case done <- result{s, e}:
		case <-ctx.Done():
			s.Close()
		}
	}()
	select {
	case r := <-done:
		return r.secret, r.err
	case <-ctx.Done():
		return nil, ErrIdentitySecret
	}
}

type identitySecretMetadata struct {
	ID                   string            `json:"id"`
	SecretName           string            `json:"secretName"`
	CompartmentID        string            `json:"compartmentId"`
	VaultID              string            `json:"vaultId"`
	KeyID                string            `json:"keyId"`
	LifecycleState       string            `json:"lifecycleState"`
	CurrentVersionNumber int64             `json:"currentVersionNumber"`
	FreeformTags         map[string]string `json:"freeformTags"`
	TimeOfDeletion       *time.Time        `json:"timeOfDeletion"`
}

func (i *IdentitySecretIssuer) metadataValid(m identitySecretMetadata, r IdentitySecretRequest) bool {
	return provider.IsOCID(m.ID, "secret") && m.SecretName == identitySecretName(r) && m.CompartmentID == i.config.CompartmentID && m.VaultID == i.config.VaultID && m.KeyID == i.config.KeyID && m.FreeformTags["purpose"] == "identity-service-auth" && m.FreeformTags["operation"] == r.OperationID && m.FreeformTags["generation"] == strconv.FormatUint(r.Generation, 10) && m.TimeOfDeletion == nil
}
func (i *IdentitySecretIssuer) endpoint(retrieval bool) string {
	if retrieval {
		return "https://secrets.vaults." + i.config.Region + ".oci.oraclecloud.com/20190301"
	}
	return "https://vaults." + i.config.Region + ".oci.oraclecloud.com/20180608"
}
func (i *IdentitySecretIssuer) request(ctx context.Context, method, path string, body []byte, retrieval bool, retry string) (*http.Response, error) {
	if ctx.Err() != nil || i.config.Authority(ctx) != nil {
		return nil, ErrIdentitySecret
	}
	protected := &lockedRequestBody{reader: bytes.NewReader(body)}
	defer protected.Close()
	req, e := http.NewRequestWithContext(ctx, method, i.endpoint(retrieval)+path, protected)
	if e != nil {
		return nil, ErrIdentitySecret
	}
	req.Header.Set("date", time.Now().UTC().Format(http.TimeFormat))
	headers := []string{"date", "(request-target)", "host"}
	if len(body) > 0 {
		req.ContentLength = int64(len(body))
		req.Header.Set("content-type", "application/json")
		req.Header.Set("content-length", strconv.Itoa(len(body)))
		h := sha256.Sum256(body)
		req.Header.Set("x-content-sha256", base64.StdEncoding.EncodeToString(h[:]))
		headers = append(headers, "content-type", "content-length", "x-content-sha256")
	}
	if retry != "" {
		req.Header.Set("opc-retry-token", retry)
		headers = append(headers, "opc-retry-token")
	}
	signer := common.RequestSignerWithBodyHashingPredicate(i.config.Provider, headers, nil, func(*http.Request) bool { return false })
	if signer.Sign(req) != nil || ctx.Err() != nil || i.config.Authority(ctx) != nil {
		return nil, ErrIdentitySecret
	}
	client := &http.Client{Transport: i.transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(req)
	if e != nil || response == nil || response.Body == nil {
		return nil, ErrIdentitySecret
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		response.Body.Close()
		return nil, ErrIdentitySecret
	}
	return response, nil
}
func (i *IdentitySecretIssuer) public(ctx context.Context, path string, out any) error {
	res, e := i.request(ctx, http.MethodGet, path, nil, false, "")
	if e != nil {
		return e
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 256<<10))
	if e != nil || len(b) >= 256<<10 || res.Header.Get("opc-next-page") != "" || json.Unmarshal(b, out) != nil {
		return ErrIdentitySecret
	}
	return nil
}
func (i *IdentitySecretIssuer) find(ctx context.Context, r IdentitySecretRequest) (string, error) {
	q := url.Values{"compartmentId": {i.config.CompartmentID}, "vaultId": {i.config.VaultID}, "name": {identitySecretName(r)}}
	var items []identitySecretMetadata
	if i.public(ctx, "/secrets?"+q.Encode(), &items) != nil {
		return "", ErrIdentitySecret
	}
	if len(items) > 1 {
		return "", ErrIdentitySecret
	}
	if len(items) == 0 {
		return "", nil
	}
	// List summaries omit the key and current version: confirm them with GetSecret.
	if !provider.IsOCID(items[0].ID, "secret") {
		return "", ErrIdentitySecret
	}
	return items[0].ID, nil
}
func (i *IdentitySecretIssuer) generate(ctx context.Context, r IdentitySecretRequest) (IdentitySecretReference, error) {
	id, e := i.find(ctx, r)
	if e != nil {
		return IdentitySecretReference{}, e
	}
	if id == "" {
		key, e := NewDataKey()
		if e != nil {
			return IdentitySecretReference{}, ErrIdentitySecret
		}
		defer ReleaseDataKey(key)
		rand.Read(key.Bytes())
		base64.RawURLEncoding.Encode(key.page[32:75], key.Bytes())
		clear(key.Bytes())
		metadata := struct {
			CompartmentID string            `json:"compartmentId"`
			VaultID       string            `json:"vaultId"`
			KeyID         string            `json:"keyId"`
			SecretName    string            `json:"secretName"`
			FreeformTags  map[string]string `json:"freeformTags"`
		}{i.config.CompartmentID, i.config.VaultID, i.config.KeyID, identitySecretName(r), map[string]string{"purpose": "identity-service-auth", "operation": r.OperationID, "generation": strconv.FormatUint(r.Generation, 10)}}
		public, e := json.Marshal(metadata)
		if e != nil || len(public) > 3000 {
			return IdentitySecretReference{}, ErrIdentitySecret
		}
		body := key.page[128:]
		n := copy(body, public[:len(public)-1])
		n += copy(body[n:], `,"secretContent":{"contentType":"BASE64","stage":"CURRENT","content":"`)
		base64.StdEncoding.Encode(body[n:n+60], key.page[32:75])
		n += 60
		n += copy(body[n:], `"}}`)
		res, createErr := i.request(ctx, http.MethodPost, "/secrets", body[:n], false, identitySecretName(r)[20:])
		if res != nil {
			res.Body.Close()
		}
		id, e = i.find(ctx, r)
		if e != nil || id == "" {
			_ = createErr
			return IdentitySecretReference{}, ErrIdentitySecret
		}
	}
	ref := IdentitySecretReference{id, 1, r.Generation, r.OperationID}
	for {
		var m identitySecretMetadata
		if i.public(ctx, "/secrets/"+url.PathEscape(id), &m) != nil || !i.metadataValid(m, r) {
			return IdentitySecretReference{}, ErrIdentitySecret
		}
		if m.LifecycleState == "ACTIVE" {
			if m.CurrentVersionNumber != 1 {
				return IdentitySecretReference{}, ErrIdentitySecret
			}
			return ref, nil
		}
		if m.LifecycleState != "CREATING" {
			return IdentitySecretReference{}, ErrIdentitySecret
		}
		select {
		case <-ctx.Done():
			return IdentitySecretReference{}, ErrIdentitySecret
		case <-time.After(time.Second):
		}
	}
}
func (i *IdentitySecretIssuer) fetch(ctx context.Context, ref IdentitySecretReference) (*IdentitySecret, error) {
	var metadata identitySecretMetadata
	if i.public(ctx, "/secrets/"+url.PathEscape(ref.SecretID), &metadata) != nil || !i.metadataValid(metadata, IdentitySecretRequest{ref.OperationID, ref.Generation}) || metadata.LifecycleState != "ACTIVE" || metadata.CurrentVersionNumber != 1 {
		return nil, ErrIdentitySecret
	}
	key, e := NewDataKey()
	if e != nil {
		return nil, ErrIdentitySecret
	}
	success := false
	defer func() {
		if !success {
			ReleaseDataKey(key)
		}
	}()
	response, e := i.request(ctx, http.MethodGet, "/secretbundles/"+url.PathEscape(ref.SecretID)+"?versionNumber=1", nil, true, "")
	if e != nil {
		return nil, e
	}
	defer response.Body.Close()
	n, e := readCryptoBody(response.Body, key.page[128:])
	if e != nil {
		return nil, ErrIdentitySecret
	}
	encoded, e := identityBundleContent(key.page[128:128+n], ref.SecretID)
	if e != nil {
		return nil, e
	}
	n, e = base64.StdEncoding.Strict().Decode(key.page[32:77], encoded)
	if e != nil || n != 43 {
		return nil, ErrIdentitySecret
	}
	n, e = base64.RawURLEncoding.Strict().Decode(key.page[:32], key.page[32:75])
	if e != nil || n != 32 {
		return nil, ErrIdentitySecret
	}
	clear(key.page[:32])
	clear(key.page[75:])
	success = true
	return &IdentitySecret{key}, nil
}
