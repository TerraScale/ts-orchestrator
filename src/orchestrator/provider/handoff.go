package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

const ReceiptAlgorithm = "ECDSA-P256-SHA256"

type CreateNodeReceiptBinding struct {
	OperationId, TenantId, NodeRequestId, IdempotencyKey, CreateKey, CellId, CompartmentId, TemplateId, PlacementId, BootstrapEnvelopeDigest, AuthorizationDigest, ProviderContextFingerprint string
	Generation, Epoch                                                                                                                                                                         uint64
	AuthorizationSequence                                                                                                                                                                     int64
}

func (b CreateNodeReceiptBinding) Digest() string {
	return digestCanonical("create-node-binding-v1", b.OperationId, b.TenantId, b.NodeRequestId, b.IdempotencyKey, b.CreateKey, b.CellId, b.CompartmentId, b.Generation, b.Epoch, b.TemplateId, b.PlacementId, b.BootstrapEnvelopeDigest, b.AuthorizationSequence, b.AuthorizationDigest, b.ProviderContextFingerprint)
}

type CreateNodeHandoffReceipt struct {
	Algorithm, KeyId    string
	Binding             CreateNodeReceiptBinding
	IssuedAt, ExpiresAt time.Time
	Signature           string
}

func (r CreateNodeHandoffReceipt) payload() []byte {
	return []byte(canonical("terrascale-create-node-handoff-v2", r.Algorithm, r.KeyId, r.Binding.OperationId, "CreateNode", r.Binding.TenantId, r.Binding.NodeRequestId, r.Binding.IdempotencyKey, r.Binding.CreateKey, r.Binding.CellId, r.Binding.CompartmentId, r.Binding.Generation, r.Binding.Epoch, r.Binding.TemplateId, r.Binding.PlacementId, r.Binding.BootstrapEnvelopeDigest, r.Binding.AuthorizationSequence, r.Binding.AuthorizationDigest, r.Binding.ProviderContextFingerprint, r.IssuedAt.UTC().UnixNano(), r.ExpiresAt.UTC().UnixNano()))
}
func canonical(values ...any) string {
	var b strings.Builder
	for _, v := range values {
		s := fmt.Sprint(v)
		fmt.Fprintf(&b, "%d:%s;", len(s), s)
	}
	return b.String()
}
func digestCanonical(values ...any) string {
	h := sha256.Sum256([]byte(canonical(values...)))
	return hex.EncodeToString(h[:])
}

type ReceiptKeyResolver interface {
	Resolve(keyID, algorithm string) ([]byte, bool)
}
type ReceiptPublicKeySource interface{ PublicKeys() map[string][]byte }
type ReceiptKeyRing struct{ keys map[string][]byte }

func NewReceiptKeyRing(keys map[string][]byte) (*ReceiptKeyRing, error) {
	r := &ReceiptKeyRing{keys: map[string][]byte{}}
	for id, key := range keys {
		if id == "" || len(key) == 0 {
			return nil, &errs.Argument{Message: "receipt key ring contains invalid key"}
		}
		r.keys[id] = append([]byte(nil), key...)
	}
	return r, nil
}
func (r *ReceiptKeyRing) Resolve(id, alg string) ([]byte, bool) {
	if r == nil || alg != ReceiptAlgorithm {
		return nil, false
	}
	v, ok := r.keys[id]
	return append([]byte(nil), v...), ok
}
func (r *ReceiptKeyRing) PublicKeys() map[string][]byte {
	out := map[string][]byte{}
	if r != nil {
		for k, v := range r.keys {
			out[k] = append([]byte(nil), v...)
		}
	}
	return out
}

type TenantAuthorityKeyRing struct{ *ReceiptKeyRing }
type ProviderAttestationKeyRing struct{ *ReceiptKeyRing }
type RecoveryLookupKeyRing struct{ *ReceiptKeyRing }
type InvocationCapabilityKeyRing struct{ *ReceiptKeyRing }

func EnsureDistinctKeyDomains(domains ...ReceiptKeyResolver) error {
	for i, a := range domains {
		sa, ok := a.(ReceiptPublicKeySource)
		if !ok {
			return &errs.Argument{Message: "key domain must expose public keys"}
		}
		for _, b := range domains[i+1:] {
			sb, ok := b.(ReceiptPublicKeySource)
			if !ok {
				return &errs.Argument{Message: "key domain must expose public keys"}
			}
			for id, key := range sa.PublicKeys() {
				for id2, key2 := range sb.PublicKeys() {
					if id == id2 || string(key) == string(key2) {
						return &errs.Argument{Message: "trust domains cannot share key material"}
					}
				}
			}
		}
	}
	return nil
}

type CreateNodeHandoffReceiptSigner struct {
	KeyId string
	key   *ecdsa.PrivateKey
}

func NewCreateNodeHandoffReceiptSigner(keyID string, key *ecdsa.PrivateKey) (*CreateNodeHandoffReceiptSigner, error) {
	if strings.TrimSpace(keyID) == "" || key == nil || key.Curve != elliptic.P256() {
		return nil, &errs.Argument{Message: "receipt signer requires NIST P-256 and a key ID"}
	}
	return &CreateNodeHandoffReceiptSigner{keyID, key}, nil
}
func (s *CreateNodeHandoffReceiptSigner) PublicKey() []byte {
	if s == nil {
		return nil
	}
	v, _ := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	return v
}
func validBinding(b CreateNodeReceiptBinding) bool {
	return b.OperationId != "" && b.TenantId != "" && b.NodeRequestId != "" && b.IdempotencyKey != "" && b.CreateKey != "" && b.CellId != "" && b.CompartmentId != "" && b.TemplateId != "" && b.PlacementId != "" && b.BootstrapEnvelopeDigest != "" && b.AuthorizationDigest != "" && b.ProviderContextFingerprint != "" && b.Generation > 0 && b.Epoch > 0 && b.AuthorizationSequence > 0
}
func (s *CreateNodeHandoffReceiptSigner) Sign(binding CreateNodeReceiptBinding, issued, expires time.Time) (CreateNodeHandoffReceipt, error) {
	if s == nil || !validBinding(binding) || issued.IsZero() || !expires.After(issued) {
		return CreateNodeHandoffReceipt{}, &errs.Argument{Message: "receipt binding must be complete and have a positive lifetime"}
	}
	r := CreateNodeHandoffReceipt{ReceiptAlgorithm, s.KeyId, binding, issued, expires, ""}
	h := sha256.Sum256(r.payload())
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, h[:])
	if err != nil {
		return CreateNodeHandoffReceipt{}, err
	}
	r.Signature = base64.StdEncoding.EncodeToString(sig)
	return r, nil
}
func VerifyCreateNodeHandoffReceipt(r CreateNodeHandoffReceipt, resolver ReceiptKeyResolver, expected CreateNodeReceiptBinding, now time.Time) bool {
	if resolver == nil || !validBinding(r.Binding) || r.Algorithm != ReceiptAlgorithm || r.Binding != expected || now.Before(r.IssuedAt) || !now.Before(r.ExpiresAt) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return false
	}
	der, err := x509.ParsePKIXPublicKey(mustResolve(resolver, r.KeyId, r.Algorithm))
	if err != nil {
		return false
	}
	key, ok := der.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return false
	}
	h := sha256.Sum256(r.payload())
	return ecdsa.VerifyASN1(key, h[:], raw)
}
func mustResolve(r ReceiptKeyResolver, id, alg string) []byte {
	v, ok := r.Resolve(id, alg)
	if !ok {
		return nil
	}
	return v
}

type CreateNodeRecoveryLookupAuthority struct {
	Algorithm, KeyId, Audience, BindingDigest string
	IssuedAt, ExpiresAt                       time.Time
	Signature                                 string
}

func (a CreateNodeRecoveryLookupAuthority) payload() []byte {
	return []byte(canonical("create-node-recovery-lookup-v1", a.Algorithm, a.KeyId, a.Audience, a.BindingDigest, a.IssuedAt.UTC().UnixNano(), a.ExpiresAt.UTC().UnixNano()))
}

type CreateNodeRecoveryLookupSigner struct {
	key   *ecdsa.PrivateKey
	KeyId string
}

func NewCreateNodeRecoveryLookupSigner(id string, key *ecdsa.PrivateKey) (*CreateNodeRecoveryLookupSigner, error) {
	if strings.TrimSpace(id) == "" || key == nil || key.Curve != elliptic.P256() {
		return nil, &errs.Argument{Message: "recovery signer requires P-256"}
	}
	return &CreateNodeRecoveryLookupSigner{key, id}, nil
}
func (s *CreateNodeRecoveryLookupSigner) Sign(b CreateNodeReceiptBinding, issued, expires time.Time) (CreateNodeRecoveryLookupAuthority, error) {
	if !expires.After(issued) || expires.Sub(issued) > 7*24*time.Hour {
		return CreateNodeRecoveryLookupAuthority{}, &errs.ArgumentOutOfRangeError{Param: "expiresAt"}
	}
	a := CreateNodeRecoveryLookupAuthority{ReceiptAlgorithm, s.KeyId, "create-node-provider-lookup", b.Digest(), issued, expires, ""}
	h := sha256.Sum256(a.payload())
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, h[:])
	if err != nil {
		return a, err
	}
	a.Signature = base64.StdEncoding.EncodeToString(sig)
	return a, nil
}
func VerifyRecoveryLookupAuthority(a CreateNodeRecoveryLookupAuthority, resolver ReceiptKeyResolver, b CreateNodeReceiptBinding, now time.Time) bool {
	if resolver == nil || a.Algorithm != ReceiptAlgorithm || a.Audience != "create-node-provider-lookup" || a.BindingDigest != b.Digest() || now.Before(a.IssuedAt) || !now.Before(a.ExpiresAt) || a.ExpiresAt.Sub(a.IssuedAt) > 7*24*time.Hour {
		return false
	}
	return verifyPayload(a.KeyId, a.Algorithm, a.payload(), a.Signature, resolver)
}
func verifyPayload(id, alg string, payload []byte, signature string, resolver ReceiptKeyResolver) bool {
	if resolver == nil {
		return false
	}
	keyBytes, ok := resolver.Resolve(id, alg)
	if !ok {
		return false
	}
	pub, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return false
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	h := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(key, h[:], sig)
}

type CreateNodeTenantAuthorizationProof struct {
	Algorithm, KeyId, Audience, TenantId, OperationId, Action, AuthorizationDigest string
	ExpiresAt                                                                      time.Time
	Signature                                                                      string
}

func (p CreateNodeTenantAuthorizationProof) payload() []byte {
	return []byte(canonical("create-node-tenant-proof-v2", p.Algorithm, p.KeyId, p.Audience, p.TenantId, p.OperationId, p.Action, p.AuthorizationDigest, p.ExpiresAt.UTC().UnixNano()))
}

type CreateNodeTenantAuthorizationSigner struct {
	key   *ecdsa.PrivateKey
	KeyId string
}

func NewCreateNodeTenantAuthorizationSigner(id string, key *ecdsa.PrivateKey) (*CreateNodeTenantAuthorizationSigner, error) {
	if strings.TrimSpace(id) == "" || key == nil || key.Curve != elliptic.P256() {
		return nil, &errs.Argument{Message: "tenant signer requires P-256"}
	}
	return &CreateNodeTenantAuthorizationSigner{key, id}, nil
}
func (s *CreateNodeTenantAuthorizationSigner) Sign(tenant, operation, digest string, expiry time.Time) (CreateNodeTenantAuthorizationProof, error) {
	if tenant == "" || operation == "" || digest == "" || expiry.IsZero() {
		return CreateNodeTenantAuthorizationProof{}, &errs.Argument{Message: "tenant authorization proof is incomplete"}
	}
	p := CreateNodeTenantAuthorizationProof{ReceiptAlgorithm, s.KeyId, "create-node-tenant-authorization", tenant, operation, "CreateNode", digest, expiry, ""}
	h := sha256.Sum256(p.payload())
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, h[:])
	if err != nil {
		return p, err
	}
	p.Signature = base64.StdEncoding.EncodeToString(sig)
	return p, nil
}
func VerifyTenantAuthorizationProof(p CreateNodeTenantAuthorizationProof, resolver ReceiptKeyResolver, operation, digest string, now time.Time) (string, bool) {
	if p.Algorithm != ReceiptAlgorithm || p.Audience != "create-node-tenant-authorization" || p.Action != "CreateNode" || p.OperationId != operation || p.AuthorizationDigest != digest || p.TenantId == "" || !now.Before(p.ExpiresAt) || !verifyPayload(p.KeyId, p.Algorithm, p.payload(), p.Signature, resolver) {
		return "", false
	}
	return p.TenantId, true
}

type CreateNodeAuthoritativeInvocationCapability struct {
	Algorithm, KeyId, Audience, OperationId, BindingDigest, LeaseOwner, LeaseToken, Nonce string
	JournalVersion                                                                        int64
	LeaseExpiresAt, IssuedAt, ExpiresAt                                                   time.Time
	Signature                                                                             string
}

func (c CreateNodeAuthoritativeInvocationCapability) payload() []byte {
	return []byte(canonical("create-node-authoritative-invocation-v3", c.Algorithm, c.KeyId, c.Audience, c.OperationId, c.BindingDigest, c.JournalVersion, c.LeaseOwner, c.LeaseToken, c.Nonce, c.LeaseExpiresAt.UTC().UnixNano(), c.IssuedAt.UTC().UnixNano(), c.ExpiresAt.UTC().UnixNano()))
}

type CreateNodeAuthoritativeInvocationCapabilitySigner struct {
	key   *ecdsa.PrivateKey
	KeyId string
}

func NewInvocationCapabilitySigner(id string, key *ecdsa.PrivateKey) (*CreateNodeAuthoritativeInvocationCapabilitySigner, error) {
	if strings.TrimSpace(id) == "" || key == nil || key.Curve != elliptic.P256() {
		return nil, &errs.Argument{Message: "invocation signer requires P-256"}
	}
	return &CreateNodeAuthoritativeInvocationCapabilitySigner{key, id}, nil
}
func (s *CreateNodeAuthoritativeInvocationCapabilitySigner) Sign(c CreateNodeAuthoritativeInvocationCapability) (CreateNodeAuthoritativeInvocationCapability, error) {
	if c.JournalVersion <= 0 || c.OperationId == "" || c.BindingDigest == "" || c.LeaseOwner == "" || c.LeaseToken == "" || c.Nonce == "" || !c.LeaseExpiresAt.After(c.IssuedAt) || !c.ExpiresAt.After(c.IssuedAt) || c.ExpiresAt.Sub(c.IssuedAt) > 10*time.Minute {
		return CreateNodeAuthoritativeInvocationCapability{}, &errs.Argument{Message: "invocation capability is invalid"}
	}
	c.Algorithm = ReceiptAlgorithm
	c.KeyId = s.KeyId
	c.Audience = "create-node-authoritative-invocation"
	c.Signature = ""
	h := sha256.Sum256(c.payload())
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, h[:])
	if err != nil {
		return c, err
	}
	c.Signature = base64.StdEncoding.EncodeToString(sig)
	return c, nil
}
func VerifyInvocationCapability(c CreateNodeAuthoritativeInvocationCapability, resolver ReceiptKeyResolver, b CreateNodeReceiptBinding, now time.Time) bool {
	return resolver != nil && c.Algorithm == ReceiptAlgorithm && c.Audience == "create-node-authoritative-invocation" && c.OperationId == b.OperationId && c.BindingDigest == b.Digest() && c.JournalVersion > 0 && c.LeaseOwner != "" && c.LeaseToken != "" && c.Nonce != "" && c.LeaseExpiresAt.After(c.IssuedAt) && !now.Before(c.IssuedAt) && now.Before(c.LeaseExpiresAt) && now.Before(c.ExpiresAt) && c.ExpiresAt.Sub(c.IssuedAt) <= 10*time.Minute && verifyPayload(c.KeyId, c.Algorithm, c.payload(), c.Signature, resolver)
}
