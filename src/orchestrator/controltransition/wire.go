package controltransition

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

const signatureDomain = "TS-CONTROL-STORAGE-TRANSITION-PLAN-V1\x00"

type signedPlan struct {
	Payload   jsontext.Value `json:"payload"`
	Signature []byte         `json:"signature"`
}

// VerifiedPlan retains immutable canonical bytes. Plan returns a fresh decoded
// value, so changing a caller's slices cannot widen the verified scope.
type VerifiedPlan struct {
	payload    string
	digest     string
	ownerKeyID string
	issuedAt   time.Time
	expiresAt  time.Time
}

func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func publicKey(public []byte) (*ecdsa.PublicKey, string, error) {
	bad := errors.New("controltransition: canonical P256 public key required")
	if len(public) > 4096 {
		return nil, "", bad
	}
	block, rest := pem.Decode(public)
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 || len(block.Headers) != 0 || !bytes.Equal(pem.EncodeToMemory(block), public) {
		return nil, "", bad
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", bad
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, "", bad
	}
	return key, Digest(block.Bytes), nil
}

func publicKeyID(public []byte) (string, error) {
	_, id, err := publicKey(public)
	return id, err
}

func canonicalDecode(raw []byte, out any) error {
	bad := errors.New("controltransition: noncanonical or oversized document")
	if len(raw) == 0 || len(raw) > MaximumBytes {
		return bad
	}
	if err := json.Unmarshal(raw, out, json.RejectUnknownMembers(true)); err != nil {
		return bad
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(canonical, raw) {
		return bad
	}
	return nil
}

func SignPlan(signer *security.CommandSignatureSigner, p Plan) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("controltransition: owner signer required")
	}
	raw, err := CanonicalPlan(p)
	if err != nil {
		return nil, err
	}
	// Host receipt signers must not be the off-host owner authority.
	if err := separateOwner(p, signer.PublicKeyID()); err != nil {
		return nil, err
	}
	sig, err := signer.SignCanonicalMaterial(append([]byte(signatureDomain), raw...))
	if err != nil {
		return nil, err
	}
	signed, err := json.Marshal(signedPlan{Payload: raw, Signature: sig.Bytes()})
	if err != nil || len(signed) > MaximumBytes {
		return nil, errors.New("controltransition: signed plan exceeds bound")
	}
	return signed, nil
}

func VerifyPlan(public, signed []byte) (VerifiedPlan, error) {
	bad := errors.New("controltransition: owner signature or plan refused")
	key, owner, err := publicKey(public)
	if err != nil {
		return VerifiedPlan{}, bad
	}
	var doc signedPlan
	if canonicalDecode(signed, &doc) != nil {
		return VerifiedPlan{}, bad
	}
	var plan Plan
	if canonicalDecode(doc.Payload, &plan) != nil || plan.Validate() != nil || separateOwner(plan, owner) != nil {
		return VerifiedPlan{}, bad
	}
	signature, ok := protocol.OpaqueSignatureTryCopyFrom(doc.Signature)
	if !ok {
		return VerifiedPlan{}, bad
	}
	id, _, sig, ok := security.DecodeCommandSignature(signature)
	hash := sha256.Sum256(append([]byte(signatureDomain), doc.Payload...))
	if !ok || id != owner || !ecdsa.VerifyASN1(key, hash[:], sig) {
		return VerifiedPlan{}, bad
	}
	return VerifiedPlan{payload: string(doc.Payload), digest: Digest(signed), ownerKeyID: owner, issuedAt: plan.IssuedAt, expiresAt: plan.ExpiresAt}, nil
}

func separateOwner(p Plan, owner string) error {
	keys := []string{p.Source.ReceiptPublicKeyPEM}
	for _, d := range p.Destinations {
		keys = append(keys, d.ReceiptPublicKeyPEM)
	}
	for _, public := range keys {
		id, err := publicKeyID([]byte(public))
		if err != nil || id == owner {
			return errors.New("controltransition: receipt signer must be separate from owner")
		}
	}
	return nil
}

func (v VerifiedPlan) Digest() string     { return v.digest }
func (v VerifiedPlan) OwnerKeyID() string { return v.ownerKeyID }

func (v VerifiedPlan) Check(now time.Time) error {
	if v.payload == "" || now.Before(v.issuedAt) || !now.Before(v.expiresAt) {
		return errors.New("controltransition: plan is unverified or outside its lifetime")
	}
	return nil
}

func (v VerifiedPlan) Plan() (Plan, error) {
	var p Plan
	if v.payload == "" {
		return p, errors.New("controltransition: verified plan required")
	}
	err := json.Unmarshal([]byte(v.payload), &p, json.RejectUnknownMembers(true))
	return p, err
}
