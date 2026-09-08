package brokeradmission

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"reflect"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

const signatureDomain = "TS-BROKER-ENROLLMENT-V1\x00"

type signedDocument struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}
type Verifier struct {
	key *ecdsa.PublicKey
	id  string
}

func NewVerifier(publicPEM []byte, pin string) (*Verifier, error) {
	block, rest := pem.Decode(publicPEM)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "PUBLIC KEY" {
		return nil, ErrInvalid
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, ErrInvalid
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	digest := sha256.Sum256(block.Bytes)
	if !ok || key.Curve != elliptic.P256() || hex.EncodeToString(digest[:]) != pin {
		return nil, ErrInvalid
	}
	return &Verifier{key: key, id: pin}, nil
}
func Sign(d Desired, signer *security.CommandSignatureSigner) ([]byte, error) {
	if signer == nil || Validate(d) != nil {
		return nil, ErrInvalid
	}
	payload, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	signature, err := signer.SignCanonicalMaterial(append([]byte(signatureDomain), payload...))
	if err != nil {
		return nil, err
	}
	wire, err := json.Marshal(signedDocument{Payload: payload, Signature: signature.Bytes()})
	if len(wire) > MaximumBytes {
		return nil, ErrInvalid
	}
	return wire, err
}
func (v *Verifier) Verify(wire []byte) (Desired, error) {
	var d Desired
	var signed signedDocument
	if v == nil || len(wire) == 0 || len(wire) > MaximumBytes || json.Unmarshal(wire, &signed, json.RejectUnknownMembers(true)) != nil {
		return d, ErrInvalid
	}
	signature, ok := protocol.OpaqueSignatureTryCopyFrom(signed.Signature)
	if !ok {
		return d, ErrInvalid
	}
	id, _, raw, ok := security.DecodeCommandSignature(signature)
	hash := sha256.Sum256(append([]byte(signatureDomain), signed.Payload...))
	if !ok || id != v.id || !ecdsa.VerifyASN1(v.key, hash[:], raw) || json.Unmarshal(signed.Payload, &d, json.RejectUnknownMembers(true)) != nil || Validate(d) != nil {
		return Desired{}, ErrInvalid
	}
	return d, nil
}

// CheckAdvance rejects any attempt to resurrect a retired key, drop a
// revocation, or silently replace a still-admitted member's credentials.
func CheckAdvance(prior, next Desired) error {
	if Validate(next) != nil {
		return ErrInvalid
	}
	if prior.Revision == 0 {
		return nil
	}
	if next.Environment != prior.Environment || next.Cluster != prior.Cluster || next.Revision < prior.Revision || next.AuthorityEpoch < prior.AuthorityEpoch {
		return ErrRollback
	}
	if next.Revision == prior.Revision {
		if reflect.DeepEqual(prior, next) {
			return nil
		}
		return ErrRollback
	}
	retired := map[string]Retired{}
	active := map[string]Member{}
	for _, r := range next.Retired {
		retired[r.Member.MemberID] = r
	}
	for _, m := range next.Members {
		active[m.MemberID] = m
	}
	for _, r := range prior.Retired {
		if !reflect.DeepEqual(retired[r.Member.MemberID], r) {
			return ErrRollback
		}
	}
	for _, m := range prior.Members {
		if reflect.DeepEqual(active[m.MemberID], m) {
			continue
		}
		r, ok := retired[m.MemberID]
		if !ok || !reflect.DeepEqual(r.Member, m) {
			return ErrRollback
		}
	}
	for _, m := range next.Members {
		for _, r := range next.Retired {
			if r.Member.Region == m.Region && r.Member.Slot == m.Slot && m.Generation <= r.Member.Generation {
				return ErrRollback
			}
		}
	}
	return nil
}
