// Package candidatesync downloads and verifies preliminary snapshots in a private
// candidate store. Its receipts confer no control-plane or runtime authority.
package candidatesync

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

const receiptDomain = "TS-CANDIDATE-PRELIMINARY-VERIFICATION-V1\x00"

type ObjectEvidence struct {
	Object  preliminarytransfer.ObjectMapping    `json:"object"`
	Restore restoredrill.SnapshotRestoreEvidence `json:"restore"`
}
type Receipt struct {
	Version                int              `json:"version"`
	PreliminaryOnly        bool             `json:"preliminaryOnly"`
	ScopeSHA256            string           `json:"scopeSha256"`
	NodeID                 string           `json:"nodeId"`
	Region                 string           `json:"region"`
	PreparationGrantSHA256 string           `json:"preparationGrantSha256"`
	BootstrapGrantSHA256   string           `json:"bootstrapGrantSha256"`
	ManifestSHA256         string           `json:"manifestSha256"`
	SourceReceiptSHA256    string           `json:"sourceReceiptSha256"`
	CaptureEpoch           uint64           `json:"captureEpoch"`
	CreatedAt              time.Time        `json:"createdAt"`
	Objects                []ObjectEvidence `json:"objects"`
}
type signedReceipt struct {
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"signature"`
}

func signReceipt(s *security.CommandSignatureSigner, r Receipt) ([]byte, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	sig, err := s.SignCanonicalMaterial(append([]byte(receiptDomain), raw...))
	if err != nil {
		return nil, err
	}
	return json.Marshal(signedReceipt{raw, sig.Bytes()})
}
func canonical(raw []byte, v any) error {
	if len(raw) == 0 || len(raw) > preliminarytransfer.MaximumBytes {
		return errors.New("candidatesync: receipt exceeds bound")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(&struct{}{}) != io.EOF {
		return errors.New("candidatesync: invalid receipt")
	}
	b, e := json.Marshal(v)
	if e != nil || !bytes.Equal(b, raw) {
		return errors.New("candidatesync: noncanonical receipt")
	}
	return nil
}

// VerifyReceipt verifies candidate attribution only. Callers must separately
// bind its scope and restore evidence; this never grants writer authority.
func VerifyReceipt(public, raw []byte) (Receipt, error) {
	var r Receipt
	var doc signedReceipt
	fail := errors.New("candidatesync: receipt signature refused")
	id, err := preliminarytransfer.PublicKeyID(public)
	if err != nil || canonical(raw, &doc) != nil {
		return r, fail
	}
	block, _ := pem.Decode(public)
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return r, fail
	}
	key := parsed.(*ecdsa.PublicKey)
	sig, ok := protocol.OpaqueSignatureTryCopyFrom(doc.Signature)
	if !ok {
		return r, fail
	}
	keyID, _, signature, ok := security.DecodeCommandSignature(sig)
	sum := sha256.Sum256(append([]byte(receiptDomain), doc.Payload...))
	if !ok || keyID != id || !ecdsa.VerifyASN1(key, sum[:], signature) || canonical(doc.Payload, &r) != nil || r.Version != 1 || !r.PreliminaryOnly || r.CreatedAt.IsZero() {
		return Receipt{}, fail
	}
	return r, nil
}
