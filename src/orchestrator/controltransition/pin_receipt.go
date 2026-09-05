package controltransition

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"slices"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

const PinReceiptMaximumBytes = 8192
const pinReceiptDomain = "TS-CONTROL-STORAGE-PLAN-PIN-RECEIPT-V1\x00"

// PinReceipt acknowledges only a durable host agreement. PlanSHA256 is its
// immediate predecessor. PinSHA256 hashes the exact private admission record;
// the receipt publishes no command body or private key material.
type PinReceipt struct {
	Version              int       `json:"version"`
	Phase                string    `json:"phase"`
	PlanSHA256           string    `json:"planSha256"`
	NodeID               string    `json:"nodeId"`
	Role                 string    `json:"role"`
	PinSHA256            string    `json:"pinSha256"`
	BootstrapGrantSHA256 string    `json:"bootstrapGrantSha256"`
	ManifestSHA256       string    `json:"manifestSha256"`
	CommandID            string    `json:"commandId"`
	CommandSHA256        string    `json:"commandSha256"`
	AuthorityID          string    `json:"authorityId"`
	Epoch                int64     `json:"epoch"`
	CandidateID          string    `json:"candidateId"`
	LeaseID              string    `json:"leaseId"`
	AdmittedAt           time.Time `json:"admittedAt"`
	PublishedAt          time.Time `json:"publishedAt"`
}

func pinReceiptKey(v VerifiedPlan, r PinReceipt) (string, error) {
	bad := errors.New("controltransition: pin receipt scope differs")
	p, err := v.Plan()
	if err != nil {
		return "", err
	}
	if r.Version != 1 || r.Phase != "plan-pinned" || r.PlanSHA256 != v.Digest() || !validDigest(r.PinSHA256) || v.Check(r.AdmittedAt) != nil || v.Check(r.PublishedAt) != nil || r.PublishedAt.Before(r.AdmittedAt) {
		return "", bad
	}
	if r.NodeID == p.Source.NodeID {
		if r.Role != "source" || r.BootstrapGrantSHA256 != p.Source.BootstrapGrantSHA256 || r.ManifestSHA256 != p.Source.InitialManifestSHA256 || !token(r.CommandID) || !validDigest(r.CommandSHA256) || r.AuthorityID != "gru-regional" || r.Epoch <= 0 || !pinAuthorityToken(r.CandidateID) || !pinAuthorityToken(r.LeaseID) {
			return "", bad
		}
		return p.Source.ReceiptPublicKeyPEM, nil
	}
	for _, d := range p.Destinations {
		if d.NodeID != r.NodeID {
			continue
		}
		if r.Role != "destination" || r.BootstrapGrantSHA256 != d.BootstrapGrantSHA256 || r.ManifestSHA256 != d.PreparedManifestSHA256 || r.CommandID != "" || r.CommandSHA256 != "" || r.AuthorityID != "" || r.Epoch != 0 || r.CandidateID != "" || r.LeaseID != "" {
			return "", bad
		}
		return d.ReceiptPublicKeyPEM, nil
	}
	return "", bad
}

// Match the existing host journal's bounded authority identities, which may
// include a controller prefix in addition to the host's 63-character token.
func pinAuthorityToken(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// SignPinReceipt signs host-supplied evidence. The trusted host must first
// persist and reread the referenced pin. This function performs no disk I/O.
func SignPinReceipt(signer *security.CommandSignatureSigner, v VerifiedPlan, r PinReceipt) ([]byte, error) {
	public, err := pinReceiptKey(v, r)
	if err != nil {
		return nil, err
	}
	id, err := publicKeyID([]byte(public))
	if err != nil || signer == nil || signer.PublicKeyID() != id {
		return nil, errors.New("controltransition: wrong host pin receipt signer")
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	sig, err := signer.SignCanonicalMaterial(append([]byte(pinReceiptDomain), raw...))
	if err != nil {
		return nil, err
	}
	signed, err := json.Marshal(signedPlan{Payload: raw, Signature: sig.Bytes()})
	if err != nil || len(signed) > PinReceiptMaximumBytes {
		return nil, errors.New("controltransition: pin receipt exceeds bound")
	}
	return signed, nil
}

// VerifyPinReceipt checks historical evidence. Current authorization requires
// an additional live-plan check; a receipt cannot extend the plan's lifetime.
func VerifyPinReceipt(v VerifiedPlan, raw []byte) (PinReceipt, error) {
	var r PinReceipt
	bad := errors.New("controltransition: pin receipt signature refused")
	var doc signedPlan
	if len(raw) > PinReceiptMaximumBytes || canonicalDecode(raw, &doc) != nil || canonicalDecode(doc.Payload, &r) != nil {
		return PinReceipt{}, bad
	}
	public, err := pinReceiptKey(v, r)
	if err != nil {
		return PinReceipt{}, err
	}
	key, owner, err := publicKey([]byte(public))
	if err != nil {
		return PinReceipt{}, bad
	}
	signature, ok := protocol.OpaqueSignatureTryCopyFrom(doc.Signature)
	if !ok {
		return PinReceipt{}, bad
	}
	id, _, sig, ok := security.DecodeCommandSignature(signature)
	hash := sha256.Sum256(append([]byte(pinReceiptDomain), doc.Payload...))
	if !ok || id != owner || !ecdsa.VerifyASN1(key, hash[:], sig) {
		return PinReceipt{}, bad
	}
	return r, nil
}

type VerifiedPlanPins struct {
	plan     VerifiedPlan
	receipts []string
}

// ReceiptDigests returns copies in source-first, then GRU/SFO/FRA destination
// order, omitting the source node when it also hosts the GRU destination.
func (v VerifiedPlanPins) ReceiptDigests(now time.Time) ([]string, error) {
	if err := v.plan.Check(now); err != nil {
		return nil, err
	}
	return slices.Clone(v.receipts), nil
}

// VerifyPlanPins requires one acknowledgement per distinct host. A co-hosted
// source/GRU destination uses its source pin receipt, which acknowledges the
// entire plan but does NOT prove that destination storage has been prepared.
func VerifyPlanPins(v VerifiedPlan, signed [][]byte, now time.Time) (VerifiedPlanPins, error) {
	var zero VerifiedPlanPins
	if err := v.Check(now); err != nil {
		return zero, err
	}
	p, err := v.Plan()
	if err != nil {
		return zero, err
	}
	nodes := []string{p.Source.NodeID}
	for _, d := range p.Destinations {
		if d.NodeID != p.Source.NodeID {
			nodes = append(nodes, d.NodeID)
		}
	}
	if len(signed) != len(nodes) {
		return zero, errors.New("controltransition: incomplete host pin receipts")
	}
	digests := make([]string, 0, len(nodes))
	pins := map[string]bool{}
	for i, node := range nodes {
		r, err := VerifyPinReceipt(v, signed[i])
		if err != nil {
			return zero, err
		}
		if r.NodeID != node || r.PublishedAt.After(now) || pins[r.PinSHA256] {
			return zero, errors.New("controltransition: conflicting host pin receipts")
		}
		pins[r.PinSHA256] = true
		digests = append(digests, Digest(signed[i]))
	}
	return VerifiedPlanPins{plan: v, receipts: digests}, nil
}
