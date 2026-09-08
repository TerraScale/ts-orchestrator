package controltransition

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"slices"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"time"
)

const restoreReceiptDomain = "TS-CONTROL-FINAL-RESTORE-QUORUM-V1\x00"

type RestoredStream struct {
	SourceCreated time.Time      `json:"sourceCreated"`
	Observed      StreamEvidence `json:"observed"`
	Servers       []string       `json:"servers"`
}

// RestoreReceipt is historical evidence, never a lease or authority activation.
type RestoreReceipt struct {
	Version               int              `json:"version"`
	Phase                 string           `json:"phase"`
	PlanSHA256            string           `json:"planSha256"`
	CaptureReceiptSHA256  string           `json:"captureReceiptSha256"`
	NodeID                string           `json:"nodeId"`
	Cluster               string           `json:"cluster"`
	GlobalElectionFloor   int64            `json:"globalElectionFloor"`
	RegionalElectionFloor int64            `json:"regionalElectionFloor"`
	RestoredAt            time.Time        `json:"restoredAt"`
	Streams               []RestoredStream `json:"streams"`
}

func validateRestoreReceipt(v VerifiedPlan, capture CaptureReceipt, r RestoreReceipt) error {
	p, err := v.Plan()
	if err != nil {
		return err
	}
	bad := errors.New("controltransition: final restore evidence differs")
	if r.Version != 1 || r.Phase != "final-restored-r3" || r.PlanSHA256 != v.Digest() || !validDigest(r.CaptureReceiptSHA256) || r.NodeID != p.Destinations[0].NodeID || r.Cluster != p.ClusterName || v.Check(r.RestoredAt) != nil || r.RestoredAt.Before(capture.CapturedAt) || r.GlobalElectionFloor != capture.GlobalElectionFloor || r.RegionalElectionFloor != capture.RegionalElectionFloor || len(r.Streams) != len(capture.Streams) {
		return bad
	}
	servers := make([]string, 0, 3)
	for _, d := range p.Destinations {
		servers = append(servers, d.ServerName)
	}
	slices.Sort(servers)
	index := 0
	for _, account := range p.Accounts {
		for _, stream := range account.Streams {
			actual, source := r.Streams[index], capture.Streams[index]
			index++
			observed := actual.Observed
			if !actual.SourceCreated.Equal(source.Created) || observed.Created.IsZero() || observed.Role != account.Role || observed.Account != account.DestinationName || observed.Stream != stream.Name || observed.ConfigSHA256 != stream.FinalConfigSHA256 || observed.RecordsSHA256 != source.RecordsSHA256 || observed.StateSHA256 != source.StateSHA256 || !slices.Equal(actual.Servers, servers) || len(observed.Consumers) != len(source.Consumers) {
				return bad
			}
			for i, c := range observed.Consumers {
				prior := source.Consumers[i]
				if c.Name != prior.Name || !c.Created.Equal(prior.Created) || c.Durable != prior.Durable || c.ConfigSHA256 != stream.Consumers[i].FinalConfigSHA256 || c.CheckpointSHA256 != prior.CheckpointSHA256 {
					return bad
				}
			}
		}
	}
	return nil
}
func SignRestoreReceipt(signer *security.CommandSignatureSigner, v VerifiedPlan, cutRaw, sourceRaw, captureRaw []byte, r RestoreReceipt) ([]byte, error) {
	capture, err := VerifyCaptureReceipt(v, cutRaw, sourceRaw, captureRaw)
	if err != nil {
		return nil, err
	}
	if r.CaptureReceiptSHA256 != Digest(captureRaw) {
		return nil, errors.New("controltransition: restore predecessor differs")
	}
	if err := validateRestoreReceipt(v, capture, r); err != nil {
		return nil, err
	}
	p, _ := v.Plan()
	id, err := publicKeyID([]byte(p.Destinations[0].ReceiptPublicKeyPEM))
	if err != nil || signer == nil || signer.PublicKeyID() != id {
		return nil, errors.New("controltransition: wrong restore signer")
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	signature, err := signer.SignCanonicalMaterial(append([]byte(restoreReceiptDomain), raw...))
	if err != nil {
		return nil, err
	}
	signed, err := json.Marshal(signedPlan{Payload: raw, Signature: signature.Bytes()})
	if err != nil || len(signed) > MaximumBytes {
		return nil, errors.New("controltransition: restore receipt exceeds bound")
	}
	return signed, nil
}
func VerifyRestoreReceipt(v VerifiedPlan, cutRaw, sourceRaw, captureRaw, raw []byte) (RestoreReceipt, error) {
	var r RestoreReceipt
	var doc signedPlan
	bad := errors.New("controltransition: restore receipt signature refused")
	if len(raw) > MaximumBytes || canonicalDecode(raw, &doc) != nil || canonicalDecode(doc.Payload, &r) != nil {
		return r, bad
	}
	p, err := v.Plan()
	if err != nil {
		return r, err
	}
	key, owner, err := publicKey([]byte(p.Destinations[0].ReceiptPublicKeyPEM))
	if err != nil {
		return r, bad
	}
	signature, ok := protocol.OpaqueSignatureTryCopyFrom(doc.Signature)
	if !ok {
		return r, bad
	}
	id, _, sig, ok := security.DecodeCommandSignature(signature)
	hash := sha256.Sum256(append([]byte(restoreReceiptDomain), doc.Payload...))
	if !ok || id != owner || !ecdsa.VerifyASN1(key, hash[:], sig) {
		return r, bad
	}
	capture, err := VerifyCaptureReceipt(v, cutRaw, sourceRaw, captureRaw)
	if err != nil {
		return r, err
	}
	if r.CaptureReceiptSHA256 != Digest(captureRaw) {
		return r, bad
	}
	return r, validateRestoreReceipt(v, capture, r)
}
