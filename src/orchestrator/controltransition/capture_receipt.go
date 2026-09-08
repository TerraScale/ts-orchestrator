package controltransition

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"math"
	"reflect"
	"strconv"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

const sourceStateDomain = "TS-CONTROL-SOURCE-QUIESCED-STATE-V1\x00"
const captureReceiptDomain = "TS-CONTROL-FINAL-CAPTURE-V1\x00"

// StreamEvidence binds retained records, allocator/deletion state, and every
// persistent consumer checkpoint. It excludes transport and archive timestamps.
type StreamEvidence struct {
	Role          string             `json:"role"`
	Account       string             `json:"account"`
	Stream        string             `json:"stream"`
	Created       time.Time          `json:"created"`
	ConfigSHA256  string             `json:"configSha256"`
	RecordsSHA256 string             `json:"recordsSha256"`
	StateSHA256   string             `json:"stateSha256"`
	Consumers     []ConsumerEvidence `json:"consumers"`
}

type ConsumerEvidence struct {
	Name             string    `json:"name"`
	Created          time.Time `json:"created"`
	Durable          bool      `json:"durable"`
	ConfigSHA256     string    `json:"configSha256"`
	CheckpointSHA256 string    `json:"checkpointSha256"`
}

// SourceStateReceipt must be produced while ordinary source clients and
// workers are quiesced. Signing this value does not perform that fencing.
type SourceStateReceipt struct {
	Version               int              `json:"version"`
	Phase                 string           `json:"phase"`
	PlanSHA256            string           `json:"planSha256"`
	NodeID                string           `json:"nodeId"`
	QuiescedAt            time.Time        `json:"quiescedAt"`
	ObservedAt            time.Time        `json:"observedAt"`
	GlobalElectionFloor   int64            `json:"globalElectionFloor"`
	RegionalElectionFloor int64            `json:"regionalElectionFloor"`
	Streams               []StreamEvidence `json:"streams"`
}

type CaptureObject struct {
	ControlEpoch uint64 `json:"controlEpoch"`
	Role         string `json:"role"`
	Stream       string `json:"stream"`
	Key          string `json:"key"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
}

type CaptureReceipt struct {
	Version                  int              `json:"version"`
	Phase                    string           `json:"phase"`
	PlanSHA256               string           `json:"planSha256"`
	CutReceiptSHA256         string           `json:"cutReceiptSha256"`
	SourceStateReceiptSHA256 string           `json:"sourceStateReceiptSha256"`
	NodeID                   string           `json:"nodeId"`
	StoreSHA256              string           `json:"storeSha256"`
	CopySHA256               string           `json:"copySha256"`
	CapturedAt               time.Time        `json:"capturedAt"`
	GlobalElectionFloor      int64            `json:"globalElectionFloor"`
	RegionalElectionFloor    int64            `json:"regionalElectionFloor"`
	Streams                  []StreamEvidence `json:"streams"`
	Objects                  []CaptureObject  `json:"objects"`
}

func CaptureObjectKey(v VerifiedPlan, role, stream string, controlEpoch uint64) (string, error) {
	p, err := v.Plan()
	if err != nil {
		return "", err
	}
	if controlEpoch < uint64(p.GlobalElectionFloor) || controlEpoch > math.MaxInt64 {
		return "", errors.New("controltransition: snapshot election floor invalid")
	}
	for _, account := range p.Accounts {
		for _, item := range account.Streams {
			if role == account.Role && stream == item.Name {
				return "final/" + v.Digest() + "/" + role + "/" + stream + ".epoch-" + strconv.FormatUint(controlEpoch, 10) + ".snapshot", nil
			}
		}
	}
	return "", errors.New("controltransition: unadmitted final snapshot")
}

func ValidateStreamEvidence(v VerifiedPlan, streams []StreamEvidence) error {
	p, err := v.Plan()
	if err != nil {
		return err
	}
	bad := errors.New("controltransition: final source inventory differs from plan")
	index := 0
	for _, account := range p.Accounts {
		for _, stream := range account.Streams {
			if index >= len(streams) {
				return bad
			}
			e := streams[index]
			index++
			if e.Role != account.Role || e.Account != account.SourceName || e.Stream != stream.Name || e.Created.IsZero() || e.ConfigSHA256 != stream.SourceConfigSHA256 || !validDigest(e.RecordsSHA256) || !validDigest(e.StateSHA256) || len(e.Consumers) != len(stream.Consumers) {
				return bad
			}
			for i, consumer := range stream.Consumers {
				c := e.Consumers[i]
				if c.Name != consumer.Name || c.Durable != consumer.Durable || c.Created.IsZero() || c.ConfigSHA256 != consumer.SourceConfigSHA256 || !validDigest(c.CheckpointSHA256) {
					return bad
				}
			}
		}
	}
	if index != len(streams) {
		return bad
	}
	return nil
}

func sourceStateValid(v VerifiedPlan, r SourceStateReceipt) error {
	p, err := v.Plan()
	if err != nil {
		return err
	}
	if r.Version != 1 || r.Phase != "source-quiesced" || r.PlanSHA256 != v.Digest() || r.NodeID != p.Source.NodeID || v.Check(r.QuiescedAt) != nil || v.Check(r.ObservedAt) != nil || r.ObservedAt.Before(r.QuiescedAt) || r.GlobalElectionFloor < p.GlobalElectionFloor || r.RegionalElectionFloor < p.RegionalElectionFloor {
		return errors.New("controltransition: invalid quiescent source evidence")
	}
	return ValidateStreamEvidence(v, r.Streams)
}

func SignSourceStateReceipt(signer *security.CommandSignatureSigner, v VerifiedPlan, r SourceStateReceipt) ([]byte, error) {
	if err := sourceStateValid(v, r); err != nil {
		return nil, err
	}
	return signSourceDocument(signer, v, sourceStateDomain, r)
}

func VerifySourceStateReceipt(v VerifiedPlan, raw []byte) (SourceStateReceipt, error) {
	var r SourceStateReceipt
	if err := verifySourceDocument(v, sourceStateDomain, raw, &r); err != nil {
		return r, err
	}
	return r, sourceStateValid(v, r)
}

func captureReceiptValid(v VerifiedPlan, cutRaw, sourceRaw []byte, r CaptureReceipt) error {
	cut, err := VerifyCutReceipt(v, cutRaw)
	if err != nil {
		return err
	}
	source, err := VerifySourceStateReceipt(v, sourceRaw)
	if err != nil {
		return err
	}
	p, _ := v.Plan()
	if r.Version != 1 || r.Phase != "final-capture" || r.PlanSHA256 != v.Digest() || r.CutReceiptSHA256 != Digest(cutRaw) || r.SourceStateReceiptSHA256 != Digest(sourceRaw) || cut.SourceStateReceiptSHA256 != Digest(sourceRaw) || r.NodeID != p.Source.NodeID || r.StoreSHA256 != cut.StoreSHA256 || r.CopySHA256 != cut.CopySHA256 || v.Check(r.CapturedAt) != nil || r.CapturedAt.Before(cut.CopiedAt) || source.ObservedAt.After(cut.StoppedAt) || r.GlobalElectionFloor != source.GlobalElectionFloor || r.RegionalElectionFloor != source.RegionalElectionFloor || !reflect.DeepEqual(r.Streams, source.Streams) || len(r.Objects) != len(r.Streams) {
		return errors.New("controltransition: final capture predecessor or state differs")
	}
	var total int64
	for i, object := range r.Objects {
		e := r.Streams[i]
		key, err := CaptureObjectKey(v, e.Role, e.Stream, uint64(r.GlobalElectionFloor))
		if err != nil || object.ControlEpoch != uint64(r.GlobalElectionFloor) || object.Role != e.Role || object.Stream != e.Stream || object.Key != key || !validDigest(object.SHA256) || object.Size <= 0 || object.Size > p.Limits.MaxSnapshotBytes || total > p.Limits.MaxTransferBytes-object.Size {
			return errors.New("controltransition: final capture archive inventory differs")
		}
		total += object.Size
	}
	return nil
}

func SignCaptureReceipt(signer *security.CommandSignatureSigner, v VerifiedPlan, cutRaw, sourceRaw []byte, r CaptureReceipt) ([]byte, error) {
	if err := captureReceiptValid(v, cutRaw, sourceRaw, r); err != nil {
		return nil, err
	}
	return signSourceDocument(signer, v, captureReceiptDomain, r)
}

func VerifyCaptureReceipt(v VerifiedPlan, cutRaw, sourceRaw, raw []byte) (CaptureReceipt, error) {
	var r CaptureReceipt
	if err := verifySourceDocument(v, captureReceiptDomain, raw, &r); err != nil {
		return r, err
	}
	return r, captureReceiptValid(v, cutRaw, sourceRaw, r)
}

func signSourceDocument(signer *security.CommandSignatureSigner, v VerifiedPlan, domain string, value any) ([]byte, error) {
	p, err := v.Plan()
	if err != nil {
		return nil, err
	}
	id, err := publicKeyID([]byte(p.Source.ReceiptPublicKeyPEM))
	if err != nil || signer == nil || signer.PublicKeyID() != id {
		return nil, errors.New("controltransition: wrong source receipt signer")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	sig, err := signer.SignCanonicalMaterial(append([]byte(domain), raw...))
	if err != nil {
		return nil, err
	}
	signed, err := json.Marshal(signedPlan{Payload: raw, Signature: sig.Bytes()})
	if err != nil || len(signed) > MaximumBytes {
		return nil, errors.New("controltransition: source receipt exceeds bound")
	}
	return signed, nil
}

func verifySourceDocument(v VerifiedPlan, domain string, raw []byte, value any) error {
	bad := errors.New("controltransition: source receipt signature refused")
	p, err := v.Plan()
	if err != nil {
		return err
	}
	var doc signedPlan
	if canonicalDecode(raw, &doc) != nil || canonicalDecode(doc.Payload, value) != nil {
		return bad
	}
	key, id, err := publicKey([]byte(p.Source.ReceiptPublicKeyPEM))
	if err != nil {
		return bad
	}
	signature, ok := protocol.OpaqueSignatureTryCopyFrom(doc.Signature)
	if !ok {
		return bad
	}
	got, _, sig, ok := security.DecodeCommandSignature(signature)
	hash := sha256.Sum256(append([]byte(domain), doc.Payload...))
	if !ok || got != id || !ecdsa.VerifyASN1(key, hash[:], sig) {
		return bad
	}
	return nil
}
