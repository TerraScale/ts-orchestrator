package preliminarytransfer

import (
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/security"
)

const uploadDomain = "TS-PRELIMINARY-TRANSFER-UPLOAD-V1\x00"
const candidateDomain = "TS-PRELIMINARY-TRANSFER-CANDIDATE-V1\x00"

type UploadAuthorization struct {
	Version      int       `json:"version"`
	ScopeSHA256  string    `json:"scopeSha256"`
	ControlEpoch uint64    `json:"controlEpoch"`
	IssuedAt     time.Time `json:"issuedAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
}
type CandidateAuthorization struct {
	Version     int       `json:"version"`
	ScopeSHA256 string    `json:"scopeSha256"`
	NodeID      string    `json:"nodeId"`
	IssuedAt    time.Time `json:"issuedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

// Request contains two independently owner-signed documents. Renewing an
// authorization cannot change the canonical immutable scope digest.
type Request struct {
	Scope         json.RawMessage `json:"scope"`
	Authorization json.RawMessage `json:"authorization"`
}
type VerifiedUpload struct {
	Scope         VerifiedScope
	Authorization UploadAuthorization
	Digest        string
	Signed        []byte
	public        []byte
}
type VerifiedCandidate struct {
	Scope         VerifiedScope
	Authorization CandidateAuthorization
	Digest        string
	Signed        []byte
	public        []byte
}

func validUpload(a UploadAuthorization) bool {
	return a.Version == 1 && validDigest(a.ScopeSHA256) && a.ControlEpoch > 0 && finite(a.IssuedAt, a.ExpiresAt)
}
func validCandidate(a CandidateAuthorization) bool {
	return a.Version == 1 && validDigest(a.ScopeSHA256) && validToken(a.NodeID) && finite(a.IssuedAt, a.ExpiresAt)
}
func SignUploadAuthorization(s *security.CommandSignatureSigner, a UploadAuthorization) ([]byte, error) {
	if !validUpload(a) {
		return nil, errors.New("preliminarytransfer: invalid upload authorization")
	}
	return signDocument(s, uploadDomain, a)
}
func SignCandidateAuthorization(s *security.CommandSignatureSigner, a CandidateAuthorization) ([]byte, error) {
	if !validCandidate(a) {
		return nil, errors.New("preliminarytransfer: invalid candidate authorization")
	}
	return signDocument(s, candidateDomain, a)
}
func MarshalRequest(scope, authorization []byte) ([]byte, error) {
	raw, err := json.Marshal(Request{scope, authorization})
	if err != nil || len(raw) > MaximumBytes {
		return nil, errors.New("preliminarytransfer: request exceeds bound")
	}
	return raw, nil
}
func VerifyUploadRequest(public, raw []byte, now time.Time) (VerifiedUpload, error) {
	var r Request
	var a UploadAuthorization
	if err := canonicalDecode(raw, &r); err != nil {
		return VerifiedUpload{}, err
	}
	s, err := VerifyScope(public, r.Scope)
	if err != nil {
		return VerifiedUpload{}, err
	}
	if _, err := verifyDocument(public, r.Authorization, uploadDomain, &a); err != nil {
		return VerifiedUpload{}, err
	}
	if !validUpload(a) || a.ScopeSHA256 != s.Digest || now.Before(a.IssuedAt) || !now.Before(a.ExpiresAt) {
		return VerifiedUpload{}, errors.New("preliminarytransfer: upload authorization scope or time refused")
	}
	captured, err := s.CaptureTime()
	if err != nil || a.IssuedAt.Before(captured) {
		return VerifiedUpload{}, errors.New("preliminarytransfer: upload predates completed capture")
	}
	epoch, err := s.CaptureEpoch()
	if err != nil || a.ControlEpoch < epoch {
		return VerifiedUpload{}, errors.New("preliminarytransfer: upload epoch regresses capture epoch")
	}
	return VerifiedUpload{Scope: s, Authorization: a, Digest: Digest(raw), Signed: append([]byte(nil), raw...), public: append([]byte(nil), public...)}, nil
}
func VerifyCandidateRequest(public, raw []byte, now time.Time) (VerifiedCandidate, error) {
	var r Request
	var a CandidateAuthorization
	if err := canonicalDecode(raw, &r); err != nil {
		return VerifiedCandidate{}, err
	}
	s, err := VerifyScope(public, r.Scope)
	if err != nil {
		return VerifiedCandidate{}, err
	}
	if _, err := verifyDocument(public, r.Authorization, candidateDomain, &a); err != nil {
		return VerifiedCandidate{}, err
	}
	if !validCandidate(a) || a.ScopeSHA256 != s.Digest || now.Before(a.IssuedAt) || !now.Before(a.ExpiresAt) {
		return VerifiedCandidate{}, errors.New("preliminarytransfer: candidate authorization scope or time refused")
	}
	captured, err := s.CaptureTime()
	if err != nil || a.IssuedAt.Before(captured) {
		return VerifiedCandidate{}, errors.New("preliminarytransfer: candidate authorization predates capture")
	}
	found := false
	for _, c := range s.Scope.Candidates {
		found = found || c.NodeID == a.NodeID
	}
	if !found {
		return VerifiedCandidate{}, errors.New("preliminarytransfer: candidate not in exact prepared inventory")
	}
	return VerifiedCandidate{Scope: s, Authorization: a, Digest: Digest(raw), Signed: append([]byte(nil), raw...), public: append([]byte(nil), public...)}, nil
}
func (v VerifiedUpload) Check(now time.Time) error {
	fresh, err := VerifyUploadRequest(v.public, v.Signed, now)
	if err != nil || v.Digest != fresh.Digest || v.Authorization != fresh.Authorization || !reflect.DeepEqual(v.Scope.Scope, fresh.Scope.Scope) || v.Scope.Digest != fresh.Scope.Digest {
		return errors.New("preliminarytransfer: upload authorization changed or expired")
	}
	return v.Scope.Check()
}
func (v VerifiedCandidate) Check(now time.Time) error {
	fresh, err := VerifyCandidateRequest(v.public, v.Signed, now)
	if err != nil || v.Digest != fresh.Digest || v.Authorization != fresh.Authorization || !reflect.DeepEqual(v.Scope.Scope, fresh.Scope.Scope) || v.Scope.Digest != fresh.Scope.Digest {
		return errors.New("preliminarytransfer: candidate authorization changed or expired")
	}
	return v.Scope.Check()
}

// CheckUploadRenewal compares independently verified authorizations. The prior
// request may have expired; validate its signature at its own IssuedAt first.
func CheckUploadRenewal(prior, next VerifiedUpload) error {
	if prior.Check(prior.Authorization.IssuedAt) != nil || next.Check(next.Authorization.IssuedAt) != nil || prior.Scope.Digest != next.Scope.Digest || prior.Scope.OwnerKeyID != next.Scope.OwnerKeyID || next.Authorization.ControlEpoch < prior.Authorization.ControlEpoch || next.Authorization.IssuedAt.Before(prior.Authorization.IssuedAt) || next.Authorization.ExpiresAt.Before(prior.Authorization.ExpiresAt) {
		return errors.New("preliminarytransfer: upload renewal changed scope or regressed authority")
	}
	return nil
}
