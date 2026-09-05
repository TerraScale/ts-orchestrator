package preliminarytransfer

import (
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/security"
)

const publicationDomain = "TS-PRELIMINARY-TRANSFER-PUBLICATION-V1\x00"

type PublishedObject struct {
	ObjectMapping
	ETag string `json:"etag"`
}
type PublicationReceipt struct {
	UploadAuthorization json.RawMessage   `json:"uploadAuthorization"`
	Version             int               `json:"version"`
	ScopeSHA256         string            `json:"scopeSha256"`
	UploadRequestSHA256 string            `json:"uploadRequestSha256"`
	ControlEpoch        uint64            `json:"controlEpoch"`
	CreatedAt           time.Time         `json:"createdAt"`
	Objects             []PublishedObject `json:"objects"`
}

func validPublication(r PublicationReceipt) bool {
	if len(r.UploadAuthorization) == 0 || len(r.UploadAuthorization) > MaximumBytes || r.Version != 1 || !validDigest(r.ScopeSHA256) || !validDigest(r.UploadRequestSHA256) || r.ControlEpoch == 0 || r.CreatedAt.IsZero() || len(r.Objects) == 0 || len(r.Objects) > 768 {
		return false
	}
	for _, o := range r.Objects {
		if !validToken(o.Region) || !captureName(o.Account) || !captureName(o.Stream) || !validObjectKey(o.LocalKey) || !validObjectKey(o.ObjectKey) || !validSHA256(o.SHA256) || o.Size <= 0 || o.Size > 1<<30 || !boundedIdentifier(o.ETag) {
			return false
		}
	}
	return true
}
func SignPublicationReceipt(s *security.CommandSignatureSigner, r PublicationReceipt) ([]byte, error) {
	if !validPublication(r) {
		return nil, errors.New("preliminarytransfer: invalid publication receipt")
	}
	return signDocument(s, publicationDomain, r)
}
func VerifyPublicationReceipt(public, signed []byte) (PublicationReceipt, error) {
	var r PublicationReceipt
	if _, err := verifyDocument(public, signed, publicationDomain, &r); err != nil {
		return r, err
	}
	if !validPublication(r) {
		return r, errors.New("preliminarytransfer: invalid publication receipt")
	}
	return r, nil
}

// CheckPublication proves every exact regional mapping was observed under this
// finite upload request. It does not assert final-cut freshness or candidate sync.
func CheckPublication(upload VerifiedUpload, signed []byte) (PublicationReceipt, error) {
	r, err := CheckPublicationForScope(upload.Scope, signed)
	if err != nil {
		return r, err
	}
	var request Request
	if canonicalDecode(upload.Signed, &request) != nil || upload.Check(r.CreatedAt) != nil || r.UploadRequestSHA256 != upload.Digest || r.ControlEpoch != upload.Authorization.ControlEpoch || !reflect.DeepEqual(r.UploadAuthorization, request.Authorization) {
		return r, errors.New("preliminarytransfer: publication upload request differs")
	}
	return r, nil
}

// CheckPublicationForScope validates a historical receipt under its original
// finite owner upload authorization. A renewal needs no source lease to verify
// that receipt and cannot replace its captured bytes, mappings or prior term.
func CheckPublicationForScope(scope VerifiedScope, signed []byte) (PublicationReceipt, error) {
	var empty PublicationReceipt
	if err := scope.Check(); err != nil {
		return empty, err
	}
	r, err := VerifyPublicationReceipt([]byte(scope.Scope.SourcePublicKeyPEM), signed)
	if err != nil {
		return r, err
	}
	var auth UploadAuthorization
	if _, err := verifyDocument(scope.public, r.UploadAuthorization, uploadDomain, &auth); err != nil {
		return r, err
	}
	captured, err := scope.CaptureTime()
	if err != nil {
		return r, err
	}
	epoch, err := scope.CaptureEpoch()
	if err != nil {
		return r, err
	}
	if !validUpload(auth) || auth.ScopeSHA256 != scope.Digest || auth.ControlEpoch != r.ControlEpoch || auth.IssuedAt.Before(captured) || r.CreatedAt.Before(auth.IssuedAt) || !r.CreatedAt.Before(auth.ExpiresAt) || r.CreatedAt.Before(captured) || r.ControlEpoch < epoch || r.ScopeSHA256 != scope.Digest || len(r.Objects) != len(scope.Scope.Objects) {
		return r, errors.New("preliminarytransfer: historical publication authority or scope differs")
	}
	for i, o := range r.Objects {
		if !reflect.DeepEqual(o.ObjectMapping, scope.Scope.Objects[i]) {
			return r, errors.New("preliminarytransfer: publication mapping differs")
		}
	}
	return r, nil
}

func PublicationKey(scope Scope) string {
	return scope.Prefix + "/" + scope.RequestSHA256 + "/publication.receipt.json"
}

func captureName(value string) bool {
	if len(value) == 0 || len(value) > 255 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
