package preliminarytransfer

import (
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
	Version             int               `json:"version"`
	ScopeSHA256         string            `json:"scopeSha256"`
	UploadRequestSHA256 string            `json:"uploadRequestSha256"`
	ControlEpoch        uint64            `json:"controlEpoch"`
	CreatedAt           time.Time         `json:"createdAt"`
	Objects             []PublishedObject `json:"objects"`
}

func validPublication(r PublicationReceipt) bool {
	if r.Version != 1 || !validDigest(r.ScopeSHA256) || !validDigest(r.UploadRequestSHA256) || r.ControlEpoch == 0 || r.CreatedAt.IsZero() || len(r.Objects) == 0 || len(r.Objects) > 768 {
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
	r, err := VerifyPublicationReceipt([]byte(upload.Scope.Scope.SourcePublicKeyPEM), signed)
	if err != nil {
		return r, err
	}
	if upload.Check(r.CreatedAt) != nil || r.ScopeSHA256 != upload.Scope.Digest || r.UploadRequestSHA256 != upload.Digest || r.ControlEpoch != upload.Authorization.ControlEpoch || len(r.Objects) != len(upload.Scope.Scope.Objects) {
		return r, errors.New("preliminarytransfer: publication scope or authority differs")
	}
	for i, o := range r.Objects {
		if !reflect.DeepEqual(o.ObjectMapping, upload.Scope.Scope.Objects[i]) {
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
