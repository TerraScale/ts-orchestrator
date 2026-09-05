// Package preliminarytransfer binds immutable captured bytes to exact OCI
// destinations and finite upload or candidate-only restore authority.
package preliminarytransfer

import (
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

const scopeDomain = "TS-PRELIMINARY-TRANSFER-SCOPE-V1\x00"

type Destination struct {
	Region              string            `json:"region"`
	OCIRegion           string            `json:"ociRegion"`
	Namespace           string            `json:"namespace"`
	Bucket              string            `json:"bucket"`
	BucketResourceID    string            `json:"bucketResourceId"`
	CompartmentID       string            `json:"compartmentId"`
	OwnershipGeneration uint64            `json:"ownershipGeneration"`
	OwnershipTags       map[string]string `json:"ownershipTags"`
}
type ObjectMapping struct {
	Region    string `json:"region"`
	Account   string `json:"account"`
	Stream    string `json:"stream"`
	LocalKey  string `json:"localKey"`
	ObjectKey string `json:"objectKey"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
}
type Candidate struct {
	Region               string `json:"region"`
	NodeID               string `json:"nodeId"`
	ServerName           string `json:"serverName"`
	BootstrapGrantSHA256 string `json:"bootstrapGrantSha256"`
	ManifestSHA256       string `json:"manifestSha256"`
	ReceiptPublicKeyPEM  string `json:"receiptPublicKeyPem"`
}
type Scope struct {
	Version                int             `json:"version"`
	TransitionID           string          `json:"transitionId"`
	SourceNodeID           string          `json:"sourceNodeId"`
	InitialGrantSHA256     string          `json:"initialGrantSha256"`
	StoreScopeSHA256       string          `json:"storeScopeSha256"`
	ProfileSHA256          string          `json:"profileSha256"`
	SourcePublicKeyPEM     string          `json:"sourcePublicKeyPem"`
	CaptureRequest         json.RawMessage `json:"captureRequest"`
	CaptureReceipt         json.RawMessage `json:"captureReceipt"`
	RequestSHA256          string          `json:"requestSha256"`
	ReceiptSHA256          string          `json:"receiptSha256"`
	PreparationGrantSHA256 string          `json:"preparationGrantSha256"`
	Destinations           []Destination   `json:"destinations"`
	Objects                []ObjectMapping `json:"objects"`
	Candidates             []Candidate     `json:"candidates"`
	Prefix                 string          `json:"prefix"`
	MaxRestoreBytes        int64           `json:"maxRestoreBytes"`
	MaxSnapshotBytes       int64           `json:"maxSnapshotBytes"`
	MaxTotalBytes          int64           `json:"maxTotalBytes"`
}
type VerifiedScope struct {
	Scope      Scope
	Digest     string
	OwnerKeyID string
	Signed     []byte
	public     []byte
}

func CanonicalScope(s Scope) ([]byte, error) {
	if s.Version != 1 || !validToken(s.TransitionID) || !validToken(s.SourceNodeID) || !validDigest(s.InitialGrantSHA256) || !validDigest(s.StoreScopeSHA256) || !validDigest(s.ProfileSHA256) || !validDigest(s.PreparationGrantSHA256) || Digest(s.CaptureRequest) != s.RequestSHA256 || Digest(s.CaptureReceipt) != s.ReceiptSHA256 || !validObjectKey(s.Prefix) || s.MaxRestoreBytes < 1024 || s.MaxRestoreBytes > 256<<30 || s.MaxSnapshotBytes < 1024 || s.MaxSnapshotBytes > 1<<30 || s.MaxTotalBytes < s.MaxSnapshotBytes || s.MaxTotalBytes > 256<<30 {
		return nil, errors.New("preliminarytransfer: invalid immutable scope")
	}
	if _, err := PublicKeyID([]byte(s.SourcePublicKeyPEM)); err != nil {
		return nil, err
	}
	if len(s.Destinations) != 3 || len(s.Candidates) != 2 {
		return nil, errors.New("preliminarytransfer: exact launch destination and candidate inventory required")
	}
	seenRegions, seenBuckets := map[string]bool{}, map[string]bool{}
	for i, region := range []string{"gru", "sfo", "fra"} {
		d := s.Destinations[i]
		if seenRegions[d.OCIRegion] || seenBuckets[d.BucketResourceID] || d.Region != region || !validToken(d.OCIRegion) || !validToken(d.Namespace) || !validToken(d.Bucket) || !boundedIdentifier(d.BucketResourceID) || !boundedIdentifier(d.CompartmentID) || d.OwnershipGeneration == 0 || len(d.OwnershipTags) < 2 || len(d.OwnershipTags) > 32 || d.OwnershipTags["terrascale-managed"] == "" || d.OwnershipTags["terrascale-region"] != region {
			return nil, errors.New("preliminarytransfer: invalid exact OCI ownership destination")
		}
		seenRegions[d.OCIRegion], seenBuckets[d.BucketResourceID] = true, true
		for k, v := range d.OwnershipTags {
			if !boundedIdentifier(k) || !boundedIdentifier(v) {
				return nil, errors.New("preliminarytransfer: invalid ownership tag")
			}
		}
	}
	pins := map[string]bool{}
	for i, region := range []string{"sfo", "fra"} {
		c := s.Candidates[i]
		id, err := PublicKeyID([]byte(c.ReceiptPublicKeyPEM))
		if c.Region != region || !validToken(c.NodeID) || !validToken(c.ServerName) || !validDigest(c.BootstrapGrantSHA256) || !validDigest(c.ManifestSHA256) || err != nil || pins[id] {
			return nil, errors.New("preliminarytransfer: invalid candidate receipt binding")
		}
		pins[id] = true
	}
	if s.Candidates[0].NodeID == s.Candidates[1].NodeID || s.Candidates[0].ServerName == s.Candidates[1].ServerName {
		return nil, errors.New("preliminarytransfer: duplicate candidate identity")
	}
	receipt, err := preliminarycapture.VerifyReceipt([]byte(s.SourcePublicKeyPEM), s.CaptureReceipt)
	if err != nil || receipt.SourceNodeID != s.SourceNodeID || receipt.TransitionID != s.TransitionID || receipt.RequestSHA256 != s.RequestSHA256 {
		return nil, errors.New("preliminarytransfer: capture receipt differs from source")
	}
	if len(s.Objects) != 3*len(receipt.Objects) {
		return nil, errors.New("preliminarytransfer: incomplete regional object mapping")
	}
	total := int64(0)
	for _, o := range receipt.Objects {
		if o.Size > s.MaxSnapshotBytes || total > s.MaxTotalBytes-o.Size {
			return nil, errors.New("preliminarytransfer: capture exceeds admitted capacity")
		}
		total += o.Size
	}
	seen := map[string]bool{}
	for i, d := range s.Destinations {
		for j, o := range receipt.Objects {
			m := s.Objects[i*len(receipt.Objects)+j]
			key := d.Region + "\x00" + m.ObjectKey
			if m.Region != d.Region || m.Account != o.Account || m.Stream != o.Stream || m.LocalKey != o.Key || m.SHA256 != o.SHA256 || m.Size != o.Size || !validObjectKey(m.ObjectKey) || m.ObjectKey != s.Prefix+"/"+s.RequestSHA256+"/"+o.Key || seen[key] {
				return nil, errors.New("preliminarytransfer: object bytes or destination changed")
			}
			seen[key] = true
		}
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > MaximumBytes {
		return nil, errors.New("preliminarytransfer: scope exceeds bound")
	}
	return raw, nil
}
func boundedIdentifier(v string) bool {
	if len(v) == 0 || len(v) > 512 {
		return false
	}
	for _, r := range v {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}
func SignScope(signer *security.CommandSignatureSigner, s Scope) ([]byte, error) {
	if _, err := CanonicalScope(s); err != nil {
		return nil, err
	}
	return signDocument(signer, scopeDomain, s)
}
func VerifyScope(public, signed []byte) (VerifiedScope, error) {
	var s Scope
	id, err := verifyDocument(public, signed, scopeDomain, &s)
	if err != nil {
		return VerifiedScope{}, err
	}
	if _, err := CanonicalScope(s); err != nil {
		return VerifiedScope{}, err
	}
	request, err := preliminarycapture.VerifyRequest(public, s.CaptureRequest)
	if err != nil {
		return VerifiedScope{}, err
	}
	r := request.Request
	receipt, err := preliminarycapture.VerifyReceipt([]byte(s.SourcePublicKeyPEM), s.CaptureReceipt)
	if err != nil || r.TransitionID != s.TransitionID || r.SourceNodeID != s.SourceNodeID || r.InitialGrantSHA256 != s.InitialGrantSHA256 || r.StoreScopeSHA256 != s.StoreScopeSHA256 || r.ProfileSHA256 != s.ProfileSHA256 || r.ControlEpoch != receipt.ControlEpoch || receipt.CreatedAt.Before(r.IssuedAt) || !receipt.CreatedAt.Before(r.ExpiresAt) {
		return VerifiedScope{}, errors.New("preliminarytransfer: source capture lineage differs")
	}
	index := 0
	for _, account := range r.Accounts {
		for _, stream := range account.Streams {
			if index >= len(receipt.Objects) {
				return VerifiedScope{}, errors.New("preliminarytransfer: incomplete capture inventory")
			}
			o := receipt.Objects[index]
			if o.Account != account.Account || o.Stream != stream || o.CreatedAt.Before(r.IssuedAt) || !o.CreatedAt.Before(r.ExpiresAt) {
				return VerifiedScope{}, errors.New("preliminarytransfer: capture inventory or time differs")
			}
			index++
		}
	}
	if index != len(receipt.Objects) {
		return VerifiedScope{}, errors.New("preliminarytransfer: extra capture object")
	}
	canonical, _ := CanonicalScope(s)
	return VerifiedScope{Scope: s, Digest: Digest(canonical), OwnerKeyID: id, Signed: append([]byte(nil), signed...), public: append([]byte(nil), public...)}, nil
}
func (v VerifiedScope) Check() error {
	fresh, err := VerifyScope(v.public, v.Signed)
	if err != nil || v.Digest != fresh.Digest || v.OwnerKeyID != fresh.OwnerKeyID || !reflect.DeepEqual(v.Scope, fresh.Scope) {
		return errors.New("preliminarytransfer: verified scope changed")
	}
	return nil
}

// CaptureEpoch is historical and never replaced by an upload authority epoch.
func (v VerifiedScope) CaptureEpoch() (uint64, error) {
	if err := v.Check(); err != nil {
		return 0, err
	}
	r, err := preliminarycapture.VerifyReceipt([]byte(v.Scope.SourcePublicKeyPEM), v.Scope.CaptureReceipt)
	return r.ControlEpoch, err
}

// CaptureTime returns the signed source completion time, without requiring the
// historical capture request to still be live during an authorized transfer.
func (v VerifiedScope) CaptureTime() (time.Time, error) {
	if err := v.Check(); err != nil {
		return time.Time{}, err
	}
	r, err := preliminarycapture.VerifyReceipt([]byte(v.Scope.SourcePublicKeyPEM), v.Scope.CaptureReceipt)
	return r.CreatedAt, err
}

// HistoricalCapture returns the verified completed capture request. Its original
// expiry remains intact; this grants no fresh capture or source mutation.
func (v VerifiedScope) HistoricalCapture() (preliminarycapture.VerifiedRequest, error) {
	if err := v.Check(); err != nil {
		return preliminarycapture.VerifiedRequest{}, err
	}
	return preliminarycapture.VerifyRequest(v.public, v.Scope.CaptureRequest)
}
