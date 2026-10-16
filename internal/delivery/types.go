package delivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	SchemaVersion                = 1
	MaxIntentBytes               = 32 << 10
	MaxArtifactBytes             = 512 << 20
	DefaultArtifactStoreMaxBytes = int64(2 << 30)
	// maxReplicas bounds intent and shaped replica counts. It is the
	// autoscaler's own bound, so shaped plans can never exceed it.
	maxReplicas = autoscale.MaxReplicas
)

var (
	ErrStoreNotReady     = errors.New("new delivery store is not yet visible")
	ErrInvalid           = errors.New("invalid delivery input")
	ErrConflict          = errors.New("delivery operation conflicts with its durable identity")
	ErrPending           = errors.New("delivery operation has no terminal receipt")
	ErrUnauthorized      = errors.New("delivery actor is unauthorized")
	ErrArtifactStoreFull = errors.New("delivery artifact store quota is full")
	sha256RE             = regexp.MustCompile(`^[0-9a-f]{64}$`)
	nameRE               = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	commitRE             = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
)

// ArtifactSource is an asserted, signed source identity. It is not a claim that
// this service has built or reproduced the binary from that source.
type ArtifactSource struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	TreeDigest string `json:"treeDigest"`
}

type ArtifactClaimRequest struct {
	Source      ArtifactSource `json:"source"`
	Cell        string         `json:"cell"`
	Role        string         `json:"role"`
	Environment string         `json:"environment"`
}

func (r ArtifactClaimRequest) validate() error {
	if !nameRE.MatchString(r.Cell) || !nameRE.MatchString(r.Role) || !nameRE.MatchString(r.Environment) {
		return fmt.Errorf("%w: artifact target", ErrInvalid)
	}
	return r.Source.validate()
}

func (s ArtifactSource) validate() error {
	u, err := url.Parse(s.Repository)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(s.Repository) > 512 || !commitRE.MatchString(s.Commit) || !sha256RE.MatchString(s.TreeDigest) {
		return fmt.Errorf("%w: source must bind an HTTPS repository, commit and SHA-256 tree", ErrInvalid)
	}
	return nil
}

// ArtifactRecord is the immutable, content-addressed admission record. The
// manifest digest is SHA-256 of the canonical JSON encoding of these fields.
type ArtifactRecord struct {
	SchemaVersion  int            `json:"schemaVersion"`
	Digest         string         `json:"digest"`
	Source         ArtifactSource `json:"source"`
	Cell           string         `json:"cell"`
	Role           string         `json:"role"`
	Environment    string         `json:"environment"`
	Size           int64          `json:"size"`
	ManifestDigest string         `json:"manifestDigest"`
}

// NewArtifactRecord is the record of size bytes with SHA-256 digest that
// request claims, as PrepareArtifact builds it. CI signs it with
// Ed25519Codec.SignArtifact for a controller to admit (AdmitClaim).
func NewArtifactRecord(request ArtifactClaimRequest, digest string, size int64) (ArtifactRecord, error) {
	if err := request.validate(); err != nil {
		return ArtifactRecord{}, err
	}
	r := ArtifactRecord{SchemaVersion: SchemaVersion, Digest: digest, Source: request.Source, Cell: request.Cell,
		Role: request.Role, Environment: request.Environment, Size: size}
	manifest, err := r.calculatedManifestDigest()
	if err != nil {
		return ArtifactRecord{}, err
	}
	r.ManifestDigest = manifest
	return r, r.validate()
}

func (r ArtifactRecord) calculatedManifestDigest() (string, error) {
	r.ManifestDigest = ""
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (r ArtifactRecord) validate() error {
	if r.SchemaVersion != SchemaVersion || !sha256RE.MatchString(r.Digest) || !sha256RE.MatchString(r.ManifestDigest) || r.Size <= 0 || r.Size > MaxArtifactBytes || !nameRE.MatchString(r.Cell) || !nameRE.MatchString(r.Role) || !nameRE.MatchString(r.Environment) {
		return fmt.Errorf("%w: artifact record", ErrInvalid)
	}
	if err := r.Source.validate(); err != nil {
		return err
	}
	got, err := r.calculatedManifestDigest()
	if err != nil || got != r.ManifestDigest {
		return fmt.Errorf("%w: manifest digest mismatch", ErrInvalid)
	}
	return nil
}

// Intent asks the regional controller to accept an exact admitted artifact as
// desired state. A rollback is a new Intent with a higher generation and a
// previously admitted artifact digest.
type Intent struct {
	SchemaVersion   int            `json:"schemaVersion"`
	OperationID     string         `json:"operationId"`
	Source          ArtifactSource `json:"source"`
	ArtifactDigest  string         `json:"artifactDigest"`
	ManifestDigest  string         `json:"manifestDigest"`
	Cell            string         `json:"cell"`
	Role            string         `json:"role"`
	Environment     string         `json:"environment"`
	Generation      uint64         `json:"generation"`
	DesiredReplicas int            `json:"desiredReplicas"`
	ConfigDigest    string         `json:"configDigest"`
	AuthorityEpoch  uint64         `json:"authorityEpoch"`
}

func (i Intent) Validate() error {
	if i.SchemaVersion != SchemaVersion || !entityid.Valid(i.OperationID) || !nameRE.MatchString(i.Cell) || !nameRE.MatchString(i.Role) || !nameRE.MatchString(i.Environment) || !sha256RE.MatchString(i.ArtifactDigest) || !sha256RE.MatchString(i.ManifestDigest) || !sha256RE.MatchString(i.ConfigDigest) || i.Generation == 0 || i.AuthorityEpoch == 0 || i.DesiredReplicas < 0 || i.DesiredReplicas > maxReplicas {
		return fmt.Errorf("%w: delivery intent", ErrInvalid)
	}
	return i.Source.validate()
}

func (i Intent) fingerprint() (string, error) {
	b, err := json.Marshal(i)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Fingerprint is the stable request identity callers should retain with the
// operation ID and compare with the eventual receipt.
func (i Intent) Fingerprint() (string, error) {
	if err := i.Validate(); err != nil {
		return "", err
	}
	return i.fingerprint()
}

// DecodeIntent stays strict: an intent is signed, so a controller must not
// act on one whose members it cannot read. A newer member is omitted while
// unset, and setting it is a new schemaVersion.
func DecodeIntent(b []byte) (Intent, error) {
	if len(b) == 0 || len(b) > MaxIntentBytes {
		return Intent{}, fmt.Errorf("%w: intent size", ErrInvalid)
	}
	var i Intent
	if err := protocol.DecodeStrict(b, &i, MaxIntentBytes); err != nil {
		return Intent{}, fmt.Errorf("%w: decode intent: %v", ErrInvalid, err)
	}
	return i, i.Validate()
}
