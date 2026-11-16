package delivery

import (
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/release"
)

const (
	SchemaVersion                = 1
	MaxIntentBytes               = 32 << 10
	MaxArtifactBytes             = 512 << 20
	DefaultArtifactStoreMaxBytes = int64(2 << 30)
)

var (
	ErrInvalid           = errors.New("invalid delivery input")
	ErrConflict          = errors.New("delivery operation conflicts with its durable identity")
	ErrPending           = errors.New("delivery operation has no terminal receipt")
	ErrUnauthorized      = errors.New("delivery actor is unauthorized")
	ErrArtifactStoreFull = errors.New("delivery artifact store quota is full")
)

// ArtifactSource is an asserted, signed source identity. It is not a claim that
// this service has built or reproduced the binary from that source.
type ArtifactSource struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	TreeDigest string `json:"treeDigest"`
}

type ArtifactClaimRequest struct {
	ReleaseSequence         uint64         `json:"release_sequence,omitempty"`
	SequenceMigrationSHA256 string         `json:"sequence_migration_sha256,omitempty"`
	Source                  ArtifactSource `json:"source"`
	Cell                    string         `json:"cell"`
	Role                    string         `json:"role"`
	Environment             string         `json:"environment"`
}

// ArtifactRecord is the immutable, content-addressed admission record. The
// manifest digest is SHA-256 of the canonical JSON encoding of these fields.
type ArtifactRecord struct {
	ReleaseSequence         uint64         `json:"release_sequence,omitempty"`
	SequenceMigrationSHA256 string         `json:"sequence_migration_sha256,omitempty"`
	SchemaVersion           int            `json:"schemaVersion"`
	Digest                  string         `json:"digest"`
	Source                  ArtifactSource `json:"source"`
	Cell                    string         `json:"cell"`
	Role                    string         `json:"role"`
	Environment             string         `json:"environment"`
	Size                    int64          `json:"size"`
	ManifestDigest          string         `json:"manifestDigest"`
}

// Intent asks the regional controller to accept an exact admitted artifact as
// desired state. A rollback is a new Intent with a higher generation and a
// previously admitted artifact digest.
type Intent struct {
	Container       *release.ContainerBundle `json:"container,omitempty"`
	SchemaVersion   int                      `json:"schemaVersion"`
	OperationID     string                   `json:"operationId"`
	Source          ArtifactSource           `json:"source"`
	ArtifactDigest  string                   `json:"artifactDigest"`
	ManifestDigest  string                   `json:"manifestDigest"`
	Cell            string                   `json:"cell"`
	Role            string                   `json:"role"`
	Environment     string                   `json:"environment"`
	Generation      uint64                   `json:"generation"`
	DesiredReplicas int                      `json:"desiredReplicas"`
	ConfigDigest    string                   `json:"configDigest"`
	AuthorityEpoch  uint64                   `json:"authorityEpoch"`
}
