package bootstrapstart

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

const (
	MaterialDirectory = bootstrap.MaterialDirectory
	StagingDirectory  = "/run/terrascale-orchestrator-bootstrap"
)

var ErrMaterial = errors.New("controller credential material is invalid")

type SecretMaterializer interface {
	MaterializeCurrent(context.Context, bootstrap.StartupAuthority, bootstrap.VerifiedReceipt,
		bootstrap.SecretReference, string, func(time.Time) error) error
}

// MaterialStore transfers Vault-verified material from a root-only staging
// directory into one fixed service-owned credential directory. The configured
// service UID/GID must be resolved from the dedicated system user by the caller.
// No file is made group- or world-readable.
type MaterialStore struct {
	vault                SecretMaterializer
	installedDirectory   string
	stagingDirectory     string
	serviceUID           uint32
	serviceGID           uint32
	allowUnsafeAncestors bool
	// chainCopy is where an adopted chain is kept durably (GenerationChainCopy).
	chainCopy string
}
