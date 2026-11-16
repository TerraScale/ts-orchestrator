package manager

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

var ErrEnrollmentUncertain = errors.New("NetBird setup-key request is unresolved; quiesce the dedicated manager before retrying")

// EnrollmentAuthority fences writes and drains earlier management requests after
// a lost POST. Quiesce must stop/wait/restart the same persistent manager store.
type EnrollmentAuthority struct {
	Check   func() error
	Quiesce func(context.Context) error
}

// EnrollmentVault uses create-once OCI storage and verifies CURRENT bytes before
// delivery succeeds. It never rotates an existing secret or accepts a name alone.
type EnrollmentVault struct {
	Target     vaultsecret.Target
	Management vaultsecret.VaultClient
	Bundles    vaultsecret.BundleClient
	Name       string
}

type EnrollmentResult struct {
	OperationID string `json:"operation_id"`
	KeyID       string `json:"key_id"`
	SecretID    string `json:"secret_id"`
}
