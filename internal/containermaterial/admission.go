// Package containermaterial authenticates a root-owned container profile and
// the actual upstream task before any task-bound secret or no-secret delivery.
package containermaterial

import (
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
)

var ErrPending = errors.New("container material authority is pending")

// Profile's zero value grants nothing. A signed no-secret profile is checked
// through the same path as a profile with exact OCI Vault references.
type Profile struct {
	profile            cellspec.Profile
	identity           cellspec.Identity
	role               string
	fingerprint        string
	specSHA256         string
	hosts              []cellspec.HostGrant
	intent             delivery.Intent
	runtimePolicy      string
	runtimeOperationID string
	continuation       *Profile
}
