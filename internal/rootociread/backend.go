// Package rootociread implements finite OCI observations inside the root process.
package rootociread

import (
	"errors"
	"sync"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

var ErrPending = errors.New("root OCI observation dependency is pending")

type Backend struct {
	factory *ociclient.Factory
	mu      sync.RWMutex
	journal oci.JournalReader
	images  oci.ImageQualificationVerifier
	bound   bool
}
