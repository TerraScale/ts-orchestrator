// Package rootfoundation owns foundation and source OCI effects in the root
// process. Ordinary callers receive only the rootoci typed IPC operations.
package rootfoundation

import (
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

var ErrScope = errors.New("root foundation request differs from current protected authority")

type Backend struct {
	factory  *ociclient.Factory
	home     *region.HomeIAMAuthority
	baked    bootstrapstart.BakedInputs
	anchor   bootstrap.VerifiedBootstrapAnchor
	template bootstrap.VerifiedStartupTemplate
	cell     string
}
